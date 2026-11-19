"""Render the real PHP fragment against the pinned dashboard styles in Chrome."""
import base64
from contextlib import ExitStack
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time
from urllib.parse import parse_qs
from urllib.request import Request, urlopen


def preview_page(theme, widget):
    css = "pfSense.css" if theme == "light" else "pfSense-dark.css"
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="icon" href="data:,"><link rel="stylesheet" href="/vendor/font-awesome/css/all.min.css">
<link rel="stylesheet" href="/css/{css}"><title>SD-WAN</title>
<script src="/vendor/jquery/jquery-3.7.1.min.js"></script>
<script>var events=[],ajaxspecs=[]; function register_ajax(w){{ajaxspecs.push(w);}}</script>
</head><body id="index"><main>
<div class="panel panel-default" id="widget-sdwan-0"><div class="panel-heading"><h2 class="panel-title">
<a href="/sdwan/status.php">SD-WAN</a><span class="widget-heading-icon">
<a data-toggle="collapse" href="#widget-sdwan-0_panel-body" aria-label="Collapse widget"><i class="fa-solid fa-minus-circle" aria-hidden="true"></i></a>
<a data-toggle="close" href="#widget-sdwan-0" aria-label="Remove widget"><i class="fa-solid fa-times-circle" aria-hidden="true"></i></a>
</span></h2></div><div id="widget-sdwan-0_panel-body" class="panel-body collapse in">{widget}</div></div>
</main><script>events.forEach(function(f){{f();}});</script></body></html>"""


class WidgetHandler(SimpleHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        params = parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode())
        if self.path != "/widgets/widgets/sdwan.widget.php" or params != {"ajax": ["ajax"], "widgetkey": ["sdwan-0"]}:
            self.send_error(400)
            return
        content = (Path(self.directory) / "refresh.html").read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=UTF-8")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)


def verify_dashboard_layout(core, output, widget, fragment):
    www = core.resolve() / "src/usr/local/www"
    for name in ("css/pfSense-dark.css", "css/fonts/Roboto-Regular.woff2", "vendor/bootstrap/css/bootstrap.min.css",
                 "vendor/font-awesome/css/all.min.css", "vendor/jquery/jquery-3.7.1.min.js",
                 "vendor/jquery-ui/jquery-ui-1.13.2.min.css"):
        if not (www / name).is_file():
            raise RuntimeError(f"Missing dashboard dependency in the core checkout: {name}")
    chrome = shutil.which("google-chrome") or shutil.which("chromium")
    driver = shutil.which("chromedriver")
    if not chrome or not driver:
        raise RuntimeError("Install Chrome and a matching chromedriver for the visual test")
    output.mkdir(parents=True, exist_ok=True)
    with ExitStack() as stack:
        web = Path(stack.enter_context(tempfile.TemporaryDirectory()))
        for name in ("css", "vendor"):
            (web / name).symlink_to(www / name, target_is_directory=True)
        (web / "refresh.html").write_text(fragment)
        for theme in ("light", "dark"):
            (web / f"{theme}.html").write_text(preview_page(theme, widget))
        server = ThreadingHTTPServer(("127.0.0.1", 0), partial(WidgetHandler, directory=str(web)))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        stack.callback(server.server_close)
        stack.callback(server.shutdown)
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        process = subprocess.Popen([driver, f"--port={port}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        stack.callback(process.wait, timeout=10)
        stack.callback(process.terminate)

        def api(method, path, payload=None):
            req = Request(f"http://127.0.0.1:{port}{path}", method=method,
                          data=None if payload is None else json.dumps(payload).encode(),
                          headers={"Content-Type": "application/json"})
            with urlopen(req, timeout=35) as response:
                return json.load(response)["value"]

        for _ in range(100):
            try:
                if api("GET", "/status")["ready"]:
                    break
            except OSError:
                pass
            time.sleep(.1)
        options = {"binary": chrome, "args": ["--headless", "--no-sandbox", "--disable-dev-shm-usage",
                                             "--disable-background-networking", "--force-device-scale-factor=1"]}
        session = api("POST", "/session", {"capabilities": {"alwaysMatch": {"goog:chromeOptions": options}}})
        prefix = "/session/" + session["sessionId"]
        stack.callback(api, "DELETE", prefix)

        def call(path, payload):
            return api("POST", prefix + path, payload)

        def js(script, *args):
            return call("/execute/sync", {"script": script, "args": list(args)})

        metrics = []
        for theme in ("light", "dark"):
            for width in (640, 360, 320):
                call("/goog/cdp/execute", {"cmd": "Emulation.setDeviceMetricsOverride",
                     "params": {"width": width, "height": 800, "deviceScaleFactor": 1, "mobile": False}})
                call("/url", {"url": f"http://127.0.0.1:{server.server_port}/{theme}.html"})
                assert js("return ajaxspecs.length===1 && ajaxspecs[0].freq===10 && !!window.jQuery")
                call("/execute/async", {"args": [], "script":
                     "const done=arguments[0]; document.fonts.ready.then(()=>done(true));"})
                js("document.querySelector('.panel-title a').focus()")
                tabs = []
                for _ in range(5):
                    call("/actions", {"actions": [{"type": "key", "id": "keyboard", "actions":
                         [{"type": "keyDown", "value": "\ue004"}, {"type": "keyUp", "value": "\ue004"}]}]})
                    tabs.append(js("return document.activeElement.getAttribute('href')"))
                expected = [f"/sdwan/diagnostics.php?policy={p}" for p in ("Voice", "BranchVPN", "Backups")]
                assert tabs[-3:] == expected, tabs
                # Drive the real fragment callback, including its HTTP method and parameter names.
                updated = call("/execute/async", {"args": [], "script": """
                    const done=arguments[0], w=ajaxspecs[0];
                    document.querySelector('.sdwan-widget-rtt').textContent='pending-test';
                    $.post(w.url,w.parms).done(html=>{
                        w.callback(html);
                        done(document.querySelector('.sdwan-widget-rtt').textContent==='23.45');
                    }).fail(()=>done(false));
                """})
                assert updated and js("return document.activeElement.getAttribute('href')") == expected[-1]
                js("document.activeElement.blur();")
                layout_script = """
                    const panel=document.querySelector('.panel'), region=panel.querySelector('.sdwan-status-widget');
                    const nodes=[panel, region, ...region.querySelectorAll('table, tr, th, td, small, p')];
                    const box=panel.getBoundingClientRect();
                    function rgba(css) {return css.match(/[0-9.]+/g).map(Number);}
                    function over(rgb,paint) {
                        const alpha=paint.length===4 ? paint[3] : 1;
                        return rgb.map((v,i)=>v*(1-alpha)+paint[i]*alpha);
                    }
                    function luminance(rgb) {
                        const [r,g,b]=rgb.map(v=>v/255).map(v=>v<=.04045 ? v/12.92 : ((v+.055)/1.055)**2.4);
                        return .2126*r+.7152*g+.0722*b;
                    }
                    function contrast(el) {
                        const layers=[];
                        for(let p=el;p;p=p.parentElement) layers.unshift(rgba(getComputedStyle(p).backgroundColor));
                        const bg=layers.reduce(over,[255,255,255]);
                        const a=luminance(bg),b=luminance(over(bg,rgba(getComputedStyle(el).color)));
                        return (Math.max(a,b)+.05)/(Math.min(a,b)+.05);
                    }
                    const readouts=region.querySelectorAll('tbody th, tbody a, tbody td, .sdwan-widget-note, .sdwan-widget-note a');
                    const rows=region.querySelectorAll('tbody tr');
                    return {width:box.width,height:Math.ceil(box.height),viewport:innerWidth,
                            horizontalOverflow:Math.max(...nodes.map(e=>e.scrollWidth-e.clientWidth)),
                            background:getComputedStyle(document.body).backgroundColor,
                            rows:rows.length,
                            neutralStatusCells:Array.from(rows).every(row=>Array.from(row.cells).every(c=>!c.className.includes('bg-'))),
                            gatewayStates:Array.from(rows).map(row=>row.lastElementChild.textContent.trim()),
                            latency:Array.from(rows).map(row=>row.querySelector('.sdwan-widget-rtt').textContent.trim()),
                            timestamps:region.querySelectorAll('time').length,
                            minimumReadoutContrast:Math.min(...Array.from(readouts,contrast)),
                            positiveTabindex:panel.querySelectorAll('[tabindex]:not([tabindex="-1"]):not([tabindex="0"])').length};
                """
                data = js(layout_script)
                assert data["width"] == width and data["viewport"] == width and data["horizontalOverflow"] <= 1, data
                assert data["rows"] == 3 and data["positiveTabindex"] == 0
                assert data["neutralStatusCells"] and data["gatewayStates"] == ["Warning", "Online", "Down"]
                assert data["latency"] == ["23.45", "9.8", "—"] and data["timestamps"] == 0
                assert data["minimumReadoutContrast"] >= 4.5, data
                expected_bg = "rgb(245, 245, 245)" if theme == "light" else "rgb(33, 33, 33)"
                assert data["background"] == expected_bg, data
                shot = call("/goog/cdp/execute", {"cmd": "Page.captureScreenshot", "params": {
                    "format": "png", "clip": dict(js("""const r=document.querySelector('.panel').getBoundingClientRect();
                    return {x:r.left+scrollX,y:r.top+scrollY,width:r.width,height:Math.ceil(r.height)};"""), scale=1)}})
                png = base64.b64decode(shot["data"], validate=True)
                assert png[:8] == b"\x89PNG\r\n\x1a\n" and struct.unpack(">II", png[16:24]) == (width, data["height"])
                (output / f"widget-{theme}-{width}.png").write_bytes(png)
                js("""document.querySelector('tbody th').firstChild.textContent='X'.repeat(32);
                      document.querySelector('.sdwan-widget-detail').append('Y'.repeat(96));""")
                stress = js(layout_script)["horizontalOverflow"]
                assert stress <= 1, (theme, width, stress)
                metrics.append(dict(data, theme=theme, tabOrder=tabs, focusRetainedAfterRefresh=True,
                                    longIdentifierOverflow=stress))
        (output / "widget-fragment.html").write_text(widget)
        (output / "metrics.json").write_text(json.dumps(metrics, indent=2) + "\n")
        print("ok - six native theme/width screenshots, no horizontal overflow, keyboard navigation and AJAX focus")
