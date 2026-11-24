"""Verify paired offline changes, safe compensation and scope validation."""

import importlib.util
import json
from pathlib import Path
import tempfile
from unittest.mock import patch


path = Path(__file__).resolve().parents[1] / "tools/paired-vti.py"
spec = importlib.util.spec_from_file_location("paired_vti", path)
pilot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pilot)

a = {"name": "hub", "wan": "wan", "vti": "opt2", "gateway": "VTI_BRANCH", "outer": "198.51.100.1",
     "inner": "169.254.33.1/30", "lan": "10.44.0.0/24", "ikeid": 11, "reqid": 101}
b = {"name": "branch", "wan": "wan", "vti": "opt3", "gateway": "VTI_HUB", "outer": "203.0.113.1",
     "inner": "169.254.33.2/30", "lan": "10.45.0.0/24", "ikeid": 12, "reqid": 102}


def configuration(site, peer, staged=False):
    ipsec = ""
    interface = ""
    routes = ""
    if staged:
        ipsec = (f"<phase1><ikeid>{site['ikeid']}</ikeid><interface>wan</interface>"
                 f"<iketype>ikev2</iketype><remote-gateway>{peer['outer']}</remote-gateway>"
                 f"<authentication_method>pre_shared_key</authentication_method>"
                 f"<pre-shared-key>FIXTURE_ONLY</pre-shared-key></phase1>"
                 f"<phase2><ikeid>{site['ikeid']}</ikeid><reqid>{site['reqid']}</reqid><mode>vti</mode>"
                 f"<localid><address>{site['inner'].split('/')[0]}</address></localid>"
                 f"<remoteid><address>{peer['inner'].split('/')[0]}</address></remoteid></phase2>")
        interface = f"<{site['vti']}><if>ipsec{site['reqid']}</if><enable/></{site['vti']}>"
        routes = (f"<gateways><gateway_item><name>{site['gateway']}</name><interface>{site['vti']}</interface>"
                  f"<ipprotocol>inet</ipprotocol><gateway>{peer['inner'].split('/')[0]}</gateway></gateway_item></gateways>"
                  f"<staticroutes><route><network>{peer['lan']}</network><gateway>{site['gateway']}</gateway></route></staticroutes>")
    return (f"<pfsense><interfaces><wan><ipaddr>{site['outer']}</ipaddr></wan>"
            f"<lan><ipaddr>{site['lan'].replace('0/24', '1')}</ipaddr><subnet>24</subnet></lan>{interface}</interfaces>"
            f"<ipsec><enable/>{ipsec}</ipsec><nat><outbound><mode>automatic</mode></outbound></nat>"
            f"<filter><rule><type>block</type><floating>yes</floating><direction>out</direction>"
            f"<quick>yes</quick><ipprotocol>inet</ipprotocol><interface>wan</interface><source><any/></source>"
            f"<destination><address>{peer['lan']}</address></destination></rule></filter>{routes}</pfsense>").encode()


def reject(action, text, error=ValueError):
    try:
        action()
    except error as failure:
        assert text in str(failure), failure
    else:
        raise AssertionError("Expected rejection.")


with tempfile.TemporaryDirectory(prefix="paired-vti-") as temporary:
    root = Path(temporary)
    plan = root / "plan.json"
    plan.write_text(json.dumps({"schema": 1, "sites": [a, b]}), encoding="utf-8")
    changes = []
    for site, peer in ((a, b), (b, a)):
        folder = root / site["name"]
        folder.mkdir()
        current = folder / "current.xml"
        staged = folder / "staged.xml"
        before, after = configuration(site, peer), configuration(site, peer, staged=True)
        current.write_bytes(before)
        staged.write_bytes(after)
        changes.append((current, staged, before, after))

    assert "FIXTURE_ONLY" not in json.dumps(pilot.execute(root, plan, "preview"))
    assert all(current.read_bytes() == before for current, _, before, _ in changes)
    endpoint, staged, _, after = changes[1]
    staged.write_bytes(after.replace(b"FIXTURE_ONLY", b"DIFFERENT_FIXTURE_ONLY"))
    reject(lambda: pilot.execute(root, plan, "apply"), "keys differ")
    staged.write_bytes(after.replace(b"automatic", b"disabled"))
    reject(lambda: pilot.execute(root, plan, "apply"), "outside the new VTI objects")
    staged.write_bytes(after)

    def fail_second(target, data):
        if target == endpoint:
            raise OSError("simulated second endpoint write")
        atomic_write(target, data)

    atomic_write = pilot.atomic_write
    with patch.object(pilot, "atomic_write", fail_second):
        reject(lambda: pilot.execute(root, plan, "apply"), "second endpoint write", OSError)
    assert all(current.read_bytes() == before for current, _, before, _ in changes)
    pilot.execute(root, plan, "apply")
    assert all(current.read_bytes() == after for current, _, _, after in changes)
    endpoint.write_bytes(b"operator change")
    reject(lambda: pilot.execute(root, plan, "rollback"), "differs from both saved revisions")
    assert endpoint.read_bytes() == b"operator change"
    endpoint.write_bytes(after)
    pilot.execute(root, plan, "rollback")
    assert all(current.read_bytes() == before for current, _, before, _ in changes)
    plan.write_text(json.dumps({"schema": 1, "sites": [a, {**b, "lan": a["lan"]}]}), encoding="utf-8")
    reject(lambda: pilot.execute(root, plan, "apply"), "overlapping")
print("ok - paired VTI preview, WAN guard, scope validation, partial write compensation and rollback")
