#!/usr/bin/env python3
"""Exercise the pfSense pkg lifecycle entry points with isolated service and registry adapters."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET


FILES = Path(__file__).resolve().parents[1] / "files"


def check_install_xml(php):
    hook = ET.parse(FILES / "usr/local/pkg/sdwan.xml").findtext("custom_php_install_command")
    if not hook:
        raise AssertionError("Missing package installation hook")
    # Execute exactly the PHP fragment read by install_package_xml.
    harness = """$calls = [];
function mwexec($command, $nologentry = false) {
    global $calls, $argv;
    $calls[] = $command;
    return str_ends_with($command, ' status') ? (int)$argv[1] : 0;
}
""" + hook + "\necho json_encode($calls);"
    rcfile = "/usr/local/etc/rc.d/sdwand.sh "
    for status, action in [(0, "restart"), (1, "start")]:
        result = subprocess.run([php, "-r", harness, "--", str(status)],
                                check=True, text=True, capture_output=True)
        if json.loads(result.stdout) != [rcfile + "status", rcfile + action]:
            raise AssertionError("Unexpected worker lifecycle during package registration")


def check_shell_hooks(tmp):
    log = tmp / "calls"
    helper = tmp / "invalidate.inc"
    state = tmp / "sdwan-observer.json"
    fpm_pid = tmp / "php-fpm.pid"
    service = tmp / "rc.d" / "sdwand.sh"
    service.parent.mkdir()
    service.write_text('#!/bin/sh\nprintf "service %s\\n" "$1" >> "$CALLS"\n')
    service.chmod(0o755)
    registry = tmp / "php"
    registry.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$CALLS"\n')
    registry.chmod(0o755)
    for phase in ("install", "deinstall"):
        contents = (FILES / f"pkg-{phase}.in").read_text()
        # Model the same absolute paths under a temporary root. No system tools are changed.
        for source, target in [
            ("%%PORTNAME%%", "pfSense-pkg-SDWAN"),
            ("/usr/local/etc/rc.d/sdwand.sh", str(service)),
            ("/usr/local/bin/php", str(registry)),
            ("/usr/local/pkg/sdwan_invalidate.inc", str(helper)),
            ("/var/run/sdwan-observer.json", str(state)),
            ("/var/run/php-fpm.pid", str(fpm_pid)),
        ]:
            contents = contents.replace(source, target)
        (tmp / phase).write_text(contents)

    def run(phase, when, root="/"):
        env = dict(os.environ, PKG_ROOTDIR=root, CALLS=str(log))
        return subprocess.run(["sh", str(tmp / phase), "pfSense-pkg-SDWAN", when],
                              env=env, check=True, text=True, capture_output=True)

    def calls():
        return log.read_text().splitlines() if log.exists() else []

    state.write_text("measurement")
    for phase, when in [("install", "POST-INSTALL"), ("deinstall", "DEINSTALL"),
                        ("deinstall", "POST-DEINSTALL")]:
        run(phase, when, root="/staging/image")
    run("install", "PRE-INSTALL")
    if calls() or not state.exists():
        raise AssertionError("A staged install or unsupported phase touched the host")

    deferred = run("install", "POST-INSTALL")
    if calls() or "rc.packages pfSense-pkg-SDWAN POST-INSTALL" not in deferred.stderr:
        raise AssertionError("Missing PHP-FPM must defer registration and show how to resume")
    fpm_pid.touch()
    run("install", "POST-INSTALL")
    run("deinstall", "DEINSTALL")
    if state.exists():
        raise AssertionError("The measurement file survived removal")
    run("deinstall", "POST-DEINSTALL")
    expected = ["-f /etc/rc.packages pfSense-pkg-SDWAN POST-INSTALL", "service stop",
                "-f /etc/rc.packages pfSense-pkg-SDWAN DEINSTALL",
                "-f /etc/rc.packages pfSense-pkg-SDWAN POST-DEINSTALL"]
    if calls() != expected:
        raise AssertionError(f"Unexpected hook order {calls()}")

    # The installed helper invalidates runtime decisions even if the service is down.
    helper.touch()
    run("deinstall", "DEINSTALL")
    if calls()[-3:] != ["service stop", "-f " + str(helper), expected[2]]:
        raise AssertionError("Removal did not invoke invalidation before unregistering")
    helper.unlink()
    # Cleanup can be retried when the prior attempt already removed the service.
    service.unlink()
    run("deinstall", "DEINSTALL")
    if calls()[-1] != expected[2]:
        raise AssertionError("Removal recovery failed")


def check_invalidation(tmp, php):
    helper = tmp / "sdwan_invalidate.inc"
    helper.write_bytes((FILES / "usr/local/pkg/sdwan_invalidate.inc").read_bytes())
    state = tmp / "sdwan-observer.json"
    receipt = tmp / "sdwan-observer.json.forwarded"
    marker = tmp / "reload"
    (tmp / "sdwan_engine.inc").write_text("<?php const SDWAN_SNAPSHOT_PATH = __DIR__ . '/sdwan-observer.json';")
    (tmp / "config.inc").write_text("""<?php
        function config_get_path($path, $default) {
            if ($path !== 'gateways/sdwan_bindings/item') { exit(64); }
            return getenv('ACTIVE') === 'yes' ? [['group' => 'lab']] : $default;
        }
    """)
    (tmp / "filter.inc").write_text("""<?php
        if (getenv('PATCHED') === 'yes') { function filter_sdwan_binding_api() { return 1; } }
        function filter_configure() {
            if (file_exists(SDWAN_SNAPSHOT_PATH) || file_exists(SDWAN_SNAPSHOT_PATH . '.forwarded')) {
                exit(65);
            }
            file_put_contents(__DIR__ . '/reload', 'queued');
        }
    """)
    for active, patched in [(False, False), (False, True), (True, False), (True, True)]:
        state.write_text("prior choice")
        receipt.write_text("prior reload")
        env = dict(os.environ, ACTIVE="yes" if active else "", PATCHED="yes" if patched else "")
        subprocess.run([php, "-d", f"include_path={tmp}", "-f", str(helper)], env=env, check=True)
        if state.exists() or receipt.exists() or marker.exists() != (active and patched):
            raise AssertionError("Invalid cleanup or reload for the installed core and bindings")
        marker.unlink(missing_ok=True)


if __name__ == "__main__":
    php = sys.argv[1] if len(sys.argv) > 1 else "php"
    check_install_xml(php)
    with tempfile.TemporaryDirectory(prefix="sdwan-lifecycle-") as root:
        check_shell_hooks(Path(root))
        check_invalidation(Path(root), php)
    print("ok - package hooks, worker startup/replacement, staged roots and removal retry")
