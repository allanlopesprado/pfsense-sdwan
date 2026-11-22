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
    harness = "require " + json.dumps(str(FILES / "usr/local/pkg/sdwan.inc")) + ";\n" + """$calls = [];
$progress = [];
$services = json_decode($argv[3], true, 512, JSON_THROW_ON_ERROR);
$writes = 0;
function config_get_path($path, $default) {
    if ($path !== 'installedpackages/service') { exit(64); }
    return $GLOBALS['services'];
}
function config_set_path($path, $value) {
    if ($path !== 'installedpackages/service') { exit(64); }
    $GLOBALS['services'] = $value;
    $GLOBALS['writes']++;
}
function mwexec($command, $nologentry = false) {
    global $calls, $argv;
    $calls[] = $command;
    return str_ends_with($command, ' status') ? (int)$argv[1] : (int)$argv[2];
}
function update_status($message) {
    $GLOBALS['progress'][] = trim($message);
}
""" + hook + "\necho json_encode([$calls, $services, $writes, $progress]);"
    rcfile = "/usr/local/etc/rc.d/sdwand.sh "
    current = [{"name": "other", "rcfile": "other.sh"}, {"name": "sdwan", "rcfile": "sdwand.sh"},
               {"name": "sdwand", "rcfile": "unrelated.sh"}]
    legacy = {"name": "sdwand", "rcfile": "sdwand.sh"}
    for status, action, services, writes in [(0, "restart", [legacy, *current, legacy], 1), (1, "start", current, 0)]:
        messages = {
            0: f"SD-WAN observer {action} requested. Check Services > SD-WAN > Status for a current observation.",
            1: f"SD-WAN observer {action} failed (exit 1). Package registration continues. "
               "Check Status > Services and System Logs.",
            127: f"SD-WAN observer {action} failed (exit 127). Package registration continues. "
                 "Check Status > Services and System Logs.",
        }
        for action_exit, message in messages.items():
            command = [php, "-r", harness, "--", str(status), str(action_exit), json.dumps(services)]
            result = subprocess.run(command, check=True, text=True, capture_output=True)
            expected = [[rcfile + "status", rcfile + action], current, writes, [message]]
            if json.loads(result.stdout) != expected:
                raise AssertionError(f"Unexpected {action} result for exit {action_exit}: {result.stdout}")


def check_shell_hooks(tmp):
    log = tmp / "calls"
    helper = tmp / "invalidate.inc"
    state = tmp / "sdwan-observer.json"
    log_state = tmp / "sdwan-observer.json.events"
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
    log_state.write_text("event suppression state")
    for phase, when in [("install", "POST-INSTALL"), ("deinstall", "DEINSTALL"),
                        ("deinstall", "POST-DEINSTALL")]:
        run(phase, when, root="/staging/image")
    run("install", "PRE-INSTALL")
    if calls() or not state.exists() or not log_state.exists():
        raise AssertionError("A staged install or unsupported phase touched the host")

    deferred = run("install", "POST-INSTALL")
    if calls() or "rc.packages pfSense-pkg-SDWAN POST-INSTALL" not in deferred.stderr:
        raise AssertionError("Missing PHP-FPM must defer registration and show how to resume")
    fpm_pid.touch()
    run("install", "POST-INSTALL")
    run("deinstall", "DEINSTALL")
    if state.exists() or log_state.exists():
        raise AssertionError("Runtime measurement or event suppression state survived removal")
    run("deinstall", "POST-DEINSTALL")
    expected = ["-f /etc/rc.packages pfSense-pkg-SDWAN POST-INSTALL", "service stop",
                "-f /etc/rc.packages pfSense-pkg-SDWAN DEINSTALL",
                "-f /etc/rc.packages pfSense-pkg-SDWAN POST-DEINSTALL"]
    if calls() != expected:
        raise AssertionError(f"Unexpected hook order {calls()}")

    # The installed helper invalidates runtime decisions even if the service is down.
    helper.touch()
    log_state.touch()
    run("deinstall", "DEINSTALL")
    if log_state.exists():
        raise AssertionError("Event suppression state survived removal with the helper installed")
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
    for name in (helper.name, "sdwan.inc", "sdwan_log.inc", "sdwan_preflight.inc"):
        (tmp / name).write_bytes((FILES / "usr/local/pkg" / name).read_bytes())
    state = tmp / "sdwan-observer.json"
    receipt = tmp / "sdwan-observer.json.forwarded"
    marker = tmp / "reload"
    (tmp / "sdwan_engine.inc").write_text("<?php const SDWAN_SNAPSHOT_PATH = __DIR__ . '/sdwan-observer.json';")
    (tmp / "config.inc").write_text("""<?php
        function config_get_path($path, $default) {
            if ($path !== 'gateways/sdwan_bindings/item') { exit(64); }
            return getenv('ACTIVE') === 'yes' ? [['trackers' => ['item' => ['301']]]] : $default;
        }
        function config_read_file($backup, $cache) { return getenv('UNREADABLE_CONFIG') !== 'yes'; }
        function fixture_monotonic() {
            static $time = 0;
            return $time += 1000000000;
        }
        function fixture_sleep($time) {}
    """)
    (tmp / "filter.inc").write_text("""<?php
        if (getenv('PATCHED') === 'yes') { function filter_sdwan_binding_api() { return 1; } }
    """)
    steering = (FILES / "usr/local/pkg/sdwan_steering.inc").read_text()
    for name, body in {
        "sdwan_steering_request_reload(): bool": """
            if (is_file(SDWAN_SNAPSHOT_PATH) ||
                sdwan_steering_read_receipt(SDWAN_SNAPSHOT_PATH . '.forwarded')['attempts'] < 1) {
                exit(65);
            }
            file_put_contents(__DIR__ . '/reload', 'queued');
            return getenv('FILTER_RESULT') !== 'queue-refused';
        """,
        "sdwan_steering_pf_rules(): ?array": """
            $result = getenv('FILTER_RESULT');
            if ($result === 'unavailable') {
                return null;
            }
            if ($result === 'already-closed' || ($result === 'applied' && is_file(__DIR__ . '/reload'))) {
                return ['block drop in quick on em0 inet all ridentifier 301',
                    'pass in quick on em0 inet all ridentifier 401'];
            }
            return ['pass in quick on em0 inet all ridentifier 301'];
        """,
    }.items():
        start = steering.index(f"function {name} {{")
        end = steering.index("\n}", start)
        steering = steering[:start] + f"function {name} {{" + body + steering[end:]
    steering = steering.replace("hrtime(true)", "fixture_monotonic()").replace("usleep(", "fixture_sleep(")
    (tmp / "sdwan_steering.inc").write_text(steering, encoding="utf-8")

    for active, patched, outcome, config_error, ok, requested in [
        (False, False, "ignored", False, True, False),
        (False, True, "ignored", False, True, False),
        (True, False, "ignored", False, True, False),
        (True, True, "already-closed", False, True, False),
        (True, True, "applied", False, True, True),
        (True, True, "accepted-stale", False, False, True),
        (True, True, "queue-refused", False, False, True),
        (True, True, "unavailable", False, False, True),
        (True, True, "applied", True, False, False),
    ]:
        state.write_text("prior choice")
        receipt.write_text("prior reload")
        env = dict(os.environ, ACTIVE="yes" if active else "", PATCHED="yes" if patched else "",
                   FILTER_RESULT=outcome, UNREADABLE_CONFIG="yes" if config_error else "")
        run = subprocess.run([php, "-d", f"include_path={tmp}", "-f", str(helper)], env=env,
                             text=True, capture_output=True, timeout=15)
        assert run.returncode == (0 if ok else 1), (outcome, run)
        assert not state.exists() and receipt.exists() != ok and marker.exists() == requested, (outcome, run)
        if not ok:
            assert "Cannot confirm withdrawal" in run.stderr, (outcome, run)
            if requested:
                pending = json.loads(receipt.read_text())
                assert pending["attempts"] == 1 and not pending["confirmed"], pending
                assert pending["accepted"] == (outcome != "queue-refused"), pending
            else:
                assert receipt.read_text() == "prior reload"
        marker.unlink(missing_ok=True)


if __name__ == "__main__":
    php = sys.argv[1] if len(sys.argv) > 1 else "php"
    check_install_xml(php)
    with tempfile.TemporaryDirectory(prefix="sdwan-lifecycle-") as root:
        check_shell_hooks(Path(root))
        check_invalidation(Path(root), php)
    print("ok - package hooks, worker startup/replacement, staged roots and removal retry")
