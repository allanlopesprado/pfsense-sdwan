#!/usr/bin/env python3
"""Exercise the pfSense pkg lifecycle entry points with isolated service and registry adapters."""
import json
import os
from pathlib import Path
import shlex
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


def check_shell_hooks(tmp, php):
    log = tmp / "calls"
    helper = tmp / "invalidate.inc"
    state = tmp / "sdwan-observer.json"
    log_state = tmp / "sdwan-observer.json.events"
    receipt = tmp / "sdwan-observer.json.forwarded"
    lock = tmp / "sdwan-observer.json.lock"
    settings_lock = tmp / "sdwan-settings.lock"
    upgrade_lock = tmp / "sdwan-package-upgrade.lock"
    commit = tmp / "sdwan-filter-commit.json"
    pid = tmp / "sdwand.pid"
    watchdog_pid = tmp / "sdwan-expiry.pid"
    removal_ready = tmp / "sdwan-package-removal.ready"
    fpm_pid = tmp / "php-fpm.pid"
    service = tmp / "rc.d" / "sdwand.sh"
    service.parent.mkdir()
    service.write_text('''#!/bin/sh
printf 'service %s\\n' "$1" >> "$CALLS"
test "$SDWAN_PACKAGE_REMOVING" = 1 || exit 64
if [ "$1" = stop ]; then
    exit "$STOP_RESULT"
fi
exit "$STATUS_RESULT"
''')
    service.chmod(0o755)
    registry = tmp / "php"
    registry.write_text('''#!/bin/sh
if [ "$1" = -r ]; then
    exec "$PHP_TEST" -d "include_path=$NATIVE_PHP" "$@"
fi
printf '%s\\n' "$*" >> "$CALLS"
if [ "$2" = "$INVALIDATE_HELPER" ]; then
    exit "$WITHDRAWAL_RESULT"
fi
exit "$REGISTRY_RESULT"
''')
    registry.chmod(0o755)
    lockf = tmp / "lockf"
    lockf.write_text('''#!/bin/sh
test "$1 $2 $3" = '-kns -t 0' || exit 64
test -f "$4" && test "$4" != "$BUSY_LOCK" || exit 1
shift 4
exec "$@"
''')
    lockf.chmod(0o755)
    native_php = tmp / "native"
    native_php.mkdir()
    for name in ("config", "functions", "filter", "shaper", "captiveportal", "pfsense-utils"):
        (native_php / f"{name}.inc").write_text("<?php\n")
    (native_php / "pkg-utils.inc").write_text('''<?php
function pkg_remove_prefix(&$name) {
    $name = substr($name, strlen('pfSense-pkg-'));
}
function delete_package_xml($name, $phase) {
    if ($GLOBALS['pkg_interface'] !== 'console') { exit(64); }
    file_put_contents(getenv('CALLS'), "offline $name $phase\\n", FILE_APPEND);
}
''')
    for phase in ("install", "deinstall"):
        contents = (FILES / f"pkg-{phase}.in").read_text()
        # Model the same absolute paths under a temporary root. No system tools are changed.
        for source, target in [
            ("/usr/local/etc/rc.d/sdwand.sh", str(service)),
            ("/usr/local/bin/php", str(registry)),
            ("/usr/local/pkg/sdwan_invalidate.inc", str(helper)),
            ("/usr/bin/lockf", str(lockf)),
            ("/var/run/sdwan-observer.json", str(state)),
            ("/var/run/sdwan-filter-commit.json", str(commit)),
            ("/var/run/sdwand.pid", str(pid)),
            ("/var/run/sdwan-expiry.pid", str(watchdog_pid)),
            ("/var/run/sdwan-package-removal.ready", str(removal_ready)),
            ("/var/run/sdwan-settings.lock", str(settings_lock)),
            ("/var/run/sdwan-package-upgrade.lock", str(upgrade_lock)),
            ("/var/run/php-fpm.pid", str(fpm_pid)),
        ]:
            contents = contents.replace(source, shlex.quote(Path(target).as_posix()))
        contents = contents.replace("%%PORTNAME%%", "pfSense-pkg-SDWAN")
        (tmp / phase).write_text(contents)

    def run(phase, when, root="/", code=0, **overrides):
        env = dict(os.environ, PKG_ROOTDIR=root, CALLS=log.as_posix(), PHP_TEST=Path(php).as_posix(),
                   NATIVE_PHP=native_php.as_posix(), INVALIDATE_HELPER=helper.as_posix(),
                   PKG_CHROOTED="", PKG_UPGRADE="", STOP_RESULT="0", STATUS_RESULT="1", WITHDRAWAL_RESULT="0",
                   REGISTRY_RESULT="0", BUSY_LOCK="")
        env.update(overrides)
        result = subprocess.run(["sh", (tmp / phase).as_posix(), "pfSense-pkg-SDWAN", when],
                                env=env, text=True, capture_output=True)
        if result.returncode != code:
            raise AssertionError(f"Unexpected {phase} {when} result: {result}")
        return result

    def calls():
        return log.read_text().splitlines() if log.exists() else []

    state.write_text("measurement")
    log_state.write_text("event suppression state")
    for phase, when in [("install", "POST-INSTALL"), ("deinstall", "DEINSTALL"),
                        ("deinstall", "POST-DEINSTALL")]:
        run(phase, when, root="/staging/image")
        run(phase, when, PKG_CHROOTED="true")
    run("deinstall", "DEINSTALL", PKG_UPGRADE="true")
    run("deinstall", "POST-DEINSTALL", PKG_UPGRADE="true")
    run("install", "PRE-INSTALL")
    if calls() or not state.exists() or not log_state.exists():
        raise AssertionError("A staged install or unsupported phase touched the host")

    deferred = run("install", "POST-INSTALL")
    if calls() or "rc.packages pfSense-pkg-SDWAN POST-INSTALL" not in deferred.stderr:
        raise AssertionError("Missing PHP-FPM must defer registration and show how to resume")
    fpm_pid.touch()
    run("install", "POST-INSTALL", PKG_UPGRADE="true")
    run("deinstall", "DEINSTALL")
    assert removal_ready.exists()
    run("deinstall", "POST-DEINSTALL")
    assert not removal_ready.exists()
    if state.exists() or log_state.exists():
        raise AssertionError("Runtime measurement or event suppression state survived removal")
    expected = ["-f /etc/rc.packages pfSense-pkg-SDWAN POST-INSTALL", "service stop",
                "-f /etc/rc.packages pfSense-pkg-SDWAN DEINSTALL",
                "-f /etc/rc.packages pfSense-pkg-SDWAN POST-DEINSTALL"]
    if calls() != expected:
        raise AssertionError(f"Unexpected hook order {calls()}")

    # The installed helper invalidates runtime decisions even if the service is down.
    helper.touch()
    for artifact in (state, receipt, lock, log_state, pid, commit, settings_lock, upgrade_lock):
        artifact.touch()
    removal_ready.touch()  # A prior interrupted transaction must not authorize this cleanup.
    still_running = run("deinstall", "DEINSTALL", code=1, STOP_RESULT="1", STATUS_RESULT="0")
    assert "observer is still running" in still_running.stderr
    assert calls()[-2:] == ["service stop", "service status"] and receipt.exists()
    assert not removal_ready.exists()
    run("deinstall", "DEINSTALL", code=1, WITHDRAWAL_RESULT="1")
    assert calls()[-2:] == ["service stop", "-f " + helper.as_posix()]
    before = calls()
    run("deinstall", "POST-DEINSTALL")  # Default pkg mode may call it after a failed DEINSTALL.
    assert calls() == before
    assert receipt.exists() and lock.exists() and commit.exists()
    assert settings_lock.exists() and upgrade_lock.exists()
    run("deinstall", "DEINSTALL", code=1, REGISTRY_RESULT="1")
    before = calls()
    run("deinstall", "POST-DEINSTALL")
    assert calls() == before
    assert receipt.exists() and lock.exists() and commit.exists()
    run("deinstall", "DEINSTALL", STOP_RESULT="1")
    if calls()[-4:] != ["service stop", "service status", "-f " + helper.as_posix(), expected[2]]:
        raise AssertionError("Removal did not invoke invalidation before unregistering")
    assert receipt.exists() and lock.exists()
    run("deinstall", "POST-DEINSTALL", BUSY_LOCK=upgrade_lock.as_posix())
    assert not removal_ready.exists()
    assert not any(artifact.exists() for artifact in (state, receipt, lock, log_state, pid, commit))
    assert not settings_lock.exists() and upgrade_lock.exists()
    helper.unlink()
    receipt.touch()
    no_helper = run("deinstall", "DEINSTALL", code=1)
    assert "withdrawal cannot be checked" in no_helper.stderr and receipt.exists()
    receipt.unlink()
    # A surviving watchdog must be stopped before deleting the helper.
    watchdog_pid.touch()
    surviving_guard = run("deinstall", "DEINSTALL", code=1, STATUS_RESULT="0")
    assert "expiry guard is still running" in surviving_guard.stderr
    watchdog_pid.unlink()
    # Cleanup can be retried when the prior attempt already removed the service.
    service.unlink()
    run("deinstall", "DEINSTALL")
    if calls()[-1] != expected[2]:
        raise AssertionError("Removal recovery failed")
    fpm_pid.unlink()
    run("deinstall", "DEINSTALL")
    run("deinstall", "POST-DEINSTALL")
    assert calls()[-2:] == ["offline SDWAN deinstall", "offline SDWAN post-deinstall"]


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
        check_shell_hooks(Path(root), php)
        check_invalidation(Path(root), php)
    print("ok - package hooks, worker startup/replacement, staged roots and removal retry")
