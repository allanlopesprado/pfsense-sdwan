#!/bin/sh
# Run from any directory. PHP_BIN may point to a compatible PHP CLI.
set -eu
cd "$(dirname "$0")/.."
PHP_BIN=${PHP_BIN:-php}
"$PHP_BIN" -v
python3 tests/check_port.py
python3 tools/update-release-index.py --check
python3 -B tests/release_notes.py
python3 -B tests/package_lifecycle.py "$PHP_BIN"
python3 -B tests/lab/test_observe_path.py
find files tests -type f \( -name '*.php' -o -name '*.inc' \) -print0 |
    xargs -0 -n 1 "$PHP_BIN" -l
"$PHP_BIN" tests/behavior.php
"$PHP_BIN" tests/policy_topology.php
"$PHP_BIN" tests/system_logs.php
"$PHP_BIN" tests/core_routes.php
"$PHP_BIN" tests/steering_preflight.php
"$PHP_BIN" tests/steering.php
python3 -B tests/steering_daemon.py "$PHP_BIN"
"$PHP_BIN" tests/config_edits.php
python3 -B tests/widget.py "$PHP_BIN"
"$PHP_BIN" tests/release.php
"$PHP_BIN" -d disable_functions=curl_init,curl_setopt_array,curl_exec,curl_getinfo tests/release_transport.php
if [ "${REQUIRE_NATIVE_SOCKET_TEST:-0}" = "1" ]; then
    python3 tests/daemon_integration.py --php "$PHP_BIN" --require-unix
else
    python3 tests/daemon_integration.py --php "$PHP_BIN"
fi
