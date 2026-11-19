#!/bin/sh
# Run from any directory. PHP_BIN may point to a compatible PHP CLI.
set -eu
cd "$(dirname "$0")/.."
PHP_BIN=${PHP_BIN:-php}
"$PHP_BIN" -v
python3 tests/check_port.py
find files tests -type f \( -name '*.php' -o -name '*.inc' \) -print0 |
    xargs -0 -n 1 "$PHP_BIN" -l
"$PHP_BIN" tests/behavior.php
"$PHP_BIN" tests/config_edits.php
if [ "${REQUIRE_NATIVE_SOCKET_TEST:-0}" = "1" ]; then
    python3 tests/daemon_integration.py --php "$PHP_BIN" --require-unix
else
    python3 tests/daemon_integration.py --php "$PHP_BIN"
fi
