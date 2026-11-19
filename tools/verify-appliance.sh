#!/bin/sh
# Read-only acceptance check for an installed SD-WAN package on pfSense CE.
set -eu

if [ "$#" -ne 1 ]; then
    echo "Usage: sh verify-appliance.sh <expected-package-version>" >&2
    exit 2
fi

package=pfSense-pkg-SDWAN
installed=$(pkg query '%v' "$package")
if [ "$installed" != "$1" ]; then
    printf 'Installed %s version %s; expected %s\n' "$package" "$installed" "$1" >&2
    exit 1
fi
printf 'pfSense %s · %s %s · %s\n' "$(cat /etc/version)" "$package" "$installed" "$(pkg config ABI)"
pkg check -s "$package"
/usr/local/etc/rc.d/sdwand.sh status

/usr/local/bin/php -r '
require_once("config.inc");
require_once("/usr/local/pkg/sdwan.inc");
require_once("/usr/local/pkg/sdwan_engine.inc");

$expected = [
    "package" => static fn($row) => strtolower($row["name"] ?? "") === "sdwan",
    "menu" => static fn($row) => ltrim($row["url"] ?? "", "/") === "sdwan/status.php",
    "service" => static fn($row) => ($row["name"] ?? "") === "sdwand",
];
foreach ($expected as $entry => $match) {
    $rows = config_get_path("installedpackages/" . $entry, []);
    if (!is_array($rows) || !array_filter($rows, static fn($row) => is_array($row) && $match($row))) {
        fwrite(STDERR, "Missing SD-WAN " . $entry . " registration.\n");
        exit(1);
    }
}

try {
    $config = sdwan_get_config();
    $snapshot = sdwan_read_snapshot();
    if (($snapshot["config_revision"] ?? null) !== sdwan_config_revision($config)) {
        throw new RuntimeException();
    }
} catch (Throwable $error) {
    fwrite(STDERR, "No current SD-WAN sample matching the saved configuration.\n");
    exit(1);
}
printf("Package, Services menu and service registered. Latest sample: %d seconds, %d members, %d policies.\n",
    time() - $snapshot["generated_at"], count($snapshot["members"]), count($snapshot["policies"]));

require_once("filter.inc");
$abi = function_exists("filter_sdwan_binding_api") ? filter_sdwan_binding_api() : "unavailable";
printf("Native forwarding ABI: %s.\n", $abi);
if (is_readable("/var/log/system.log")) {
    require_once("syslog.inc");
    $rows = conv_log_filter("/var/log/system.log", 500, 500, "", "");
    $events = array_filter($rows, static fn($row) => ($row["process"] ?? null) === "sdwan");
    printf("SD-WAN events in recent native System Logs rows: %d.\n", count($events));
}
'
