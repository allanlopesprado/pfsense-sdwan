#!/bin/sh
# Read-only acceptance check for an installed SD-WAN package on pfSense CE.
set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ] || { [ "$#" -eq 2 ] && [ "$2" != "--forwarding" ] && [ "$2" != "--forwarding-active" ]; }; then
    echo "Usage: sh verify-appliance.sh <expected-package-version> [--forwarding|--forwarding-active]" >&2
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

# The single-quoted argument is PHP source.
# shellcheck disable=SC2016
/usr/local/bin/php -r '
require_once("config.inc");
require_once("/usr/local/pkg/sdwan.inc");
require_once("/usr/local/pkg/sdwan_engine.inc");

$expected = [
    "package" => static fn($row) => strtolower($row["name"] ?? "") === "sdwan",
    "menu" => static fn($row) => ltrim($row["url"] ?? "", "/") === "sdwan/status.php",
];
foreach ($expected as $entry => $match) {
    $rows = config_get_path("installedpackages/" . $entry, []);
    if (!is_array($rows) || !array_filter($rows, static fn($row) => is_array($row) && $match($row))) {
        fwrite(STDERR, "Missing SD-WAN " . $entry . " registration.\n");
        exit(1);
    }
}

$service_name = version_compare($argv[1], "0.4.12", "<") ? "sdwand" : "sdwan";
$services = config_get_path("installedpackages/service", []);
$registered = array_values(array_filter((array)$services, static fn($row) =>
    is_array($row) && ($row["rcfile"] ?? "") === "sdwand.sh"));
if (count($registered) !== 1 || ($registered[0]["name"] ?? "") !== $service_name) {
    fwrite(STDERR, "Expected one registered SD-WAN service named " . $service_name . ".\n");
    exit(1);
}

try {
    // Keep the native pfSense $config global available for gateway discovery.
    $sdwan_settings = sdwan_get_config();
    $inventory = function_exists("sdwan_current_snapshot") ? sdwan_gateways() : [];
    $snapshot = function_exists("sdwan_current_snapshot") ?
        sdwan_current_snapshot($sdwan_settings, $inventory) : sdwan_read_snapshot();
    if (($snapshot["config_revision"] ?? null) !== sdwan_config_revision($sdwan_settings)) {
        throw new RuntimeException();
    }
} catch (Throwable $error) {
    fwrite(STDERR, "No current SD-WAN sample matching the saved configuration and monitored gateways.\n");
    exit(1);
}
printf("Package, Services menu and service registered. Latest sample: %d seconds, %d members, %d policies.\n",
    time() - $snapshot["generated_at"], count($snapshot["members"]), count($snapshot["policies"]));

require_once("filter.inc");
$abi = function_exists("filter_sdwan_binding_api") ? filter_sdwan_binding_api() : "unavailable";
printf("Native forwarding ABI: %s.\n", $abi);
$require_active = $argv[2] === "--forwarding-active";
if ($argv[2] === "--forwarding" || $require_active) {
    $steering = "/usr/local/pkg/sdwan_steering.inc";
    if (is_file($steering)) {
        require_once($steering);
    }
    if (!function_exists("sdwan_steering_supported") || !sdwan_steering_supported()) {
        fwrite(STDERR, "Native SD-WAN forwarding is unavailable on this appliance.\n");
        exit(1);
    }
    if ($require_active && (!function_exists("filter_sdwan_boot_ready") || !filter_sdwan_boot_ready())) {
        fwrite(STDERR, "No verified boot with the installed SD-WAN forwarding adapter.\n");
        exit(1);
    }
    if (!function_exists("sdwan_steering_pf_status") ||
        (new ReflectionFunction("sdwan_steering_pf_status"))->getNumberOfParameters() < 5 ||
        !function_exists("sdwan_steering_preflight_matches")) {
        fwrite(STDERR, "The installed package cannot verify the loaded PF match scope and fallback guard.\n");
        exit(1);
    }
    try {
        $bindings = sdwan_steering_bindings();
    } catch (UnexpectedValueException $error) {
        fwrite(STDERR, "Invalid saved SD-WAN forwarding bindings.\n");
        exit(1);
    }
    if (!$bindings) {
        fwrite(STDERR, "No SD-WAN forwarding bindings are configured.\n");
        exit(1);
    }
    $rules = sdwan_steering_pf_rules();
    $native = sdwan_steering_native($inventory);
    $verified = true;
    foreach ($bindings as $group => $binding) {
        $state = $snapshot["steering"][$group] ?? [];
        $approval = sdwan_steering_preflight($sdwan_settings, $binding["policy"], $group, $native);
        $status = "binding_changed";
        if (sdwan_steering_preflight_matches($binding, $approval) &&
            $binding["policy_revision"] === sdwan_steering_policy_revision($sdwan_settings, $binding["policy"]) &&
            !empty($approval["rule_pairs"])) {
            $status = sdwan_steering_pf_status($binding, is_array($state) ? $state : [], $inventory, $rules,
                $approval["rule_pairs"]);
        }
        printf("Group %s, policy %s, trackers %s: %s.\n", $group, $binding["policy"],
            implode(", ", $binding["trackers"]), $require_active && $status === "blocked" ?
            "blocked; an active path is required" : $status);
        if ($status === "applied") {
            printf("  Gateways confirmed in PF: %s.\n", implode(", ", $state["pool"] ?? [$state["gateway"]]));
        }
        $verified = $verified && ($status === "applied" || (!$require_active && $status === "blocked"));
    }
    if (!$verified) {
        fwrite(STDERR, "Active PF rules could not be confirmed for every SD-WAN binding.\n");
        exit(1);
    }
}
if (is_readable("/var/log/system.log")) {
    require_once("syslog.inc");
    $rows = conv_log_filter("/var/log/system.log", 500, 500, "", "");
    $events = array_filter($rows, static fn($row) => ($row["process"] ?? null) === "sdwan");
    printf("SD-WAN events in recent native System Logs rows: %d.\n", count($events));
}
' -- "$installed" "${2:-}"
