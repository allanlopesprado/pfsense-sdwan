#!/usr/bin/env python3
"""Run the appliance verifier's real PHP against an isolated config and PF fixture."""
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]

CONFIG = """<?php
function config_get_path($path, $default = null) {
    return $GLOBALS['fixture_paths'][$path] ?? $default;
}
function config_path_enabled($path, $field): bool {
    return isset(config_get_path($path, [])[$field]);
}
function get_real_interface($name, $family, $real, $flush): ?string {
    return config_get_path('interfaces', [])[$name]['if'] ?? null;
}
require_once __DIR__ . '/sdwan_steering.inc';
$settings = ['version' => '1', 'members' => [
    ['name' => 'a', 'gateway' => 'A', 'cost' => '1'], ['name' => 'b', 'gateway' => 'B', 'cost' => '2']
], 'slas' => [['name' => 's', 'latency_ms' => '100', 'loss_pct' => '5']],
    'policies' => [['name' => 'p', 'sla' => 's', 'strategy' => 'cost', 'members' => ['a', 'b']]]];
$rule = ['tracker' => '301', 'type' => 'pass', 'ipprotocol' => 'inet', 'gateway' => 'G',
    'interface' => 'lan', 'source' => ['address' => '10.23.0.0/24'], 'destination' => ['any' => '']];
$guard = array_replace($rule, ['tracker' => '302', 'type' => 'block']);
unset($guard['gateway']);
$fixture_paths = [
    'installedpackages/package' => [['name' => 'sdwan']],
    'installedpackages/menu' => [['url' => 'sdwan/status.php']],
    'installedpackages/service' => [['name' => 'sdwan', 'rcfile' => 'sdwand.sh']],
    SDWAN_CONFIG_PATH => sdwan_encode_config($settings),
    'gateways/gateway_group' => [['name' => 'G', 'item' => ['A|1|', 'B|2|']]],
    'filter/rule' => [$rule, $guard],
    'interfaces' => [
        'wan' => ['enable' => '', 'if' => 'igb0'], 'opt1' => ['enable' => '', 'if' => 'igb1'],
        'lan' => ['enable' => '', 'if' => 'igb2']
    ],
    'gateways/gateway_item' => [
        ['name' => 'A', 'interface' => 'wan', 'gateway' => '192.0.2.1'],
        ['name' => 'B', 'interface' => 'opt1', 'gateway' => '198.51.100.1']
    ]
];
$inventory = sdwan_gateways();
$settings = sdwan_get_config();
$approval = sdwan_steering_preflight($settings, 'p', 'G', sdwan_steering_native($inventory));
if ($approval['errors']) {
    throw new RuntimeException(implode(' ', $approval['errors']));
}
$binding = $approval['binding'] + ['group' => 'G', 'policy' => 'p',
    'policy_revision' => sdwan_steering_policy_revision($settings, 'p')];
$fixture_paths[SDWAN_BINDINGS_PATH] = ['item' => [array_replace($binding, [
    'group' => ['G'], 'gateways' => ['item' => $binding['gateways']], 'trackers' => ['item' => $binding['trackers']]
])]];
$binding = sdwan_steering_bindings()['G'];

$case = getenv('SDWAN_FIXTURE_CASE');
$online = ['status' => 'online', 'substatus' => 'none', 'delay' => '12ms', 'stddev' => '1ms', 'loss' => '0%'];
$snapshot = sdwan_evaluate($settings, ['A' => $online, 'B' => $online], time(), $inventory);
$blocked = $case === 'blocked';
$snapshot['config_revision'] = sdwan_config_revision($settings);
$snapshot['gateway_inventory_revision'] = sdwan_gateway_inventory_revision($settings, $inventory);
$snapshot['steering'] = ['G' => ['gateway' => $blocked ? null : 'A', 'revision' => sdwan_config_revision($binding)]];
file_put_contents(SDWAN_SNAPSHOT_PATH, json_encode($snapshot, JSON_THROW_ON_ERROR));

$action = $blocked ? 'block drop in quick on igb2' : 'pass in quick on igb2 route-to (igb0 192.0.2.1)';
$clause = ' inet from 10.23.0.0/24 to any';
// PF applies its default TCP mask to stateful passes even without an explicit protocol.
$state = $blocked ? '' : ' flags S/SA keep state (if-bound) label "gw=1:G"';
$fixture_loaded_pf = [$action . $clause . $state . ' ridentifier 301'];
if ($case !== 'missing_guard') {
    $fixture_loaded_pf[] = 'block drop in quick on igb2' . $clause . ' ridentifier 302';
}
if ($case === 'loaded_scope_changed') {
    $fixture_loaded_pf = str_replace('10.23.0.0/24', '10.24.0.0/24', $fixture_loaded_pf);
}
if ($case === 'native_rule_changed') {
    $fixture_paths['filter/rule'][0]['source']['address'] = '10.24.0.0/24';
    $fixture_paths['filter/rule'][1]['source']['address'] = '10.24.0.0/24';
}
if ($case === 'pf_unavailable') {
    $fixture_loaded_pf = null;
}
if ($case === 'observe') {
    unset($fixture_paths[SDWAN_BINDINGS_PATH]);
}
"""


def run(php, fixture, code, case, abi, forwarding, expected_code, message):
    env = dict(os.environ, SDWAN_FIXTURE_CASE=case, SDWAN_FIXTURE_ABI=str(abi))
    result = subprocess.run(
        [php, "-d", f"include_path={fixture}", "-r", code, "--", "0.4.29", "--forwarding" if forwarding else ""],
        env=env, text=True, capture_output=True, check=False,
    )
    if result.returncode != expected_code or message not in result.stdout + result.stderr:
        raise AssertionError(f"{case}, ABI {abi}, exit {result.returncode}:\n{result.stdout}{result.stderr}")
    if expected_code and (": applied." in result.stdout or ": blocked." in result.stdout):
        raise AssertionError(f"{case} emitted an ambiguous success: {result.stdout}")
    print(f"ok - appliance verifier {case}, ABI {abi}")


def main(php):
    script = (ROOT / "tools/verify-appliance.sh").read_text(encoding="utf-8")
    match = re.search(r"/usr/local/bin/php -r '\n(.*?)\n' -- ", script, re.S)
    if match is None:
        raise AssertionError("Missing PHP verifier entry point")
    with tempfile.TemporaryDirectory(prefix="sdwan-verify-") as path:
        fixture = Path(path)
        code = match[1].replace("/usr/local/pkg/", fixture.as_posix() + "/")
        code = code.replace("/var/log/system.log", (fixture / "system.log").as_posix())
        package = ROOT / "files/usr/local/pkg"
        for entry in ("sdwan", "sdwan_engine", "sdwan_steering", "sdwan_preflight", "sdwan_log", "sdwan_probe"):
            file = package / f"{entry}.inc"
            source = file.read_text(encoding="utf-8").replace(
                "/var/run/sdwan-observer.json", (fixture / "sample.json").as_posix()
            )
            if entry == "sdwan_steering":
                source, count = re.subn(
                    r"(?ms)^function sdwan_steering_pf_rules\(\): \?array \{.*?^}",
                    "function sdwan_steering_pf_rules(): ?array { return $GLOBALS['fixture_loaded_pf']; }", source,
                )
                if count != 1:
                    raise AssertionError("Missing PF fixture boundary")
            (fixture / file.name).write_text(source, encoding="utf-8")
        (fixture / "config.inc").write_text(CONFIG, encoding="utf-8")
        (fixture / "filter.inc").write_text(
            "<?php function filter_sdwan_binding_api(): int { return (int)getenv('SDWAN_FIXTURE_ABI'); }\n",
            encoding="utf-8",
        )
        run(php, fixture, code, "healthy", 1, True, 0, ": applied.")
        run(php, fixture, code, "healthy", 2, True, 0, ": applied.")
        run(php, fixture, code, "blocked", 2, True, 0, ": blocked.")
        run(php, fixture, code, "missing_guard", 2, True, 1, ": pending.")
        run(php, fixture, code, "loaded_scope_changed", 2, True, 1, ": pending.")
        run(php, fixture, code, "native_rule_changed", 2, True, 1, ": binding_changed.")
        run(php, fixture, code, "pf_unavailable", 2, True, 1, ": unavailable.")
        run(php, fixture, code, "observe", 0, False, 0, "Native forwarding ABI: 0.")
        run(php, fixture, code, "unsupported", 0, True, 1, "forwarding is unavailable on this appliance")

        steering = fixture / "sdwan_steering.inc"
        legacy = steering.read_text(encoding="utf-8").replace(
            ",\n    ?array $rule_pairs = null): string {", "): string {\n\t$rule_pairs = null;", 1
        )
        steering.write_text(legacy, encoding="utf-8")
        run(php, fixture, code, "legacy-package", 1, True, 1, "cannot verify the loaded PF match scope")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "php")
