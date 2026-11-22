<?php
declare(strict_types=1);

// Change only the temporary snapshot location and use a deterministic wall clock.
// All live native values below are fixtures. This driver never runs a shell or
// opens a network socket.
$repository = dirname(__DIR__, 2);
$package = $repository . '/files/usr/local/pkg';
$directory = sys_get_temp_dir() . '/sdwan-dynamic-route-' . bin2hex(random_bytes(8));
mkdir($directory, 0700);
$sources = ['sdwan.inc', 'sdwan_engine.inc', 'sdwan_steering.inc', 'sdwan_preflight.inc', 'sdwan_log.inc',
    'sdwan_probe.inc'];
register_shutdown_function(static function () use ($directory, $sources): void {
    foreach ([...$sources, 'snapshot.json'] as $name) {
        $path = $directory . '/' . $name;
        if (is_file($path)) {
            unlink($path);
        }
    }
    rmdir($directory);
});
foreach ($sources as $name) {
    $code = file_get_contents($package . '/' . $name);
    if ($name === 'sdwan_engine.inc') {
        $code = str_replace(
            ["'/var/run/sdwan-observer.json'", 'time()'],
            [var_export($directory . '/snapshot.json', true), 'fixture_time()'],
            $code,
        );
    } elseif ($name === 'sdwan_probe.inc') {
        $code = str_replace(
            ["!is_executable('/sbin/route')", "!is_executable('/bin/timeout')", "exec('/bin/timeout 0.3 /sbin/route"],
            ['false', 'false', "fixture_route_get('/bin/timeout 0.3 /sbin/route"],
            $code,
        );
    }
    file_put_contents($directory . '/' . $name, $code);
}
set_include_path($repository . '/tests/fixtures/write');
require_once 'config.inc';
require_once $directory . '/sdwan_steering.inc';

function fixture_time(): int {
    return 1700000000;
}

function filter_sdwan_binding_api(): int {
    return 2;
}

function get_real_interface($interface, $family, $realV6, $refresh): ?string {
    return config_get_path('interfaces', [])[$interface]['if'] ?? null;
}

function get_interface_gateway($interface): ?string {
    return config_get_path('fixture/gateway/' . $interface);
}

function find_interface_ip($device, $refresh): ?string {
    return config_get_path('fixture/source/' . $device);
}

function interface_isppp_type($interface): bool {
    return (config_get_path('interfaces', [])[$interface]['ipaddr'] ?? null) === 'pppoe';
}

function pfSense_get_ifaddrs($device): ?array {
    return config_get_path('fixture/interface/' . $device);
}

function fixture_route_get(string $command, &$lines, &$result): void {
    $lines = explode("\n", config_get_path('fixture/route-output', ''));
    $result = config_get_path('fixture/route-exit', 0);
}

function fixture_append(
    array &$result,
    string $case,
    string $expected,
    string $observed,
    ?string $known = null
): void {
    $row = ['id' => "dynamic_route.{$case}", 'expected' => $expected, 'observed' => $observed];
    if ($known !== null) {
        $row['known_observed'] = $known;
    }
    $result[] = $row;
}

function fixture_wire_binding(array $settings): array {
    $preview = sdwan_steering_preview($settings, 'p', 'G');
    if ($preview['errors']) {
        throw new RuntimeException('Fixture preflight failed: ' . implode(', ', $preview['errors']));
    }
    $wire = $preview['binding'];
    foreach (['gateways', 'trackers'] as $key) {
        $wire[$key] = ['item' => $wire[$key]];
    }
    return $wire;
}

function fixture_publish(array $settings, array $wire, array $observations, array $checks = []): array {
    $inventory = sdwan_gateways();
    $binding = sdwan_steering_decode($wire);
    $sample = sdwan_evaluate($settings, $observations, fixture_time(), $inventory, $checks);
    $sample['config_revision'] = sdwan_config_revision($settings);
    $sample['gateway_inventory_revision'] = sdwan_gateway_inventory_revision($settings, $inventory);
    $sample['steering'] = ['G' => sdwan_steering_state($settings, $binding, $sample['policies']['p'], [], fixture_time())];
    fixture_store($sample);
    return $sample;
}

function fixture_store(array $sample): void {
    file_put_contents(SDWAN_SNAPSHOT_PATH, json_encode($sample, JSON_THROW_ON_ERROR));
}

function fixture_decision(array $settings, array $wire, array $rule): string {
    $accepted = sdwan_current_snapshot($settings, sdwan_gateways()) !== null;
    $choice = sdwan_steering_gateway_for_rule($wire, $rule) ?? 'none';
    return ($accepted ? 'current' : 'stale') . '/' . $choice;
}

$settings = [
    'version' => '1',
    'members' => [['name' => 'a', 'gateway' => 'A', 'cost' => '1'], ['name' => 'b', 'gateway' => 'B', 'cost' => '2']],
    'slas' => [['name' => 's', 'latency_ms' => '40', 'rttsd_ms' => '30', 'loss_pct' => '5']],
    'policies' => [['name' => 'p', 'sla' => 's', 'strategy' => 'cost', 'members' => ['a', 'b']]],
];
$rule = [
    'tracker' => '301', 'type' => 'pass', 'ipprotocol' => 'inet', 'gateway' => 'G',
    'interface' => 'lan', 'source' => ['address' => '192.168.1.0/24'], 'destination' => ['any' => ''],
];
$guard = array_replace($rule, ['tracker' => '302', 'type' => 'block']);
unset($guard['gateway']);
$current = [
    SDWAN_CONFIG_PATH => sdwan_encode_config($settings),
    'gateways/gateway_group' => [['name' => 'G', 'item' => ['A|1|', 'B|2|']]],
    'filter/rule' => [$rule, $guard],
    'interfaces' => [
        'wan' => ['enable' => '', 'if' => 'em0', 'ipaddr' => 'dhcp'],
        'opt1' => ['enable' => '', 'if' => 'em1', 'ipaddr' => '198.51.100.10'],
        'lan' => ['enable' => '', 'if' => 'em2'],
    ],
    'gateways/gateway_item' => [
        ['name' => 'A', 'interface' => 'wan', 'gateway' => 'dynamic', 'monitor' => 'dynamic', 'ipprotocol' => 'inet'],
        ['name' => 'B', 'interface' => 'opt1', 'gateway' => '198.51.100.1'],
    ],
    'fixture/gateway/wan' => '192.0.2.1',
    'fixture/source/em0' => '192.0.2.10',
];
$initial = $current;
$healthy = ['status' => 'online', 'substatus' => 'none', 'delay' => '10ms', 'stddev' => '2ms', 'loss' => '0%'];
$observations = ['A' => $healthy, 'B' => $healthy];
$next = ['srcip' => '192.0.2.10', 'targetip' => '192.0.2.1'];
$wire = fixture_wire_binding($settings);
$sample = fixture_publish($settings, $wire, $observations);
$receipt = sdwan_steering_runtime_signature($sample, sdwan_gateways());
$result = [];
fixture_append($result, 'valid_initial_lease', 'current/A', fixture_decision($settings, $wire, $rule));
fixture_append($result, 'lease_monitor_before_renewal', 'matching',
    sdwan_monitor_matches(sdwan_gateways()['A'], $next) ? 'matching' : 'rejected');

$current['fixture/source/em0'] = '192.0.2.11';
fixture_append($result, 'lease_source_only_change', 'stale/none', fixture_decision($settings, $wire, $rule), 'current/A');
fixture_append($result, 'lease_monitor_after_source_change', 'rejected',
    sdwan_monitor_matches(sdwan_gateways()['A'], $next) ? 'matching' : 'rejected');
fixture_append($result, 'lease_source_old_receipt', 'changed',
    sdwan_steering_runtime_signature($sample, sdwan_gateways()) === $receipt ? 'same' : 'changed', 'same');

$current = $initial;
$current['fixture/gateway/wan'] = '192.0.2.2';
fixture_append($result, 'lease_next_hop_only_change', 'stale/none', fixture_decision($settings, $wire, $rule), 'current/A');
fixture_append($result, 'lease_next_hop_old_receipt', 'changed',
    sdwan_steering_runtime_signature($sample, sdwan_gateways()) === $receipt ? 'same' : 'changed');
$current['fixture/source/em0'] = '192.0.2.11';
fixture_append($result, 'lease_both_changed_before_poll', 'stale/none', fixture_decision($settings, $wire, $rule), 'current/A');
foreach ([30, 31] as $age) {
    fixture_store(array_replace($sample, ['generated_at' => fixture_time() - $age]));
    fixture_append($result, "lease_both_changed_age_{$age}s", 'stale/none', fixture_decision($settings, $wire, $rule),
        $age === 30 ? 'current/A' : null);
}
fixture_publish($settings, $wire, ['B' => $healthy]);
fixture_append($result, 'lease_new_poll_backup', 'current/B', fixture_decision($settings, $wire, $rule));
fixture_publish($settings, $wire, $observations);
fixture_append($result, 'lease_new_poll_healthy', 'current/A', fixture_decision($settings, $wire, $rule));
$current['gateways/gateway_item'][0]['monitor'] = '192.0.2.4';
fixture_append($result, 'saved_monitor_change_control', 'stale/none', fixture_decision($settings, $wire, $rule));

// Change only the saved route used by an existing service check.
$current = $initial;
$settings['members'][0]['probe_primary'] = 'tcp://203.0.113.53:443';
$current[SDWAN_CONFIG_PATH] = sdwan_encode_config($settings);
$current['staticroutes/route'] = [['network' => '203.0.113.53/32', 'gateway' => 'A']];
$wire = fixture_wire_binding($settings);
fixture_publish($settings, $wire, $observations, ['a' => ['probe_primary' => 'Passed']]);
fixture_append($result, 'pinned_probe_control', 'current/A', fixture_decision($settings, $wire, $rule));
$pinnedRoute = "gateway: 192.0.2.1\ninterface: em0\nflags: <UP,GATEWAY,HOST,DONE,STATIC>";
$movedRoute = "gateway: 198.51.100.1\ninterface: em1\nflags: <UP,GATEWAY,HOST,DONE,STATIC>";
fixture_append($result, 'pinned_probe_path_match', 'matching',
    sdwan_probe_route_matches($pinnedRoute, 'em0', '192.0.2.1') ? 'matching' : 'rejected');
$notPinned = str_replace('HOST,', '', $pinnedRoute);
fixture_append($result, 'probe_default_route_is_not_host_route', 'rejected',
    sdwan_probe_route_matches($notPinned, 'em0', '192.0.2.1') ? 'matching' : 'rejected');
fixture_append($result, 'probe_other_egress_is_not_same_path', 'rejected',
    sdwan_probe_route_matches($movedRoute, 'em0', '192.0.2.1') ? 'matching' : 'rejected');
$linkLocalRoute = str_replace('192.0.2.1', 'fe80::1%em0', $pinnedRoute);
fixture_append($result, 'probe_ipv6_correct_next_hop_zone', 'matching',
    sdwan_probe_route_matches($linkLocalRoute, 'em0', 'fe80::1%em0') ? 'matching' : 'rejected');
fixture_append($result, 'probe_ipv6_conflicting_next_hop_zone', 'rejected',
    sdwan_probe_route_matches(str_replace('%em0', '%em1', $linkLocalRoute), 'em0', 'fe80::1%em0') ? 'matching' : 'rejected');
fixture_append($result, 'probe_ipv6_infers_omitted_zone_from_device', 'matching',
    sdwan_probe_route_matches(str_replace('%em0', '', $linkLocalRoute), 'em0', 'fe80::1%em0') ? 'matching' : 'rejected');
fixture_append($result, 'probe_ipv6_global_next_hop_has_no_zone', 'rejected',
    sdwan_probe_route_matches(str_replace('fe80::1', '2001:db8::1', $linkLocalRoute), 'em0', '2001:db8::1') ? 'matching' : 'rejected');
$directRoute = "   route to: 203.0.113.53\n destination: 203.0.113.53\n  interface: pppoe0\n      flags: <UP,HOST,DONE,STATIC>";
$directCases = [
    'ppp_direct_host_route' => [$directRoute, 'pppoe0', '203.0.113.53', 'matching'],
    'ppp_config_without_live_point_to_point' => [$directRoute, 'pppoe0', null, 'rejected'],
    'ppp_interface_mismatch' => [$directRoute, 'pppoe1', '203.0.113.53', 'rejected'],
    'ppp_destination_mismatch' => [$directRoute, 'pppoe0', '203.0.113.54', 'rejected'],
    'ppp_route_to_is_not_destination' => [str_replace('destination:', 'lookup:', $directRoute), 'pppoe0', '203.0.113.53', 'rejected'],
    'ppp_connected_network' => [str_replace('HOST,', '', $directRoute), 'pppoe0', '203.0.113.53', 'rejected'],
    'ppp_route_not_up' => [str_replace('UP,', '', $directRoute), 'pppoe0', '203.0.113.53', 'rejected'],
    'ppp_route_rejects' => [str_replace('STATIC', 'STATIC,REJECT', $directRoute), 'pppoe0', '203.0.113.53', 'rejected'],
    'ppp_route_is_blackhole' => [str_replace('STATIC', 'STATIC,BLACKHOLE', $directRoute), 'pppoe0', '203.0.113.53', 'rejected'],
    'ppp_gateway_flag_missing_address' => [str_replace('UP,', 'UP,GATEWAY,', $directRoute), 'pppoe0', '203.0.113.53', 'rejected'],
    'ppp_gateway_field_is_link_metadata' => [$directRoute . "\ngateway: link#12", 'pppoe0', '203.0.113.53', 'rejected'],
    'ppp_gateway_field_is_empty' => [$directRoute . "\ngateway: ", 'pppoe0', '203.0.113.53', 'rejected'],
    'ppp_ipv6_direct_host_route' => [str_replace('203.0.113.53', '2001:0db8:0:0::53', $directRoute), 'pppoe0', '2001:db8::53', 'matching'],
];
foreach ($directCases as $case => [$route, $device, $destination, $expected]) {
    $nextHop = str_contains($destination ?? '', ':') ? 'fe80::1%pppoe0' : '192.0.2.1';
    fixture_append($result, $case, $expected,
        sdwan_probe_route_matches($route, $device, $nextHop, $destination) ? 'matching' : 'rejected',
        $expected === 'matching' ? 'rejected' : null);
}
$beforePpp = $current;
$current['interfaces']['wan'] = ['enable' => '', 'if' => 'pppoe0', 'ipaddr' => 'pppoe'];
$current['fixture/source/pppoe0'] = '192.0.2.10';
$current['fixture/interface/pppoe0'] = ['pointtopoint' => 1, 'status' => 'up'];
$current['fixture/route-output'] = $directRoute;
$target = sdwan_probe_target('tcp://203.0.113.53:443');
$probeGateway = ['interface' => 'wan', 'address' => 'dynamic', 'family' => 'inet'];
$originalPath = sdwan_probe_path($target, $probeGateway);
fixture_append($result, 'ppp_live_route_path', 'pppoe0/192.0.2.10/192.0.2.1',
    $originalPath === null ? 'rejected' : implode('/', $originalPath), 'rejected');
$current['fixture/gateway/wan'] = '192.0.2.2';
fixture_append($result, 'ppp_reconnected_peer_changes_path', 'changed',
    sdwan_probe_path($target, $probeGateway) !== $originalPath ? 'changed' : 'unchanged', 'unchanged');
$current['fixture/interface/pppoe0']['status'] = 'down';
fixture_append($result, 'ppp_direct_route_on_down_interface', 'rejected',
    sdwan_probe_path($target, $probeGateway) === null ? 'rejected' : 'matching');
$current['fixture/interface/pppoe0'] = ['status' => 'up'];
fixture_append($result, 'ppp_direct_route_on_broadcast_interface', 'rejected',
    sdwan_probe_path($target, $probeGateway) === null ? 'rejected' : 'matching');
$current['fixture/interface/pppoe0']['pointtopoint'] = 1;
$current['interfaces']['wan']['ipaddr'] = 'dhcp';
fixture_append($result, 'ppp_unmanaged_point_to_point_route', 'rejected',
    sdwan_probe_path($target, $probeGateway) === null ? 'rejected' : 'matching');
$current = $beforePpp;
$current['staticroutes/route'][] = ['network' => '203.0.113.78/32', 'gateway' => 'B'];
fixture_append($result, 'unrelated_route_change_control', 'current/A', fixture_decision($settings, $wire, $rule));
$current['staticroutes/route'][0]['gateway'] = 'B';
fixture_append($result, 'probe_route_moved_before_poll', 'stale/none', fixture_decision($settings, $wire, $rule), 'current/A');
array_shift($current['staticroutes/route']);
fixture_append($result, 'probe_route_removed_before_poll', 'stale/none', fixture_decision($settings, $wire, $rule), 'current/A');
fixture_publish($settings, $wire, $observations, ['a' => ['probe_primary' => 'No matching host route or source']]);
fixture_append($result, 'probe_route_new_poll_backup', 'current/B', fixture_decision($settings, $wire, $rule));

echo json_encode($result, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES), PHP_EOL;
