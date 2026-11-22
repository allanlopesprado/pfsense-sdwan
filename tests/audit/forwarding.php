<?php
declare(strict_types=1);

// Exercise package and core functions with offline data only.
require_once __DIR__ . '/../../files/usr/local/pkg/sdwan_steering.inc';
require_once __DIR__ . '/../../core/filter-sdwan.inc';

function get_real_interface(string $name, string $family, bool $real, bool $flush): ?string {
	return ['wan' => 'em0', 'opt1' => 'em2', 'lan' => 'em1'][$name] ?? null;
}

function get_interface_gateway_v6(string $name): ?string {
	return $name === 'wan' ? 'fe80::a%em0' : null;
}

function find_interface_ipv6_ll(string $device, bool $flush): ?string {
	return $device === 'em0' ? 'fe80::b' : null;
}

function config_get_path(string $path, mixed $default = null): mixed {
	return $default;
}

function config_path_enabled(string $path, string $field): bool {
	return $path === 'system' && $field === 'lb_use_sticky' && $GLOBALS['audit_sticky'];
}

function audit_case(string $id, mixed $expected, mixed $observed, mixed $known = null): array {
	$row = ['id' => "pf.{$id}", 'expected' => $expected, 'observed' => $observed];
	if ($known !== null) {
		$row['known_observed'] = $known;
	}
	return $row;
}

$audit_sticky = false;
$binding = [
	'group' => 'LAB_SD', 'policy' => 'office', 'gateways' => ['WAN1', 'WAN2'],
	'trackers' => ['771292101'], 'rules_revision' => str_repeat('a', 64),
	'policy_revision' => str_repeat('b', 64),
];
$inventory = [
	'WAN1' => ['interface' => 'wan', 'family' => 'inet', 'address' => '198.18.10.2'],
	'WAN2' => ['interface' => 'opt1', 'family' => 'inet', 'address' => '198.18.20.2', 'weight' => 2],
];
$state = ['gateway' => 'WAN2', 'revision' => sdwan_config_revision($binding)];
$blocked_state = array_replace($state, ['gateway' => null]);

// The unmodified rows come from the CE 2.9.2 interface lab in
// docs/benchmarks/evidence/ce292-current-profile/pf.csv.
$pass = 'pass in quick on em1 route-to (em2 198.18.20.2) inet proto tcp from 192.168.1.10 to any port = 18080 ' .
	'flags S/SA keep state (if-bound) label "id=771292101" label "gw=1:LAB_SD" label "tags=user_rule" ' .
	'label "descr=Lab SD-WAN TCP 18080" ridentifier 771292101';
$block = 'block drop in quick on em1 inet proto tcp from 192.168.1.10 to any port = 18080 ' .
	'label "id=771292101" label "tags=user_rule" label "descr=Lab SD-WAN TCP 18080" ridentifier 771292101';
$guard = 'block drop in quick on em1 inet proto tcp from 192.168.1.10 to any port = 18080 flags S/SA ' .
	'label "id=771292102" label "tags=user_rule" label "descr=Lab SD-WAN fallback block" ridentifier 771292102';
$logged = str_replace('pass in quick', 'pass in log (all, to pflog0) quick', $pass) . ' dnpipe 10';
$logged = str_replace('descr=Lab SD-WAN TCP 18080', 'descr=Lab rule with ridentifier 441', $logged);
$status = static fn(array $selection, ?array $rules): string =>
	sdwan_steering_pf_status($binding, $selection, $inventory, $rules);

$rows = [
	audit_case('ce292_pass', 'applied', $status($state, [$pass, $guard])),
	audit_case('ce292_block', 'blocked', $status($blocked_state, [$block, $guard])),
	audit_case('logging_and_dummynet', 'applied', $status($state, [$logged, $guard])),
	audit_case('real_tracker_after_description', '771292101', sdwan_steering_rule_tracker($logged)),
	audit_case('description_alone_is_not_tracker', true,
		sdwan_steering_rule_tracker('label "descr=An example with ridentifier 771292101" queue wan') === null),
	audit_case('changed_tracker', 'pending', $status($state,
		[str_replace('ridentifier 771292101', 'ridentifier 771292109', $logged), $guard])),
	audit_case('wrong_egress', 'pending', $status($state, [str_replace('(em2 ', '(em0 ', $pass), $guard])),
	audit_case('wrong_next_hop', 'pending', $status($state,
		[str_replace('198.18.20.2', '198.18.20.3', $pass), $guard])),
	audit_case('reply_to_is_not_route_to', 'pending', $status($state, [str_replace('route-to', 'reply-to', $pass), $guard])),
	audit_case('stale_binding_revision', 'pending', $status(array_replace($state, ['revision' => 'stale']), [$pass, $guard])),
	audit_case('active_pass_when_block_required', 'pending', $status($blocked_state, [$pass, $guard])),
	audit_case('pf_unavailable', 'unavailable', $status($state, null)),
];

$pass_mutations = [
	'wrong_ingress' => ['on em1', 'on em3'],
	'wrong_ingress_negated' => ['on em1', 'on ! em1'],
	'wrong_tier' => ['gw=1:LAB_SD', 'gw=2:LAB_SD'],
	'wrong_group' => ['gw=1:LAB_SD', 'gw=1:OLD_SD'],
	'wrong_source' => ['from 192.168.1.10', 'from any'],
	'wrong_destination' => ['to any port', 'to 198.51.100.1 port'],
	'wrong_destination_port' => ['port = 18080', 'port = 18081'],
	'wrong_protocol' => ['proto tcp', 'proto udp'],
	'wrong_state_type' => ['keep state (if-bound)', 'no state'],
	'wrong_state_policy' => ['keep state (if-bound)', 'keep state (floating)'],
];
foreach ($pass_mutations as $case => [$old, $changed]) {
	$rows[] = audit_case($case, 'pending', $status($state, [str_replace($old, $changed, $pass), $guard]), 'applied');
}

$rows[] = audit_case('duplicate_tracker_wrong_ingress', 'pending',
	$status($state, [$pass, str_replace('on em1', 'on em3', $pass), $guard]), 'applied');
$rows[] = audit_case('guard_missing', 'pending', $status($state, [$pass]), 'applied');
$rows[] = audit_case('guard_before_pass', 'pending', $status($state, [$guard, $pass]), 'applied');
$rows[] = audit_case('guard_wrong_port', 'pending',
	$status($state, [$pass, str_replace('port = 18080', 'port = 18081', $guard)]), 'applied');
$rows[] = audit_case('block_wrong_ingress', 'pending',
	$status($blocked_state, [str_replace('on em1', 'on em3', $block), $guard]), 'blocked');
$rows[] = audit_case('block_wrong_scope', 'pending',
	$status($blocked_state, [str_replace('from 192.168.1.10', 'from any', $block), $guard]), 'blocked');
$rows[] = audit_case('block_restricted_to_syn', 'pending',
	$status($blocked_state, [str_replace('label "id=', 'flags S/SA label "id=', $block), $guard]), 'blocked');

$pool_state = ['gateway' => 'WAN1', 'pool' => ['WAN1', 'WAN2'], 'revision' => $state['revision']];
$weighted = str_replace('route-to (em2 198.18.20.2)', 'route-to { ' . str_repeat('(em0 198.18.10.2), ', 2) .
	str_repeat('(em2 198.18.20.2), ', 3) . '(em2 198.18.20.2) } round-robin', $pass);
$reordered = str_replace('route-to (em2 198.18.20.2)', 'route-to { ' . str_repeat('(em2 198.18.20.2), ', 4) .
	'(em0 198.18.10.2), (em0 198.18.10.2) } round-robin', $pass);
$rows[] = audit_case('native_weights', 'applied', $status($pool_state, [$weighted, $guard]));
$rows[] = audit_case('weighted_pool_same_counts_reordered', 'applied', $status($pool_state, [$reordered, $guard]));
$rows[] = audit_case('native_weight_changed', 'pending',
	$status($pool_state, [preg_replace('/\(em0 198\.18\.10\.2\), /', '', $weighted, 1), $guard]));
$audit_sticky = true;
$rows[] = audit_case('sticky_missing', 'pending', $status($pool_state, [$weighted, $guard]));
$rows[] = audit_case('sticky_expected', 'applied',
	$status($pool_state, [str_replace('round-robin', 'round-robin sticky-address', $weighted), $guard]));
$audit_sticky = false;

$inventory6 = ['WAN2' => ['interface' => 'opt1', 'family' => 'inet6', 'address' => 'fe80::20%em2']];
$scope6 = static fn(string $zone): string => str_replace(
	['(em2 198.18.20.2) inet', 'from 192.168.1.10'], ["(em2 fe80::20%{$zone}) inet6", 'from 2001:db8::10'], $pass);
$guard6 = str_replace('inet proto tcp from 192.168.1.10', 'inet6 proto tcp from 2001:db8::10', $guard);
$rows[] = audit_case('ipv6_link_local_scope', 'applied',
	sdwan_steering_pf_status($binding, $state, $inventory6, [$scope6('em2'), $guard6]));
$rows[] = audit_case('ipv6_link_local_wrong_scope', 'pending',
	sdwan_steering_pf_status($binding, $state, $inventory6, [$scope6('em0'), $guard6]), 'applied');
$rows[] = audit_case('renderer_rejects_wrong_ipv6_scope', true,
	filter_sdwan_gateway_route(['interface' => 'em2', 'ipprotocol' => 'inet6'], 'fe80::20%em0') === null);

$native = array_fill_keys(['groups', 'rules', 'gateways', 'interfaces', 'phase1', 'phase2', 'vips',
	'openvpn_servers', 'openvpn_clients', 'dyndns', 'dnsupdates'], []);
$native += ['default4' => 'GW0', 'default6' => '', 'filtermode' => 'enc', 'steering_abi' => 2];
$native['groups'] = [['name' => 'LAB_SD', 'item' => [], 'trigger' => 'down']];
$native['interfaces'] = ['lan' => ['enable' => '', 'if' => 'igb0']];
$native_pass = ['tracker' => '771292101', 'type' => 'pass', 'gateway' => 'LAB_SD', 'interface' => 'lan',
	'source' => ['address' => '192.0.2.10'], 'destination' => ['any' => ''], 'ipprotocol' => 'inet'];
$native_guard = array_replace($native_pass, ['tracker' => '771292102', 'type' => 'block']);
unset($native_guard['gateway']);
$native['rules'] = [$native_pass, $native_guard];
$settings = ['version' => '1', 'members' => [], 'slas' => [['name' => 'sla', 'latency_ms' => '40', 'loss_pct' => '5']],
	'policies' => [['name' => 'office', 'members' => [], 'strategy' => 'balance', 'sla' => 'sla']]];
$native_routes = [];
foreach ([1, 30, 30, 30, 30, 30, 30, 11] as $index => $weight) {
	$interface = 'opt' . $index;
	$device = 'igb' . ($index + 1);
	$gateway = 'GW' . $index;
	$member = 'WAN' . $index;
	$address = '192.0.2.' . ($index + 1);
	$native['interfaces'][$interface] = ['enable' => '', 'if' => $device];
	$native['gateways'][$gateway] = ['interface' => $interface, 'family' => 'inet', 'address' => $address,
		'monitor_disabled' => false, 'action_disabled' => false, 'monitor' => '198.51.100.' . ($index + 1), 'weight' => $weight];
	$native['groups'][0]['item'][] = "{$gateway}|1|address";
	$settings['members'][] = ['name' => $member, 'gateway' => $gateway, 'cost' => '1'];
	$settings['policies'][0]['members'][] = $member;
	$native_routes[$gateway] = filter_sdwan_gateway_route(['interface' => $device, 'ipprotocol' => 'inet', 'weight' => $weight], $address);
}

$approved = sdwan_steering_preflight($settings, 'office', 'LAB_SD', $native);
$rows[] = audit_case('preflight_at_384_hops', true, $approved['errors'] === []);
$rows[] = audit_case('renders_384_hops', 384, substr_count(filter_sdwan_pool_route($native_routes), '('));
foreach ([386 => 12, 422 => 30] as $hops => $weight) {
	$native['gateways']['GW7']['weight'] = $weight;
	$native_routes['GW7']['weight'] = $weight;
	$preflight = sdwan_steering_preflight($settings, 'office', 'LAB_SD', $native);
	$rows[] = audit_case("preflight_above_cap_{$hops}", false, $preflight['errors'] === [], true);
	$rows[] = audit_case("renderer_rejects_{$hops}_hops", true, filter_sdwan_pool_route($native_routes) === null);
}
$native['gateways']['GW7']['weight'] = 11;

$renumbered = $native;
$renumbered['groups'][0]['item'] = array_map(static fn($item) => str_replace('|1|', '|2|', $item), $native['groups'][0]['item']);
$changed = sdwan_steering_preflight($settings, 'office', 'LAB_SD', $renumbered);
$rows[] = audit_case('native_tier_changes_binding_revision', true,
	$changed['errors'] === [] && $changed['binding']['rules_revision'] !== $approved['binding']['rules_revision']);
$invalid = $native;
array_splice($invalid['rules'], 1, 0, [['tracker' => '771292103', 'type' => 'pass']]);
$rows[] = audit_case('preflight_guard_no_longer_adjacent', true,
	sdwan_steering_preflight($settings, 'office', 'LAB_SD', $invalid)['errors'] !== []);

$pair = $native;
$pair['groups'][0]['item'] = ['GW0|1|address', 'GW1|2|address'];
$pair['interfaces'] = ['lan' => ['enable' => '', 'if' => 'em1'], 'wan' => ['enable' => '', 'if' => 'em0'],
	'opt1' => ['enable' => '', 'if' => 'em2']];
$pair['gateways'] = array_intersect_key($native['gateways'], ['GW0' => true, 'GW1' => true]);
$pair['gateways']['GW0']['interface'] = 'wan';
$pair['default4'] = 'WAN_DEFAULT';
$pair_settings = $settings;
$pair_settings['members'] = array_slice($settings['members'], 0, 2);
$pair_settings['policies'][0]['members'] = array_slice($settings['policies'][0]['members'], 0, 2);
$pair_settings['policies'][0]['strategy'] = 'cost';
$preflight = static fn(array $fixture): array => sdwan_steering_preflight($pair_settings, 'office', 'LAB_SD', $fixture);

// A saved static address can be unusable after an import or a reassignment.
// Dynamic gateways must be left to the native resolver.
$hop_cases = [
	'valid_ipv4' => ['192.0.2.1', true],
	'ipv4_unspecified' => ['0.0.0.0', false],
	'ipv4_loopback' => ['127.0.0.1', false],
	'ipv4_multicast' => ['224.0.0.1', false],
	'ipv4_with_scope' => ['192.0.2.1%em0', false],
];
foreach ($hop_cases as $case => [$hop, $usable]) {
	$fixture = $pair;
	$fixture['gateways']['GW0']['address'] = $hop;
	$rows[] = audit_case("static_hop_preflight_{$case}", $usable, $preflight($fixture)['errors'] === [], $usable ? null : true);
	$rows[] = audit_case("static_hop_renderer_{$case}", $usable,
		filter_sdwan_gateway_route(['interface' => 'em0', 'ipprotocol' => 'inet'], $hop) !== null);
}

$ipv6_pair = $pair;
$ipv6_pair['rules'][0]['ipprotocol'] = $ipv6_pair['rules'][1]['ipprotocol'] = 'inet6';
$ipv6_pair['rules'][0]['source'] = $ipv6_pair['rules'][1]['source'] = ['address' => '2001:db8:1::10'];
$ipv6_pair['rules'][0]['destination'] = $ipv6_pair['rules'][1]['destination'] = ['address' => '2001:db8:15::/64'];
foreach (['GW0' => 'em0', 'GW1' => 'em2'] as $key => $device) {
	$ipv6_pair['gateways'][$key]['family'] = 'inet6';
	$ipv6_pair['gateways'][$key]['address'] = "fe80::1%{$device}";
	$ipv6_pair['gateways'][$key]['monitor'] = "fe80::a%{$device}";
}
$running_monitor = ['targetip' => 'fe80::a%em0', 'srcip' => 'fe80::b%em0'];
$monitor_cases = [
	'correct_scope' => ['fe80::a%em0', true, true],
	'implicit_scope' => ['fe80::a', true, true],
	'dynamic_resolves' => ['dynamic', true, true],
	'wrong_scope' => ['fe80::a%em9', false, false],
	'wrong_family' => ['192.0.2.44', false, false],
	'invalid_address' => ['invalid-address', false, false],
	'other_member_target' => ['fe80::a%em2', false, false],
];
foreach ($monitor_cases as $case => [$target, $allowed, $matches]) {
	$fixture = $ipv6_pair;
	$fixture['gateways']['GW0']['monitor'] = $target;
	$known = !$allowed && $case !== 'other_member_target' ? true : null;
	$rows[] = audit_case("monitor_preflight_{$case}", $allowed, $preflight($fixture)['errors'] === [], $known);
	$rows[] = audit_case("monitor_runtime_{$case}", $matches, sdwan_monitor_matches($fixture['gateways']['GW0'], $running_monitor));
}

// These cases cover the authorization digest only. They do not assume a
// different native route or a failed IPsec association after an address edit.
$vti = $ipv6_pair;
$vti['filtermode'] = 'if_ipsec';
$vti['vips'][] = ['uniqid' => 'routed_a', 'mode' => 'carp', 'interface' => 'wan', 'subnet' => '203.0.113.6', 'vhid' => '3'];
foreach (['GW0' => ['_viprouted_a', '13', '218', 'opt11'], 'GW1' => ['opt1', '14', '219', 'opt12']] as
    $key => [$transport, $ike, $req, $assigned]) {
	$vti['interfaces'][$assigned] = ['enable' => '', 'if' => 'ipsec' . $req];
	$vti['gateways'][$key]['interface'] = $assigned;
	$vti['gateways'][$key]['monitor'] = '2001:db8:1::' . $ike;
	$vti['gateways'][$key]['address'] = 'dynamic';
	$vti['phase1'][] = ['ikeid' => $ike, 'interface' => $transport, 'iketype' => 'ikev2', 'remote-gateway' => '198.51.100.' . $ike];
	$vti['phase2'][] = ['ikeid' => $ike, 'reqid' => $req, 'mode' => 'vti',
		'localid' => ['type' => 'address', 'address' => "2001:db8:{$ike}::1"],
		'remoteid' => ['type' => 'address', 'address' => "2001:db8:{$ike}::2"]];
}
$vti_approved = $preflight($vti);
$rows[] = audit_case('vti_preflight_baseline', true, $vti_approved['errors'] === []);
$vti_mutations = [
	'phase2_local_endpoint' => ['phase2', 'localid', ['type' => 'address', 'address' => '2001:db8:13::3'], true],
	'phase2_remote_endpoint' => ['phase2', 'remoteid', ['type' => 'address', 'address' => '2001:db8:13::4'], true],
	'carp_local_ip' => ['vips', 'subnet', '203.0.113.7', true],
	'carp_vhid' => ['vips', 'vhid', '4', true],
	'phase1_remote_peer' => ['phase1', 'remote-gateway', '198.51.100.77', false],
];
foreach ($vti_mutations as $case => [$section, $key, $value, $known_same]) {
	$fixture = $vti;
	$fixture[$section][0][$key] = $value;
	$revision = $preflight($fixture)['binding']['rules_revision'] ?? null;
	$same = $revision !== null && $revision === $vti_approved['binding']['rules_revision'];
	$rows[] = audit_case("vti_binding_unchanged_after_{$case}", false, $same, $known_same ? true : null);
}
$fixture = $vti;
$fixture['phase2'][0]['lifetime'] = '7200';
$rows[] = audit_case('vti_binding_stable_after_lifetime_edit', true, $preflight($fixture)['binding'] === $vti_approved['binding']);
$fixture = $vti;
$fixture['phase2'][0]['disabled'] = '';
$rows[] = audit_case('vti_preflight_rejects_disabled_phase2', true, $preflight($fixture)['errors'] !== []);

echo json_encode($rows, JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT), PHP_EOL;
