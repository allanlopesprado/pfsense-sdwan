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
$rule_pairs = ['771292101' => ['guard' => '771292102', 'action' => 'block', 'state_policy' => 'if-bound',
	'gateway_tiers' => ['WAN1' => '1', 'WAN2' => '1']]];
$status = static fn(array $selection, ?array $rules): string =>
	sdwan_steering_pf_status($binding, $selection, $inventory, $rules, $rule_pairs);

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
$rows[] = audit_case('gateway_label_absent', 'pending',
	$status($state, [str_replace('label "gw=1:LAB_SD" ', '', $pass), $guard]));
$rows[] = audit_case('duplicate_gateway_label', 'pending',
	$status($state, [str_replace('label "gw=1:LAB_SD"', 'label "gw=1:LAB_SD" label "gw=2:LAB_SD"', $pass), $guard]));
$floating_pairs = $rule_pairs;
$floating_pairs['771292101']['state_policy'] = 'floating';
$rows[] = audit_case('native_floating_state_policy', 'applied', sdwan_steering_pf_status($binding, $state,
	$inventory, [str_replace('keep state (if-bound)', 'keep state (floating)', $pass), $guard], $floating_pairs));

$rows[] = audit_case('duplicate_tracker_wrong_ingress', 'pending',
	$status($state, [$pass, str_replace('on em1', 'on em3', $pass), $guard]), 'applied');
$rows[] = audit_case('guard_missing', 'pending', $status($state, [$pass]), 'applied');
$rows[] = audit_case('guard_before_pass', 'pending', $status($state, [$guard, $pass]), 'applied');
$rows[] = audit_case('guard_wrong_port', 'pending',
	$status($state, [$pass, str_replace('port = 18080', 'port = 18081', $guard)]), 'applied');
$earlier_pass = 'pass in quick on em1 inet from 192.168.1.0/24 to any keep state ridentifier 771292099';
$rows[] = audit_case('earlier_quick_pass_shadows_policy', 'pending',
	$status($state, [$earlier_pass, $pass, $guard]), 'applied');
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
	sdwan_steering_pf_status($binding, $state, $inventory6, [$scope6('em2'), $guard6], $rule_pairs));
$rows[] = audit_case('ipv6_link_local_wrong_scope', 'pending',
	sdwan_steering_pf_status($binding, $state, $inventory6, [$scope6('em0'), $guard6], $rule_pairs), 'applied');
$rows[] = audit_case('ipv6_link_local_scope_inferred_from_device', 'applied',
	sdwan_steering_pf_status($binding, $state, $inventory6, [str_replace('%em2', '', $scope6('em2')), $guard6], $rule_pairs));
$state6 = [
	'all tcp 2001:db8::1:443 <- 2001:db8::10:51000 ESTABLISHED:ESTABLISHED',
	'   id: 000000010000000a creatorid: 12345678',
	'   ridentifier 771292101',
	'   route-to: fe80::20%em2@em2',
];
$rows[] = audit_case('reconnect_ipv6_state_scope_matches', '000000010000000a/12345678',
	implode(',', sdwan_steering_state_ids($state6, $binding['trackers'], 'em2', 'fe80::20%em2')));
$state6[3] = '   route-to: fe80::20%em0@em2';
$rows[] = audit_case('reconnect_ipv6_state_scope_conflicts', '',
	implode(',', sdwan_steering_state_ids($state6, $binding['trackers'], 'em2', 'fe80::20%em2')));
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
$shadowed = $native;
$preceding = array_replace($native_pass, ['tracker' => '771292099', 'source' => ['address' => '192.0.2.0/24']]);
unset($preceding['gateway']);
array_unshift($shadowed['rules'], $preceding);
$shadowed_check = sdwan_steering_preflight($settings, 'office', 'LAB_SD', $shadowed);
$rows[] = audit_case('preflight_earlier_pass_shadows_policy', true,
	$shadowed_check['errors'] !== [] ||
	    ($shadowed_check['binding']['rules_revision'] ?? null) !== $approved['binding']['rules_revision'], false);
$rows[] = audit_case('renders_384_hops', 384, substr_count(filter_sdwan_pool_route($native_routes), '('));
foreach ([386 => 12, 422 => 30] as $hops => $weight) {
	$native['gateways']['GW7']['weight'] = $weight;
	$native_routes['GW7']['weight'] = $weight;
	$preflight = sdwan_steering_preflight($settings, 'office', 'LAB_SD', $native);
	$rows[] = audit_case("preflight_above_cap_{$hops}", false, $preflight['errors'] === [], true);
	$rows[] = audit_case("renderer_rejects_{$hops}_hops", true, filter_sdwan_pool_route($native_routes) === null);
}
$native['gateways']['GW7']['weight'] = 11;
$native_routes['GW7']['weight'] = 11;

$oversized = $native;
$oversized['gateways']['GW7']['weight'] = 12;
$single_path = $settings;
$single_path['policies'][0]['strategy'] = 'cost';
$rows[] = audit_case('cost_policy_not_subject_to_pool_limit', true,
	sdwan_steering_preflight($single_path, 'office', 'LAB_SD', $oversized)['errors'] === []);

$unscaled = $native;
$unscaled['gateways']['GW0']['weight'] = 2;
$unscaled_routes = $native_routes;
$unscaled_routes['GW0']['weight'] = 2;
$rows[] = audit_case('preflight_without_unit_weight', true,
	sdwan_steering_preflight($settings, 'office', 'LAB_SD', $unscaled)['errors'] === []);
$rows[] = audit_case('renderer_uses_unscaled_pool_without_unit_weight', 193,
	substr_count(filter_sdwan_pool_route($unscaled_routes), '('));

$clamped = $native;
$clamped['gateways']['GW0']['weight'] = 0;
$clamped['gateways']['GW1']['weight'] = 300;
$clamped_routes = $native_routes;
foreach (['GW0' => ['igb1', '192.0.2.1'], 'GW1' => ['igb2', '192.0.2.2']] as $gateway => [$device, $hop]) {
	$clamped_routes[$gateway] = filter_sdwan_gateway_route(['interface' => $device, 'ipprotocol' => 'inet',
	    'weight' => $clamped['gateways'][$gateway]['weight']], $hop);
}
$rows[] = audit_case('preflight_clamps_weights_like_renderer', true,
	sdwan_steering_preflight($settings, 'office', 'LAB_SD', $clamped)['errors'] === []);
$rows[] = audit_case('renderer_clamped_pool', 384, substr_count(filter_sdwan_pool_route($clamped_routes), '('));

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
	'ipv4_private' => ['10.0.0.1', true],
	'ipv4_shared' => ['100.64.0.1', true],
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
$ipv6_hops = [
	'ipv6_ula' => ['fd00::1', true],
	'ipv6_link_local_unscoped' => ['fe80::1', true],
	'ipv6_link_local_scoped' => ['fe80::1%em0', true],
	'ipv6_wrong_scope' => ['fe80::1%em9', false],
	'ipv6_unspecified' => ['::', false],
	'ipv6_loopback' => ['::1', false],
	'ipv6_multicast' => ['ff02::1%em0', false],
];
foreach ($ipv6_hops as $case => [$hop, $usable]) {
	$fixture = $ipv6_pair;
	$fixture['gateways']['GW0']['address'] = $hop;
	$rows[] = audit_case("static_hop_preflight_{$case}", $usable, $preflight($fixture)['errors'] === []);
	$rows[] = audit_case("static_hop_renderer_{$case}", $usable,
	    filter_sdwan_gateway_route(['interface' => 'em0', 'ipprotocol' => 'inet6'], $hop) !== null);
}

$fixture = $pair;
$fixture['gateways']['GW0']['address'] = $fixture['gateways']['GW0']['monitor'] = 'dynamic';
$rows[] = audit_case('preflight_pending_dynamic_gateway_and_monitor', true, $preflight($fixture)['errors'] === []);
$fixture['gateways']['GW0']['monitor'] = '100.64.1.20';
$rows[] = audit_case('preflight_dynamic_gateway_with_shared_monitor', true, $preflight($fixture)['errors'] === []);
$fixture['gateways']['GW0']['monitor'] = '10.11.0.20';
$rows[] = audit_case('preflight_dynamic_gateway_with_private_monitor', true, $preflight($fixture)['errors'] === []);

$pppoe = $ipv6_pair;
$pppoe['interfaces']['wan']['if'] = 'pppoe0';
// The IPv6 path uses the Ethernet parent while IPv4 uses PPPoE.
$pppoe['gateways'] = sdwan_steering_native($pppoe['gateways'])['gateways'];
$rows[] = audit_case('preflight_ipv6_pppoe_parent_scope', true, $preflight($pppoe)['errors'] === []);
$pppoe['gateways']['GW0']['monitor'] = 'fe80::a%pppoe0';
$rows[] = audit_case('preflight_ipv6_pppoe_wrong_scope', false, $preflight($pppoe)['errors'] === []);

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

$stacked = $vti;
$stacked['phase1'][0]['interface'] = '_vipalias_a';
$stacked['vips'][] = ['uniqid' => 'alias_a', 'mode' => 'ipalias', 'interface' => '_viprouted_a',
	'subnet' => '203.0.113.8', 'subnet_bits' => '32'];
$stacked_approval = $preflight($stacked)['binding'];
$rows[] = audit_case('vti_stacked_vip_accepted', true, $stacked_approval !== null);
foreach (['parent_vhid' => [0, 'vhid', '9'], 'alias_endpoint' => [1, 'subnet', '203.0.113.9']] as
    $case => [$offset, $field, $value]) {
	$fixture = $stacked;
	$fixture['vips'][$offset][$field] = $value;
	$updated_binding = $preflight($fixture)['binding'];
	$rows[] = audit_case("vti_stacked_vip_{$case}_changes_revision", true,
	    $updated_binding !== null && $updated_binding !== $stacked_approval);
}
$fixture = $stacked;
$fixture['phase1'][0]['descr'] = 'Renamed VTI';
$fixture['phase1'][0]['pre-shared-key'] = 'fixture-psk';
$fixture['phase2'][0]['localid']['descr'] = 'Renamed local endpoint';
$fixture['phase2'][0]['rekey_time'] = '7200';
$fixture['vips'][0]['password'] = 'fixture-carp-password';
$fixture['vips'][0]['advskew'] = '100';
$fixture['vips'][1]['descr'] = 'Renamed alias';
$fixture['vips'][] = ['uniqid' => 'unrelated', 'mode' => 'carp', 'interface' => 'wan', 'subnet' => '203.0.113.10', 'vhid' => '10'];
$rows[] = audit_case('vti_keeps_approval_for_cosmetic_and_secret_fields', true,
	$stacked_approval !== null && $preflight($fixture)['binding'] === $stacked_approval);
$fixture = $vti;
$fixture['phase2'][0]['localid']['address'] = '2001:0db8:0013:0000:0000:0000:0000:0001';
$rows[] = audit_case('vti_equivalent_ipv6_endpoint_keeps_revision', true,
	$preflight($fixture)['binding'] === $vti_approved['binding']);

$merged = $vti;
$merged['phase2'][] = ['ikeid' => '13', 'reqid' => '220', 'mode' => 'vti',
	'localid' => ['type' => 'address', 'address' => '198.51.100.33'],
	'remoteid' => ['type' => 'address', 'address' => '198.51.100.34']];
$merged_approval = $preflight($merged)['binding'];
$rows[] = audit_case('vti_merged_uses_first_reqid_for_both_families', true, $merged_approval !== null);
$fixture = $merged;
$fixture['phase2'][2]['remoteid']['address'] = '198.51.100.35';
$updated_binding = $preflight($fixture)['binding'];
$rows[] = audit_case('vti_merged_secondary_endpoint_changes_revision', true,
	$updated_binding !== null && $updated_binding !== $merged_approval);
$fixture = $merged;
[$fixture['phase2'][0], $fixture['phase2'][2]] = [$fixture['phase2'][2], $fixture['phase2'][0]];
$rows[] = audit_case('vti_merged_new_first_reqid_retires_old_device', true, $preflight($fixture)['errors'] !== []);

$merged_aliases = $merged;
$extra_alias = $merged['phase2'][2];
$extra_alias['reqid'] = '221';
$extra_alias['localid']['address'] = '198.51.100.37';
$extra_alias['remoteid']['address'] = '198.51.100.38';
$merged_aliases['phase2'][] = $extra_alias;
$ordered = $preflight($merged_aliases)['binding'];
[$merged_aliases['phase2'][2], $merged_aliases['phase2'][3]] = [$merged_aliases['phase2'][3], $merged_aliases['phase2'][2]];
$updated_binding = $preflight($merged_aliases)['binding'];
$rows[] = audit_case('vti_merged_ipv4_alias_order_changes_default_peer', true,
	$updated_binding !== null && $updated_binding !== $ordered);

foreach (['ikev1', 'ikev2'] as $ike) {
	$split = $merged;
	$split['phase1'][0]['iketype'] = $ike;
	if ($ike === 'ikev2') {
		$split['phase1'][0]['splitconn'] = '';
	}
	$split_approval = $preflight($split)['binding'];
	$split['phase2'][2]['remoteid']['address'] = '198.51.100.35';
	$rows[] = audit_case("vti_{$ike}_other_split_device_keeps_revision", true,
	    $split_approval !== null && $preflight($split)['binding'] === $split_approval);
}

echo json_encode($rows, JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT), PHP_EOL;
