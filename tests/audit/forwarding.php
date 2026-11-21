<?php
declare(strict_types=1);

// Exercise package and core functions with offline data only.
require_once __DIR__ . '/../../files/usr/local/pkg/sdwan_steering.inc';
require_once __DIR__ . '/../../core/filter-sdwan.inc';

function get_real_interface(string $name, string $family, bool $real, bool $flush): ?string {
	return ['wan' => 'em0', 'opt1' => 'em2', 'lan' => 'em1'][$name] ?? null;
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

echo json_encode($rows, JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT), PHP_EOL;
