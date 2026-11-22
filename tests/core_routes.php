<?php
declare(strict_types=1);
require_once(__DIR__ . '/../core/filter-sdwan.inc');

$gateway = ['interface' => 'igb0.431', 'ipprotocol' => 'inet'];
$v6 = array_replace($gateway, ['ipprotocol' => 'inet6']);
foreach ([
	[$gateway, '198.51.100.2', ' route-to (igb0.431 198.51.100.2) '],
	[$gateway, '100.64.0.1', ' route-to (igb0.431 100.64.0.1) '],
	[$gateway, '172.22.10.1', ' route-to (igb0.431 172.22.10.1) '],
	[$v6, 'fe80::1', ' route-to (igb0.431 fe80::1%igb0.431) '],
	[$v6, 'fe80::1%igb0.431', ' route-to (igb0.431 fe80::1%igb0.431) '],
	[$v6, '2001:db8::2', ' route-to (igb0.431 2001:db8::2) '],
	[$v6, 'fe80::1%other0', null], [$v6, '2001:db8::2%igb0.431', null],
	[$v6, '::', null], [$v6, '::1', null], [$v6, 'ff02::1', null],
	[$gateway, '0.0.0.0', null], [$gateway, '127.0.0.1', null],
	[$gateway, '255.255.255.255', null], [$gateway, '224.0.0.1', null],
	[$gateway, 'dynamic', null], [$gateway, '::1', null], [$v6, '192.0.2.1', null],
	[$gateway + ['force_down' => ''], '192.0.2.1', null],
	[$gateway + ['action_disable' => ''], '192.0.2.1', null],
	[$gateway + ['monitor_disable' => ''], '192.0.2.1', null],
	[array_replace($gateway, ['interface' => 'bad nic']), '192.0.2.1', null],
] as [$gw, $next, $expected]) {
	$route = filter_sdwan_gateway_route($gw, $next);
	if (($route['route'] ?? null) !== $expected || ($route !== null && $route['family'] !== $gw['ipprotocol'])) {
		throw new RuntimeException('Unexpected route normalization for ' . json_encode([$gw, $next]));
	}
}
echo "ok - concrete next hops, IP family, gateway action, interface and IPv6 scope validated\n";
$a = filter_sdwan_gateway_route($gateway, '192.0.2.1');
$b = filter_sdwan_gateway_route(array_replace($gateway, ['interface' => 'igb1', 'weight' => 2]), '192.0.2.2');
$pool = ' route-to { ' . str_repeat('(igb0.431 192.0.2.1) ', 2) .
    str_repeat('(igb1 192.0.2.2) ', 4) . '} round-robin ';
if (filter_sdwan_pool_route([$a, $b]) !== $pool ||
    filter_sdwan_pool_route([$a, $b], true) !== $pool . 'sticky-address ' ||
    filter_sdwan_pool_route([$b]) !== ' route-to (igb1 192.0.2.2) ' ||
    filter_sdwan_pool_route([$b], true) !== ' route-to (igb1 192.0.2.2) ' ||
    filter_sdwan_pool_route([]) !== null) {
	throw new RuntimeException('Unexpected weighted, sticky, single-gateway or empty route pool');
}
echo "ok - weighted pool preserves the configured ratio and sticky option; one hop or no hop is unchanged\n";
foreach ([null, 0, -1, 31] as $invalid_weight) {
	$invalid = array_replace($b, ['weight' => $invalid_weight]);
	if (filter_sdwan_pool_route([$invalid]) !== null || filter_sdwan_pool_route([$a, $invalid]) !== null) {
		throw new RuntimeException('Malformed pool weight created a route');
	}
}
echo "ok - null and out-of-range weights fail closed before pool arithmetic\n";
