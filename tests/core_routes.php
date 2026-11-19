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
