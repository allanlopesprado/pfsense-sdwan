<?php
declare(strict_types=1);
set_include_path(__DIR__ . '/fixtures/write');
require 'config.inc';
require __DIR__ . '/../files/usr/local/pkg/sdwan.inc';
require __DIR__ . '/../files/usr/local/pkg/sdwan_engine.inc';

function verify(bool $result, string $title): void {
	if (!$result) {
		throw new RuntimeException($title);
	}
	echo "ok - {$title}\n";
}

$current = [
	'interfaces' => [
		'wan' => ['if' => 'igb0', 'enable' => ''],
		'opt1' => ['if' => 'ipsec10', 'enable' => ''],
		'opt2' => ['if' => 'ipsec20', 'enable' => ''],
		'opt3' => ['if' => 'ipsec30', 'enable' => ''],
	],
	'ipsec/phase1' => [
		['ikeid' => '1', 'interface' => 'wan', 'splitconn' => ''],
		['ikeid' => '2', 'interface' => 'wan', 'iketype' => 'ikev2'],
		['ikeid' => '3', 'interface' => 'WAN_GROUP'],
	],
	'ipsec/phase2' => [
		['reqid' => '10', 'ikeid' => '1', 'mode' => 'vti'],
		['reqid' => '20', 'ikeid' => '2', 'mode' => 'vti'],
		['reqid' => '21', 'ikeid' => '2', 'mode' => 'vti'],
		['reqid' => '30', 'ikeid' => '3', 'mode' => 'vti'],
	],
	'gateways/gateway_item' => [
		['name' => 'A', 'interface' => 'opt1', 'gateway' => '2001:db8:1::1'],
		['name' => 'B', 'interface' => 'opt2', 'gateway' => '2001:db8:2::1'],
		['name' => 'C', 'interface' => 'opt3', 'gateway' => 'fe80::1%ipsec30'],
		['name' => 'WAN', 'interface' => 'wan', 'gateway' => '192.0.2.1'],
	],
];
$before = $current;
$inventory = sdwan_gateways();
verify($inventory['A']['transport'] === 'wan' && $inventory['B']['transport'] === 'wan', 'split and merged VTI transports traced to assigned Phase 1 interface');
verify($inventory['C']['transport'] === '' && $inventory['C']['family'] === 'inet6', 'gateway-group underlay remains unknown and scoped IPv6 family is preserved');
verify($inventory['WAN']['transport'] === 'wan' && $before === $current, 'gateway discovery preserves native configuration');
$transports = sdwan_vti_transports($current['interfaces'], $current['ipsec/phase1'], $current['ipsec/phase2']);
verify(!isset($transports['ipsec21']), 'merged IKEv2 reuses first Phase 2 device');

$config = ['version' => '1', 'members' => [
	['name' => 'one', 'gateway' => 'A', 'cost' => '0'],
	['name' => 'two', 'gateway' => 'B', 'cost' => '10'],
], 'slas' => [['name' => 'sla', 'latency_ms' => '100', 'loss_pct' => '4']],
   'policies' => [['name' => 'p', 'members' => ['one','two'], 'sla' => 'sla', 'strategy' => 'cost']]];
$sample = ['status' => 'online', 'substatus' => 'none', 'delay' => '12ms', 'stddev' => '1ms', 'loss' => '1%'];
$measurements = ['A' => $sample, 'B' => $sample];
function outcome(array $settings, array $observations, array $gateways): array {
	return sdwan_evaluate($settings, $observations, 1, $gateways)['policies']['p'];
}
$result = outcome($config, $measurements, $inventory);
verify(sdwan_validate_config($config, $inventory) === [] && $result['path_status'] === 'alternatives' &&
    $result['eligible_count'] === 2 && $result['shared_underlay'] && !$result['shared_interface'], 'two working tunnels over one WAN remain valid alternatives with a shared transport');
$current['interfaces']['opt4'] = ['if' => 'igb1', 'enable' => ''];
$current['virtualip/vip'] = [
	['uniqid' => '101', 'mode' => 'carp', 'interface' => 'wan'],
	['uniqid' => '102', 'mode' => 'ipalias', 'interface' => '_vip101'],
	['uniqid' => '103', 'mode' => 'carp', 'interface' => 'opt4'],
];
$current['ipsec/phase1'][0]['interface'] = '_vip101';
$current['ipsec/phase1'][1]['interface'] = '_vip102';
$before_vips = $current;
$vip_inventory = sdwan_gateways();
verify($vip_inventory['A']['transport'] === 'wan' && $vip_inventory['B']['transport'] === 'wan' &&
    outcome($config, $measurements, $vip_inventory)['shared_underlay'] && $current === $before_vips,
    'CARP and stacked IP alias on the same WAN share a VTI transport without writing configuration');
$current['ipsec/phase1'][1]['interface'] = '_vip103';
$vip_inventory = sdwan_gateways();
verify($vip_inventory['B']['transport'] === 'opt4' && !outcome($config, $measurements, $vip_inventory)['shared_underlay'],
    'VTIs on CARP VIPs with distinct parent WANs remain independent');
$current['virtualip/vip'][0]['interface'] = '_vip102';
verify(sdwan_gateways()['A']['transport'] === '', 'a loop in VIP parent references leaves the VTI transport unresolved');
$current = $before;
$on_same = $inventory;
$on_same['B']['interface'] = 'opt1';
verify(sdwan_validate_config($config, $on_same) === [] && outcome($config, $measurements, $on_same)['shared_interface'], 'distinct gateways on one logical interface are allowed and signaled');
$survivor = outcome($config, ['B' => $sample], $inventory);
verify($survivor['path_status'] === 'degraded' && $survivor['eligible_count'] === 1 && $survivor['selected'] === 'two', 'one surviving path in a multi-member policy is still recommended');
$single = $config;
$single['policies'][0]['members'] = ['one'];
$result = outcome($single, $measurements, $inventory);
verify(sdwan_validate_config($single, $inventory) === [] && $result['path_status'] === 'single' && $result['selected'] === 'one', 'single-member policy observes SLA with no alternate');
verify(sdwan_decode_config(sdwan_encode_config($single)) === $single, '0.1.1 single-member configuration round-trips without migration');
verify(outcome($single, [], $inventory)['path_status'] === 'no_eligible' && outcome($config, [], $inventory)['selected'] === null, 'all missing measurements leave no recommendation');
$disabled = $inventory;
$disabled['A']['monitor_disabled'] = true;
verify(sdwan_validate_config($config, $disabled) !== [] && sdwan_validate_config($config, $disabled, $config) === [], 'new unmonitored paths are rejected while existing paths survive');
$new_policy = $config;
$new_policy['policies'][0]['name'] = 'other';
verify(sdwan_validate_config($new_policy, $disabled, $config) !== [], 'new policy cannot reuse a restored unavailable member');
$mixed = $inventory;
$mixed['A']['family'] = 'inet';
verify(sdwan_validate_config($config, $mixed) !== [] && outcome($config, $measurements, $mixed)['selected'] === null, 'mixed-family paths cannot be compared');
verify(sdwan_validate_config($single, $mixed, $config) === [] && sdwan_validate_config($config, $mixed, $config) === [], 'restore permits repair of one policy while unchanged mixed paths stay suppressed');
$high = $sample;
$high['substatus'] = 'highloss';
verify(sdwan_member_sample($high)['status'] === 'degraded' && sdwan_member_sample(array_replace($high, ['status' => 'down']))['status'] === 'down', 'native status controls gateway alarm action');
verify(sdwan_member_sample(array_replace($high, ['loss' => '100%']))['status'] === 'down', 'total loss stays ineligible even when alarm action is disabled');

foreach ([
	['fe80::1', 'inet6', true, 'fe80::1%igb0'],
	['fe80::0001%igb0', 'inet6', false, 'fe80::1%igb0'],
	['fe80::1%igb1', 'inet6', true, null],
	['fe80::1', 'inet6', false, null],
	['2001:db8::0001', 'inet6', false, '2001:db8::1'],
	['2001:db8::1%igb0', 'inet6', false, null],
	['192.0.2.1', 'inet6', true, null],
	['192.0.2.1%igb0', 'inet', true, null],
	['192.0.2.1', 'inet', false, '192.0.2.1'],
] as [$address, $family, $infer, $expected]) {
	verify(sdwan_monitor_address($address, $family, 'igb0', $infer) === $expected,
	    "native monitor address {$address} with family {$family} and scope inference " . (int)$infer);
}

require __DIR__ . '/fixtures/gwlb.inc';
$current['fixture_devices'] = ['wan' => 'igb0'];
$current['fixture_dynamic_targets'] = ['wan' => 'fe80::a'];
$current['fixture_sources'] = ['igb0' => 'fe80::b%igb0'];
$gateway = ['interface' => 'wan', 'family' => 'inet6', 'monitor' => 'dynamic'];
$process = ['srcip' => 'fe80::b%igb0', 'targetip' => 'fe80::a%igb0'];
verify(sdwan_monitor_matches($gateway, $process), 'link-local dynamic gateway matches dpinger on its live interface');
verify(!sdwan_monitor_matches($gateway, array_replace($process, ['targetip' => 'fe80::a%igb1'])), 'same link-local next hop on another interface is rejected');
verify(!sdwan_monitor_matches($gateway, array_replace($process, ['targetip' => 'fe80::c%igb0'])), 'stale DHCP target is ignored');
verify(!sdwan_monitor_matches($gateway, array_replace($process, ['srcip' => 'fe80::e%igb0'])), 'stale bind address is ignored');
$source = '2001:db8:ffff:ffff:ffff:ffff:ffff:aaaa';
$current['fixture_sources']['igb0'] = $source;
$global = array_replace($gateway, ['monitor' => '2001:db8:ffff:ffff:ffff:ffff:ffff:bbbb']);
$hashed = ['srcip' => substr(md5($source), 0, 8), 'targetip' => $global['monitor']];
verify(sdwan_monitor_matches($global, $hashed), 'native shortened source field is matched to the live IPv6 source');
$hashed['srcip'] = substr(md5('previous source'), 0, 8);
verify(!sdwan_monitor_matches($global, $hashed), 'obsolete shortened source field is rejected');
unset($current['fixture_dynamic_targets']['wan']);
verify(!sdwan_monitor_matches($gateway, $process), 'a DHCP gateway without a current lease cannot reuse an old socket');
