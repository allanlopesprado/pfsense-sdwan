<?php
require_once __DIR__ . '/../files/usr/local/pkg/sdwan.inc';
require_once __DIR__ . '/../files/usr/local/pkg/sdwan_preflight.inc';
require_once __DIR__ . '/fixtures/write/config.inc';

$config = [
	'policies' => [['name' => 'Office', 'members' => ['First', 'Second']]],
	'members' => [['name' => 'First', 'gateway' => 'ISP_A'], ['name' => 'Second', 'gateway' => 'ISP_B']],
];
$native = [
	'groups' => [['name' => 'BRANCH', 'item' => ['ISP_A|1|address', 'ISP_B|2|address'], 'trigger' => 'down']],
	'rules' => [['type' => 'pass', 'tracker' => 101, 'interface' => 'lan', 'gateway' => 'BRANCH',
	    'source' => ['network' => 'lan'], 'destination' => ['address' => '192.0.2.0/24', 'port' => '443'],
	    'protocol' => 'tcp', 'ipprotocol' => 'inet']],
	'gateways' => [], 'interfaces' => ['lan' => ['enable' => '', 'if' => 'vtnet0']],
	'phase1' => [], 'phase2' => [], 'vips' => [], 'dyndns' => [], 'dnsupdates' => [],
	'openvpn_servers' => [], 'openvpn_clients' => [], 'default4' => 'ISP_A', 'default6' => '', 'filtermode' => 'enc',
];
foreach (['ISP_A' => 'wan', 'ISP_B' => 'opt1'] as $name => $if) {
	$native['interfaces'][$if] = ['enable' => '', 'if' => 'vtnet' . count($native['interfaces'])];
	$native['gateways'][$name] = ['interface' => $if, 'family' => 'inet',
	    'monitor_disabled' => false, 'action_disabled' => false, 'force_down' => false];
}
function guard_for(array $rule): array {
	$rule['tracker'] = '102';
	$rule['type'] = 'block';
	unset($rule['gateway']);
	return $rule;
}
$native['rules'][] = guard_for($native['rules'][0]);
function preflight_check(array $n, bool $ok, string $label, ?array $c = null): ?array {
	global $config;
	$result = sdwan_steering_preflight($c ?? $config, 'Office', 'BRANCH', $n);
	if ((empty($result['errors']) !== $ok) || (isset($result['binding']) !== $ok)) {
		throw new Exception($label . ': ' . json_encode($result));
	}
	return $result['binding'];
}
$baseline = preflight_check($native, true, 'WAN pair');
if ($baseline['trackers'] !== ['101'] || $baseline['gateways'] !== ['ISP_A', 'ISP_B']) {
	throw new Exception('Binding identities must match native rules and configured candidates.');
}
$n = $native;
$n['gateways']['ISP_A']['monitor'] = '192.0.2.45';
$n['gateways']['ISP_B']['monitor'] = '192.0.2.45';
preflight_check($n, false, 'shared static IPv4 monitor');
$n['gateways']['ISP_B']['monitor'] = 'dynamic';
$n['gateways']['ISP_B']['resolved_monitor'] = '192.0.2.45';
preflight_check($n, false, 'DHCP gateway resolves to the other member monitor');
unset($n['gateways']['ISP_B']['resolved_monitor']);
preflight_check($n, true, 'pending DHCP gateway keeps the other path available');
$n['gateways']['ISP_C'] = ['monitor' => '192.0.2.45', 'monitor_disabled' => false];
preflight_check($n, false, 'another monitored gateway outside the group owns the same target');
$n['gateways']['ISP_C']['monitor_disabled'] = true;
preflight_check($n, true, 'a gateway with monitoring disabled cannot consume a target');
foreach (['phase1', 'openvpn_clients', 'openvpn_servers', 'dnsupdates', 'dyndns'] as $key) {
	$n = $native;
	$n[$key][] = ['interface' => 'BRANCH'];
	preflight_check($n, false, "also used in {$key}");
}
foreach (['default4', 'default6'] as $key) {
	$n = $native;
	$n[$key] = 'BRANCH';
	preflight_check($n, false, $key);
}
foreach (['floating' => 'yes', 'direction' => 'out', 'ipprotocol' => 'inet6', 'tracker' => '0',
    'type' => 'match', 'nat' => ['enable' => ''], 'associated-rule-id' => 11, 'disabled' => '',
    'sched' => 'weekdays', 'interface' => 'wan', 'force_category' => 'early', 'statetype' => 'none'] as $key => $value) {
	$n = $native;
	$n['rules'][0][$key] = $value;
	preflight_check($n, false, $key);
}
foreach ([['address' => 'changesByDNS'], ['network' => 'bogus'], ['address' => '192.0.2.1/33'],
    ['any' => '', 'port' => 'web_ports'], ['any' => '', 'port' => '65536']] as $selector) {
	$n = $native;
	$n['rules'][0]['destination'] = $selector;
	preflight_check($n, false, 'unstable rule selector');
}
foreach (['monitor_disabled', 'action_disabled'] as $key) {
	$n = $native;
	$n['gateways']['ISP_B'][$key] = true;
	preflight_check($n, false, $key);
}
$n = $native;
array_pop($n['rules']);
preflight_check($n, false, 'independent native blocker is required');
foreach (['type' => 'pass', 'disabled' => '', 'tagged' => 'special', 'direction' => 'out',
    'gateway' => 'ISP_A', 'destination' => ['address' => '198.51.100.0/24'], 'sched' => 'evening'] as $k => $val) {
	$n = $native;
	$n['rules'][1][$k] = $val;
	preflight_check($n, false, 'guard ' . $k);
}
$n = $native;
array_splice($n['rules'], 1, 0, [['type' => 'pass', 'interface' => 'lan', 'tracker' => 109]]);
preflight_check($n, false, 'guard moved after an intervening pass');
$n = $native;
$n['rules'][0]['source'] = ['any' => ''];
$n['rules'][0]['destination'] = ['address' => '0.0.0.0/0'];
$n['rules'][1] = guard_for($n['rules'][0]);
preflight_check($n, false, 'unrestricted source and destination');
$n = $native;
$n['rules'][0]['tagged'] = 'limit';
$n['rules'][1] = guard_for($n['rules'][0]);
preflight_check($n, false, 'tagged binding');
$n = $native;
$n['rules'][] = ['tracker' => '101', 'gateway' => 'ISP_A'];
preflight_check($n, false, 'tracker collision outside group');
$n = $native;
$n['groups'][0]['item'][] = 'ISP_B|3|address';
preflight_check($n, false, 'duplicate group member');
$n = $native;
unset($n['gateways']['ISP_B']);
preflight_check($n, false, 'missing gateway');
$n = $native;
$n['groups'][0]['item'][] = 'ISP_C|3|address';
preflight_check($n, false, 'extra group member');
$n = $native;
$n['interfaces']['opt1']['if'] = 'vtnet1';
preflight_check($n, false, 'one device');
$n = $native;
$n['gateways']['ISP_A']['family'] = 'inet6';
preflight_check($n, false, 'mixed family');
$n = $native;
$n['rules'][0]['descr'] = 'new description only';
if (preflight_check($n, true, 'description')['rules_revision'] !== $baseline['rules_revision']) {
	throw new Exception('Description changed substantive revision');
}
$n['rules'][0]['destination']['address'] = '198.51.100.0/24';
$n['rules'][1] = guard_for($n['rules'][0]);
if (preflight_check($n, true, 'natively edited rule')['rules_revision'] === $baseline['rules_revision']) {
	throw new Exception('Changed native rule scope must invalidate saved binding');
}
$n = $native;
$n['groups'][0]['item'][1] = 'ISP_B|1|address';
if (preflight_check($n, true, 'native tier change')['rules_revision'] === $baseline['rules_revision']) {
	throw new Exception('Changed native group must invalidate saved binding');
}
$n = $native;
$n['groups'][0]['item'] = ['ISP_A|1|address'];
$single = $config;
$single['policies'][0]['members'] = ['First'];
preflight_check($n, false, 'one observed path', $single);
$n = $native;
foreach ($n['gateways'] as &$entry) {
	$entry['family'] = 'inet6';
}
unset($entry);
$n['rules'][0]['ipprotocol'] = 'inet6';
$n['rules'][0]['destination'] = ['address' => '::/0'];
$n['rules'][1] = guard_for($n['rules'][0]);
preflight_check($n, true, 'dual-WAN IPv6 default');
$n['gateways']['ISP_A']['monitor'] = '2001:DB8:0:0::9';
$n['gateways']['ISP_B']['monitor'] = '2001:db8::9';
preflight_check($n, false, 'equivalent compressed IPv6 monitors collide');
$n['gateways']['ISP_A']['monitor'] = 'fe80::1';
$n['gateways']['ISP_B']['monitor'] = 'fe80::1';
preflight_check($n, false, 'duplicate unscoped link-local monitors');
$n['gateways']['ISP_A']['monitor'] = 'fe80::1%vtnet1';
$n['gateways']['ISP_B']['monitor'] = 'fe80::1%vtnet2';
preflight_check($n, true, 'link-local monitors on different explicit scopes');
$n = $native;
$n['rules'][0]['destination'] = ['address' => '0.0.0.0/0'];
$n['rules'][1] = guard_for($n['rules'][0]);
preflight_check($n, true, 'IPv4 default');
$n = $native;
$n['interfaces']['lan']['ipaddr'] = '10.23.0.254';
$n['interfaces']['lan']['subnet'] = '24';
$n['full_tunnel_sources'] = ['inet' => ['10.23.0.128/25']];
preflight_check($n, false, 'native WAN rule overlaps the policy IPsec full-tunnel source');
$n['full_tunnel_sources']['inet'] = ['10.23.1.0/24'];
preflight_check($n, true, 'unrelated source remains routed by SD-WAN');
$n['rules'][0]['source'] = ['address' => '10.23.0.129'];
$n['rules'][1] = guard_for($n['rules'][0]);
$n['full_tunnel_sources']['inet'] = ['10.23.0.128/25'];
preflight_check($n, false, 'literal host inside the protected prefix');
$n['rules'][0]['source'] = ['address' => '10.23.0.12'];
$n['rules'][1] = guard_for($n['rules'][0]);
preflight_check($n, true, 'literal host outside the protected prefix');
$n['full_tunnel_sources']['inet'] = [null];
preflight_check($n, false, 'unresolved IPsec local source is treated as a possible overlap');
$n['full_tunnel_sources'] = ['inet6' => ['2001:db8::/64']];
preflight_check($n, true, 'IPv6 full tunnel does not conflict with an IPv4 rule');
if (!sdwan_preflight_prefixes_overlap('2001:db8:1:8000::5', '2001:db8:1:8000::/49') ||
    sdwan_preflight_prefixes_overlap('2001:db8:1:7fff::5', '2001:db8:1:8000::/49')) {
	throw new Exception('IPv6 non-octet subnet boundaries must be respected');
}
$n = $native;
$n['filtermode'] = 'if_ipsec';
$n['vips'] = [['uniqid' => 'carp', 'mode' => 'carp', 'interface' => 'wan']];
foreach ([1 => ['ISP_A', '_vipcarp'], 2 => ['ISP_B', 'opt1']] as $id => [$name, $transport]) {
	$if = "opt1{$id}";
	$n['interfaces'][$if] = ['enable' => '', 'if' => "ipsec5{$id}"];
	$n['phase1'][] = ['ikeid' => $id, 'interface' => $transport, 'iketype' => 'ikev2'];
	$n['phase2'][] = ['ikeid' => $id, 'reqid' => "5{$id}", 'mode' => 'vti'];
	$n['gateways'][$name]['interface'] = $if;
}
$vti_binding = preflight_check($n, true, 'two VTIs and a CARP parent');
$vti = $n;
foreach ([['any' => ''], ['address' => '0.0.0.0/0']] as $unrestricted) {
	$n = $vti;
	$n['rules'][0]['destination'] = $unrestricted;
	$n['rules'][1] = guard_for($n['rules'][0]);
	preflight_check($n, false, 'VTI protection requires a specific destination');
}
$n = $vti;
$n['phase1'][0]['remote-gateway'] = '203.0.113.7';
if (preflight_check($n, true, 'new IPsec peer')['rules_revision'] === $vti_binding['rules_revision']) {
	throw new Exception('A new IPsec peer cannot reuse the previous steering consent.');
}
$n = $vti;
$n['filtermode'] = 'enc';
preflight_check($n, false, 'unqualified VTI filter mode');
$n = $vti;
$n['phase1'][1]['interface'] = 'wan';
preflight_check($n, false, 'VTIs share the same WAN');
$n = $vti;
$n['phase1'][1]['interface'] = '_vipmissing';
preflight_check($n, false, 'unresolved VTI transport');
$n = $vti;
$n['gateways']['ISP_B']['interface'] = 'opt1';
preflight_check($n, false, 'do not steer protected flows to cleartext WAN');
$n = $vti;
$n['phase1'][] = ['ikeid' => '3', 'mobile' => ''];
preflight_check($n, false, 'mobile IPsec conflict');
$n = $vti;
$n['phase2'][] = ['ikeid' => '2', 'mode' => 'tunnel'];
preflight_check($n, false, 'enabled policy-based child conflict');
$n['phase2'][2]['disabled'] = '';
preflight_check($n, true, 'disabled policy-based child');
$current = [
	'vlans/vlan' => [
		['vlanif' => 'igb0.10', 'if' => 'igb0'],
		['vlanif' => 'igb0.20', 'if' => 'igb0'],
		['vlanif' => 'lagg0.40', 'if' => 'lagg0'],
	],
	'qinqs/qinqentry' => [['vlanif' => 'igb0.50', 'if' => 'igb0', 'members' => '7  9']],
	'laggs/lagg' => [['laggif' => 'lagg0', 'members' => 'igb1,igb2']],
	'bridges/bridged' => [['bridgeif' => 'bridge0', 'members' => 'opt99,lan']],
	'ppps/ppp' => [['if' => 'pppoe0', 'ports' => 'igb0.20']],
];
$n = $native;
$n['interfaces']['opt99'] = ['enable' => '', 'if' => 'lagg0.40'];
$n['links'] = sdwan_preflight_link_graph($n['interfaces']);
$n['interfaces']['wan']['if'] = 'igb0.10';
foreach (['igb0', 'igb0.20', 'igb0.50.7', 'pppoe0'] as $device) {
	$n['interfaces']['opt1']['if'] = $device;
	preflight_check($n, false, "shared physical parent through {$device}");
}
$n['interfaces']['opt1']['if'] = 'lagg0.40';
$independent = preflight_check($n, true, 'distinct physical parent and LAGG');
$topology = $n;
$topology['links']['lagg0'] = ['igb1', 'igb3'];
if (preflight_check($topology, true, 'changed LAGG membership')['rules_revision'] === $independent['rules_revision']) {
	throw new Exception('Changed physical dependencies must invalidate the previous approval.');
}
$topology = $n;
$topology['links']['lagg0'] = ['igb2', 'igb1'];
if (preflight_check($topology, true, 'reordered LAGG membership')['rules_revision'] !== $independent['rules_revision']) {
	throw new Exception('Device list order changed a stable physical topology.');
}
$topology['links']['lagg0'] = ['igb0', 'igb1'];
preflight_check($topology, false, 'LAGG includes other WAN port');
$topology['links']['lagg0'] = ['lagg0.40'];
preflight_check($topology, false, 'recursive link dependency cannot be established');
$n['interfaces']['wan']['if'] = 'igb2';
$n['interfaces']['opt1']['if'] = 'bridge0';
preflight_check($n, false, 'bridge contains VLAN on the other WAN port');

$n = $vti;
$n['links'] = sdwan_preflight_link_graph($n['interfaces']);
$n['interfaces']['wan']['if'] = 'igb0.10';
$n['interfaces']['opt1']['if'] = 'pppoe0';
preflight_check($n, false, 'VTIs on separate logical interfaces share the same physical link');
$n['interfaces']['opt1']['if'] = 'lagg0.40';
preflight_check($n, true, 'VTIs use independent physical links');

foreach (['ovpnc1', 'wg0', 'gif0', 'gre0'] as $device) {
	$n = $native;
	$n['interfaces']['opt1']['if'] = $device;
	preflight_check($n, false, "unsupported active member {$device}");
	$n['interfaces']['opt1']['if'] = 'vtnet2';
	$n['interfaces']['opt9'] = ['enable' => '', 'if' => $device];
	preflight_check($n, true, "unrelated tunnel {$device} can coexist");
}
echo "Native ingress, gateway-group, scope drift, physical dependency, VPN and HA preflight tests passed.\n";
