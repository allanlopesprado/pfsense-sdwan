<?php
// Supply the appliance config and kernel inventory to the real upstream renderer.
[$script, $work, $core, $operation] = $argv;
set_include_path($work);
require_once('config.inc');
require_once($core . '/src/etc/inc/util.inc');
require_once($work . '/native-renderer.inc');
require_once($work . '/filter-sdwan.inc');
if (!function_exists('gettext')) {
	function gettext($text) { return $text; }
}
function g_get($key) { return false; }
function refresh_gateways() {}
function return_gateways_status($cached) { return []; }
function get_gateways() { return config_get_path('reload_gateways'); }
function lookup_gateway_ip_by_name($name) { return get_gateways()[$name]['address']; }
function is_gateway_online($gateway) { return $gateway['online']; }
function is_gateway_action_enabled($gateway) { return !isset($gateway['action_disable']); }
function return_gateway_groups_array($fixed) { return config_get_path('reload_groups', ['G' => []]); }
function config_path_enabled($path, $key) { return isset(config_get_path($path, [])[$key]); }
function get_failover_gateway_group_label_item($gateway) { return []; }
function interface_has_gateway($interface) { return $interface === 'wan'; }
function interface_has_gatewayv6($interface) { return $interface === 'wan'; }
if ($operation === 'preview') {
	require_once($work . '/gwlb.inc');
} else {
	function get_interface_gateway($interface) { return '198.51.100.2'; }
	function get_interface_gateway_v6($interface) { return '2001:db8:20::2'; }
}
// This format matches printing rules on the WebGUI. Optional unused fields in
// the pinned upstream generator may be absent in config.xml.
set_error_handler(static function ($level, $message, $file) use ($work) {
	return str_replace('\\', '/', $file) === str_replace('\\', '/', $work) . '/native-renderer.inc' && $level === E_WARNING &&
	    (str_starts_with($message, 'Undefined array key') || str_starts_with($message, 'Undefined variable'));
});
$PFConfig = new class {
	public array $gateway_rules = [];
	function set_config($section, $lines, $group, $id) { $this->gateway_rules = $lines; }
};
$g = ['varrun_path' => $work];
$FilterIflist = [
	'lan' => [0 => null, 'if' => 'lablan', 'descr' => 'LABLAN'],
	'wan' => [0 => null, 'if' => 'labwana', 'ifv6' => 'labwana', 'descr' => 'LABWANA'],
	'enc0' => [0 => null, 'if' => 'enc0', 'descr' => 'IPSEC'],
	'openvpn' => [0 => null, 'if' => 'ovpns1', 'descr' => 'OPENVPN'],
	'opt9' => [0 => null, 'if' => 'wg0', 'descr' => 'WIREGUARD'],
];
$vpns_list = false;
$use_floating_states_for_ipsec = false;
$rule = config_get_path('filter/rule')[0];
if ($operation === 'preview') {
	require $work . '/sdwan_steering.inc';
	echo json_encode(sdwan_steering_preview(sdwan_get_config(), 'calls', 'G'), JSON_THROW_ON_ERROR);
	return;
}
filter_generate_gateways(); // Starts a single generation, populating the native route inventory.
if ($operation === 'render') {
	echo filter_generate_user_rule($rule);
} elseif ($operation === 'render-pair') {
	echo json_encode([
	    'macros' => $PFConfig->gateway_rules,
	    'rules' => [filter_generate_user_rule($rule), filter_generate_user_rule(config_get_path('filter/rule')[1])],
	], JSON_THROW_ON_ERROR);
} elseif ($operation === 'freeze') {
	// Publishing the newer snapshot between two rule compilations must not split a binding.
	$first = filter_generate_user_rule($rule);
	copy($work . '/sample-b.json', $work . '/snapshot.json');
	$second = filter_generate_user_rule(config_get_path('filter/rule')[2]);
	filter_generate_gateways();
	$third = filter_generate_user_rule($rule);
	echo json_encode([$first, $second, $third], JSON_THROW_ON_ERROR);
} elseif ($operation === 'control') {
	$rule['tracker'] = '49009';
	$default = array_replace($rule, ['gateway' => '', 'destination' => ['any' => ''], 'protocol' => 'udp']);
	$use_floating_states_for_ipsec = true;
	$dummynet_name_list = ['ControlPipe' => '7'];
	$controls = [
		'gateway group' => [$rule, '$GWG'],
		'adjacent native deny' => [config_get_path('filter/rule')[1], 'block'],
		'local or default DNS' => [array_replace($default, ['destination' => ['any' => '', 'port' => '53']]), 'port 53'],
		'WAN reply-to' => [array_replace($default, ['interface' => 'wan']), 'reply-to'],
		'policy-based IPsec' => [array_replace($default, ['interface' => 'enc0']), '(floating)'],
		'OpenVPN' => [array_replace($default, ['interface' => 'openvpn']), '$OPENVPN'],
		'WireGuard' => [array_replace($default, ['interface' => 'opt9']), '$WIREGUARD'],
		'floating QoS' => [array_replace($default, ['floating' => 'yes', 'direction' => 'out',
		    'tagged' => 'test', 'dnpipe' => 'ControlPipe', 'nopfsync' => '']), 'dnpipe'],
	];
	foreach ($controls as $feature => [$control, $expected]) {
		$stock = lab_stock_user_rule($control);
		if (!str_contains($stock, $expected) || filter_generate_user_rule($control) !== $stock) {
			throw new RuntimeException("Native {$feature} rule changed or had no expected predicate: {$stock}");
		}
	}
	echo 'unchanged';
} elseif ($operation === 'rollback') {
	$rendered = filter_generate_user_rule($rule);
	if ($rendered !== lab_stock_user_rule($rule)) {
		throw new RuntimeException('Unbinding did not restore the native gateway rule.');
	}
	echo $rendered;
} elseif ($operation === 'withdrawal-proof') {
	$hash = 'cb65f7d1dae49b63';
	$active = [
	    'Status: Enabled for 0 days 00:01:00',
	    "block drop in log inet all label \"descr=Default deny rule IPv4\" label \"tags=ruleset:{$hash}\" ridentifier 1000000103",
	    "block drop out log inet6 all label \"descr=Default deny rule IPv6\" label \"tags=ruleset:{$hash}\" ridentifier 1000000106",
	];
	$proof = filter_sdwan_withdrawal_proof([true, ''], $hash, $active);
	if (filter_sdwan_binding_api() !== 2 || filter_sdwan_withdrawal_proof_api() !== 1 ||
	    ($proof['trackers'] ?? null) !== ['41001', '41003'] || ($proof['ruleset'] ?? null) !== $hash ||
	    !is_int($proof['started_ns'] ?? null) || $proof['started_ns'] <= 0) {
		throw new RuntimeException('The native proof did not identify the compiled tracker set.');
	}
	$disabled = $active;
	$disabled[0] = 'Status: Disabled';
	$conflict = $active;
	$conflict[2] = str_replace($hash, '1111111111111111', $conflict[2]);
	foreach ([
	    [[false, 1], $hash, $active], [[true, 'native error'], $hash, $active],
	    [null, '1111111111111111', $active], [null, $hash, $disabled],
	    [null, $hash, $conflict], [null, $hash, [$active[0]]],
	] as [$result, $expected, $observed]) {
		if (filter_sdwan_withdrawal_proof($result, $expected, $observed) !== null) {
			throw new RuntimeException('Incomplete native evidence produced a withdrawal proof.');
		}
	}
	$path = $work . '/fixture.json';
	$config = json_decode(file_get_contents($path), true, 512, JSON_THROW_ON_ERROR);
	$config['gateways/sdwan_bindings/item'] = [];
	file_put_contents($path, json_encode($config, JSON_THROW_ON_ERROR));
	if (filter_sdwan_withdrawal_proof(null, $hash, $active) !== $proof) {
		throw new RuntimeException('An ongoing native generation picked up the newer binding set.');
	}
	filter_generate_gateways();
	$withdrawn = filter_sdwan_withdrawal_proof(null, $hash, $active);
	$receipt = $work . '/filter-commit.json';
	filter_sdwan_write_withdrawal_proof($receipt, $proof);
	filter_sdwan_write_withdrawal_proof($receipt, $withdrawn ?? []);
	if (($withdrawn['trackers'] ?? null) !== [] || $withdrawn['started_ns'] <= $proof['started_ns'] ||
	    $withdrawn['ruleset'] !== $hash || json_decode(file_get_contents($receipt), true) !== $withdrawn ||
	    (PHP_OS_FAMILY !== 'Windows' && (fileperms($receipt) & 0777) !== 0644) ||
	    glob($work . '/.sdwan-filter-*') !== []) {
		throw new RuntimeException('The identical native ruleset did not record a new, complete unbound generation.');
	}
	echo 'confirmed';
} else {
	throw new InvalidArgumentException('Unknown renderer test operation.');
}
