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
function return_gateway_groups_array($fixed) {
	return array_fill_keys(array_column(config_get_path('gateways/gateway_group', []), 'name'), []);
}
function config_path_enabled($path, $key) { return isset(config_get_path($path, [])[$key]); }
function get_failover_gateway_group_label_item($gateway) { return []; }
function interface_has_gateway($interface) { return $interface === 'wan'; }
function interface_has_gatewayv6($interface) { return $interface === 'wan'; }
function get_interface_gateway($interface) { return '198.51.100.2'; }
function get_interface_gateway_v6($interface) { return '2001:db8:20::2'; }
// This format matches printing rules on the WebGUI. Optional unused fields in
// the pinned upstream generator may be absent in config.xml.
set_error_handler(static function ($level, $message, $file) use ($work) {
	return $file === $work . '/native-renderer.inc' && $level === E_WARNING &&
	    (str_starts_with($message, 'Undefined array key') || str_starts_with($message, 'Undefined variable'));
});
$PFConfig = new class {
	function set_config($section, $lines, $group, $id) {}
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
if ($operation === 'preview_policy') {
	require $work . '/sdwan_steering.inc';
	echo json_encode(sdwan_steering_preview(sdwan_get_config(), $argv[4], $argv[5]), JSON_THROW_ON_ERROR);
	return;
}
if ($operation === 'preview') {
	require $work . '/sdwan_steering.inc';
	echo json_encode(sdwan_steering_preview(sdwan_get_config(), 'calls', 'G'), JSON_THROW_ON_ERROR);
	return;
}
filter_generate_gateways(); // Starts a single generation, populating the native route inventory.
if ($operation === 'render') {
	echo filter_generate_user_rule($rule);
} elseif (in_array($operation, ['paired', 'paired_rollback'], true)) {
	foreach (config_get_path('filter/rule') as $native_rule) {
		$compiled = filter_generate_user_rule($native_rule);
		if ($operation === 'paired_rollback' && $compiled !== lab_stock_user_rule($native_rule)) {
			throw new RuntimeException('The native rule changed after unbinding.');
		}
		echo $compiled, PHP_EOL;
	}
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
} else {
	throw new InvalidArgumentException('Unknown renderer test operation.');
}
