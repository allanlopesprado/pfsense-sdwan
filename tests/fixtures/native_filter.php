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
function return_gateway_groups_array($fixed) { return ['G' => []]; }
function config_path_enabled($path, $key) { return isset(config_get_path($path, [])[$key]); }
function get_failover_gateway_group_label_item($gateway) { return []; }
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
$FilterIflist = ['lan' => [0 => null, 'if' => 'lablan', 'descr' => 'LABLAN']];
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
} elseif ($operation === 'freeze') {
	// Publishing the newer snapshot between two rule compilations must not split a binding.
	$first = filter_generate_user_rule($rule);
	copy($work . '/sample-b.json', $work . '/snapshot.json');
	$second = filter_generate_user_rule($rule);
	filter_generate_gateways();
	$third = filter_generate_user_rule($rule);
	echo json_encode([$first, $second, $third], JSON_THROW_ON_ERROR);
} elseif ($operation === 'control') {
	$rule['tracker'] = '49009';
	if (filter_generate_user_rule($rule) !== lab_stock_user_rule($rule)) {
		throw new RuntimeException('An unbound gateway-group rule changed.');
	}
	$native_guard = config_get_path('filter/rule')[1];
	if (filter_generate_user_rule($native_guard) !== lab_stock_user_rule($native_guard)) {
		throw new RuntimeException('The adjacent native deny rule changed.');
	}
	echo 'unchanged';
} else {
	throw new InvalidArgumentException('Unknown renderer test operation.');
}
