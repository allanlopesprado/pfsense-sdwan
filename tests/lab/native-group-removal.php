<?php
/* Exercise the pinned CE deletion handler, not a reimplementation of its loop. */
$core = realpath(($argv[1] ?? '') . '/src/usr/local/www/system_gateway_groups.php');
if ($core === false) {
	throw new RuntimeException('Provide the CE source checkout used for the adapter.');
}
require dirname(__DIR__, 2) . '/core/filter-sdwan.inc';
$store = [
	'gateways/gateway_group' => [['name' => 'LAB']],
	'gateways/sdwan_bindings/item' => [['group' => 'LAB', 'trackers' => ['item' => ['42']]]],
	'filter/rule' => [
		['tracker' => '42', 'gateway' => 'LAB', 'type' => 'pass'],
		['tracker' => '43', 'gateway' => 'EXISTING', 'type' => 'pass'],
	],
];
$commits = 0;
function config_get_path($path, $default = null) {
	return $GLOBALS['store'][$path] ?? $default;
}
function config_del_path($path) {
	global $store;
	if ($path === 'gateways/gateway_group/0') {
		unset($store['gateways/gateway_group'][0]);
	} elseif ($path === 'filter/rule/0/gateway') {
		unset($store['filter/rule'][0]['gateway']);
	} else {
		throw new RuntimeException('Unexpected config deletion');
	}
}
function get_filter_rules_list() { return config_get_path('filter/rule', []); }
function write_config($message) { $GLOBALS['commits']++; }
function mark_subsystem_dirty($key) {}
function is_subsystem_dirty($key) { return false; }
if (!function_exists('gettext')) {
	function gettext($message) { return $message; }
}
$tmp = sys_get_temp_dir() . '/sdwan-native-delete-' . bin2hex(random_bytes(8));
mkdir($tmp, 0700);
$stubs = ['guiconfig.inc', 'functions.inc', 'filter.inc', 'shaper.inc', 'openvpn.inc'];
foreach ($stubs as $stub) {
	file_put_contents($tmp . '/' . $stub, "<?php\n");
}
set_include_path($tmp);
$_POST = $_REQUEST = ['id' => 0, 'act' => 'del', 'apply' => ''];
register_shutdown_function(static function () use ($tmp, $stubs): void {
	global $store, $commits;
	foreach ($stubs as $stub) {
		unlink($tmp . '/' . $stub);
	}
	rmdir($tmp);
	[$bound, $other] = $store['filter/rule'];
	if ($commits !== 1 || $store['gateways/gateway_group'] !== [] ||
	    array_key_exists('gateway', $bound) || $bound['tracker'] !== '42' ||
	    filter_sdwan_rule_route($bound, []) !== false ||
	    $other['gateway'] !== 'EXISTING' || filter_sdwan_rule_route($other, []) !== null) {
		throw new RuntimeException('Removing a group did not preserve the bound tracker and deny decision');
	}
	echo "ok - native GUI group deletion clears gateway; core still denies the bound tracker and preserves unrelated rules\n";
});
require $core;
