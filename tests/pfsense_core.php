<?php
/*
 * Exercise the upstream XML readers, page privilege matcher and Dashboard
 * widget-key validator. The caller supplies an explicitly pinned CE checkout.
 * A temporary bootstrap supplies only the appliance environment these need.
 */
ob_start(); // Keep HTTP result codes available across in-process widget requests.
$root = dirname(__DIR__);
$core = realpath(($argv[1] ?? '') . '/src/etc/inc');
if ($core === false || !extension_loaded('xml')) {
	throw new RuntimeException('Usage: php (with ext-xml) tests/pfsense_core.php path/to/pfsense');
}
$www = $root . '/files/usr/local/www';
$local = $root . '/files/usr/local';
$temp = sys_get_temp_dir() . '/sdwan-core-' . bin2hex(random_bytes(10));
mkdir($temp, 0700);
mkdir($temp . '/Net');
register_shutdown_function(static function () use ($temp): void {
	foreach (['Net/IPv6.php', 'globals.inc', 'guiconfig.inc', 'config.inc', 'sdwan.widget.php', 'config.xml'] as $path) {
		if (is_file($temp . '/' . $path)) {
			unlink($temp . '/' . $path);
		}
	}
	rmdir($temp . '/Net');
	rmdir($temp);
});
// The selected upstream routines do not use the PEAR IPv6 class or need an
// appliance bootstrap. Provide their include paths without reading host files.
foreach (['Net/IPv6.php', 'globals.inc', 'guiconfig.inc', 'config.inc'] as $path) {
	file_put_contents($temp . '/' . $path, "<?php\n");
}
set_include_path($temp);
function g_get($key) {
	return $key === 'www_path' ? $GLOBALS['www'] : false;
}
function isAllowedPage($path) {
	// Real WebGUI page names may include a query. Providing the delimiter
	// keeps PHP from warning in the native two-element explode assignment.
	return cmp_page_matches(str_contains($path, '?') ? $path : $path . '?', $GLOBALS['role']);
}
function config_get_path(string $path, $default = null) {
	return $GLOBALS['test_config'][$path] ?? $default;
}
if (!function_exists('gettext')) {
	function gettext($message) { return $message; }
}
function verify(bool $condition, string $description): void {
	if (!$condition) {
		throw new RuntimeException($description);
	}
}
require $core . '/xmlparse.inc';
require $core . '/auth_func.inc';
require $core . '/util.inc';
require $local . '/pkg/sdwan.inc';
require $root . '/files/etc/inc/priv/sdwan.priv.inc';

$package = parse_xml_config_pkg($local . '/share/pfSense-pkg-SDWAN/info.xml', 'pfsensepkgs')['package'][0];
$gui = parse_xml_config_pkg($local . '/pkg/' . $package['configurationfile'], 'packagegui');
verify($gui['menu'][0]['url'] === '/sdwan/status.php' && $gui['menu'][0]['section'] === 'Services', 'Package menu');
verify($gui['service'][0]['name'] === 'sdwand' && is_file($local . '/etc/rc.d/' . $gui['service'][0]['rcfile']), 'Service metadata');
echo "ok - upstream package XML parser loads the menu and service\n";

$single = [
	'version' => '1',
	'members' => [['name' => 'wan', 'gateway' => 'GW', 'cost' => '3']],
	'slas' => [['name' => 'voice', 'latency_ms' => '25', 'loss_pct' => '1']],
	'policies' => [['name' => 'calls', 'sla' => 'voice', 'strategy' => 'cost', 'members' => ['wan']]],
];
foreach ([sdwan_empty_config(), $single] as $fixture) {
	$system = ['ipsec' => ['phase2' => [['mode' => 'vti']]], 'nat' => ['outbound' => ['mode' => 'hybrid']]];
	$system['installedpackages']['sdwan'] = sdwan_encode_config($fixture);
	file_put_contents($temp . '/config.xml', dump_xml_config($system, 'pfsense'));
	$restored = parse_xml_config($temp . '/config.xml', 'pfsense');
	verify($restored['nat'] === $system['nat'] && $restored['ipsec'] === $system['ipsec'], 'Unrelated config round-trip');
	verify(sdwan_decode_config($restored['installedpackages']['sdwan']) === $fixture, 'Observer config round-trip');
}
echo "ok - upstream backup/restore parser preserves single-item policy lists alongside IPsec and NAT\n";

$view = $priv_list['page-services-sdwan-view']['match'];
$manage = $priv_list['page-services-sdwan-manage']['match'];
$role = $view;
verify(isAllowedPage('/sdwan/status.php') && isAllowedPage('/sdwan/diagnostics.php?policy=calls'), 'View permission');
verify(isAllowedPage('/widgets/widgets/sdwan.widget.php') && !isAllowedPage('/sdwan/updates.php'), 'Widget and update permissions');
foreach (['members', 'slas', 'policies', 'forwarding', 'updates'] as $page) {
	$role = $manage;
	verify(isAllowedPage("/sdwan/{$page}.php"), "Manage {$page}");
	$role = $view;
	verify(!isAllowedPage("/sdwan/{$page}.php"), "Read-only role denied {$page}");
}
echo "ok - upstream page matcher enforces the SD-WAN view and manage roles\n";

// Relocate absolute installed includes, preserving the shipped widget basename
// because the native widget validator compares the key to the endpoint filename.
$widget = $temp . '/sdwan.widget.php';
$source = file_get_contents($www . '/widgets/widgets/sdwan.widget.php');
file_put_contents($widget, str_replace('/usr/local/pkg/', $local . '/pkg/', $source));
function widget_request(array $privileges, string $method, array $post, string $sequence, bool $dashboard): array {
	global $widget, $role;
	$role = $privileges;
	$_SERVER['REQUEST_METHOD'] = $method;
	$_POST = $post;
	$user_settings = ['widgets' => ['sequence' => $sequence]];
	if ($dashboard) {
		$widgetkey = 'sdwan-0';
	}
	http_response_code(200);
	ob_start();
	include $widget;
	return [http_response_code(), ob_get_clean()];
}
$sequence = 'sdwan:col1:show:0,';
$post = ['ajax' => 'ajax', 'widgetkey' => 'sdwan-0'];
[$code, $content] = widget_request($view, 'GET', [], $sequence, true);
verify($code === 200 && str_contains($content, 'register_ajax') && str_contains($content, 'No SD-WAN policies'), 'Dashboard include');
[$code, $content] = widget_request($view, 'POST', $post, $sequence, false);
verify($code === 200 && str_contains($content, 'No SD-WAN policies') && !str_contains($content, 'register_ajax'), 'Authorized fragment');
foreach ([
	[[], 'POST', $post, $sequence, 403],
	[$view, 'GET', $post, $sequence, 400],
	[$view, 'POST', $post, 'system_information:col1:show:0,', 400],
	[$view, 'POST', ['ajax' => 'ajax', 'widgetkey' => 'sdwan-1'], $sequence, 400],
] as [$privileges, $method, $body, $layout, $status]) {
	[$code, $content] = widget_request($privileges, $method, $body, $layout, false);
	verify($code === $status && !str_contains($content, 'No SD-WAN policies'), 'Unauthorized or unconfigured widget request');
}
echo "ok - dashboard rendering and refresh enforce status privilege and native widget instance membership\n";
