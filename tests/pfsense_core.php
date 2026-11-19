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
	foreach (['Net/IPv6.php', 'globals.inc', 'guiconfig.inc', 'config.inc', 'sdwan.widget.php', 'config.xml',
	    'shortcuts.inc', 'webgui/status_logs.php', 'webgui/sdwan/members.php', 'webgui/sdwan/status.php'] as $path) {
		if (is_file($temp . '/' . $path)) {
			unlink($temp . '/' . $path);
		}
	}
	foreach (['native-shortcuts', 'webgui/sdwan', 'webgui', 'Net'] as $directory) {
		if (is_dir($temp . '/' . $directory)) {
			rmdir($temp . '/' . $directory);
		}
	}
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
verify($gui['service'][0]['name'] === 'sdwan' && $gui['service'][0]['rcfile'] === 'sdwand.sh' &&
    is_file($local . '/etc/rc.d/' . $gui['service'][0]['rcfile']), 'Service metadata');
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

require_once $local . '/pkg/sdwan_engine.inc';
$system['interfaces'] = ['wan' => ['enable' => '', 'if' => 'em0']];
$system['gateways']['gateway_item'] = [['name' => 'GW', 'interface' => 'wan', 'gateway' => '192.0.2.1']];
$import = static function (array $system) use ($temp): void {
	file_put_contents($temp . '/config.xml', dump_xml_config($system, 'pfsense'));
	$restored = parse_xml_config($temp . '/config.xml', 'pfsense');
	$GLOBALS['test_config'] = [
	    SDWAN_CONFIG_PATH => $restored['installedpackages']['sdwan'] ?? null,
	    'interfaces' => $restored['interfaces'] ?? [],
	    'gateways/gateway_item' => $restored['gateways']['gateway_item'] ?? [],
	];
};
$import($system);
$original = sdwan_gateways();
verify(($original['GW']['device'] ?? null) === 'em0', 'Imported configuration has the original adapter');
$original_revision = sdwan_gateway_inventory_revision(sdwan_get_config(), $original);
$system['interfaces']['wan']['if'] = 'vtnet0';
$import($system);
$remapped = sdwan_gateways();
verify(sdwan_get_config() === $single && ($remapped['GW']['device'] ?? null) === 'vtnet0', 'Remap preserves the logical member');
verify(sdwan_gateway_inventory_revision(sdwan_get_config(), $remapped) !== $original_revision, 'Remap invalidates old measurements');

$system['gateways']['gateway_item'][0]['name'] = 'NEW_GW';
$import($system);
$renamed = sdwan_gateways();
verify(sdwan_get_config() === $single && !isset($renamed['GW']) && isset($renamed['NEW_GW']), 'Missing member is preserved for editing');
$other_sample = ['status' => 'online', 'substatus' => 'none', 'delay' => '1ms', 'stddev' => '0ms', 'loss' => '0%'];
$observed = sdwan_evaluate(sdwan_get_config(), ['NEW_GW' => $other_sample], time(), $renamed);
verify($observed['policies']['calls']['selected'] === null, 'Restoring does not silently adopt a different logical gateway');
$repaired = $single;
$repaired['members'][0]['gateway'] = 'NEW_GW';
verify(sdwan_validate_config($repaired, $renamed, $single) === [], 'Administrator can explicitly remap the member');
$observed = sdwan_evaluate($repaired, ['NEW_GW' => $other_sample], time(), $renamed);
verify($observed['policies']['calls']['selected'] === 'wan', 'A fresh reading restores eligibility after explicit remapping');

unset($system['installedpackages']);
$import($system);
verify(sdwan_get_config() === sdwan_empty_config(), 'A backup without packages starts with empty settings');
unset($GLOBALS['test_config']);
echo "ok - native XML recovery covers physical remapping, renamed gateways, explicit repair and backups without packages\n";

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

$corewww = $argv[1] . '/src/usr/local/www';
$packagewww = $www;
$www = $temp . '/webgui';
mkdir($www . '/sdwan', 0700, true);
mkdir($temp . '/native-shortcuts', 0700);
foreach (['members.php', 'status.php'] as $page) {
	copy($packagewww . '/sdwan/' . $page, $www . '/sdwan/' . $page);
}
copy($corewww . '/status_logs.php', $www . '/status_logs.php');
file_put_contents($temp . '/shortcuts.inc', strtr(file_get_contents($corewww . '/shortcuts.inc'), [
	'/usr/local/www/shortcuts' => $temp . '/native-shortcuts',
	'/usr/local/pkg/shortcuts' => $local . '/pkg/shortcuts',
]));
$role = ['*'];
$_SERVER['REQUEST_URI'] = '/status_services.php';
require $temp . '/shortcuts.inc';
$shortcut = get_shortcut_by_service_name($gui['service'][0]['name']);
verify($shortcut === 'sdwan' && get_shortcut_by_service_name('sdwand') === null, 'Shortcut bound to the registered service');
verify(str_contains(get_shortcut_main_link($shortcut), 'href="/sdwan/members.php"') &&
    str_contains(get_shortcut_status_link($shortcut), 'href="/sdwan/status.php"'), 'Native settings and status icons');
$log_link = get_shortcut_log_link($shortcut);
preg_match('/href="([^"]+)"/', $log_link, $href);
verify(str_contains($log_link, 'Related log entries') && isset($href[1]), 'Native log icon');
$log_url = html_entity_decode($href[1], ENT_QUOTES, 'UTF-8');
parse_str(parse_url($log_url, PHP_URL_QUERY), $log_query);
verify($log_query === ['logfile' => 'system', 'filterlogentries_submit' => '1', 'filterlogentries_process' => 'sdwan'],
    'Native system log filter URL');

$role = array_merge($view, ['status_logs.php']);
require $local . '/pkg/shortcuts/pkg_sdwan.inc';
verify(get_shortcut_main_link($shortcut) === '' && str_contains(get_shortcut_status_link($shortcut), 'sdwan/status.php'),
    'View-only accounts only see allowed SD-WAN shortcuts');
verify(!isAllowedPage($log_url) && str_contains(get_shortcut_log_link($shortcut), 'href="/status_logs.php"'),
    'Exact native System Logs privilege gets its authorized URL');
$role = $manage;
require $local . '/pkg/shortcuts/pkg_sdwan.inc';
verify(get_shortcut_log_link($shortcut) === '', 'Missing log privilege hides the log shortcut');
$role = ['*'];
foreach (['status.php' => 'status', 'members.php' => 'main', 'diagnostics.php' => 'log'] as $page => $hidden) {
	$_SERVER['REQUEST_URI'] = '/sdwan/' . $page . '?probe=1';
	require $local . '/pkg/shortcuts/pkg_sdwan.inc';
	verify($shortcuts['sdwan'][$hidden] === '', 'Subpage avoids own or duplicate shortcut');
}
$www = $packagewww;
echo "ok - native service shortcut loader renders SD-WAN settings, status and authorized log links\n";

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
$test_config = [
	'interfaces' => ['wan' => ['enable' => '', 'if' => 'vtnet0']],
	'gateways/gateway_item' => [['name' => 'WANGW', 'interface' => 'wan', 'gateway' => '192.0.2.1']],
];
$sequence = 'sdwan:col1:show:0,';
$post = ['ajax' => 'ajax', 'widgetkey' => 'sdwan-0'];
[$code, $content] = widget_request($view, 'GET', [], $sequence, true);
verify($code === 200 && str_contains($content, 'register_ajax') && str_contains($content, 'WANGW'), 'Dashboard include');
[$code, $content] = widget_request($view, 'POST', $post, $sequence, false);
verify($code === 200 && str_contains($content, 'WANGW') && !str_contains($content, 'register_ajax') && !str_contains($content, '<time'), 'Authorized fragment');
foreach ([
	[[], 'POST', $post, $sequence, 403],
	[$view, 'GET', $post, $sequence, 400],
	[$view, 'POST', $post, 'system_information:col1:show:0,', 400],
	[$view, 'POST', ['ajax' => 'ajax', 'widgetkey' => 'sdwan-1'], $sequence, 400],
] as [$privileges, $method, $body, $layout, $status]) {
	[$code, $content] = widget_request($privileges, $method, $body, $layout, false);
	verify($code === $status && !str_contains($content, 'WANGW'), 'Unauthorized or unconfigured widget request');
}
echo "ok - dashboard rendering and refresh enforce status privilege and native widget instance membership\n";
