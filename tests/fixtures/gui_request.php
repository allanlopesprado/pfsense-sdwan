<?php
// Run one isolated page request against pfSense's actual Form classes.
[$script, $web, $classes, $page] = $argv;
$request = json_decode(stream_get_contents(STDIN), true, 512, JSON_THROW_ON_ERROR);
set_include_path($web . PATH_SEPARATOR . __DIR__ . '/write');
require_once($web . '/sdwan.inc');
require_once('config.inc');
const COLLAPSIBLE = 8;
const SEC_CLOSED = 4;
if (!function_exists('gettext')) {
	function gettext($text) { return $text; }
}
spl_autoload_register(function ($name) use ($classes) {
	$file = $classes . '/' . str_replace('_', '/', $name) . '.class.php';
	if (is_file($file)) {
		require_once($file);
	}
});
// Supply the preference normally loaded by guiconfig.inc. The pinned upstream
// Form classes also read optional attributes and two uninitialized display variables.
$user_settings = ['webgui' => ['webguileftcolumnhyper' => false]];
set_error_handler(function ($severity, $message, $file) use ($classes) {
	if ($severity === E_DEPRECATED && $file === $classes . '/Form/Group.class.php' &&
	    str_starts_with($message, 'strtolower(): Passing null to parameter #1')) {
		return true;
	}
	if ($severity !== E_WARNING || !str_starts_with($file, $classes . '/Form/')) {
		return false;
	}
	return str_starts_with($message, 'Undefined array key') ||
	    ($file === $classes . '/Form/Group.class.php' && $message === 'Undefined variable $hidden') ||
	    ($file === $classes . '/Form/Input.class.php' && $message === 'Undefined variable $help');
});
function pkg_exec($query, &$stdout, &$stderr) { $stdout = '0.4.2'; $stderr = ''; return 0; }
function isAllowedPage($url) { global $request; return $request['privileges'][$url] ?? $request['inspect'] ?? true; }
if ($request['steering_abi'] ?? false) {
	// Emulate the optional hook in the WebGUI test. A separate test exercises the actual core patch.
	function filter_sdwan_binding_api() { return 1; }
	function filter_configure() { return 0; }
}
function csrf_startup() {
	csrf_conf('auto-session', false);
	csrf_conf('secret', 'isolated-form-regression-fixture');
	csrf_conf('callback', 'fixture_csrf_failure');
}
function fixture_csrf_failure($token) { echo 'CSRF check failed'; }
$GLOBALS['csrf'] = [];
session_id('sdwan-editor-fixture');
$_COOKIE['PHPSESSID'] = session_id();
$disk = $current = $request['native'];
$config = $request['config'];
$disk[SDWAN_CONFIG_PATH] = $current[SDWAN_CONFIG_PATH] = sdwan_encode_config($config);
$writes = 0;
$busy = $fail = false;
$_GET = $request['get'] ?? [];
$_POST = $request['post'] ?? [];
$_SERVER['REQUEST_URI'] = '/sdwan/' . $page . '.php';
$_SERVER['REQUEST_METHOD'] = $_POST ? 'POST' : 'GET';
if (isset($request['snapshot'])) {
	$snapshot = $request['snapshot'] + ['generated_at' => time(), 'config_revision' => sdwan_config_revision($config)];
	file_put_contents($web . '/observer.json', json_encode($snapshot));
}
if ($_POST) {
	$_POST['revision'] ??= sdwan_config_revision($config);
	register_shutdown_function(function () {
		global $disk, $writes, $request;
		if (!empty($request['capture_bindings'])) {
			echo "\nBINDINGS=" . json_encode($disk['gateways/sdwan_bindings'] ?? []);
		}
		echo "\nSAVED=" . json_encode([$writes, sdwan_decode_config($disk[SDWAN_CONFIG_PATH])]);
	});
}
include $web . '/sdwan/' . $page . '.php';
