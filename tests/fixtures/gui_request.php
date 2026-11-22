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
$installed_release = $request['installed_release'] ?? '0.4.7';
$upgrade_calls = 0;
$rollback_calls = 0;
function pkg_exec($query, &$stdout, &$stderr) {
	global $installed_release, $upgrade_calls, $rollback_calls, $request, $config;
	$stderr = '';
	if ($query === 'query %v pfSense-pkg-SDWAN') {
		$stdout = $installed_release;
	} elseif ($query === 'config ABI') {
		$stdout = $request['abi'] ?? 'FreeBSD:16:amd64';
	} elseif (preg_match('~^create -q -o ([\'"])(.+)\\1 pfSense-pkg-SDWAN$~', $query, $arguments)) {
		if (!empty($request['backup_failure'])) {
			return 1;
		}
		file_put_contents($arguments[2] . "/pfSense-pkg-SDWAN-{$installed_release}.pkg", 'previous package fixture');
	} elseif (str_starts_with($query, 'query -F ')) {
		$archive_version = str_contains($query, 'pfSense-pkg-SDWAN-0.4.8.pkg') ? '0.4.8' : $installed_release;
		$stdout = "pfSense-pkg-SDWAN {$archive_version} net/pfSense-pkg-SDWAN";
	} elseif (str_starts_with($query, '-o DEVELOPER_MODE=yes add -f ')) {
		$rollback_calls++;
		if (!empty($request['rollback_failure'])) {
			return 1;
		}
		$installed_release = '0.4.7';
	} elseif (str_starts_with($query, '-o DEVELOPER_MODE=yes add ')) {
		$upgrade_calls++;
		if (!empty($request['install_failure'])) {
			return 1;
		}
		$installed_release = '0.4.8';
		if (!empty($request['install_hook_failure'])) {
			$stdout = "pkg-static: POST-INSTALL script failed\n";
		}
		if (isset($request['snapshot'])) {
			fixture_write_snapshot($request['snapshot'], $config);
		}
	} elseif ($query === 'check -s pfSense-pkg-SDWAN') {
		return !empty($request['installed_checksum_failure']) ||
		    (!empty($request['broken_upgrade']) && $installed_release === '0.4.8') ? 1 : 0;
	} else {
		throw new RuntimeException('Unexpected package command');
	}
	return 0;
}

function pkg_version_compare($installed, $version) {
	return ['<', '=', '>'][version_compare($installed, $version) + 1];
}

function mwexec($command, $quiet) {
	if ($quiet && $command === '/usr/local/etc/rc.d/sdwand.sh status') {
		return !empty($GLOBALS['request']['service_failure']) ? 1 : 0;
	}
	if ($quiet && str_starts_with($command, '/bin/pgrep -P 501 -u 0 -fx ') &&
	    preg_match('~ \| /usr/bin/grep -Fx ([1-9][0-9]*)\z~', $command, $matches)) {
		return empty($GLOBALS['request']['worker_failure']) && $matches[1] === '502' ? 0 : 1;
	}
	throw new RuntimeException('Unexpected service command');
}

if ($page === 'updates') {
	require __DIR__ . '/release_curl.php';
	$archive = 'package fixture';
	$release_http = fixture_release_http('0.4.8', $archive);
	if (isset($request['release_http_failure'])) {
		$url = array_keys($release_http)[$request['release_http_failure']];
		$release_http[$url]['status'] = 404;
	}
	if (!empty($request['corrupt_release'])) {
		$release_http[array_key_last($release_http)]['body'] = str_repeat('x', strlen($archive));
	}
	register_shutdown_function(static function () {
		echo "\nUPGRADES=" . $GLOBALS['upgrade_calls'] . ' HTTP=' . http_response_code() .
		    ' REQUESTS=' . count($GLOBALS['release_requests'] ?? []) .
		    ' ROLLBACKS=' . $GLOBALS['rollback_calls'] . "\n";
	});
}
function isAllowedPage($url) {
	global $request;
	return $request['privileges'][$url] ?? $request['privileges']['/' . ltrim($url, '/')] ?? $request['inspect'] ?? true;
}

function get_services(): array {
	return ($GLOBALS['request']['service_state'] ?? 'running') === 'unregistered' ? [] :
	    [['name' => 'sdwan', 'rcfile' => 'sdwand.sh']];
}

function is_service_running($name): bool {
	return $name === 'sdwan' && ($GLOBALS['request']['service_state'] ?? 'running') === 'running';
}
function get_interface_gateway($interface) { return config_get_path('fixture_dynamic_targets', [])[$interface] ?? null; }
function get_interface_gateway_v6($interface) { return get_interface_gateway($interface); }
if (isset($request['interface_counters'])) {
	function get_real_interface($interface, $family, $real, $flush) {
		return config_get_path('interfaces', [])[$interface]['if'] ?? null;
	}
	function pfSense_get_interface_stats($device) {
		return $GLOBALS['request']['interface_counters'][$device] ?? null;
	}
}
if ($request['steering_abi'] ?? false) {
	// Emulate the optional hook in the WebGUI test. A separate test exercises the actual core patch.
	function filter_sdwan_binding_api() { return 1; }
	function filter_configure() { return 0; }
}
function csrf_startup() {
	csrf_conf('auto-session', false);
	csrf_conf('secret', 'isolated-form-regression-fixture');
	csrf_conf('rewrite-js', '/csrf/csrf-magic.js');
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
$upgrade_lock = empty($request['upgrade_busy']) ? null : sdwan_lock('sdwan-package-upgrade', 0);
$fail = false;
$_GET = $request['get'] ?? [];
$_POST = $request['post'] ?? [];
$_SERVER['REQUEST_URI'] = '/sdwan/' . $page . '.php';
$_SERVER['REQUEST_METHOD'] = $_POST ? 'POST' : 'GET';
function fixture_write_snapshot(array $snapshot, array $config): void {
	$snapshot += [
		'generated_at' => time(),
		'config_revision' => sdwan_config_revision($config),
		'gateway_inventory_revision' => sdwan_gateway_inventory_revision($config, sdwan_gateways()),
		'observer' => ['pid' => 502, 'version' => $GLOBALS['installed_release']],
	];
	file_put_contents($GLOBALS['web'] . '/observer.json', json_encode($snapshot));
}
if (isset($request['snapshot'])) {
	fixture_write_snapshot($request['snapshot'], $config);
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
if (is_resource($upgrade_lock)) {
	sdwan_unlock($upgrade_lock);
}
