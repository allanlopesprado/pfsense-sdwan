<?php
// CLI lifecycle hook. Keep the native markers until an administrator rolls back the binding.
if (PHP_SAPI !== 'cli') {
	exit(1);
}
require_once(__DIR__ . '/sdwan_engine.inc');
require_once(__DIR__ . '/sdwan_log.inc');

// A manual --once that began before shutdown must finish publishing first.
$lock = fopen(SDWAN_SNAPSHOT_PATH . '.lock', 'c');
if ($lock === false || !flock($lock, LOCK_EX)) {
	fwrite(STDERR, "Cannot retire the SD-WAN snapshot.\n");
	exit(1);
}
$ok = true;
foreach ([SDWAN_SNAPSHOT_PATH, SDWAN_SNAPSHOT_PATH . '.forwarded'] as $path) {
	if (file_exists($path) && !unlink($path)) {
		$ok = false;
	}
}
fclose($lock);
sdwan_log_event($ok ? 'stop' : 'error', [], 'status');
require_once('config.inc');
if (config_get_path('gateways/sdwan_bindings/item', [])) {
	require_once('filter.inc');
	if (function_exists('filter_sdwan_binding_api') && in_array(filter_sdwan_binding_api(), [1, 2], true)) {
		// Queue the native reload outside the package database transaction.
		filter_configure();
	}
}
exit($ok ? 0 : 1);
