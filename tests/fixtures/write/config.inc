<?php
/* This in-memory pfSense fixture distinguishes a pending edit from a durable write. */
if (!defined('SDWAN_LOCK_DIRECTORY')) {
	$lock_dir = sys_get_temp_dir() . '/sdwan-locks-' . bin2hex(random_bytes(8));
	mkdir($lock_dir, 0700);
	define('SDWAN_LOCK_DIRECTORY', $lock_dir);
	register_shutdown_function(static function () use ($lock_dir) {
		foreach (glob($lock_dir . '/*.lock') as $path) {
			unlink($path);
		}
		rmdir($lock_dir);
	});
}
function config_read_file($backup, $cache) {
	global $current, $disk;
	$current = $disk;
	return true;
}
function config_get_path($path, $default = null) {
	global $current;
	return $current[$path] ?? $default;
}
function config_set_path($path, $value) {
	global $current;
	return $current[$path] = $value;
}
function write_config($reason) {
	global $current, $disk, $fail, $writes;
	if ($fail) {
		return false;
	}
	$writes++;
	return $disk = $current;
}
