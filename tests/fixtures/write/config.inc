<?php
/* This in-memory pfSense fixture distinguishes a pending edit from a durable write. */
function try_lock($name, $timeout) {
	global $busy;
	return $busy ? null : tmpfile();
}
function unlock($handle) { fclose($handle); }
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
