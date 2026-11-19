<?php
/* Minimal read-only config repository used by daemon_integration.py. */
function config_read_file(bool $backup, bool $cache): bool {
	return !$backup && $cache;
}

function config_get_path(string $path, $default = null) {
	$config = json_decode(file_get_contents(__DIR__ . '/fixture.json'), true, 512, JSON_THROW_ON_ERROR);
	return $config[$path] ?? $default;
}
