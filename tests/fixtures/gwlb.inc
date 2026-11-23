<?php
/* Read-only gateway and live-address lookups used by the observer. */
function return_dpinger_defaults(): array {
	return ['latencyhigh' => 500, 'latencylow' => 150, 'losshigh' => 30, 'losslow' => 10];
}

function running_dpinger_processes(): array {
	return config_get_path('processes', []);
}

if (!function_exists('isvalidpid')) {
	function isvalidpid(string $pidfile): bool {
		return is_file($pidfile) && trim(file_get_contents($pidfile)) ===
		    (string)config_get_path('fixture_live_dpinger_pid', 0);
	}
}

function get_real_interface($interface, $family, $realv6iface, $flush) {
	return config_get_path('fixture_devices', [])[$interface] ?? $interface;
}

function get_interface_gateway($interface) {
	return config_get_path('fixture_dynamic_targets', [])[$interface] ?? null;
}

function get_interface_gateway_v6($interface) {
	return get_interface_gateway($interface);
}

function find_interface_ip($device, $flush) {
	return config_get_path('fixture_sources', [])[$device] ?? null;
}

function find_interface_ipv6($device, $flush) {
	return find_interface_ip($device, $flush);
}

function find_interface_ipv6_ll($device, $flush) {
	return find_interface_ip($device, $flush);
}
