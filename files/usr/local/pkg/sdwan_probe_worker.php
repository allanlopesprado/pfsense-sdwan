<?php
/* Private CLI worker launched by setfib, outside the WebGUI document root. */
if (PHP_SAPI !== 'cli') {
	exit(64);
}

require_once('config.inc');
require_once('gwlb.inc');
require_once(__DIR__ . '/sdwan.inc');
require_once(__DIR__ . '/sdwan_engine.inc');
require_once(__DIR__ . '/sdwan_probe.inc');

$input = stream_get_contents(STDIN, 4097);
if (!is_string($input) || strlen($input) > 4096) {
	exit(64);
}
$request = json_decode($input, true, 8);
if (!is_array($request) || !array_is_list($request) || count($request) !== 3) {
	exit(64);
}
[$value, $gateway, $deadline] = $request;
$probe = sdwan_probe_target($value);
if (empty($probe['fib']) || !is_array($gateway) || !is_string($gateway['interface'] ?? null) ||
    !is_string($gateway['address'] ?? null) || ($gateway['family'] ?? null) !== $probe['family'] ||
    !is_int($deadline) || $deadline > hrtime(true) + 2500000000) {
	exit(64);
}

$result = sdwan_probe_observe(
    [['name' => 'probe', 'gateway' => 'selected', 'probe_primary' => $value]],
    ['selected' => $gateway], ['selected' => ['status' => 'online']], [], $deadline, $probe['fib']
);
echo $result['probe']['probe_primary'], PHP_EOL;
