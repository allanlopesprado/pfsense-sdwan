#!/usr/local/bin/php
<?php

require_once('config.inc');
require_once('gwlb.inc');
require_once('/usr/local/pkg/sdwan.inc');
require_once('/usr/local/pkg/sdwan_engine.inc');

/*
 * Read the four fields of the native pfSense dpinger status socket. Bound the
 * read time. An initializing monitor returns all zeros, not a healthy sample.
 */
function sdwan_sample_socket(array $process, string $name): ?array {
	$socket = @stream_socket_client('unix://' . $process['socket'], $errno, $error, 0.25);
	if ($socket === false) {
		return null;
	}
	try {
		stream_set_timeout($socket, 0, 250000);
		$line = fgets($socket, 512);
		if (!is_string($line) || stream_get_meta_data($socket)['timed_out']) {
			return null;
		}
	} finally {
		fclose($socket);
	}
	return sdwan_parse_dpinger_line($line, $name);
}

function sdwan_gateway_observations(array $config): array {
	$processes = running_dpinger_processes();
	$inventory = sdwan_gateways();
	$settings = array_column(config_get_path('gateways/gateway_item', []), null, 'name');
	$defaults = return_dpinger_defaults();
	$observations = [];
	foreach (array_unique(array_column($config['members'], 'gateway')) as $name) {
		$gateway = $inventory[$name] ?? null;
		if ($gateway === null || $gateway['monitor_disabled']) {
			continue;
		}
		if ($gateway['force_down']) {
			$observations[$name] = ['status' => 'down', 'substatus' => 'force_down'];
			continue;
		}
		$process = $processes[$name] ?? null;
		if ($process === null) {
			continue;
		}
		// A renamed monitor may leave an old socket until pfSense reloads.
		$expected = $gateway['monitor'];
		if (filter_var($expected, FILTER_VALIDATE_IP) !== false &&
		    @inet_pton($process['targetip']) !== inet_pton($expected)) {
			continue;
		}
		$values = sdwan_sample_socket($process, $name);
		if ($values === null) {
			continue;
		}
		[$rtt, $variation, $loss] = $values;
		$limits = $defaults;
		foreach (['latencyhigh', 'latencylow', 'losshigh', 'losslow'] as $limit) {
			$value = $settings[$name][$limit] ?? null;
			if (is_numeric($value)) {
				$limits[$limit] = (float)$value;
			}
		}
		$substatus = match (true) {
			$rtt > $limits['latencyhigh'] => 'highdelay',
			$loss > $limits['losshigh'] => 'highloss',
			$rtt > $limits['latencylow'] => 'delay',
			$loss > $limits['losslow'] => 'loss',
			default => 'none'
		};
		$observations[$name] = [
			'status' => 'online', 'substatus' => $substatus,
			'delay' => number_format($rtt, 3, '.', '') . 'ms',
			'stddev' => number_format($variation, 3, '.', '') . 'ms',
			'loss' => $loss . '%'
		];
	}
	return $observations;
}

function sdwan_observe_once(): void {
	$lock = fopen(SDWAN_SNAPSHOT_PATH . '.lock', 'c');
	if ($lock === false) {
		throw new RuntimeException('Cannot open snapshot lock');
	}
	try {
		if (!flock($lock, LOCK_EX | LOCK_NB)) {
			throw new RuntimeException('Another observation is running');
		}
		clearstatcache();
		if (!config_read_file(false, true)) {
			throw new RuntimeException('Cannot refresh pfSense configuration');
		}
		$config = sdwan_get_config();
		$started = time();
		$observations = sdwan_gateway_observations($config);
		$snapshot = sdwan_evaluate($config, $observations, $started);
		$snapshot['config_revision'] = sdwan_config_revision($config);
		$json = json_encode($snapshot, JSON_THROW_ON_ERROR);
		$temp = tempnam(dirname(SDWAN_SNAPSHOT_PATH), '.sdwan-');
		if ($temp === false) {
			throw new RuntimeException('Cannot create temporary snapshot');
		}
		try {
			if (file_put_contents($temp, $json) !== strlen($json) ||
			    !chmod($temp, 0644) || !rename($temp, SDWAN_SNAPSHOT_PATH)) {
				throw new RuntimeException('Cannot publish snapshot');
			}
		} finally {
			if (file_exists($temp)) {
				unlink($temp);
			}
		}
	} finally {
		fclose($lock);
	}
}

if (PHP_SAPI !== 'cli' || !in_array(array_slice($argv, 1), [[], ['--once']], true)) {
	fwrite(STDERR, "Usage: sdwand.php [--once]\n");
	exit(64);
}
$once = count($argv) === 2;
do {
	try {
		sdwan_observe_once();
	} catch (Throwable $e) {
		error_log('sdwand: ' . $e->getMessage());
		if ($once) {
			exit(1);
		}
	}
	if (!$once) {
		sleep(10);
	}
} while (!$once);
