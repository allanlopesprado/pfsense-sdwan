#!/usr/local/bin/php
<?php

const SDWAN_LOG_DEDICATED_CLI = true;

require_once('config.inc');
require_once('gwlb.inc');
require_once('/usr/local/pkg/sdwan.inc');
require_once('/usr/local/pkg/sdwan_engine.inc');
require_once('/usr/local/pkg/sdwan_log.inc');

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

function sdwan_gateway_observations(array $names, array $inventory): array {
	$processes = running_dpinger_processes();
	$defaults = return_dpinger_defaults();
	$observations = [];
	foreach (array_unique($names) as $name) {
		$gateway = $inventory[$name] ?? null;
		if ($gateway === null || $gateway['monitor_disabled']) {
			continue;
		}
		if ($gateway['force_down']) {
			$observations[$name] = ['status' => 'down', 'substatus' => 'force_down'];
			continue;
		}
		$process = $processes[$name] ?? null;
		if ($process === null || !sdwan_monitor_matches($gateway, $process)) {
			continue;
		}
		$values = sdwan_sample_socket($process, $name);
		if ($values === null) {
			continue;
		}
		[$rtt, $variation, $loss] = $values;
		$limits = $gateway['probe'] + $defaults;
		$substatus = match (true) {
			$rtt > $limits['latencyhigh'] => 'highdelay',
			$loss > $limits['losshigh'] => 'highloss',
			$rtt > $limits['latencylow'] => 'delay',
			$loss > $limits['losslow'] => 'loss',
			default => 'none'
		};
		$alarm_down = in_array($substatus, ['highdelay', 'highloss'], true) &&
		    !$gateway['action_disabled'];
		$observations[$name] = [
			'status' => $alarm_down ? 'down' : 'online', 'substatus' => $substatus,
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
		$inventory = sdwan_gateways();
		$members = array_column($config['members'], 'gateway');
		$observations = sdwan_gateway_observations($members ?: array_keys($inventory), $inventory);
		$snapshot = sdwan_evaluate($config, $observations, $started, $inventory);
		$snapshot['config_revision'] = sdwan_config_revision($config);
		$snapshot['gateway_inventory_revision'] = sdwan_gateway_inventory_revision($config, $inventory);
		if (!$members) {
			// Show native gateways on the dashboard before any members are configured.
			$snapshot['gateways'] = array_map('sdwan_member_sample', $observations);
		}
		$receipt = SDWAN_SNAPSHOT_PATH . '.forwarded';
		$reload = false;
		$invalid_bindings = false;
		/* Stock systems without bindings never run the native adapter. */
		if (config_get_path('gateways/sdwan_bindings/item', []) || is_file($receipt)) {
			require_once('/usr/local/pkg/sdwan_steering.inc');
			if (sdwan_steering_supported()) {
				$prior = sdwan_current_snapshot($config, $inventory);
				try {
					$snapshot['steering'] = sdwan_steering_observations($config, $snapshot, $prior['steering'] ?? []);
				} catch (UnexpectedValueException $e) {
					/* Unreadable bindings produce no pass decisions. */
					$invalid_bindings = true;
					$snapshot['steering'] = [];
				}
				$signature = 'ack:' . $snapshot['config_revision'] . ':' . sdwan_steering_signature($snapshot['steering']);
				$reload = $prior === null ||
				    !is_file($receipt) || file_get_contents($receipt) !== $signature;
			}
		}
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
		if ($reload && !is_platform_booting()) {
			/* Publish before enqueueing. A rejected request or a crash before
			 * the receipt leaves the next observation free to retry. */
			if (!sdwan_steering_request_reload()) {
				throw new RuntimeException('pfSense did not accept the filter reload request');
			}
			if (config_get_path('gateways/sdwan_bindings/item', [])) {
				if (file_put_contents($receipt, $signature, LOCK_EX) !== strlen($signature)) {
					throw new RuntimeException('Cannot record the filter reload request');
				}
			} elseif (is_file($receipt)) {
				unlink($receipt);
			}
		}
		if ($invalid_bindings) {
			sdwan_log_event('error', [], 'bindings');
		} else {
			sdwan_log_event('observation', $snapshot);
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
if (!$once) {
	sdwan_log_event('start');
}
do {
	try {
		sdwan_observe_once();
	} catch (Throwable $e) {
		/* A concurrent manual --once is expected. Its caller still receives
		 * an error without producing repeated operational log records. */
		$cause = match ($e->getMessage()) {
			'Cannot refresh pfSense configuration' => 'config',
			'Cannot create temporary snapshot', 'Cannot publish snapshot', 'Cannot open snapshot lock' => 'status',
			'Cannot record the filter reload request', 'pfSense did not accept the filter reload request' => 'reload',
			default => $e instanceof UnexpectedValueException ? 'config' : 'observation',
		};
		if ($e->getMessage() !== 'Another observation is running') {
			sdwan_log_event('error', [], $cause);
		}
		if ($once) {
			$detail = match ($e->getMessage()) {
				'Another observation is running', 'Unsupported SD-WAN configuration format.' => $e->getMessage(),
				default => 'Observation failed. See the system log.',
			};
			fwrite(STDERR, "sdwand: {$detail}\n");
			exit(1);
		}
	}
	if (!$once) {
		sleep(10);
	}
} while (!$once);
