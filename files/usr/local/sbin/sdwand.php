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
		$service_checks = [];
		if (array_column($config['members'], 'probe_primary')) {
			require_once('/usr/local/pkg/sdwan_probe.inc');
			$service_checks = sdwan_probe_observe($config['members'], $inventory, $observations);
		}
		$snapshot = sdwan_evaluate($config, $observations, $started, $inventory, $service_checks);
		$snapshot['config_revision'] = sdwan_config_revision($config);
		$snapshot['gateway_inventory_revision'] = sdwan_gateway_inventory_revision($config, $inventory);
		if (!$members) {
			// Show native gateways on the dashboard before any members are configured.
			$snapshot['gateways'] = array_map('sdwan_member_sample', $observations);
		}
		$receipt = SDWAN_SNAPSHOT_PATH . '.forwarded';
		$reload = false;
		$invalid_bindings = false;
		$record = $prior_record = $filter_status = [];
		$has_bindings = (bool)config_get_path('gateways/sdwan_bindings/item', []);
		$expired = sdwan_snapshot_expired();
		/* Stock systems without bindings never run the native adapter. */
		if ($has_bindings || is_file($receipt)) {
			require_once('/usr/local/pkg/sdwan_steering.inc');
			if (sdwan_steering_supported()) {
				$prior = sdwan_current_snapshot($config, $inventory);
				try {
					$snapshot['steering'] = sdwan_steering_observations($config, $snapshot,
					    $prior['steering'] ?? [], $prior['forwarding_check'] ?? null);
					$bindings = sdwan_steering_bindings();
				} catch (UnexpectedValueException $e) {
					$invalid_bindings = true;
					$snapshot['steering'] = $bindings = [];
				}
				$lines = $bindings ? sdwan_steering_pf_rules() : null;
				foreach ($bindings as $group => $binding) {
					$filter_status[$group] = sdwan_steering_runtime_pf_status($binding,
					    $snapshot['steering'][$group], $inventory, $lines);
				}
				$snapshot['forwarding_check'] = $filter_status;
				$snapshot['forwarding_id'] = sdwan_steering_decision_id($snapshot, $inventory);
				$prior_record = sdwan_steering_receipt($receipt);
				[$record, $reload] = sdwan_steering_reconcile($prior_record, $snapshot['forwarding_id'],
				    $filter_status, time(), is_platform_booting());
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
		if ($reload) {
			/* Publishing before enqueueing lets the native renderer read the
			 * same decision. Count even unacknowledged requests across restarts. */
			$record['attempts']++;
			$record['at'] = time();
			$record['accepted'] = false;
			sdwan_steering_write_receipt($receipt, $record);
			$record['accepted'] = sdwan_steering_request_reload();
			sdwan_steering_write_receipt($receipt, $record);
		} elseif ($record && $record !== $prior_record && ($record['attempts'] > 0 ||
		    ($filter_status && !array_diff($filter_status, ['applied', 'blocked'])))) {
			sdwan_steering_write_receipt($receipt, $record);
		}
		if ($record && !$has_bindings && $record['accepted'] && is_file($receipt)) {
			unlink($receipt);
		}
		if ($expired) {
			sdwan_log_event('expired');
		}
		foreach ($filter_status as $group => $status) {
			if ($reload && $status === 'pending' && ($prior_record['attempts'] ?? 0) > 0) {
				sdwan_log_event('filter_pending');
			}
			$snapshot['forwarding_application'][$group] = sdwan_steering_application($status, $snapshot, $record);
		}
		if ($reload && !$record['accepted']) {
			sdwan_log_event('observation', $snapshot);
			throw new RuntimeException('pfSense did not accept the filter reload request');
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
