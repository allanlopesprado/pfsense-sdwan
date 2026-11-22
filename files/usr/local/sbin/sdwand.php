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

function sdwan_load_steering(): void {
	require_once('/usr/local/pkg/sdwan_steering.inc');
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
		$inventory_revision = sdwan_gateway_inventory_revision($config, $inventory);
		$members = array_column($config['members'], 'gateway');
		$observations = sdwan_gateway_observations($members ?: array_keys($inventory), $inventory);
		$service_checks = [];
		if (array_column($config['members'], 'probe_primary')) {
			require_once('/usr/local/pkg/sdwan_probe.inc');
			$service_checks = sdwan_probe_observe($config['members'], $inventory, $observations);
		}
		$snapshot = sdwan_evaluate($config, $observations, $started, $inventory, $service_checks);
		$snapshot['config_revision'] = sdwan_config_revision($config);
		if (sdwan_gateway_inventory_revision($config, $inventory) !== $inventory_revision) {
			throw new RuntimeException('Gateway path changed during observation');
		}
		$snapshot['gateway_inventory_revision'] = $inventory_revision;
		if (!$members) {
			// Show native gateways on the dashboard before any members are configured.
			$snapshot['gateways'] = array_map('sdwan_member_sample', $observations);
		}
		$receipt_path = SDWAN_SNAPSHOT_PATH . '.forwarded';
		$receipt = null;
		$action = null;
		$invalid_bindings = false;
		/* Stock systems without bindings never run the native adapter. */
		$bound = config_get_path('gateways/sdwan_bindings/item', []);
		if ($bound || is_file($receipt_path)) {
			sdwan_load_steering();
			if (sdwan_steering_supported()) {
				$prior = sdwan_current_snapshot($config, $inventory);
				try {
					$bindings = sdwan_steering_bindings();
					$rule_pairs = [];
					$snapshot['steering'] = sdwan_steering_observations($config, $snapshot, $prior['steering'] ?? [], $rule_pairs);
				} catch (UnexpectedValueException $e) {
					/* Unreadable bindings produce no pass decisions. */
					$invalid_bindings = true;
					$bindings = [];
					$snapshot['steering'] = [];
				}
				if (!is_platform_booting()) {
					$signature = sdwan_steering_runtime_signature($snapshot, $inventory);
					$previous = sdwan_steering_read_receipt($receipt_path);
					$now = time();
					$same = ($previous['signature'] ?? null) === $signature && $previous['requested_at'] <= $now;
					$receipt = $same ? $previous : [
						'signature' => $signature, 'attempts' => 0, 'requested_at' => 0,
						'accepted' => false, 'confirmed' => false,
					];
					$rules = $same && $bindings ? sdwan_steering_pf_rules() : null;
					$matches = $rules !== null;
					foreach ($bindings as $group => $binding) {
						$status = sdwan_steering_pf_status($binding, $snapshot['steering'][$group] ?? [], $inventory, $rules,
						    $rule_pairs[$group] ?? null);
						$matches = $matches && in_array($status, ['applied', 'blocked'], true);
					}
					if ($matches && !$receipt['confirmed']) {
						$receipt['attempts'] = 0;
						$receipt['confirmed'] = true;
						$action = 'filter_applied';
					} elseif ($rules === null && $bindings && $receipt['accepted'] && !$receipt['confirmed'] &&
					    $now - $receipt['requested_at'] >= SDWAN_RELOAD_RETRY_INTERVAL) {
						$action = 'filter_unavailable';
					} elseif (!$matches && ($rules !== null || !$receipt['accepted'])) {
						$cooldown = !$receipt['confirmed'] && $now - $receipt['requested_at'] < SDWAN_RELOAD_RETRY_INTERVAL;
						if (!$cooldown && $receipt['attempts'] >= SDWAN_RELOAD_MAX_ATTEMPTS) {
							$action = 'filter_divergent';
						} elseif (!$cooldown) {
							$receipt['attempts']++;
							$receipt['requested_at'] = $now;
							$receipt['accepted'] = false;
							$receipt['confirmed'] = false;
							$action = 'filter_requested';
						}
					}
				}
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
		if ($action === 'filter_requested') {
			/* Reserve the attempt before enqueueing, even on refusal or crash.
			 * A fresh decision or a verified PF match resets the retry budget. */
			if (!sdwan_steering_write_receipt($receipt_path, $receipt)) {
				throw new RuntimeException('Cannot record the filter reload request');
			}
			if (!sdwan_steering_request_reload()) {
				throw new RuntimeException('pfSense did not accept the filter reload request');
			}
			$receipt['accepted'] = true;
			if ($bound) {
				if (!sdwan_steering_write_receipt($receipt_path, $receipt)) {
					throw new RuntimeException('Cannot record the filter reload request');
				}
			} elseif (is_file($receipt_path)) {
				unlink($receipt_path);
			}
		} elseif ($action === 'filter_applied' && !sdwan_steering_write_receipt($receipt_path, $receipt)) {
			throw new RuntimeException('Cannot record the filter reload request');
		}
		if ($action !== null) {
			sdwan_log_event($action);
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
	if (config_get_path('gateways/sdwan_bindings/item', [])) {
		sdwan_load_steering();
		if (!sdwan_steering_retire_on_start()) {
			// The FreeBSD daemon supervisor retries service starts.
			sdwan_log_event('error', [], 'startup_filter');
			exit(1);
		}
	}
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
