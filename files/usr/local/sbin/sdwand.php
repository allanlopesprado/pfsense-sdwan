#!/usr/local/bin/php
<?php

if (PHP_SAPI !== 'cli') {
	exit(64);
}

const SDWAN_LOG_DEDICATED_CLI = true;
const SDWAN_OBSERVER_PACKAGE_VERSION = '%%PKGVERSION%%';

require_once('config.inc');
require_once('gwlb.inc');
require_once('/usr/local/pkg/sdwan.inc');
require_once('/usr/local/pkg/sdwan_engine.inc');
require_once('/usr/local/pkg/sdwan_log.inc');

/*
 * Read the four fields of the native pfSense dpinger status socket. Bound the
 * read time. An initializing monitor returns all zeros, not a healthy sample.
 */
function sdwan_sample_socket(array $process, array $gateway, string $name, int $deadline): ?array {
	if (!sdwan_monitor_matches($gateway, $process) ||
	    (isset($process['pidfile']) && !@isvalidpid($process['pidfile']))) {
		return null;
	}
	$remaining = intdiv($deadline - hrtime(true), 1000);
	if ($remaining <= 0) {
		return null;
	}
	$socket = @stream_socket_client('unix://' . $process['socket'], $errno, $error, $remaining / 1_000_000);
	if ($socket === false) {
		return null;
	}
	try {
		$remaining = intdiv($deadline - hrtime(true), 1000);
		if ($remaining <= 0 || !stream_set_timeout($socket, 0, $remaining)) {
			return null;
		}
		$line = fgets($socket, 512);
		if (!is_string($line) || !str_ends_with($line, "\n") || stream_get_meta_data($socket)['timed_out']) {
			return null;
		}
	} finally {
		fclose($socket);
	}
	return sdwan_parse_dpinger_line($line, $name);
}

/* The native lookup retains only the last PID filename for each gateway.
 * Keep alternatives when stale files hide the process for the current path. */
function sdwan_dpinger_candidates(): array {
	$processes = [];
	foreach (glob(dirname(SDWAN_SNAPSHOT_PATH) . '/dpinger_*.pid') ?: [] as $pidfile) {
		if (preg_match('/^dpinger_(.+)~([^~]+)~([^~]+)\.pid$/D', basename($pidfile), $parts)) {
			$processes[$parts[1]][] = [
				'srcip' => $parts[2], 'targetip' => $parts[3], 'pidfile' => $pidfile,
				'socket' => substr($pidfile, 0, -4) . '.sock',
			];
		}
	}
	return $processes;
}

function sdwan_gateway_observations(array $names, array $inventory): array {
	$processes = running_dpinger_processes();
	$candidates = null;
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
		$deadline = hrtime(true) + 250_000_000;
		$values = $process !== null ? sdwan_sample_socket($process, $gateway, $name, $deadline) : null;
		if ($values === null) {
			$candidates ??= sdwan_dpinger_candidates();
			foreach ($candidates[$name] ?? [] as $candidate) {
				if (hrtime(true) >= $deadline) {
					break;
				}
				if ($candidate['socket'] === ($process['socket'] ?? null)) {
					continue;
				}
				$values = sdwan_sample_socket($candidate, $gateway, $name, $deadline);
				if ($values !== null) {
					break;
				}
			}
		}
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
		$observed_at = hrtime(true);
		$inventory = sdwan_gateways();
		$inventory_revision = sdwan_gateway_inventory_revision($config, $inventory);
		$members = array_column($config['members'], 'gateway');
		$observations = sdwan_gateway_observations($members ?: array_keys($inventory), $inventory);
		$service_checks = [];
		if (array_column($config['members'], 'probe_primary')) {
			require_once('/usr/local/pkg/sdwan_probe.inc');
			$service_checks = sdwan_probe_observe($config['members'], $inventory, $observations,
			    sdwan_probe_secondary_first($config));
		}
		$snapshot = sdwan_evaluate($config, $observations, $started, $inventory, $service_checks);
		$snapshot['observed_at_ns'] = $observed_at;
		$snapshot['config_revision'] = sdwan_config_revision($config);
		// A native or SD-WAN edit can land while the observer waits on probe I/O.
		if (!config_read_file(false, true)) {
			throw new RuntimeException('Cannot refresh pfSense configuration');
		}
		$current_config = sdwan_get_config();
		if (sdwan_config_revision($current_config) !== $snapshot['config_revision'] ||
		    sdwan_gateway_inventory_revision($current_config, sdwan_gateways()) !== $inventory_revision) {
			throw new RuntimeException('Configuration or gateway path changed during observation');
		}
		$snapshot['gateway_inventory_revision'] = $inventory_revision;
		$snapshot['observer'] = ['pid' => getmypid(), 'version' => SDWAN_OBSERVER_PACKAGE_VERSION];
		if (!$members) {
			// Show native gateways on the dashboard before any members are configured.
			$snapshot['gateways'] = array_map('sdwan_member_sample', $observations);
		}
		$receipt_path = SDWAN_SNAPSHOT_PATH . '.forwarded';
		$receipt = null;
		$previous = [];
		$action = null;
		$clear_receipt = false;
		$withdrawal_verified = false;
		$invalid_bindings = false;
		$prior = sdwan_current_snapshot($config, $inventory, $expired);
		if ($expired) {
			sdwan_log_event('sample_expired');
		}
		/* Stock systems without bindings never run the native adapter. */
		$bound = config_get_path('gateways/sdwan_bindings/item', []);
		if ($bound || is_file($receipt_path)) {
			sdwan_load_steering();
			$adapter_supported = sdwan_steering_supported();
			if ($bound && !$adapter_supported) {
				sdwan_log_event('adapter_unavailable');
			}
			if ($adapter_supported) {
				try {
					$bindings = sdwan_steering_bindings();
					$rule_pairs = [];
					$prior_steering = $prior['steering'] ?? [];
					if (!isset($prior['observed_at_ns'])) {
						// Keep the previous paths but restart holds inherited from a civil clock.
						$prior_steering = array_map(static fn($state) =>
						    array_intersect_key($state, ['gateway' => true, 'pool' => true, 'revision' => true]), $prior_steering);
					}
					$snapshot['steering'] = sdwan_steering_observations($config, $snapshot, $prior_steering, $rule_pairs);
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
					$trackers = $invalid_bindings ? ($previous['trackers'] ?? []) : sdwan_steering_trackers($bindings);
					$withdrawal = $invalid_bindings ? ($previous['withdrawal'] ?? null) :
					    sdwan_steering_withdrawal($previous, $trackers);
					if (!$invalid_bindings && !$previous && !$trackers && !$bound) {
						$withdrawal = ['trackers' => [], 'unknown' => true, 'since_ns' => hrtime(true)];
					}
					$receipt = $same && $withdrawal === ($previous['withdrawal'] ?? null) ? $previous : [
						'signature' => $signature, 'attempts' => 0, 'requested_at' => 0,
						'accepted' => false, 'confirmed' => false,
					];
					$receipt['trackers'] = $trackers;
					$rules = ($same && $bindings) || $withdrawal !== null ? sdwan_steering_pf_rules() : null;
					if ($withdrawal !== null && !$invalid_bindings &&
					    sdwan_steering_withdrawal_confirmed($withdrawal, $trackers, $rules)) {
						$withdrawal_verified = true;
						$withdrawal = null;
					}
					if ($withdrawal === null) {
						unset($receipt['withdrawal']);
					} else {
						$receipt['withdrawal'] = $withdrawal;
					}
					$clear_receipt = !$bindings && !$invalid_bindings && $withdrawal === null;
					$matches = $rules !== null && $withdrawal === null && !$invalid_bindings;
					$confirmed_bindings = [];
					foreach ($bindings as $group => $binding) {
						$state = $snapshot['steering'][$group] ?? [];
						$status = sdwan_steering_pf_status($binding, $state, $inventory, $rules,
						    $rule_pairs[$group] ?? null);
						$matches = $matches && in_array($status, ['applied', 'blocked'], true);
						if ($matches) {
							$confirmed_bindings[$group] = ['policy' => $binding['policy'], 'status' => $status, 'state' => $state];
						}
					}
					if (!$matches) {
						$confirmed_bindings = [];
					}
					if ($clear_receipt) {
						$receipt = null;
					} elseif ($matches && !$receipt['confirmed']) {
						$receipt['attempts'] = 0;
						$receipt['confirmed'] = true;
						$action = 'filter_applied';
					} elseif ($rules === null && ($bindings || $withdrawal !== null) && $receipt['accepted'] && !$receipt['confirmed'] &&
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
			if (!sdwan_steering_write_receipt($receipt_path, $receipt)) {
				throw new RuntimeException('Cannot record the filter reload request');
			}
		} elseif ($clear_receipt) {
			if (is_file($receipt_path) && !unlink($receipt_path)) {
				throw new RuntimeException('Cannot clear the confirmed withdrawal receipt');
			}
		} elseif ($receipt !== null && $receipt !== $previous && !sdwan_steering_write_receipt($receipt_path, $receipt)) {
			throw new RuntimeException('Cannot update the filter reload receipt');
		}
		if ($withdrawal_verified) {
			sdwan_log_event('filter_withdrawal_confirmed');
		}
		if ($action !== null) {
			sdwan_log_event($action);
		}
		static $reconnect_baseline = [];
		if (function_exists('sdwan_steering_auto_reconnect')) {
			sdwan_steering_auto_reconnect($reconnect_baseline, $config, $inventory, $bindings ?? [],
			    $confirmed_bindings ?? [], $snapshot, $action === 'filter_applied');
		}
		if ($invalid_bindings) {
			sdwan_log_event('error', [], 'bindings');
		} else {
			// These events describe the active PF readback, not merely the prospective steering choice.
			sdwan_log_event('observation', $snapshot + ['pf_confirmed' => $confirmed_bindings ?? []]);
		}
	} finally {
		fclose($lock);
	}
}

/* The observer can stop while holding its snapshot lock. This independent
 * supervisor only reads the atomic snapshot and waits on the native filter. */
function sdwan_expiry_watchdog(): never {
	sdwan_load_steering();
	$heartbeat = dirname(SDWAN_SNAPSHOT_PATH) . '/sdwan-expiry.heartbeat';
	$previous = [];
	$withdrawal = null;
	$attempts = 0;
	$retry_at = 0;
	for (;;) {
		try {
			clearstatcache();
			if (!sdwan_steering_write_receipt($heartbeat, ['pid' => getmypid(), 'updated_ns' => hrtime(true)])) {
				sdwan_log_event('filter_expiry_unconfirmed');
			}
			$pending = sdwan_steering_watchdog_pending($withdrawal);
			if ($pending === null) {
				sdwan_log_event('filter_expiry_unconfirmed');
			} elseif (!$pending) {
				$previous = [];
				$attempts = 0;
				$retry_at = 0;
			} else {
				if ($pending !== $previous) {
					$previous = $pending;
					$attempts = 0;
				}
				if ($attempts >= SDWAN_RELOAD_MAX_ATTEMPTS) {
					sdwan_log_event('filter_expiry_divergent');
				} elseif (hrtime(true) >= $retry_at) {
					$attempts++;
					sdwan_log_event('filter_expiry_requested');
					// A fresh PHP process rechecks the on-disk native adapter.
					$ok = sdwan_expiry_reload();
					$retry_at = hrtime(true) + SDWAN_RELOAD_RETRY_INTERVAL * 1_000_000_000;
					if (!$ok) {
						sdwan_log_event('filter_expiry_unconfirmed');
					}
				}
			}
		} catch (Throwable) {
			sdwan_log_event('filter_expiry_unconfirmed');
		}
		sleep(5);
	}
}

function sdwan_expiry_reload(): bool {
	if (!function_exists('exec') || !is_executable('/bin/timeout')) {
		return false;
	}
	exec('/bin/timeout -k 5 45 /usr/local/bin/php ' . escapeshellarg(__FILE__) .
	    ' --expiry-reload >/dev/null 2>&1', $output, $status);
	return $status === 0;
}

$arguments = array_slice($argv, 1);
if (!in_array($arguments, [[], ['--once'], ['--expiry-watchdog'], ['--expiry-reload']], true)) {
	fwrite(STDERR, "Usage: sdwand.php [--once|--expiry-watchdog|--expiry-reload]\n");
	exit(64);
}
if ($arguments === ['--expiry-watchdog']) {
	sdwan_expiry_watchdog();
}
if ($arguments === ['--expiry-reload']) {
	// Initialize the same native globals and modules as pfSense's filter entrypoint.
	require_once('functions.inc');
	require_once('filter.inc');
	require_once('shaper.inc');
	sdwan_load_steering();
	exit(sdwan_steering_reconcile_expiry() ? 0 : 1);
}
$once = $arguments === ['--once'];
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
