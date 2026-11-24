<?php
/* Root console pilot. Inputs authorize only SLA and strategy for an existing policy. */
declare(strict_types=1);

function fleet_read(string $path, int $limit): string {
	$path = realpath($path);
	if ($path === false || !is_file($path) || ($data = @file_get_contents($path, false, null, 0, $limit + 1)) === false ||
	    strlen($data) > $limit) {
		throw new RuntimeException('Cannot read the bounded local file.');
	}
	return $data;
}

function fleet_write(string $path, array $state): void {
	$file = tempnam(dirname($path), '.sdwan-fleet-');
	if ($file === false) {
		throw new RuntimeException('Cannot create the site journal.');
	}
	try {
		$data = json_encode($state, JSON_THROW_ON_ERROR);
		if (!chmod($file, 0600) || file_put_contents($file, $data) !== strlen($data) || !rename($file, $path)) {
			throw new RuntimeException('Cannot replace the site journal.');
		}
	} finally {
		if (file_exists($file)) {
			unlink($file);
		}
	}
}

function fleet_manifest(string $file, string $checksum, array $state, string $revision): array {
	$raw = fleet_read($file, 4096);
	if (!preg_match('/\A[a-f0-9]{64}\z/', $checksum) || !hash_equals(hash('sha256', $raw), $checksum)) {
		throw new RuntimeException('Policy SHA-256 does not match.');
	}
	$plan = json_decode($raw, true, 4, JSON_THROW_ON_ERROR);
	if (!is_array($plan) || count($plan) !== 7 || ($plan['schema'] ?? null) !== 1 || ($plan['site'] ?? null) !== $state['site'] ||
	    !is_int($plan['revision'] ?? null) || $plan['revision'] <= $state['high_water'] || $plan['revision'] > 2147483647 ||
	    ($plan['expected_config'] ?? null) !== $revision ||
	    !sdwan_valid_name($plan['policy'] ?? null) || !sdwan_valid_name($plan['sla'] ?? null) ||
	    !in_array($plan['strategy'] ?? null, ['cost', 'latency', 'balance'], true)) {
		throw new RuntimeException('Policy is invalid, belongs to another site, was superseded or has a stale configuration revision.');
	}
	return $plan;
}

function fleet_resume(string $path, array $state, string $revision): array {
	$pending = $state['pending'] ?? null;
	if ($pending === null) {
		return $state;
	}
	if ($revision === $pending['after']) {
		$state = $pending['commit'];
	} elseif ($revision === $pending['before']) {
		unset($state['pending']);
	} else {
		throw new RuntimeException('An interrupted change has an unexpected configuration revision. Review the site journal and native configuration backup from the console.');
	}
	fleet_write($path, $state);
	return $state;
}

function fleet_update(string $path, array $state, array $current, array $policy, array $commit): void {
	$index = array_search($policy['name'], array_column($current['policies'], 'name'), true);
	if ($index === false) {
		throw new RuntimeException('The policy must already exist on the site.');
	}
	$candidate = $current;
	$candidate['policies'][$index] = array_replace($current['policies'][$index], $policy);
	$before = sdwan_config_revision($current);
	$after = sdwan_config_revision($candidate);
	if ($before === $after) {
		throw new RuntimeException('The revision must change the site policy.');
	}
	$commit['config_sha256'] = $after;
	if (isset($commit['rollback'])) {
		$commit['rollback']['expected_config'] = $after;
	}
	$state['pending'] = ['before' => $before, 'after' => $after, 'commit' => $commit];
	fleet_write($path, $state);
	$errors = sdwan_save_config($candidate, $before, true);
	if (!config_read_file(false, false)) {
		throw new RuntimeException('The native configuration could not be read after the change.');
	}
	$revision = sdwan_config_revision(sdwan_get_config());
	fleet_resume($path, $state, $revision);
	if ($errors || $revision !== $after) {
		throw new RuntimeException($errors ? implode(' ', $errors) : 'Native settings did not confirm the expected revision.');
	}
}

function fleet_report(array $state, array $settings): array {
	$paths = [];
	$inventory = sdwan_gateways();
	$sample = sdwan_current_snapshot($settings, $inventory);
	$supported = sdwan_steering_supported();
	$bindings = sdwan_steering_bindings();
	$rules = $supported && $sample !== null && $bindings ? sdwan_steering_pf_rules() : null;
	$native = $rules !== null ? sdwan_steering_native($inventory) : [];
	foreach ($bindings as $group => $binding) {
		$decision = $sample['steering'][$group] ?? [];
		$result = 'unverified';
		if ($rules !== null && sdwan_steering_approval_error() === null) {
			$check = sdwan_steering_preflight($settings, $binding['policy'], $group, $native);
			$result = sdwan_steering_preflight_matches($binding, $check) &&
			    $binding['policy_revision'] === sdwan_steering_policy_revision($settings, $binding['policy']) ?
			    sdwan_steering_pf_status($binding, $decision, $inventory, $rules, $check['rule_pairs']) : 'binding_changed';
		}
		$paths[] = ['group' => $group, 'policy' => $binding['policy'], 'trackers' => $binding['trackers'], 'pf' => $result,
		    'gateways' => $result === 'applied' ? ($decision['pool'] ?? [$decision['gateway']]) : []];
	}
	return ['schema' => 1, 'site' => $state['site'], 'revision' => $state['revision'], 'observed_at' => time(),
	    'pfSense' => trim(fleet_read('/etc/version', 64)), 'package' => sdwan_release_installed(),
	    'config_sha256' => sdwan_config_revision($settings),
	    'drifted' => isset($state['config_sha256']) && $state['config_sha256'] !== sdwan_config_revision($settings),
	    'paths' => $paths];
}

if (PHP_SAPI !== 'cli' || realpath($_SERVER['SCRIPT_FILENAME'] ?? '') !== __FILE__) {
	return;
}
require_once('config.inc');
require_once('pkg-utils.inc');
require_once('/usr/local/pkg/sdwan_steering.inc');
require_once('/usr/local/pkg/sdwan_release.inc');

try {
	if (!function_exists('posix_geteuid') || posix_geteuid() !== 0) {
		throw new RuntimeException('Use the root appliance console.');
	}
	umask(0077);
	$file = '/conf/sdwan-fleet.json';
	$action = $argv[1] ?? '';
	$expected_count = ['enroll' => 3, 'apply' => 4, 'status' => 2, 'rollback' => 2];
	if (($expected_count[$action] ?? 0) !== $argc) {
		throw new RuntimeException('Usage: php fleet-site.php enroll SITE | status | apply FILE SHA256 | rollback');
	}
	$lock_path = '/var/run/sdwan-fleet.lock';
	$lock = !is_link($lock_path) ? @fopen($lock_path, 'c') : false;
	if ($lock === false || !flock($lock, LOCK_EX | LOCK_NB)) {
		throw new RuntimeException('The site journal is busy.');
	}
	if ($action === 'enroll') {
		if (@lstat($file) !== false || !preg_match('/\A[a-z][a-z0-9-]{0,31}\z/', $argv[2])) {
			throw new RuntimeException('Site identifier is invalid or the appliance is already enrolled.');
		}
		fleet_write($file, ['site' => $argv[2], 'revision' => 0, 'high_water' => 0]);
		echo "Site enrolled.\n";
		exit;
	}
	$settings = sdwan_get_config();
	$revision = sdwan_config_revision($settings);
	$state = fleet_resume($file, json_decode(fleet_read($file, 8192), true, 8, JSON_THROW_ON_ERROR), $revision);
	if ($action === 'status') {
		echo json_encode(fleet_report($state, $settings), JSON_THROW_ON_ERROR), "\n";
		exit;
	}
	$next = $state;
	if ($action === 'rollback') {
		$previous = $state['rollback'] ?? null;
		if ($previous === null || $previous['expected_config'] !== $revision) {
			throw new RuntimeException('No rollback matches the current settings. Review local changes in the WebGUI.');
		}
		$next['revision'] = $previous['revision'];
		unset($next['rollback']);
		fleet_update($file, $state, $settings, $previous['policy'], $next);
		echo "Previous policy saved. Confirm the active PF path with status.\n";
		exit;
	}
	$plan = fleet_manifest($argv[2], $argv[3], $state, $revision);
	$saved = array_column($settings['policies'], null, 'name')[$plan['policy']] ?? null;
	if ($saved === null) {
		throw new RuntimeException('The policy must already exist on the site.');
	}
	$next['revision'] = $next['high_water'] = $plan['revision'];
	$next['rollback'] = ['revision' => $state['revision'], 'policy' => array_intersect_key($saved,
	    array_flip(['name', 'sla', 'strategy']))];
	fleet_update($file, $state, $settings, ['name' => $plan['policy'], 'strategy' => $plan['strategy'], 'sla' => $plan['sla']], $next);
	echo "Policy saved. Confirm the active PF path with status.\n";
} catch (Throwable $error) {
	fwrite(STDERR, $error->getMessage() . "\n");
	exit(1);
}
