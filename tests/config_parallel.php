<?php
/* Multiple real PHP processes share the package lock and one test configuration on disk. */
function parallel_wait(callable $ready, string $description): void {
	$deadline = hrtime(true) + 30000000000;
	do {
		clearstatcache();
		if ($ready()) {
			return;
		}
		usleep(10000);
	} while (hrtime(true) < $deadline);
	throw new RuntimeException("Timed out waiting for {$description}.");
}

function parallel_read(string $path): array {
	$contents = file_get_contents($path);
	if ($contents === false) {
		throw new RuntimeException('Could not read the shared test configuration.');
	}
	return json_decode($contents, true, 512, JSON_THROW_ON_ERROR);
}

function parallel_write(string $path, array $state): void {
	$temp = tempnam(dirname($path), 'config-');
	if ($temp === false) {
		throw new RuntimeException('Could not create a temporary configuration file.');
	}
	try {
		$data = json_encode($state, JSON_THROW_ON_ERROR);
		if (file_put_contents($temp, $data) !== strlen($data) || !rename($temp, $path)) {
			throw new RuntimeException('Could not commit the shared test configuration.');
		}
	} finally {
		if (file_exists($temp)) {
			unlink($temp);
		}
	}
}

function parallel_candidate(array $baseline, int $wave, int $worker): array {
	$baseline['members'][0]['cost'] = (string)(100 + ($wave - 1) * 64 + $worker);
	$baseline['policies'][0]['strategy'] = ['cost', 'latency', 'balance'][$worker % 3];
	return $baseline;
}

$worker_mode = ($argv[1] ?? '') === '--worker';
$waves = filter_var($argv[1] ?? '4', FILTER_VALIDATE_INT, ['options' => ['min_range' => 1, 'max_range' => 64]]);
$workers = filter_var($argv[2] ?? '16', FILTER_VALIDATE_INT, ['options' => ['min_range' => 2, 'max_range' => 64]]);
if (!$worker_mode && ($argc > 3 || $waves === false || $workers === false)) {
	fwrite(STDERR, "Usage: php tests/config_parallel.php [waves] [writers-per-wave]\n");
	exit(2);
}

$directory = $worker_mode ? ($argv[2] ?? '') : sys_get_temp_dir() . '/sdwan-parallel-' . bin2hex(random_bytes(8));
if ($worker_mode) {
	if (realpath(dirname($directory)) !== realpath(sys_get_temp_dir()) ||
	    !preg_match('/\Asdwan-parallel-[0-9a-f]{16}\z/D', basename($directory)) ||
	    !is_dir($directory) || is_link($directory) || $argc !== 5 ||
	    !ctype_digit($argv[3]) || !ctype_digit($argv[4])) {
		throw new InvalidArgumentException('The worker requires the private directory and identifiers from the test runner.');
	}
} elseif (!mkdir($directory, 0700)) {
	throw new RuntimeException('Could not create the private parallel-test directory.');
}

define('SDWAN_LOCK_DIRECTORY', $directory);
set_include_path(__DIR__ . '/fixtures/write');
require 'config.inc';
require __DIR__ . '/../files/usr/local/pkg/sdwan.inc';
$store = $directory . '/config.json';

if ($worker_mode) {
	$wave = (int)$argv[3];
	$worker = (int)$argv[4];
	$writes = 0;
	$fail = false;
	$before_config_read = static function () use ($store): void {
		global $disk;
		$disk = parallel_read($store)['config'];
	};
	$before_config_write = static function (array $configuration) use ($store, $wave, $worker): void {
		$stored = parallel_read($store);
		$stored['config'] = $configuration;
		$stored['commits'][] = ['wave' => $wave, 'worker' => $worker];
		parallel_write($store, $stored);
	};
	config_read_file(false, false);
	$baseline = sdwan_get_config();
	$revision = sdwan_config_revision($baseline);
	$candidate = parallel_candidate($baseline, $wave, $worker);
	$ready = "{$directory}/ready-{$wave}-{$worker}";
	if (file_put_contents($ready, $revision) !== strlen($revision)) {
		throw new RuntimeException('Could not report the starting revision.');
	}
	parallel_wait(static fn() => is_file("{$directory}/start-{$wave}"), "wave {$wave} start");
	$errors = sdwan_save_config($candidate, $revision);
	if (!$errors && $writes === 1) {
		echo 'saved', PHP_EOL;
	} elseif ($errors === ['Settings have changed. Reload the page before saving.'] && $writes === 0) {
		echo 'stale', PHP_EOL;
	} else {
		throw new RuntimeException('Unexpected save result: ' . json_encode(['errors' => $errors, 'writes' => $writes]));
	}
	exit(0);
}

$native = [
	'interfaces' => ['wan' => ['enable' => '']],
	'gateways/gateway_item' => [['name' => 'GW', 'interface' => 'wan', 'gateway' => '192.0.2.1']],
	'filter' => ['rule' => [['descr' => 'Existing native rule']]],
	'staticroutes/route' => [['network' => '198.51.100.0/24', 'gateway' => 'GW']],
];
$policy = sdwan_empty_config();
$policy['members'][] = ['name' => 'WAN', 'gateway' => 'GW', 'cost' => '10'];
$policy['slas'][] = ['name' => 'SLA', 'latency_ms' => '40', 'loss_pct' => '5'];
$policy['policies'][] = ['name' => 'Policy', 'sla' => 'SLA', 'members' => ['WAN'], 'strategy' => 'cost'];
$expected_commits = [];
$stale_writes = 0;
$processes = [];
$lock = null;
try {
	parallel_write($store, ['config' => $native + [SDWAN_CONFIG_PATH => sdwan_encode_config($policy)], 'commits' => []]);
	for ($wave = 1; $wave <= $waves; $wave++) {
		$lock = sdwan_lock('sdwan-settings', 0);
		if (!is_resource($lock)) {
			throw new RuntimeException('Could not hold the package lock before launching the writers.');
		}
		$expected_revision = sdwan_config_revision($policy);
		$ready_paths = [];
		for ($worker = 1; $worker <= $workers; $worker++) {
			$ready_paths[] = "{$directory}/ready-{$wave}-{$worker}";
			$output = "{$directory}/worker-{$wave}-{$worker}.log";
			$streams = [0 => ['pipe', 'r'], 1 => ['file', $output, 'w'], 2 => ['redirect', 1]];
			$process = proc_open([PHP_BINARY, __FILE__, '--worker', $directory, (string)$wave, (string)$worker], $streams, $pipes);
			if (!is_resource($process)) {
				throw new RuntimeException('Could not start a parallel writer.');
			}
			fclose($pipes[0]);
			$processes[$worker] = ['process' => $process, 'output' => $output];
		}
		parallel_wait(static function () use ($ready_paths, $expected_revision): bool {
			foreach ($ready_paths as $path) {
				if (!is_file($path) || file_get_contents($path) !== $expected_revision) {
					return false;
				}
			}
			return true;
		}, "all {$workers} workers to read the same revision");
		if (!touch("{$directory}/start-{$wave}")) {
			throw new RuntimeException('Could not release the worker start barrier.');
		}
		/* Give the ready workers an opportunity to contend before the parent unlocks. */
		usleep(100000);
		sdwan_unlock($lock);
		$lock = null;
		$winner = null;
		foreach ($processes as $worker => ['process' => $process, 'output' => $output]) {
			$status = null;
			parallel_wait(static function () use ($process, &$status): bool {
				$status = proc_get_status($process);
				return !$status['running'];
			}, "writer {$wave}/{$worker} to exit");
			proc_close($process);
			unset($processes[$worker]);
			$result = trim((string)file_get_contents($output));
			if ($status['exitcode'] !== 0 || !in_array($result, ['saved', 'stale'], true)) {
				throw new RuntimeException("Writer {$wave}/{$worker} failed: {$result}");
			}
			if ($result === 'stale') {
				$stale_writes++;
			} elseif ($winner === null) {
				$winner = $worker;
			} else {
				throw new RuntimeException("Wave {$wave} reported two successful saves.");
			}
		}
		if ($winner === null) {
			throw new RuntimeException("Wave {$wave} had no successful save.");
		}
		$policy = parallel_candidate($policy, $wave, $winner);
		$expected_commits[] = ['wave' => $wave, 'worker' => $winner];
		$expected_config = $native + [SDWAN_CONFIG_PATH => sdwan_encode_config($policy)];
		if (parallel_read($store) !== ['config' => $expected_config, 'commits' => $expected_commits]) {
			throw new RuntimeException("Wave {$wave} changed the native configuration or recorded an unexpected write.");
		}
	}
	printf("waves=%d writers_per_wave=%d submissions=%d saved=%d stale=%d\n", $waves, $workers,
	    $waves * $workers, count($expected_commits), $stale_writes);
} finally {
	if (is_resource($lock)) {
		sdwan_unlock($lock);
	}
	foreach ($processes as ['process' => $process]) {
		proc_terminate($process);
		proc_close($process);
	}
	foreach (glob($directory . '/*') as $path) {
		unlink($path);
	}
	rmdir($directory);
}
