<?php
declare(strict_types=1);
require __DIR__ . '/../tools/fleet-site.php';

function sdwan_valid_name($value): bool {
	return is_string($value) && preg_match('/\A[A-Za-z0-9][A-Za-z0-9_-]{0,31}\z/', $value) === 1;
}

function rejected(callable $operation, string $message): void {
	try {
		$operation();
	} catch (RuntimeException $error) {
		if (str_contains($error->getMessage(), $message)) {
			return;
		}
		throw $error;
	}
	throw new RuntimeException('Expected rejection: ' . $message);
}

$file = tempnam(sys_get_temp_dir(), 'sdwan-fleet-');
if ($file === false) {
	throw new RuntimeException('Cannot create a temporary fixture.');
}
try {
	$revision = str_repeat('a', 64);
	$site = ['site' => 'pilot', 'revision' => 1, 'high_water' => 2];
	$plan = ['schema' => 1, 'site' => 'pilot', 'revision' => 3, 'expected_config' => $revision, 'policy' => 'ERP',
	    'sla' => 'lab', 'strategy' => 'balance'];
	fleet_write($file, $plan);
	$digest = hash_file('sha256', $file);
	if (fleet_manifest($file, $digest, $site, $revision) !== $plan) {
		throw new RuntimeException('The policy manifest changed.');
	}
	rejected(fn() => fleet_manifest($file, str_repeat('b', 64), $site, $revision), 'SHA-256');
	rejected(fn() => fleet_manifest($file, $digest, ['site' => 'wrong-site'] + $site, $revision), 'another site');
	rejected(fn() => fleet_manifest($file, $digest, ['high_water' => 4] + $site, $revision), 'superseded');
	rejected(fn() => fleet_manifest($file, $digest, $site, str_repeat('b', 64)), 'stale configuration');

	$after = str_repeat('c', 64);
	$commit = ['revision' => 3, 'high_water' => 3] + $site;
	$pending = $site + ['pending' => ['before' => $revision, 'after' => $after, 'commit' => $commit]];
	if (fleet_resume($file, $pending, $after) !== $commit ||
	    fleet_resume($file, $pending, $revision) !== $site) {
		throw new RuntimeException('The interrupted journal did not reconcile.');
	}
	rejected(fn() => fleet_resume($file, $pending, str_repeat('d', 64)), 'unexpected configuration revision');
	echo "ok - site binding, monotonic revisions, exact digest, and interrupted journal recovery\n";
} finally {
	unlink($file);
}
