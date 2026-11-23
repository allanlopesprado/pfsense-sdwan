<?php
declare(strict_types=1);

require_once __DIR__ . '/../../files/usr/local/pkg/sdwan_steering.inc';

function pool_audit_measure(array $gateways, array $eligible, array $soft = []): array {
	$candidates = [];
	foreach ($gateways as $gateway) {
		$candidates[$gateway] = match (true) {
			in_array($gateway, $eligible, true) => 'Eligible',
			in_array($gateway, $soft, true) => 'Loss exceeds the SLA',
			default => 'No verified required service measurement',
		};
	}
	return ['candidates' => $candidates, 'soft' => $soft];
}

$seed = getenv('SDWAN_AUDIT_SEED');
mt_srand($seed === false || $seed === '' ? 172831 : (int)$seed);
$trials = 256;
$inputHash = hash_init('sha256');
$passed = array_fill_keys([
	'duplicate_sample', 'sample_limit', 'unconfirmed_path', 'staggered_readmission',
	'independent_flap', 'clock_rollback', 'outage_and_first_recovery', 'binding_revision',
], 0);
$clockHolds = 0;
$prematureReadmissions = 0;

for ($trial = 0; $trial < $trials; $trial++) {
	$gateways = ['WAN_A', 'WAN_B', 'WAN_C'];
	shuffle($gateways);
	[$first, $survivor, $last] = $gateways;
	$hold = mt_rand(4, 28);
	$stagger = mt_rand(2, $hold - 2);
	$elapsed = mt_rand(1, $hold - 1);
	$limit = mt_rand(2, 6);
	$start = mt_rand(10000, 10000000);
	hash_update($inputHash, json_encode([$gateways, $hold, $stagger, $elapsed, $limit, $start], JSON_THROW_ON_ERROR) . "\n");
	$config = [
		'members' => array_map(static fn($name) => ['name' => $name, 'gateway' => $name], $gateways),
		'policies' => [['name' => 'pool', 'strategy' => 'balance', 'sla' => 'sla', 'members' => $gateways,
		    'recover_seconds' => $hold, 'degrade_samples' => $limit]],
		'slas' => [['name' => 'sla']],
	];
	$binding = ['policy' => 'pool', 'policy_revision' => sdwan_steering_policy_revision($config, 'pool'),
	    'gateways' => $gateways];
	$next = static fn(array $quality, array $old, int $time, bool $applied = false) =>
	    sdwan_steering_state($config, $binding, $quality, $old, $time, $applied);
	$all = pool_audit_measure($gateways, $gateways);
	$ongoing = $next($all, [], $start - 1);
	$quality = pool_audit_measure($gateways, [$survivor, $last], [$first]);
	$initial = $next($quality, $ongoing, $start, true);
	$replayed = $next($quality, $initial, $start, true);
	$passed['duplicate_sample'] += (int)($initial['pool'] === $gateways &&
	    $initial['degraded'] === [$first => 1] && $replayed === $initial);
	$passed['unconfirmed_path'] += (int)($next($quality, $ongoing, $start)['pool'] === [$survivor, $last]);
	$qualified = true;
	$measured = $initial;
	for ($sample = 2; $sample < $limit; $sample++) {
		$measured = $next($quality, $measured, $start + $sample - 1, true);
		$qualified = $qualified && $measured['pool'] === $gateways && $measured['degraded'] === [$first => $sample];
	}
	$excluded = $next($quality, $measured, $start + $limit - 1, true);
	$passed['sample_limit'] += (int)($qualified && $excluded['pool'] === [$survivor, $last] && !isset($excluded['degraded']));

	$onlySurvivor = pool_audit_measure($gateways, [$survivor]);
	$start += $limit + 1;
	$isolated = $next($onlySurvivor, $excluded, $start - 1);
	$firstRecovers = $next(pool_audit_measure($gateways, [$first, $survivor]), $isolated, $start);
	$bothRecover = $next($all, $firstRecovers, $start + $stagger);
	$beforeBoundary = $next($all, $bothRecover, $start + $hold - 1);
	$firstAdmitted = $next($all, $beforeBoundary, $start + $hold);
	$fullPool = $next($all, $firstAdmitted, $start + $stagger + $hold);
	$passed['staggered_readmission'] += (int)($isolated['pool'] === [$survivor] &&
	    $beforeBoundary['pool'] === [$survivor] && $beforeBoundary['recovering'] === [$first => $start, $last => $start + $stagger] &&
	    $firstAdmitted['pool'] === [$first, $survivor] && $firstAdmitted['recovering'] === [$last => $start + $stagger] &&
	    $fullPool['pool'] === $gateways && !isset($fullPool['recovering']));
	$flapped = $next(pool_audit_measure($gateways, [$survivor, $last]), $bothRecover, $start + $stagger + 1);
	$resumed = $next($all, $flapped, $start + $stagger + 2);
	$lastAdmitted = $next($all, $resumed, $start + $stagger + $hold);
	$passed['independent_flap'] += (int)($lastAdmitted['pool'] === [$survivor, $last] &&
	    $lastAdmitted['recovering'] === [$first => $start + $stagger + 2]);
	$rewound = $next($all, $bothRecover, $start - 1);
	$passed['clock_rollback'] += (int)($rewound['pool'] === [$survivor] &&
	    $rewound['recovering'] === [$first => $start - 1, $last => $start - 1]);
	$blocked = $next(pool_audit_measure($gateways, []), $bothRecover, $start + $stagger + 1);
	$restored = $next(pool_audit_measure($gateways, [$last]), $blocked, $start + $stagger + 2);
	$passed['outage_and_first_recovery'] += (int)($blocked['pool'] === [] && $blocked['gateway'] === null &&
	    !isset($blocked['recovering']) && $restored['pool'] === [$last] && !isset($restored['recovering']));
	$changed = $config;
	$changed['policies'][0]['recover_seconds']++;
	$withdrawn = sdwan_steering_state($changed, $binding, $all, $bothRecover, $start + $stagger + 1, true);
	$passed['binding_revision'] += (int)($withdrawn['gateway'] === null && $withdrawn['pool'] === [] &&
	    !isset($withdrawn['recovering']) && sdwan_snapshot_steering_valid(['pool' => $withdrawn], $start + $stagger + 1));

	// The civil jump stays below the snapshot age limit. The simulated elapsed
	// time has not reached the policy hold, even though the wall clock has.
	$steady = $next($all, $firstRecovers, $start + $elapsed);
	$jumped = $next($all, $firstRecovers, sdwan_snapshot_clock([
	    'generated_at' => $start + $hold,
	    'observed_at_ns' => ($start + $elapsed) * 1_000_000_000,
	]));
	$steadyHolds = $steady['pool'] === [$survivor] && ($steady['recovering'][$first] ?? null) === $start;
	$clockHolds += (int)($steadyHolds && $jumped['pool'] === [$survivor] &&
	    ($jumped['recovering'][$first] ?? null) === $start);
	$prematureReadmissions += (int)($steadyHolds && $jumped['pool'] === [$first, $survivor] &&
	    !isset($jumped['recovering'][$first]));
}

$results = [];
foreach ($passed as $case => $count) {
	$results[] = ['id' => "pool_transitions.$case", 'expected' => $trials, 'observed' => $count];
}
$results[] = [
	'id' => 'pool_transitions.forward_clock_jump',
	'expected' => "$trials holds, 0 premature readmissions",
	'observed' => "$clockHolds holds, $prematureReadmissions premature readmissions",
	'known_observed' => "0 holds, $trials premature readmissions",
];
echo json_encode(['input_sha256' => hash_final($inputHash), 'cases' => $results],
    JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR), PHP_EOL;
