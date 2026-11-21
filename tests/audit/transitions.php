<?php
declare(strict_types=1);

require_once __DIR__ . '/../../files/usr/local/pkg/sdwan_steering.inc';

$seed = getenv('SDWAN_AUDIT_SEED');
mt_srand($seed === false || $seed === '' ? 172831 : (int)$seed);
$trials = 256;
$passed = [
    'hold_boundary' => 0,
    'changed_challenger' => 0,
    'clock_rollback' => 0,
    'ineligible_incumbent' => 0,
    'all_links_unavailable' => 0,
];

for ($trial = 0; $trial < $trials; $trial++) {
    $eligible = ['WAN_A', 'WAN_B', 'WAN_C'];
    shuffle($eligible);
    [$incumbent, $preferred, $alternate] = $eligible;
    $start = mt_rand(1000, 1000000);
    $beforeBoundary = mt_rand(1, 29);
    $prior = ['gateway' => $incumbent];
    $challenged = sdwan_steering_step($prior, $eligible, $preferred, $start);
    $holding = sdwan_steering_step($challenged, $eligible, $preferred, $start + $beforeBoundary);
    $boundary = sdwan_steering_step($holding, $eligible, $preferred, $start + 30);
    $passed['hold_boundary'] += (int)($challenged['gateway'] === $incumbent &&
        $holding['gateway'] === $incumbent && $boundary['gateway'] === $preferred);

    $changed = sdwan_steering_step($challenged, $eligible, $alternate, $start + $beforeBoundary);
    $reappeared = sdwan_steering_step($changed, $eligible, $preferred, $start + 31);
    $confirmed = sdwan_steering_step($reappeared, $eligible, $preferred, $start + 61);
    $passed['changed_challenger'] += (int)($reappeared['gateway'] === $incumbent &&
        $reappeared['since'] === $start + 31 && $confirmed['gateway'] === $preferred);

    $clockNow = $start - mt_rand(1, 30);
    $rewound = sdwan_steering_step($challenged, $eligible, $preferred, $clockNow);
    $passed['clock_rollback'] += (int)($rewound['gateway'] === $incumbent && $rewound['since'] === $clockNow);

    $failover = sdwan_steering_step($challenged, [$preferred, $alternate], $preferred, $start + 1);
    $passed['ineligible_incumbent'] += (int)($failover['gateway'] === $preferred && $failover['candidate'] === null);
    $blocked = sdwan_steering_step($failover, [], null, $start + 2);
    $passed['all_links_unavailable'] += (int)($blocked['gateway'] === null && $blocked['candidate'] === null);
}

$results = [];
foreach ($passed as $case => $count) {
    $results[] = ['id' => "transitions.$case", 'expected' => $trials, 'observed' => $count];
}
echo json_encode($results, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR), PHP_EOL;
