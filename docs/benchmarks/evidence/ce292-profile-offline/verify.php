<?php
declare(strict_types=1);

// Usage: php verify.php /path/to/source /path/to/output-directory
// The source is a checkout of pfSense-pkg-SDWAN 0.4.28.
if ($argc !== 3 || !is_dir($argv[2])) {
    fwrite(STDERR, "Usage: php verify.php <source> <existing output directory>\n");
    exit(2);
}
require $argv[1] . '/files/usr/local/pkg/sdwan_steering.inc';

$wan1 = 'WAN1';
$wan2 = 'WAN2';
$config = [
    'members' => [
        ['name' => $wan1, 'gateway' => $wan1, 'cost' => '2', 'probe_primary' => 'configured',
            'probe_secondary' => 'configured'],
        ['name' => $wan2, 'gateway' => $wan2, 'cost' => '1', 'probe_primary' => 'configured',
            'probe_secondary' => 'configured'],
    ],
    'slas' => [['name' => 'sla', 'latency_ms' => '40', 'rttsd_ms' => '30', 'loss_pct' => '5']],
    'policies' => [['name' => 'lan', 'sla' => 'sla', 'members' => [$wan1, $wan2], 'strategy' => 'cost']],
];
$passed = ['probe_primary' => 'Passed', 'probe_secondary' => 'Passed'];
$inventory = [
    $wan1 => ['family' => 'inet', 'interface' => 'wan', 'transport' => 'wan'],
    $wan2 => ['family' => 'inet', 'interface' => 'opt1', 'transport' => 'opt1'],
];

function gateway(array $metrics, string $status = 'online'): array
{
    [$rtt, $variation, $loss] = $metrics;
    return ['status' => $status, 'substatus' => 'none', 'delay' => $rtt . 'ms',
        'stddev' => $variation . 'ms', 'loss' => $loss . '%'];
}

function csvLine($file, array $columns): void
{
    if (fputcsv($file, $columns, ',', '"', '') === false) {
        throw new RuntimeException('Could not write CSV row.');
    }
}

$output = $argv[2];
$grid = fopen($output . '/threshold-grid.csv', 'wb');
$events = fopen($output . '/policy-transitions.csv', 'wb');
if ($grid === false || $events === false) {
    throw new RuntimeException('Could not open CSV outputs.');
}
csvLine($grid, ['wan1_rtt_ms', 'wan1_rttsd_ms', 'wan1_loss_pct', 'wan2_rtt_ms', 'wan2_rttsd_ms',
    'wan2_loss_pct', 'wan1_eligible', 'wan2_eligible', 'expected', 'actual', 'wan1_reason', 'wan2_reason']);
csvLine($events, ['sequence', 'simulated_seconds', 'wan1_status', 'wan2_status', 'wan2_primary',
    'wan2_secondary', 'preferred', 'expected', 'actual', 'pending_preference', 'wan2_reason']);

$vectors = [];
foreach ([39.999, 40, 40.001] as $rtt) {
    foreach ([29.999, 30, 30.001] as $variation) {
        foreach ([4, 5, 6] as $loss) {
            $vectors[] = ['metrics' => [$rtt, $variation, $loss],
                'eligible' => $rtt <= 40 && $variation <= 30 && $loss <= 5];
        }
    }
}

$counts = ['WAN1' => 0, 'WAN2' => 0, 'no_candidate' => 0];
foreach ($vectors as $first) {
    foreach ($vectors as $second) {
        $expected = $second['eligible'] ? $wan2 : ($first['eligible'] ? $wan1 : null);
        $result = sdwan_evaluate($config, [$wan1 => gateway($first['metrics']), $wan2 => gateway($second['metrics'])],
            100, $inventory, [$wan1 => $passed, $wan2 => $passed])['policies']['lan'];
        $actual = $result['selected'];
        $reasons = $result['candidates'];
        csvLine($grid, [...$first['metrics'], ...$second['metrics'], (int)$first['eligible'], (int)$second['eligible'],
            $expected ?? 'no_candidate', $actual ?? 'no_candidate', $reasons[$wan1], $reasons[$wan2]]);
        if ($actual !== $expected || ($reasons[$wan1] === 'Eligible') !== $first['eligible'] ||
            ($reasons[$wan2] === 'Eligible') !== $second['eligible']) {
            throw new RuntimeException('The policy did not select the expected profile at the threshold.');
        }
        $counts[$actual ?? 'no_candidate']++;
    }
}

$binding = ['policy' => 'lan', 'gateways' => [$wan1, $wan2],
    'policy_revision' => sdwan_steering_policy_revision($config, 'lan')];
$sequences = [
    'link_loss_and_recovery' => [
        [0, 'online', 'online', 'Passed', 'Passed', $wan2],
        [1, 'online', 'down', 'Passed', 'Passed', $wan1],
        [2, 'online', 'online', 'Passed', 'Passed', $wan1],
        [31, 'online', 'online', 'Passed', 'Passed', $wan1],
        [32, 'online', 'online', 'Passed', 'Passed', $wan2],
        [33, 'down', 'down', 'Passed', 'Passed', null],
        [34, 'down', 'online', 'Passed', 'Passed', $wan2],
    ],
    'service_probes_and_preference_hold' => [
        [0, 'online', 'online', 'Failed', 'Passed', $wan2],
        [1, 'online', 'online', 'Failed', 'Failed', $wan1],
        [2, 'online', 'online', 'Passed', 'Passed', $wan1],
        [10, 'online', 'unknown', 'Unavailable', 'Unavailable', $wan1],
        [11, 'online', 'online', 'Passed', 'Passed', $wan1],
        [40, 'online', 'online', 'Passed', 'Passed', $wan1],
        [41, 'online', 'online', 'Passed', 'Passed', $wan2],
    ],
];

$steps = 0;
foreach ($sequences as $name => $sequence) {
    $state = [];
    foreach ($sequence as [$seconds, $first, $second, $primary, $secondary, $expected]) {
        $now = 100 + $seconds;
        $result = sdwan_evaluate($config,
            [$wan1 => gateway([1, 0.2, 0], $first), $wan2 => gateway([2, 0.3, 0], $second)],
            $now, $inventory, [$wan1 => $passed, $wan2 => ['probe_primary' => $primary,
                'probe_secondary' => $secondary]])['policies']['lan'];
        $state = sdwan_steering_state($config, $binding, $result, $state, $now);
        $actual = $state['gateway'];
        csvLine($events, [$name, $seconds, $first, $second, $primary, $secondary, $result['selected'],
            $expected ?? 'no_candidate', $actual ?? 'no_candidate', $state['candidate'], $result['candidates'][$wan2]]);
        if ($actual !== $expected) {
            throw new RuntimeException("Unexpected state at $seconds seconds in $name.");
        }
        $steps++;
    }
}

fclose($grid);
fclose($events);
echo json_encode([
    'php' => PHP_VERSION, 'platform' => PHP_OS_FAMILY, 'source_tag' => 'v0.4.28',
    'sla' => $config['slas'][0], 'wan_cost' => [$wan1 => 2, $wan2 => 1], 'samples_per_WAN' => count($vectors),
    'paired_threshold_cases' => array_sum($counts), 'selected' => $counts, 'transition_steps' => $steps,
    'configured_preference_hold_seconds' => SDWAN_STEERING_HOLD,
], JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR), PHP_EOL;
