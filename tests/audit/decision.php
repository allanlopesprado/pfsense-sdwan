<?php
declare(strict_types=1);

namespace SdwanAuditProbeFixture {
    /* Only these functions are shadowed inside a copy of the production
     * probe functions. No route table, network socket, or real clock is used. */
    final class Clock {
        public static int $now = 0;
        public static int $routeLatency = 0;
    }

    function hrtime(bool $asNumber = false): int|array {
        return $asNumber ? Clock::$now : [
            intdiv(Clock::$now, 1_000_000_000),
            Clock::$now % 1_000_000_000,
        ];
    }

    function is_executable(string $path): bool {
        return in_array($path, ['/sbin/route', '/bin/timeout'], true);
    }

    function exec(string $command, ?array &$output = null, ?int &$result = null): string {
        if (!preg_match('/198\.18\.(10[1-5])\.(21|22)\b/', $command, $target) ||
            !preg_match('~/bin/timeout\s+(\d+(?:\.\d+)?)~', $command, $timeout)) {
            throw new \RuntimeException('Unexpected route lookup in the no-network probe fixture.');
        }
        $maximum = (int)round((float)$timeout[1] * 1_000_000_000);
        Clock::$now += min($maximum, Clock::$routeLatency);
        if (Clock::$routeLatency > $maximum) {
            $result = 124;
            return '';
        }
        $wan = (int)$target[1] - 100;
        $output = ["gateway: 198.18.{$wan}.2", "interface: em{$wan}", 'flags: <UP,GATEWAY,HOST,DONE,STATIC>'];
        $result = 0;
        return $output[2];
    }

    function get_real_interface(string $interface, string $family, bool $ignored = false, bool $refresh = false): string {
        if ($family !== 'inet' || !preg_match('/^wan([1-5])$/', $interface, $device)) {
            throw new \RuntimeException('Unexpected interface in the no-network probe fixture.');
        }
        return 'em' . $device[1];
    }

    function find_interface_ip(string $device, bool $refresh): string {
        return '198.18.' . substr($device, 2) . '.10';
    }

    function stream_socket_client(string $address, &$error, &$message, float $timeout, int $flags, $context) {
        if (!preg_match('~^tcp://198\.18\.(10[1-5])\.(21|22):443$~', $address, $target) ||
            (stream_context_get_options($context)['socket']['bindto'] ?? null) !==
            '198.18.' . ((int)$target[1] - 100) . '.10:0') {
            throw new \RuntimeException('The probe did not bind to its expected synthetic source.');
        }
        return fopen('php://memory', 'w+b');
    }

    function stream_select(&$read, &$write, &$except, ?int $seconds, ?int $microseconds = null): int {
        return count($write);
    }

    function stream_socket_get_name($socket, bool $remote): string {
        return '198.18.101.21:443';
    }

    function usleep(int $microseconds): void {
        Clock::$now += $microseconds * 1_000;
    }
}

namespace {
    use SdwanAuditProbeFixture\Clock;

    if (PHP_SAPI !== 'cli') {
        exit(64);
    }
    $package = dirname(__DIR__, 2) . '/files/usr/local/pkg';
    require_once $package . '/sdwan_engine.inc';
    require_once $package . '/sdwan_steering.inc';

    $probe = file_get_contents($package . '/sdwan_probe.inc');
    if (!is_string($probe) || !str_starts_with($probe, '<?php')) {
        throw new RuntimeException('Unable to load the production probe implementation.');
    }
    eval('namespace SdwanAuditProbeFixture; ' . substr($probe, 5));

    function audit_case(string $id, string $expected, string $observed, ?string $known = null): array {
        $result = ['id' => "decision.{$id}", 'expected' => $expected, 'observed' => $observed];
        if ($known !== null) {
            $result['known_observed'] = $known;
        }
        return $result;
    }

    function quality(string $rtt, string $deviation, string $loss): array {
        return [
            'status' => 'online', 'substatus' => 'none', 'delay' => $rtt . 'ms',
            'stddev' => $deviation . 'ms', 'loss' => $loss . '%',
        ];
    }

    function path_config(int $count): array {
        $members = $inventory = $observations = [];
        for ($number = 1; $number <= $count; $number++) {
            $name = "WAN{$number}";
            $subnet = $number + 100;
            $members[] = [
                'name' => $name, 'gateway' => $name, 'cost' => (string)$number,
                'probe_primary' => "tcp://198.18.{$subnet}.21:443",
                'probe_secondary' => "tcp://198.18.{$subnet}.22:443",
            ];
            $inventory[$name] = ['interface' => "wan{$number}", 'family' => 'inet', 'address' => "198.18.{$number}.2"];
            $observations[$name] = quality('25', '2', '0');
        }
        return [$members, $inventory, $observations];
    }

    function observe_bounded_probes(int $members, int $routeMs): array {
        [$paths, $inventory, $observations] = path_config($members);
        Clock::$now = 0;
        Clock::$routeLatency = $routeMs * 1_000_000;
        $observed = SdwanAuditProbeFixture\sdwan_probe_observe($paths, $inventory, $observations);
        $labels = array_merge(...array_values(array_map('array_values', $observed)));
        return [intdiv(Clock::$now, 1_000_000), count(array_keys($labels, 'Passed', true)), $labels];
    }

    [$paths, $inventory, $observations] = path_config(3);
    foreach ($paths as &$path) {
        unset($path['probe_primary'], $path['probe_secondary']);
    }
    unset($path);
    $strict = ['name' => 'interactive', 'latency_ms' => '40', 'rttsd_ms' => '30', 'loss_pct' => '5'];
    $bulk = ['name' => 'bulk', 'latency_ms' => '80', 'rttsd_ms' => '60', 'loss_pct' => '10'];
    $config = [
        'members' => $paths, 'slas' => [$strict, $bulk], 'policies' => [
            ['name' => 'calls', 'sla' => 'interactive', 'strategy' => 'cost', 'members' => ['WAN1', 'WAN2', 'WAN3']],
            ['name' => 'copies', 'sla' => 'bulk', 'strategy' => 'cost', 'members' => ['WAN1', 'WAN2', 'WAN3']],
        ],
    ];
    $observations['WAN1'] = quality('40', '30', '5');
    $observations['WAN2'] = quality('40.001', '25', '2');
    $observations['WAN3'] = quality('38', '30.001', '6');
    $initial = sdwan_evaluate($config, $observations, 500, $inventory);
    $observations['WAN1'] = quality('39', '29', '6');
    $after = sdwan_evaluate($config, $observations, 501, $inventory);

    $hold = sdwan_steering_step(['gateway' => 'WAN1'], ['WAN1', 'WAN2', 'WAN3'], 'WAN2', 100);
    $newChallenger = sdwan_steering_step($hold, ['WAN1', 'WAN3'], 'WAN3', 129);
    $beforeHold = sdwan_steering_step($newChallenger, ['WAN1', 'WAN3'], 'WAN3', 158);
    $endHold = sdwan_steering_step($beforeHold, ['WAN1', 'WAN3'], 'WAN3', 159);
    $withdrawn = sdwan_steering_step($newChallenger, ['WAN3'], 'WAN3', 130);

    [$fastMs, $fastPass, $fastLabels] = observe_bounded_probes(5, 20);
    [$slowThreeMs] = observe_bounded_probes(3, 250);
    [$slowFiveMs, $slowFivePass, $slowFiveLabels] = observe_bounded_probes(5, 250);
    $qualityLabels = array_values($initial['policies']['calls']['candidates']);
    $isolation = ($after['policies']['calls']['selected'] ?? 'blocked') . '/' .
        ($after['policies']['copies']['selected'] ?? 'blocked');
    $changes = implode('/', [
        $hold['gateway'], $newChallenger['gateway'], $newChallenger['since'],
        $beforeHold['gateway'], $endHold['gateway'], $withdrawn['gateway'],
    ]);
    $slowThree = $slowThreeMs <= 2500 ? 'within_2500ms' : "{$slowThreeMs}ms";
    $slowFive = $slowFivePass > 0 ? 'at_least_one_healthy_result' :
        "0_passed/" . count(array_keys($slowFiveLabels, 'Timed out', true)) . "_timed_out/{$slowFiveMs}ms";
    $result = [
        audit_case('sla_boundary_triple', 'Eligible|RTT exceeds the SLA|RTT standard deviation exceeds the SLA or is unavailable',
            implode('|', $qualityLabels)),
        audit_case('sla_policy_isolation', 'blocked/WAN1', $isolation),
        audit_case('challenger_replacement', 'WAN1/WAN1/129/WAN1/WAN3/WAN3', $changes),
        audit_case('probe_fast_control', '10_passed/10_checks/within_budget',
            "{$fastPass}_passed/" . count($fastLabels) . '_checks/' . ($fastMs <= 2500 ? 'within_budget' : 'over_budget')),
        audit_case('probe_three_wan_deadline', 'within_2500ms', $slowThree, '3000ms'),
        audit_case('probe_preparation_starvation', 'at_least_one_healthy_result', $slowFive, '0_passed/10_timed_out/2500ms'),
    ];
    echo json_encode($result, JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), PHP_EOL;
}
