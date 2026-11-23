<?php

const SDWAN_SNAPSHOT_PATH = '/var/run/sdwan-observer.json';
const SDWAN_MAX_SNAPSHOT_AGE = 30;
const SDWAN_QUALITY_BREACHES = ['RTT exceeds the SLA', 'RTT standard deviation exceeds the SLA or is unavailable',
    'Loss exceeds the SLA'];

/* Canonical dpinger endpoint, including the kernel interface for link-local IPv6. */
function sdwan_monitor_address(string $value, string $family, string $device, bool $infer_scope): ?string {
	[$ip, $scope] = array_pad(explode('%', $value, 2), 2, null);
	$packed = @inet_pton($ip);
	$length = match ($family) { 'inet' => 4, 'inet6' => 16, default => 0 };
	if ($packed === false || strlen($packed) !== $length) {
		return null;
	}
	$address = inet_ntop($packed);
	if ($family === 'inet6' && ord($packed[0]) === 0xfe && (ord($packed[1]) & 0xc0) === 0x80) {
		if ($scope === null && $infer_scope) {
			$scope = $device;
		}
		return $device !== '' && $scope === $device ? $address . '%' . $device : null;
	}
	return $scope === null ? $address : null;
}

/* Unscoped link-local output can inherit the separately verified device.
 * An explicit zone must agree with that device on both sides. */
function sdwan_next_hop_matches(string $observed, string $expected, string $device): bool {
	$family = str_contains($expected, ':') ? 'inet6' : 'inet';
	$next_hop = sdwan_monitor_address($expected, $family, $device, true);
	return $next_hop !== null && sdwan_monitor_address($observed, $family, $device, true) === $next_hop;
}

function sdwan_gateway_monitor(array $gateway): ?string {
	$family = $gateway['family'];
	$interface = $gateway['interface'];
	$monitor = $gateway['monitor'];
	if ($monitor === 'dynamic') {
		$monitor = $family === 'inet6' ? get_interface_gateway_v6($interface) : get_interface_gateway($interface);
	}
	return is_string($monitor) ? $monitor : null;
}

/* Match the live interface, source and target used by gwlb.inc::start_dpinger().
 * A socket with the right gateway name can outlive a DHCP change or restore. */
function sdwan_monitor_matches(array $gateway, array $process): bool {
	$family = $gateway['family'];
	$interface = $gateway['interface'];
	$device = get_real_interface($interface, $family, false, true);
	if (!is_string($device) || $device === '') {
		return false;
	}
	$monitor = sdwan_gateway_monitor($gateway);
	if ($monitor === null) {
		return false;
	}
	$target = sdwan_monitor_address($monitor, $family, $device, true);
	if ($target === null || $target !== sdwan_monitor_address($process['targetip'] ?? '', $family, $device, false)) {
		return false;
	}
	$link_local = $family === 'inet6' && str_contains($target, '%');
	if ($family === 'inet') {
		$source = find_interface_ip($device, true);
	} elseif ($link_local) {
		$source = find_interface_ipv6_ll($device, true);
		if (is_string($source) && $source !== '' && !str_contains($source, '%')) {
			$source .= '%' . $device;
		}
	} else {
		$source = find_interface_ipv6($device, true);
	}
	if (!is_string($source)) {
		return false;
	}
	$expected = sdwan_monitor_address($source, $family, $device, false);
	if ($expected === null || $expected === '0.0.0.0' || $expected === '::') {
		return false;
	}
	if (!$link_local && isset($gateway['static_source']) &&
	    $expected !== sdwan_monitor_address($gateway['static_source'], $family, $device, false)) {
		return false;
	}
	/* Native long socket names shorten only the source to eight hex digits. */
	$reported = $process['srcip'] ?? '';
	return $reported === substr(md5($source), 0, 8) ||
	    $expected === sdwan_monitor_address($reported, $family, $device, false);
}

/* dpinger uses integer microseconds for RTT and deviation, and percent for loss. */
function sdwan_parse_dpinger_line(string $line, string $name): ?array {
	$values = preg_split('/\s+/', trim($line));
	if (count($values) !== 4 || $values[0] !== $name) {
		return null;
	}
	foreach (array_slice($values, 1) as $value) {
		if (!preg_match('/^\d{1,16}$/D', $value)) {
			return null;
		}
	}
	[, $rtt, $variation, $loss] = $values;
	if ((float)$loss > 100 || ((float)$rtt === 0.0 && (float)$variation === 0.0 && (float)$loss === 0.0)) {
		return null;
	}
	return [(float)$rtt / 1000, (float)$variation / 1000, (float)$loss];
}

function sdwan_unit_value($value, string $unit): ?float {
	if (!is_string($value) || !str_ends_with($value, $unit)) {
		return null;
	}
	$number = substr($value, 0, -strlen($unit));
	if (!preg_match('/^\d+(?:\.\d+)?$/D', $number)) {
		return null;
	}
	$parsed = (float)$number;
	return is_finite($parsed) ? $parsed : null;
}

function sdwan_member_sample(array $gateway): array {
	$rtt = sdwan_unit_value($gateway['delay'] ?? null, 'ms');
	$variation = sdwan_unit_value($gateway['stddev'] ?? null, 'ms');
	$loss = sdwan_unit_value($gateway['loss'] ?? null, '%');
	if ($loss !== null && $loss > 100) {
		$loss = null;
	}
	$status = 'unknown';
	$substatus = $gateway['substatus'] ?? '';
	if (isset($gateway['monitor_disable'])) {
		$rtt = $variation = $loss = null;
	} elseif (($gateway['status'] ?? '') === 'down' || $loss === 100.0 ||
	    in_array($substatus, ['down', 'force_down'], true)) {
		$status = 'down';
	} elseif (($gateway['status'] ?? '') === 'online' && $rtt !== null && $variation !== null && $loss !== null) {
		$status = match ($substatus) {
			'none' => 'online',
			'delay', 'loss', 'highdelay', 'highloss' => 'degraded',
			default => 'unknown'
		};
	}
	return ['status' => $status, 'rtt_ms' => $rtt, 'rttsd_ms' => $variation, 'loss_pct' => $loss];
}

/* Configured member slots can be reused with different requirements per policy. */
function sdwan_policy_probe_requirements(array $policy, array $member, array $override = []): array {
	$requirements = [];
	$legacy = !isset($policy['primary_check']) && !isset($policy['secondary_check']);
	foreach (['probe_primary' => 'primary_check', 'probe_secondary' => 'secondary_check'] as $slot => $field) {
		$default = $legacy && isset($member[$slot]) ? 'optional' : 'ignored';
		$mode = $override[$field] ?? $policy[$field] ?? $default;
		if ($mode !== 'ignored') {
			$requirements[$slot] = $mode;
		}
	}
	return $requirements;
}

function sdwan_metric(mixed $value, float $maximum = PHP_FLOAT_MAX): ?float {
	if (!is_numeric($value)) {
		return null;
	}
	$number = (float)$value;
	return is_finite($number) && $number >= 0 && $number <= $maximum ? $number : null;
}

function sdwan_candidate_reason(?array $member, ?array $sample, ?array $sla, ?array $requirements = null): string {
	if ($member === null || $sample === null) {
		return 'Member is not configured';
	}
	$latency_limit = sdwan_metric($sla['latency_ms'] ?? null, 600000);
	$loss_limit = sdwan_metric($sla['loss_pct'] ?? null, 100);
	$uses_variation = $sla !== null && array_key_exists('rttsd_ms', $sla);
	$variation_limit = sdwan_metric($sla['rttsd_ms'] ?? null, 600000);
	if ($latency_limit === null || $latency_limit === 0.0 || $loss_limit === null ||
	    ($uses_variation && $variation_limit === null)) {
		return 'SLA is missing or invalid';
	}
	$status = $sample['status'] ?? null;
	if ($status === 'down') {
		return 'Gateway is down';
	}
	$latency = sdwan_metric($sample['rtt_ms'] ?? null);
	$loss = sdwan_metric($sample['loss_pct'] ?? null, 100);
	if (!in_array($status, ['online', 'degraded'], true) || $latency === null || $loss === null) {
		return 'No valid gateway measurement';
	}
	if ($loss === 100.0) {
		return 'Gateway is down';
	}
	if ($latency > $latency_limit) {
		return 'RTT exceeds the SLA';
	}
	$variation = sdwan_metric($sample['rttsd_ms'] ?? null);
	if ($variation_limit !== null && ($variation === null || $variation > $variation_limit)) {
		return 'RTT standard deviation exceeds the SLA or is unavailable';
	}
	if ($loss > $loss_limit) {
		return 'Loss exceeds the SLA';
	}
	return sdwan_service_reason($sample['checks'] ?? [], $requirements);
}

function sdwan_service_reason(array $checks, ?array $requirements): string {
	$required = array_keys($requirements ?? [], 'required', true);
	if ($requirements !== null) {
		$checks = array_intersect_key($checks, $required ? array_fill_keys($required, true) : $requirements);
	}
	$passed = count(array_keys($checks, 'Passed', true));
	$minimum = $required ? count($required) : (int)(bool)($requirements ?? $checks);
	if ($passed < $minimum) {
		$measured = ['Timed out', 'TCP check failed', 'DNS check failed', 'HTTPS check failed', 'HTTPS response marker mismatch'];
		if ($required) {
			return array_intersect($checks, $measured) ?
			    'Required service check failed' : 'No verified required service measurement';
		}
		return array_intersect($checks, $measured) ?
		    'No configured service check passed' : 'No verified service measurement';
	}
	return 'Eligible';
}

function sdwan_is_wan_quality_breach(string $reason, array $sample, array $sla): bool {
	return in_array($reason, SDWAN_QUALITY_BREACHES, true) &&
	    (!isset($sla['rttsd_ms']) || sdwan_metric($sample['rttsd_ms'] ?? null) !== null);
}

function sdwan_path_status(int $configured, int $eligible): string {
	return match (true) {
		$eligible === 0 => 'no_eligible',
		$configured === 1 => 'single',
		$eligible === 1 => 'degraded',
		default => 'alternatives',
	};
}

/* Pure evaluation. Equal ranks retain policy member order. */
function sdwan_evaluate(array $config, array $gateways, int $now, array $inventory = [], array $checks = []): array {
	$members = array_column($config['members'] ?? [], null, 'name');
	$slas = array_column($config['slas'] ?? [], null, 'name');
	$samples = [];
	foreach ($members as $name => $member) {
		$samples[$name] = sdwan_member_sample($gateways[$member['gateway']] ?? []);
		if (isset($member['probe_primary'])) {
			$fields = isset($member['probe_secondary']) ? ['probe_primary', 'probe_secondary'] : ['probe_primary'];
			foreach ($fields as $field) {
				$samples[$name]['checks'][$field] = $checks[$name][$field] ?? 'Unavailable';
			}
		}
	}
	$policies = [];
	foreach ($config['policies'] ?? [] as $policy) {
		$sla = $slas[$policy['sla']] ?? null;
		$selected = null;
		$best = INF;
		$candidates = [];
		$soft = [];
		$overrides = array_column($policy['probe_requirements'] ?? [], null, 'member');
		// Gateways can change family outside this package after a restore.
		$families = [];
		$interfaces = [];
		$transports = [];
		foreach ($policy['members'] as $name) {
			$gateway = $inventory[$members[$name]['gateway'] ?? ''] ?? [];
			$family = $gateway['family'] ?? null;
			if ($family !== null) {
				$families[$family] = true;
			}
			if (!empty($gateway['interface'])) {
				$interfaces[] = $gateway['interface'];
			}
			if (!empty($gateway['transport'])) {
				$transports[] = $gateway['transport'];
			}
		}
		$mixed = count($families) > 1;
		foreach ($policy['members'] as $name) {
			$member = $members[$name] ?? null;
			$sample = $samples[$name] ?? null;
			$requirements = sdwan_policy_probe_requirements($policy, $member ?? [], $overrides[$name] ?? []);
			$reason = $mixed ? 'Members now use different IP address families' :
			    sdwan_candidate_reason($member, $sample, $sla, $requirements);
			$candidates[$name] = $reason;
			if ($reason !== 'Eligible') {
				if ((int)($policy['degrade_samples'] ?? 1) > 1 && $sample && $sla &&
				    sdwan_is_wan_quality_breach($reason, $sample, $sla) &&
				    sdwan_service_reason($sample['checks'] ?? [], $requirements) === 'Eligible') {
					$soft[] = (string)$name;
				}
				continue;
			}
			switch ($policy['strategy']) {
				case 'cost':
					$rank = sdwan_metric($member['cost'] ?? null);
					if ($rank === null) {
						$candidates[$name] = 'Member cost is missing or invalid';
						continue 2;
					}
					break;
				case 'balance':
					$rank = 0;
					break;
				case 'latency':
					$rank = $sample['rtt_ms'];
					break;
				default:
					$candidates[$name] = 'Unknown strategy';
					continue 2;
			}
			if ($rank < $best) {
				$best = $rank;
				$selected = $name;
			}
		}
		$eligible = count(array_keys($candidates, 'Eligible', true));
		$policies[$policy['name']] = [
			'selected' => $selected,
			'reason' => $selected === null ? 'No eligible member' :
			    match ($policy['strategy']) {
				'cost' => 'Lowest configured cost within SLA',
				'balance' => 'Weighted connections across eligible gateways',
				default => 'Lowest measured RTT within SLA',
			},
			'candidates' => $candidates,
			'eligible_count' => $eligible,
			'path_status' => sdwan_path_status(count($candidates), $eligible),
			'shared_interface' => count($interfaces) !== count(array_unique($interfaces)),
			'shared_underlay' => count($transports) !== count(array_unique($transports)),
		];
		if ($soft) {
			$policies[$policy['name']]['soft'] = $soft;
		}
	}
	return ['generated_at' => $now, 'members' => $samples, 'policies' => $policies];
}

function sdwan_snapshot_steering_valid(mixed $steering, ?int $sample_time = null): bool {
	if (!is_array($steering)) {
		return false;
	}
	foreach ($steering as $state) {
		if (!is_array($state) || !is_string($state['revision'] ?? null) ||
		    !preg_match('/^[a-f0-9]{64}$/D', $state['revision']) || !array_key_exists('gateway', $state) ||
		    ($state['gateway'] !== null && (!is_string($state['gateway']) || $state['gateway'] === ''))) {
			return false;
		}
		if (array_key_exists('degraded', $state) || array_key_exists('degraded_at', $state)) {
			if (!is_array($state['degraded'] ?? null) || !$state['degraded'] ||
			    !is_int($state['degraded_at'] ?? null) || $state['degraded_at'] < 0 ||
			    ($sample_time !== null && $state['degraded_at'] !== $sample_time) ||
			    (array_key_exists('pool', $state) && !is_array($state['pool']))) {
				return false;
			}
			foreach ($state['degraded'] as $gateway => $count) {
				if (!in_array((string)$gateway, $state['pool'] ?? [$state['gateway']], true) ||
				    !is_int($count) || $count < 1 || $count > 5) {
					return false;
				}
			}
		}
		if (!array_key_exists('pool', $state)) {
			if (array_key_exists('recovering', $state)) {
				return false;
			}
			continue;
		}
		$pool = $state['pool'];
		if (!is_array($pool) || !array_is_list($pool) || ($pool[0] ?? null) !== $state['gateway']) {
			return false;
		}
		$seen = [];
		foreach ($pool as $gateway) {
			if (!is_string($gateway) || $gateway === '' || isset($seen[$gateway])) {
				return false;
			}
			$seen[$gateway] = true;
		}
		if (array_key_exists('recovering', $state)) {
			if (!$pool || !is_array($state['recovering']) || !$state['recovering']) {
				return false;
			}
			foreach ($state['recovering'] as $gateway => $since) {
				if ((string)$gateway === '' || isset($seen[$gateway]) || !is_int($since) || $since < 0 ||
				    ($sample_time !== null && $since > $sample_time)) {
					return false;
				}
			}
		}
	}
	return true;
}

function sdwan_snapshot_clock(array $snapshot): int {
	return isset($snapshot['observed_at_ns']) ? intdiv($snapshot['observed_at_ns'], 1_000_000_000) : $snapshot['generated_at'];
}

function sdwan_read_snapshot(?bool &$expired = null): ?array {
	$expired = false;
	$contents = @file_get_contents(SDWAN_SNAPSHOT_PATH);
	if ($contents === false) {
		return null;
	}
	$data = json_decode($contents, true);
	$when = $data['generated_at'] ?? null;
	if (!is_int($when) || $when < 0 ||
	    !is_array($data['members'] ?? null) || !is_array($data['policies'] ?? null) ||
	    !is_string($data['config_revision'] ?? null) ||
	    !preg_match('/^[a-f0-9]{64}$/D', $data['config_revision'])) {
		return null;
	}
	if (array_key_exists('observed_at_ns', $data)) {
		$observed = $data['observed_at_ns'];
		$now = hrtime(true);
		if (!is_int($observed) || $observed <= 0 || $observed > $now) {
			return null;
		}
		$age = ($now - $observed) / 1_000_000_000;
	} else {
		$age = time() - $when;
		if ($age < 0) {
			return null;
		}
	}
	if ($age > SDWAN_MAX_SNAPSHOT_AGE) {
		$expired = true;
		return null;
	}
	if (array_key_exists('steering', $data) && !sdwan_snapshot_steering_valid($data['steering'], sdwan_snapshot_clock($data))) {
		return null;
	}
	$gateways = $data['gateways'] ?? [];
	if ((array_key_exists('gateways', $data) && !is_array($data['gateways'])) ||
	    ((array_key_exists('gateways', $data) || array_key_exists('gateway_inventory_revision', $data)) &&
	    (!is_string($data['gateway_inventory_revision'] ?? null) ||
	    !preg_match('/^[a-f0-9]{64}$/D', $data['gateway_inventory_revision'])))) {
		return null;
	}
	foreach (array_merge(array_values($data['members']), array_values($gateways)) as $sample) {
		if (!is_array($sample) || !in_array($sample['status'] ?? null,
		    ['online', 'degraded', 'down', 'unknown'], true)) {
			return null;
		}
		foreach (['rtt_ms', 'rttsd_ms', 'loss_pct'] as $metric) {
			if (!array_key_exists($metric, $sample)) {
				return null;
			}
			$value = $sample[$metric];
			if ($value === null && in_array($sample['status'], ['unknown', 'down'], true)) {
				continue;
			}
			if ((!is_int($value) && !is_float($value)) || !is_finite($value) ||
			    $value < 0 || ($metric === 'loss_pct' && $value > 100)) {
				return null;
			}
		}
		// Older observations can omit service data or use an unavailable value.
		$checks = $sample['checks'] ?? null;
		foreach (is_array($checks) ? $checks : [] as $check) {
			if ($check !== null && !is_string($check)) {
				return null;
			}
		}
	}
	foreach ($data['policies'] as $policy) {
		if (!is_array($policy) || !array_key_exists('selected', $policy) ||
		    !is_string($policy['reason'] ?? null) || !is_array($policy['candidates'] ?? null)) {
			return null;
		}
		foreach ($policy['candidates'] as $member => $reason) {
			if (!isset($data['members'][$member]) || !is_string($reason)) {
				return null;
			}
		}
		if (array_key_exists('soft', $policy)) {
			if (!is_array($policy['soft']) || !array_is_list($policy['soft'])) {
				return null;
			}
			$seen = [];
			foreach ($policy['soft'] as $member) {
				if (!is_string($member) || isset($seen[$member]) ||
				    !in_array($policy['candidates'][$member] ?? null, SDWAN_QUALITY_BREACHES, true)) {
					return null;
				}
				$seen[$member] = true;
			}
		}
		/* Old snapshots remain readable for their normal 30-second lifetime. */
		if (array_key_exists('path_status', $policy) || array_key_exists('eligible_count', $policy) ||
		    array_key_exists('shared_interface', $policy) || array_key_exists('shared_underlay', $policy)) {
			$count = count(array_keys($policy['candidates'], 'Eligible', true));
			if (($policy['eligible_count'] ?? null) !== $count ||
			    ($policy['path_status'] ?? null) !== sdwan_path_status(count($policy['candidates']), $count) ||
			    !is_bool($policy['shared_interface'] ?? null) || !is_bool($policy['shared_underlay'] ?? null)) {
				return null;
			}
		}
		$selected = $policy['selected'];
		if ($selected !== null && (!is_string($selected) ||
		    ($policy['candidates'][$selected] ?? null) !== 'Eligible' ||
		    !in_array($data['members'][$selected]['status'], ['online', 'degraded'], true))) {
			return null;
		}
	}
	return $data;
}

/* The configuration may have changed in System > Routing since the last poll. */
function sdwan_current_snapshot(array $config, array $inventory, ?bool &$expired = null, ?bool &$identity_changed = null): ?array {
	$snapshot = sdwan_read_snapshot($expired);
	$identity_changed = $snapshot !== null && ($snapshot['config_revision'] !== sdwan_config_revision($config) ||
	    ($snapshot['gateway_inventory_revision'] ?? null) !== sdwan_gateway_inventory_revision($config, $inventory));
	return $identity_changed ? null : $snapshot;
}
