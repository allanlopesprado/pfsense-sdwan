<?php

const SDWAN_SNAPSHOT_PATH = '/var/run/sdwan-observer.json';
const SDWAN_MAX_SNAPSHOT_AGE = 30;

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
	if ($family === 'inet') {
		$source = find_interface_ip($device, true);
	} elseif (str_contains($target, '%')) {
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

function sdwan_candidate_reason(?array $member, ?array $sample, ?array $sla): string {
	if ($member === null || $sample === null) {
		return 'Member is not configured';
	}
	if ($sla === null || !is_numeric($sla['latency_ms'] ?? null) || !is_numeric($sla['loss_pct'] ?? null)) {
		return 'SLA is missing or invalid';
	}
	if ($sample['status'] === 'down') {
		return 'Gateway is down';
	}
	if ($sample['status'] === 'unknown') {
		return 'No valid gateway measurement';
	}
	if ($sample['rtt_ms'] > (float)$sla['latency_ms']) {
		return 'RTT exceeds the SLA';
	}
	if (isset($sla['rttsd_ms']) && (!is_numeric($sample['rttsd_ms'] ?? null) ||
	    $sample['rttsd_ms'] > (float)$sla['rttsd_ms'])) {
		return 'RTT standard deviation exceeds the SLA or is unavailable';
	}
	if ($sample['loss_pct'] > (float)$sla['loss_pct']) {
		return 'Loss exceeds the SLA';
	}
	return 'Eligible';
}

/* Configured member slots can be reused with different requirements per policy. */
function sdwan_policy_probe_requirements(array $policy, array $member): array {
	$requirements = [];
	$legacy = !isset($policy['primary_check']) && !isset($policy['secondary_check']);
	foreach (['probe_primary' => 'primary_check', 'probe_secondary' => 'secondary_check'] as $slot => $field) {
		$mode = $legacy && isset($member[$slot]) ? 'optional' : ($policy[$field] ?? 'ignored');
		if ($mode !== 'ignored') {
			$requirements[$slot] = $mode;
		}
	}
	return $requirements;
}

function sdwan_policy_service_status(array $policy, array $member, array $checks): string {
	$requirements = sdwan_policy_probe_requirements($policy, $member);
	if (!$requirements) {
		return 'Not selected';
	}
	$mandatory = array_keys($requirements, 'required', true);
	$passed = array_keys($checks, 'Passed', true);
	if ($mandatory ? !array_diff($mandatory, $passed) : array_intersect(array_keys($requirements), $passed)) {
		return 'Passed';
	}
	$relevant = array_intersect_key($checks, array_fill_keys($mandatory ?: array_keys($requirements), true));
	if (array_filter($relevant, static fn($value) => in_array($value,
	    ['TCP check failed', 'DNS check failed', 'HTTPS check failed', 'Timed out'], true))) {
		return 'Failed';
	}
	if (count($relevant) === count($mandatory ?: $requirements) &&
	    count(array_keys($relevant, 'Not run', true)) === count($relevant)) {
		return 'Not run';
	}
	return 'No measurement';
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
		$candidates = $services = $soft = [];
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
			$reason = $mixed ? 'Members now use different IP address families' :
			    sdwan_candidate_reason($member, $sample, $sla);
			$service = sdwan_policy_service_status($policy, $member ?? [], $sample['checks'] ?? []);
			$services[$name] = $service;
			$service_ok = in_array($service, ['Passed', 'Not selected'], true);
			if ($service_ok && in_array($reason, ['RTT exceeds the SLA',
			    'RTT standard deviation exceeds the SLA or is unavailable', 'Loss exceeds the SLA'], true) &&
			    (!isset($sla['rttsd_ms']) || $sample['rttsd_ms'] !== null)) {
				$soft[] = $name;
			}
			if ($reason === 'Eligible' && !$service_ok) {
				$reason = match ($service) {
					'Failed' => in_array('required', sdwan_policy_probe_requirements($policy, $member ?? []), true)
					    ? 'Required service check failed' : 'No configured service check passed',
					'Not run' => 'Service checks were not run',
					default => 'No service measurement',
				};
			}
			$candidates[$name] = $reason;
			if ($reason !== 'Eligible') {
				continue;
			}
			switch ($policy['strategy']) {
				case 'cost':
					$rank = is_numeric($member['cost'] ?? null) ? (float)$member['cost'] : INF;
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
			'services' => $services,
			'soft' => $soft,
			'eligible_count' => $eligible,
			'path_status' => sdwan_path_status(count($candidates), $eligible),
			'shared_interface' => count($interfaces) !== count(array_unique($interfaces)),
			'shared_underlay' => count($transports) !== count(array_unique($transports)),
		];
	}
	return ['generated_at' => $now, 'members' => $samples, 'policies' => $policies];
}

function sdwan_snapshot_expired(): bool {
	$data = json_decode((string)@file_get_contents(SDWAN_SNAPSHOT_PATH), true);
	return is_int($data['generated_at'] ?? null) && time() - $data['generated_at'] > SDWAN_MAX_SNAPSHOT_AGE;
}

function sdwan_read_snapshot(): ?array {
	$contents = @file_get_contents(SDWAN_SNAPSHOT_PATH);
	if ($contents === false) {
		return null;
	}
	$data = json_decode($contents, true);
	$when = $data['generated_at'] ?? null;
	$now = time();
	if (!is_int($when) || $when > $now || $now - $when > SDWAN_MAX_SNAPSHOT_AGE ||
	    !is_array($data['members'] ?? null) || !is_array($data['policies'] ?? null) ||
	    !is_string($data['config_revision'] ?? null) ||
	    !preg_match('/^[a-f0-9]{64}$/D', $data['config_revision'])) {
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
			foreach ($policy['soft'] as $member) {
				if (!is_string($member) || !in_array($policy['candidates'][$member] ?? null, [
				    'RTT exceeds the SLA', 'RTT standard deviation exceeds the SLA or is unavailable',
				    'Loss exceeds the SLA'], true) || !in_array($data['members'][$member]['status'] ?? null,
				    ['online', 'degraded'], true)) {
					return null;
				}
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
function sdwan_current_snapshot(array $config, array $inventory): ?array {
	$snapshot = sdwan_read_snapshot();
	if (($snapshot['config_revision'] ?? null) !== sdwan_config_revision($config) ||
	    ($snapshot['gateway_inventory_revision'] ?? null) !== sdwan_gateway_inventory_revision($config, $inventory)) {
		return null;
	}
	return $snapshot;
}
