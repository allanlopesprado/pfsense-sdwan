<?php

const SDWAN_SNAPSHOT_PATH = '/var/run/sdwan-observer.json';
const SDWAN_MAX_SNAPSHOT_AGE = 30;

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
	    in_array($substatus, ['down', 'force_down', 'highdelay', 'highloss'], true)) {
		$status = 'down';
	} elseif (($gateway['status'] ?? '') === 'online' && $rtt !== null && $variation !== null && $loss !== null) {
		$status = match ($substatus) {
			'none' => 'online',
			'delay', 'loss' => 'degraded',
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
	if ($sample['loss_pct'] > (float)$sla['loss_pct']) {
		return 'Loss exceeds the SLA';
	}
	return 'Eligible';
}

/* Pure evaluation. Equal ranks retain policy member order. */
function sdwan_evaluate(array $config, array $gateways, int $now): array {
	$members = array_column($config['members'] ?? [], null, 'name');
	$slas = array_column($config['slas'] ?? [], null, 'name');
	$samples = [];
	foreach ($members as $name => $member) {
		$samples[$name] = sdwan_member_sample($gateways[$member['gateway']] ?? []);
	}
	$policies = [];
	foreach ($config['policies'] ?? [] as $policy) {
		$sla = $slas[$policy['sla']] ?? null;
		$selected = null;
		$best = INF;
		$candidates = [];
		foreach ($policy['members'] as $name) {
			$member = $members[$name] ?? null;
			$sample = $samples[$name] ?? null;
			$reason = sdwan_candidate_reason($member, $sample, $sla);
			$candidates[$name] = $reason;
			if ($reason !== 'Eligible') {
				continue;
			}
			switch ($policy['strategy']) {
				case 'cost':
					$rank = is_numeric($member['cost'] ?? null) ? (float)$member['cost'] : INF;
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
		$policies[$policy['name']] = [
			'selected' => $selected,
			'reason' => $selected === null ? 'No eligible member' :
			    ($policy['strategy'] === 'cost' ? 'Lowest configured cost within SLA' : 'Lowest measured RTT within SLA'),
			'candidates' => $candidates
		];
	}
	return ['generated_at' => $now, 'members' => $samples, 'policies' => $policies];
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
	    !is_string($data['config_revision'] ?? null)) {
		return null;
	}
	return $data;
}
