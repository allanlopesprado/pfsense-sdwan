<?php
/* The ABI 1 core adapter applies a choice only to explicitly bound rule trackers. */
require_once(__DIR__ . '/sdwan.inc');
require_once(__DIR__ . '/sdwan_engine.inc');
require_once(__DIR__ . '/sdwan_preflight.inc');

const SDWAN_BINDINGS_PATH = 'gateways/sdwan_bindings';
const SDWAN_STEERING_HOLD = 30;

function sdwan_steering_supported(): bool {
	if (!function_exists('filter_sdwan_binding_api') && stream_resolve_include_path('filter.inc')) {
		require_once('filter.inc');
	}
	return function_exists('filter_sdwan_binding_api') && filter_sdwan_binding_api() === 1;
}

function sdwan_steering_native(): array {
	$paths = [
		'groups' => 'gateways/gateway_group', 'rules' => 'filter/rule',
		'phase1' => 'ipsec/phase1', 'phase2' => 'ipsec/phase2', 'vips' => 'virtualip/vip',
		'openvpn_servers' => 'openvpn/openvpn-server', 'openvpn_clients' => 'openvpn/openvpn-client',
		'dyndns' => 'dyndnses/dyndns', 'dnsupdates' => 'dnsupdates/dnsupdate', 'interfaces' => 'interfaces',
	];
	$native = [];
	foreach ($paths as $key => $path) {
		$native[$key] = config_get_path($path, []);
	}
	$native['gateways'] = sdwan_gateways();
	$native['default4'] = config_get_path('gateways/defaultgw4', '');
	$native['default6'] = config_get_path('gateways/defaultgw6', '');
	$native['filtermode'] = config_get_path('ipsec/filtermode', '');
	return $native;
}

function sdwan_steering_rows(): array {
	/* Empty config.xml sections may deserialize as an empty string. */
	$rows = config_get_path(SDWAN_BINDINGS_PATH, []);
	if ($rows === '' || $rows === [] || $rows === null) {
		return [];
	}
	if (!is_array($rows['item'] ?? null) || !array_is_list($rows['item'])) {
		throw new UnexpectedValueException('Unsupported forwarding binding format.');
	}
	return $rows['item'];
}

function sdwan_steering_decode(array $row): ?array {
	$group = $row['group'] ?? null;
	$policy = $row['policy'] ?? null;
	$gateways = $row['gateways']['item'] ?? null;
	$trackers = $row['trackers']['item'] ?? null;
	$revision = $row['policy_revision'] ?? null;
	$rules = $row['rules_revision'] ?? null;
	if (!is_string($group) || $group === '' || !sdwan_valid_name($policy) ||
	    !is_string($revision) || !preg_match('/^[a-f0-9]{64}$/D', $revision) ||
	    !is_string($rules) || !preg_match('/^[a-f0-9]{64}$/D', $rules) ||
	    !is_array($gateways) || !array_is_list($gateways) || count($gateways) < 2 ||
	    !is_array($trackers) || !array_is_list($trackers) || !$trackers) {
		return null;
	}
	foreach ($gateways as $gateway) {
		if (!is_string($gateway) || $gateway === '') {
			return null;
		}
	}
	foreach ($trackers as $tracker) {
		if (!is_string($tracker) || !preg_match('/^[1-9][0-9]{0,9}$/D', $tracker)) {
			return null;
		}
	}
	if (count($gateways) !== count(array_unique($gateways)) || count($trackers) !== count(array_unique($trackers))) {
		return null;
	}
	return ['group' => $group, 'policy' => $policy, 'gateways' => $gateways,
	    'trackers' => $trackers, 'rules_revision' => $rules, 'policy_revision' => $revision];
}

function sdwan_steering_bindings(): array {
	$bindings = [];
	foreach (sdwan_steering_rows() as $row) {
		$binding = is_array($row) ? sdwan_steering_decode($row) : null;
		if ($binding === null || isset($bindings[$binding['group']])) {
			throw new UnexpectedValueException('Invalid or duplicated forwarding binding.');
		}
		$bindings[$binding['group']] = $binding;
	}
	return $bindings;
}

/* Freeze only the referenced policy, its SLA and its member definitions. */
function sdwan_steering_policy_revision(array $config, string $name): ?string {
	$policy = array_column($config['policies'], null, 'name')[$name] ?? null;
	if ($policy === null) {
		return null;
	}
	$sla = array_column($config['slas'], null, 'name')[$policy['sla']] ?? null;
	$members = array_column($config['members'], null, 'name');
	$inputs = [$policy, $sla];
	foreach ($policy['members'] as $member) {
		$inputs[] = $members[$member] ?? null;
	}
	return sdwan_config_revision($inputs);
}

function sdwan_steering_revision(): string {
	return sdwan_config_revision([sdwan_get_config(), sdwan_steering_rows(), sdwan_steering_native()]);
}

function sdwan_steering_preview(array $config, string $policy, string $group): array {
	$native = sdwan_steering_native();
	$preview = sdwan_steering_preflight($config, $policy, $group, $native);
	$preview['revision'] = sdwan_config_revision([$config, sdwan_steering_rows(), $native]);
	if ($preview['binding'] !== null) {
		$preview['binding']['policy_revision'] = sdwan_steering_policy_revision($config, $policy);
	}
	return $preview;
}

function sdwan_steering_bind(string $policy, string $group, string $expected_revision): array {
	return sdwan_steering_edit($group, $policy, $expected_revision);
}

function sdwan_steering_unbind(string $group, string $expected_revision): array {
	return sdwan_steering_edit($group, null, $expected_revision);
}

function sdwan_steering_edit(string $group, ?string $policy, string $expected_revision): array {
	if ($policy !== null && !sdwan_steering_supported()) {
		return ['Forwarding requires the native pfSense steering ABI 1.'];
	}
	$lock = try_lock('sdwan-settings', 5);
	if (!is_resource($lock)) {
		return ['SD-WAN settings are busy. Reload the page and try again.'];
	}
	try {
		if (!config_read_file(false, false)) {
			return ['The current pfSense configuration could not be read.'];
		}
		if (!hash_equals(sdwan_steering_revision(), $expected_revision)) {
			return ['Settings changed. Review the current preview before applying.'];
		}
		$rows = sdwan_steering_rows();
		if ($policy === null) {
			$updated = array_values(array_filter($rows, static fn($row) => ($row['group'] ?? null) !== $group));
			if ($updated === $rows) {
				return ['This group has no saved binding.'];
			}
		} else {
			$preview = sdwan_steering_preview(sdwan_get_config(), $policy, $group);
			if ($preview['errors']) {
				return $preview['errors'];
			}
			$row = $preview['binding'];
			foreach (sdwan_steering_bindings() as $saved) {
				if ($saved['group'] === $group || array_intersect($row['trackers'], $saved['trackers'])) {
					return ['Roll back the existing binding before binding these rules.'];
				}
			}
			foreach (['trackers', 'gateways'] as $list) {
				$row[$list] = ['item' => $row[$list]];
			}
			$updated = [...$rows, $row];
		}
		if (!is_array(config_set_path(SDWAN_BINDINGS_PATH, ['item' => $updated])) ||
		    !is_array(write_config($policy === null ? 'Returned SD-WAN rules to native gateway selection' : 'Bound SD-WAN forwarding policy to native firewall rules'))) {
			config_read_file(false, false);
			return ['pfSense could not save the forwarding binding.'];
		}
	} finally {
		unlock($lock);
	}
	if (sdwan_steering_supported()) {
		filter_configure();
	}
	return [];
}

/* Quarantine loss immediately. Keep a healthy incumbent while a better path settles. */
function sdwan_steering_step(array $previous, array $eligible, ?string $best, int $now): array {
	$incumbent = $previous['gateway'] ?? null;
	$candidate = null;
	$since = null;
	if (!in_array($best, $eligible, true) || $best === null) {
		$chosen = null;
	} elseif ($incumbent === $best || !in_array($incumbent, $eligible, true)) {
		$chosen = $best;
	} else {
		$candidate = $best;
		$since = ($previous['candidate'] ?? null) === $best &&
		    is_int($previous['since'] ?? null) && $previous['since'] <= $now ? $previous['since'] : $now;
		$chosen = $incumbent;
		if ($now - $since >= SDWAN_STEERING_HOLD) {
			$chosen = $best;
			$candidate = $since = null;
		}
	}
	return ['gateway' => $chosen, 'candidate' => $candidate, 'since' => $since];
}

function sdwan_steering_state(array $config, array $binding, array $result, array $old, int $now): array {
	$eligible = [];
	$best = null;
	$revision = sdwan_config_revision($binding);
	if ($binding['policy_revision'] === sdwan_steering_policy_revision($config, $binding['policy'])) {
		$members = array_column($config['members'], 'gateway', 'name');
		foreach ($result['candidates'] ?? [] as $name => $reason) {
			$gateway = $members[$name] ?? null;
			if ($reason === 'Eligible' && in_array($gateway, $binding['gateways'], true)) {
				$eligible[] = $gateway;
				if ((string)$name === ($result['selected'] ?? null)) {
					$best = $gateway;
				}
			}
		}
	}
	$step = sdwan_steering_step(($old['revision'] ?? null) === $revision ? $old : [], $eligible, $best, $now);
	return ['revision' => $revision] + $step;
}

/* Run in the observer process. Recheck native membership/ACL drift on each
 * sample so a subsequent reload can close a binding that is no longer valid. */
function sdwan_steering_observations(array $config, array $snapshot, array $previous): array {
	$states = [];
	$native = sdwan_steering_native();
	foreach (sdwan_steering_bindings() as $group => $binding) {
		$check = sdwan_steering_preflight($config, $binding['policy'], $group, $native);
		$approved = !$check['errors'] && $binding['rules_revision'] === $check['binding']['rules_revision'] &&
		    $binding['gateways'] === $check['binding']['gateways'] && $binding['trackers'] === $check['binding']['trackers'];
		$result = $approved ? ($snapshot['policies'][$binding['policy']] ?? []) : [];
		$states[$group] = sdwan_steering_state($config, $binding, $result, $previous[$group] ?? [], $snapshot['generated_at']);
	}
	return $states;
}

/* Exclude ongoing preference timers from the native filter reload signature. */
function sdwan_steering_signature(array $states): string {
	$effective = [];
	foreach ($states as $group => $state) {
		$effective[$group] = [$state['revision'], $state['gateway']];
	}
	ksort($effective, SORT_STRING);
	return sdwan_config_revision($effective);
}

function sdwan_steering_gateway_for_rule(array $raw, array $rule): ?string {
	$binding = sdwan_steering_decode($raw);
	if ($binding === null || $binding['group'] !== ($rule['gateway'] ?? null) ||
	    !in_array((string)($rule['tracker'] ?? ''), $binding['trackers'], true)) {
		return null;
	}
	$config = sdwan_get_config();
	$snapshot = sdwan_read_snapshot();
	if (($snapshot['config_revision'] ?? null) !== sdwan_config_revision($config) ||
	    $binding['policy_revision'] !== sdwan_steering_policy_revision($config, $binding['policy'])) {
		return null;
	}
	$preflight = sdwan_steering_preflight($config, $binding['policy'], $binding['group'], sdwan_steering_native());
	if ($preflight['errors'] || $preflight['binding']['rules_revision'] !== $binding['rules_revision'] ||
	    $preflight['binding']['gateways'] !== $binding['gateways'] ||
	    $preflight['binding']['trackers'] !== $binding['trackers']) {
		return null;
	}
	$state = $snapshot['steering'][$binding['group']] ?? [];
	$gateway = $state['gateway'] ?? null;
	if (($state['revision'] ?? null) !== sdwan_config_revision($binding) || !in_array($gateway, $binding['gateways'], true)) {
		return null;
	}
	/* A snapshot with a choice must also contain its matching eligible measurement. */
	$members = array_column($config['members'], 'name', 'gateway');
	$reasons = $snapshot['policies'][$binding['policy']]['candidates'] ?? [];
	return ($reasons[$members[$gateway] ?? ''] ?? null) === 'Eligible' ? $gateway : null;
}
