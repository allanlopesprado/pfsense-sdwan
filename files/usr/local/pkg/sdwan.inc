<?php
/* Configuration for the SD-WAN observer. Persistent settings only. */

const SDWAN_CONFIG_PATH = 'installedpackages/sdwan';
const SDWAN_CONFIG_VERSION = '1';

/* pfSense registers services by name and saves the list after this install hook. */
function sdwan_remove_legacy_service(): void {
	$path = 'installedpackages/service';
	$services = config_get_path($path, []);
	if (!is_array($services)) {
		return;
	}
	$current = array_filter($services, static fn($service) =>
	    !(($service['name'] ?? null) === 'sdwand' && ($service['rcfile'] ?? null) === 'sdwand.sh'));
	if ($current !== $services) {
		config_set_path($path, array_values($current));
	}
}

function sdwan_empty_config(): array {
	return ['version' => SDWAN_CONFIG_VERSION, 'members' => [], 'slas' => [], 'policies' => []];
}

/* Native XML uses its reserved 'item' tag to preserve single-element lists. */
function sdwan_encode_config(array $config): array {
	$stored = ['version' => $config['version']];
	foreach (['members', 'slas', 'policies'] as $section) {
		foreach ($config[$section] as $row) {
			if ($section === 'policies') {
				$row['members'] = ['item' => $row['members']];
			}
			$stored[$section]['item'][] = $row;
		}
	}
	return $stored;
}

function sdwan_decode_config($stored): array {
	$config = sdwan_empty_config();
	if ($stored === null) {
		return $config;
	}
	if (!is_array($stored) || ($stored['version'] ?? null) !== SDWAN_CONFIG_VERSION ||
	    array_diff_key($stored, $config)) {
		throw new UnexpectedValueException('Unsupported SD-WAN configuration format.');
	}
	foreach (['members', 'slas', 'policies'] as $section) {
		if (!isset($stored[$section])) {
			continue;
		}
		$rows = $stored[$section]['item'] ?? null;
		if (!is_array($rows) || !array_is_list($rows)) {
			throw new UnexpectedValueException('Invalid SD-WAN configuration list.');
		}
		foreach ($rows as $row) {
			if (!is_array($row)) {
				throw new UnexpectedValueException('Invalid SD-WAN configuration row.');
			}
			if ($section === 'policies') {
				$row['members'] = $row['members']['item'] ?? null;
			}
			$config[$section][] = $row;
		}
	}
	/* Missing gateways after a restore must not make the settings uneditable. */
	$errors = sdwan_validate_config($config, null);
	if ($errors) {
		throw new UnexpectedValueException(implode(' ', $errors));
	}
	return $config;
}

function sdwan_config_revision(array $config): string {
	return hash('sha256', json_encode($config, JSON_THROW_ON_ERROR));
}

function sdwan_get_config(): array {
	require_once('config.inc');
	return sdwan_decode_config(config_get_path(SDWAN_CONFIG_PATH));
}

/* A binding exposes native rule and gateway-group information. Apply the same
 * WebGUI permission check on the page, its tab, and Dashboard refreshes. */
function sdwan_can_view_forwarding(): bool {
	return isAllowedPage('/sdwan/forwarding.php') && isAllowedPage('/firewall_rules.php') &&
	    isAllowedPage('/system_gateway_groups.php');
}

/* Only report a VTI transport when its Phase 1 names an assigned interface.
 * A gateway group, VIP or unrecognized tunnel has no known single transport. */
function sdwan_vti_transports(array $interfaces, array $phases1, array $phases2): array {
	$parents = [];
	foreach ($phases1 as $phase) {
		$interface = $phase['interface'] ?? 'wan';
		if (isset($phase['ikeid'], $interfaces[$interface]['enable']) &&
		    !isset($phase['disabled']) && !isset($phase['mobile'])) {
			$parents[$phase['ikeid']] = [
				'interface' => $interface,
				'split' => ($phase['iketype'] ?? '') === 'ikev1' || isset($phase['splitconn']),
			];
		}
	}
	$transports = [];
	$first = [];
	foreach ($phases2 as $phase) {
		$ikeid = $phase['ikeid'] ?? '';
		$parent = $parents[$ikeid] ?? null;
		$id = $phase['reqid'] ?? '';
		if ($parent === null || !preg_match('/^[1-9][0-9]*$/D', (string)$id)) {
			continue;
		}
		/* A merged IKEv2 tunnel uses the first Phase 2 reqid for its device. */
		$first[$ikeid] ??= $id;
		if (($phase['mode'] ?? '') === 'vti' && !isset($phase['disabled'])) {
			$device = 'ipsec' . ($parent['split'] ? $id : $first[$ikeid]);
			$transports[$device] = $parent['interface'];
		}
	}
	return $transports;
}

/* Never call get_gateways() here: a cache miss can persist new gateway entries. */
function sdwan_gateways(): array {
	require_once('config.inc');
	$interfaces = config_get_path('interfaces', []);
	$transports = sdwan_vti_transports($interfaces, config_get_path('ipsec/phase1', []),
	    config_get_path('ipsec/phase2', []));
	$inventory = [];
	foreach (config_get_path('gateways/gateway_item', []) as $gateway) {
		$name = $gateway['name'] ?? '';
		$interface = $gateway['interface'] ?? '';
		if (!is_string($name) || $name === '' || !is_string($interface) ||
		    isset($gateway['disabled']) || !isset($interfaces[$interface]['enable'])) {
			continue;
		}
		$address = !empty($gateway['gateway']) ? $gateway['gateway'] : 'dynamic';
		$device = $interfaces[$interface]['if'] ?? '';
		$ip = explode('%', $address, 2)[0];
		$family = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? 'inet6' :
		    (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ? 'inet' : ($gateway['ipprotocol'] ?? 'inet'));
		$inventory[$name] = [
			'interface' => $interface,
			'transport' => str_starts_with($device, 'ipsec') ? ($transports[$device] ?? '') : $interface,
			'address' => $address,
			'monitor' => !empty($gateway['monitor']) ? $gateway['monitor'] : $address,
			'family' => $family,
			'monitor_disabled' => isset($gateway['monitor_disable']),
			'action_disabled' => isset($gateway['action_disable']),
			'force_down' => isset($gateway['force_down']),
		];
	}
	ksort($inventory, SORT_STRING);
	return $inventory;
}

function sdwan_valid_name($value): bool {
	return is_string($value) && preg_match('/\A[A-Za-z0-9][A-Za-z0-9_-]{0,31}\z/', $value) === 1;
}

function sdwan_valid_decimal($value, int $maximum, bool $allow_zero): bool {
	if ((!is_string($value) && !is_int($value)) ||
	    !preg_match('/\A[0-9]{1,6}(?:\.[0-9]{1,6})?\z/', (string)$value)) {
		return false;
	}
	return ($allow_zero || (float)$value > 0) && (float)$value <= $maximum;
}

/* A null inventory checks stored structure without requiring restored interfaces. */
function sdwan_validate_config(array $config, ?array $gateways, array $previous = []): array {
	$fields = [
		'members' => ['name', 'gateway', 'cost'],
		'slas' => ['name', 'latency_ms', 'loss_pct'],
		'policies' => ['name', 'sla', 'members', 'strategy'],
	];
	if (($config['version'] ?? null) !== SDWAN_CONFIG_VERSION ||
	    array_diff_key($config, sdwan_empty_config())) {
		return ['Unsupported SD-WAN configuration format.'];
	}

	$names = [];
	$used_gateways = [];
	$member_families = [];
	$changed_gateways = [];
	$unavailable = [];
	$old_gateways = array_column($previous['members'] ?? [], 'gateway', 'name');
	$old_policies = array_column($previous['policies'] ?? [], null, 'name');
	foreach ($fields as $section => $required) {
		$rows = $config[$section] ?? null;
		if (!is_array($rows) || !array_is_list($rows)) {
			return ["Invalid list in {$section}."];
		}
		foreach ($rows as $row) {
			if (!is_array($row) || count($row) !== count($required) ||
			    array_diff($required, array_keys($row)) || !sdwan_valid_name($row['name'])) {
				return ["Invalid fields or name in {$section}."];
			}
			$name = $row['name'];
			if (isset($names[$section][$name])) {
				return ["Duplicate name in {$section}: {$name}."];
			}
			$names[$section][$name] = true;

			if ($section === 'members') {
				$gateway = $row['gateway'];
				if (!is_string($gateway) || $gateway === '') {
					return ["Select an available configured gateway for {$name}."];
				}
				if ($gateways !== null && (!isset($gateways[$gateway]) || !empty($gateways[$gateway]['monitor_disabled']))) {
					if (($old_gateways[$name] ?? null) !== $gateway) {
						return ["Select an available gateway with monitoring enabled for {$name}."];
					}
					/* Existing members survive a restore or a native monitor change. */
					$unavailable[$name] = true;
				}
				if (isset($used_gateways[$gateway])) {
					return ["Gateway already assigned to another member: {$name}."];
				}
				$used_gateways[$gateway] = true;
				$changed_gateways[$name] = ($old_gateways[$name] ?? null) !== $gateway;
				$member_families[$name] = $gateways[$gateway]['family'] ?? '';
				$cost = $row['cost'];
				if ((!is_string($cost) && !is_int($cost)) ||
				    !preg_match('/\A[0-9]{1,5}\z/', (string)$cost) || (int)$cost > 65535) {
					return ["Cost for {$name} must be an integer from 0 to 65535."];
				}
			} elseif ($section === 'slas') {
				if (!sdwan_valid_decimal($row['latency_ms'], 600000, false) ||
				    !sdwan_valid_decimal($row['loss_pct'], 100, true)) {
					return ["Invalid latency or loss threshold for {$name}."];
				}
			} else {
				if (!sdwan_valid_name($row['sla']) || !isset($names['slas'][$row['sla']]) ||
				    !in_array($row['strategy'], ['cost', 'latency'], true)) {
					return ["Invalid SLA or strategy for {$name}."];
				}
				if (!is_array($row['members']) || !array_is_list($row['members']) || !$row['members']) {
					return ["Select at least one member for {$name}."];
				}
				$selected = [];
				$families = [];
				$old_members = $old_policies[$name]['members'] ?? [];
				$unchanged_paths = $old_members === $row['members'];
				foreach ($row['members'] as $member) {
					if (!sdwan_valid_name($member) || !isset($names['members'][$member]) ||
					    isset($selected[$member])) {
						return ["Invalid or repeated member in policy {$name}."];
					}
					$selected[$member] = true;
					if (isset($unavailable[$member]) && !in_array($member, $old_members, true)) {
						return ["Select members with available monitored gateways for {$name}."];
					}
					if ($changed_gateways[$member]) {
						$unchanged_paths = false;
					}
					if ($member_families[$member] !== '') {
						$families[$member_families[$member]] = true;
					}
				}
				/* Allow unrelated edits while repairing native family drift after a restore. */
				if (count($families) > 1 && !$unchanged_paths) {
					return ["Members in policy {$name} must use the same address family."];
				}
			}
		}
	}
	return [];
}

function sdwan_save_config(array $candidate, string $expected_revision): array {
	require_once('config.inc');
	/* Serialize competing WebGUI package edits; write_config() owns the XML lock. */
	$lock = try_lock('sdwan-settings', 5);
	if (!is_resource($lock)) {
		return ['SD-WAN settings are busy. Reload the page and try again.'];
	}
	try {
		if (!config_read_file(false, false)) {
			return ['The current pfSense configuration could not be read.'];
		}
		$current = sdwan_get_config();
		if (!hash_equals(sdwan_config_revision($current), $expected_revision)) {
			return ['Settings have changed. Reload the page before saving.'];
		}
		$errors = sdwan_validate_config($candidate, sdwan_gateways(), $current);
		if ($errors) {
			return $errors;
		}
		if ($current === $candidate) {
			return [];
		}
		if (config_get_path('gateways/sdwan_bindings/item', [])) {
			require_once(__DIR__ . '/sdwan_steering.inc');
			foreach (sdwan_steering_bindings() as $binding) {
				$policy = $binding['policy'];
				if (sdwan_steering_policy_revision($candidate, $policy) !== sdwan_steering_policy_revision($current, $policy)) {
					return ['Roll back the active forwarding binding before changing its policy, SLA, or member definitions.'];
				}
			}
		}
		if (!is_array(config_set_path(SDWAN_CONFIG_PATH, sdwan_encode_config($candidate)))) {
			return ['Cannot update the SD-WAN section in the pfSense configuration.'];
		}
		if (!is_array(write_config('Updated SD-WAN observer settings'))) {
			config_read_file(false, false);
			return ['pfSense could not save the SD-WAN configuration.'];
		}
		return [];
	} finally {
		unlock($lock);
	}
}
