<?php
/* Configuration for the SD-WAN observer. Persistent settings only. */

const SDWAN_CONFIG_PATH = 'installedpackages/sdwan';
const SDWAN_CONFIG_VERSION = '1';

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

/* Never call get_gateways() here: a cache miss can persist new gateway entries. */
function sdwan_gateways(): array {
	require_once('config.inc');
	$interfaces = config_get_path('interfaces', []);
	$inventory = [];
	foreach (config_get_path('gateways/gateway_item', []) as $gateway) {
		$name = $gateway['name'] ?? '';
		$interface = $gateway['interface'] ?? '';
		if (!is_string($name) || $name === '' || !is_string($interface) ||
		    isset($gateway['disabled']) || !isset($interfaces[$interface]['enable'])) {
			continue;
		}
		$address = $gateway['gateway'] ?? 'dynamic';
		$inventory[$name] = [
			'interface' => $interface,
			'address' => $address,
			'monitor' => !empty($gateway['monitor']) ? $gateway['monitor'] : $address,
			'family' => $gateway['ipprotocol'] ??
			    (filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? 'inet6' : 'inet'),
			'monitor_disabled' => isset($gateway['monitor_disable']),
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
function sdwan_validate_config(array $config, ?array $gateways): array {
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
				if (!is_string($gateway) || $gateway === '' ||
				    ($gateways !== null && !array_key_exists($gateway, $gateways))) {
					return ["Select an available configured gateway for {$name}."];
				}
				if (isset($used_gateways[$gateway])) {
					return ["Gateway already assigned to another member: {$name}."];
				}
				$used_gateways[$gateway] = true;
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
				foreach ($row['members'] as $member) {
					if (!sdwan_valid_name($member) || !isset($names['members'][$member]) ||
					    isset($selected[$member])) {
						return ["Invalid or repeated member in policy {$name}."];
					}
					$selected[$member] = true;
					if ($member_families[$member] !== '') {
						$families[$member_families[$member]] = true;
					}
				}
				if (count($families) > 1) {
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
		$inventory = sdwan_gateways();
		/* A gateway can disappear after a restore. Allow existing references to
		 * remain while the operator fixes the members one at a time. */
		$old_gateways = array_column($current['members'], 'gateway', 'name');
		$candidate_members = $candidate['members'] ?? null;
		foreach (is_array($candidate_members) ? $candidate_members : [] as $member) {
			if (!is_array($member) || !sdwan_valid_name($member['name'] ?? null)) {
				continue;
			}
			$gateway = $member['gateway'] ?? null;
			if (is_string($gateway) && ($old_gateways[$member['name']] ?? null) === $gateway) {
				$inventory[$gateway] ??= [];
			}
		}
		$errors = sdwan_validate_config($candidate, $inventory);
		if ($errors) {
			return $errors;
		}
		if ($current === $candidate) {
			return [];
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
