<?php

/* Read-only checks for delegating existing, identified ingress rules to the
 * native steering integration. No lookup here may apply routing or PF. */
function sdwan_preflight_error(string $message): array {
	return ['errors' => [$message], 'binding' => null];
}

/* Resolve the Phase 1 transport from configuration, including a VIP or an IP
 * alias on CARP. An unresolved group, duplicate VIP or dependency cycle cannot
 * certify a single transport. */
function sdwan_preflight_vti_transports(array $native): array {
	$parents = [];
	foreach ($native['vips'] as $vip) {
		if (isset($vip['uniqid'], $vip['interface']) &&
		    in_array($vip['mode'] ?? '', ['carp', 'ipalias'], true)) {
			$key = '_vip' . $vip['uniqid'];
			$parents[$key] = array_key_exists($key, $parents) ? '' : $vip['interface'];
		}
	}
	$phases = $native['phase1'];
	foreach ($phases as &$phase) {
		$interface = $phase['interface'] ?? 'wan';
		$visited = [];
		while (is_string($interface) && isset($parents[$interface]) && !isset($visited[$interface])) {
			$visited[$interface] = true;
			$interface = $parents[$interface];
		}
		$phase['interface'] = is_string($interface) ? $interface : '';
	}
	unset($phase);
	return sdwan_vti_transports($native['interfaces'], $phases, $native['phase2']);
}

/* An ipsecX VTI uses a Phase 2 reqid for X. For merged IKEv2 children,
 * pfSense uses the first child's reqid. Pin the identifiers and traffic paths,
 * allowing a normal rekey or a cosmetic configuration edit. */
function sdwan_preflight_vti_peer(array $native, string $device): ?array {
	$ids = [];
	foreach ($native['phase2'] as $child) {
		if (isset($child['reqid'], $child['ikeid']) && 'ipsec' . $child['reqid'] === $device) {
			$ids[(string)$child['ikeid']] = true;
		}
	}
	$peers = [];
	foreach ($native['phase1'] as $peer) {
		if (isset($ids[$peer['ikeid'] ?? '']) && !isset($peer['disabled'])) {
			$peers[] = array_intersect_key($peer, array_flip(['ikeid', 'interface', 'remote-gateway',
			    'iketype', 'splitconn', 'gw_duplicates', 'peerid_type', 'peerid_data']));
		}
	}
	return count($peers) === 1 ? $peers[0] : null;
}

/* Preserve order in native rule lists while making map key order immaterial. */
function sdwan_preflight_canonical(array $value): array {
	if (!array_is_list($value)) {
		ksort($value, SORT_STRING);
	}
	foreach ($value as &$item) {
		if (is_array($item)) {
			$item = sdwan_preflight_canonical($item);
		}
	}
	unset($item);
	return $value;
}

/* Dynamic aliases and scheduled rules can be omitted by the native generator.
 * Limit initial bindings to predicates which the filter can always render. */
function sdwan_preflight_endpoint($endpoint, string $family, string $ingress): bool {
	if (!is_array($endpoint) || isset($endpoint['not'])) {
		return false;
	}
	$port = $endpoint['port'] ?? '';
	if ($port !== '') {
		if (!is_string($port) || !preg_match('/^([0-9]{1,5})(?:[-:]([0-9]{1,5}))?$/D', $port, $m)) {
			return false;
		}
		$last = $m[2] ?? $m[1];
		if ((int)$last < (int)$m[1] || (int)$last > 65535) {
			return false;
		}
	}
	$selectors = array_intersect_key($endpoint, array_flip(['any', 'address', 'network']));
	if (count($selectors) !== 1) {
		return false;
	}
	if (array_key_exists('any', $selectors)) {
		return true;
	}
	if (array_key_exists('network', $selectors)) {
		return $selectors['network'] === $ingress;
	}
	if (!is_string($selectors['address'])) {
		return false;
	}
	$parts = explode('/', $selectors['address'], 2);
	$flags = $family === 'inet' ? FILTER_FLAG_IPV4 : FILTER_FLAG_IPV6;
	return filter_var($parts[0], FILTER_VALIDATE_IP, $flags) !== false &&
	    (!isset($parts[1]) || (preg_match('/^[0-9]{1,3}$/D', $parts[1]) && (int)$parts[1] <= ($family === 'inet' ? 32 : 128)));
}

/* Compare native predicates, retaining every unfamiliar match option. The
 * action, state handling, logging and UI audit fields do not narrow a deny. */
function sdwan_preflight_guard_match(array $rule): array {
	unset($rule['type'], $rule['gateway'], $rule['statetype'], $rule['tracker'],
	    $rule['descr'], $rule['created'], $rule['updated'], $rule['log']);
	$rule['direction'] = $rule['direction'] ?? 'in';
	if ($rule['direction'] === '') {
		$rule['direction'] = 'in';
	}
	if (($rule['sched'] ?? '') === 'none') {
		unset($rule['sched']);
	}
	return sdwan_preflight_canonical($rule);
}

function sdwan_preflight_unrestricted(array $endpoint): bool {
	return array_key_exists('any', $endpoint) || preg_match('~/0+$~D', $endpoint['address'] ?? '') === 1;
}

function sdwan_preflight_native_rules(array $native, string $group, string $family, array $uplinks): array {
	$trackers = [];
	$scope = [];
	$counts = [];
	foreach ($native['rules'] as $rule) {
		$tracker = $rule['tracker'] ?? null;
		if (is_int($tracker) || is_string($tracker)) {
			$counts[(string)$tracker] = ($counts[(string)$tracker] ?? 0) + 1;
		}
	}
	$rules = array_values($native['rules']);
	foreach ($rules as $index => $rule) {
		if (($rule['gateway'] ?? '') !== $group) {
			continue;
		}
		$id = $rule['tracker'] ?? '';
		$tracker = is_int($id) || is_string($id) ? (string)$id : '';
		if (!preg_match('/^[1-9][0-9]{0,9}$/D', $tracker) ||
		    (float)$tracker > 4294967295 || ($counts[$tracker] ?? 0) !== 1) {
			return sdwan_preflight_error('Every rule using the group needs a unique native rule tracker.');
		}
		$ingress = $rule['interface'] ?? '';
		$device = is_string($ingress) ? ($native['interfaces'][$ingress]['if'] ?? '') : '';
		if (($rule['type'] ?? '') !== 'pass' || isset($rule['floating']) || isset($rule['disabled']) ||
		    isset($rule['force_category']) || isset($rule['associated-rule-id']) ||
		    !empty($rule['tag']) || !empty($rule['tagged']) || isset($rule['nat']) || !in_array($rule['direction'] ?? '', ['', 'in'], true) ||
		    ($rule['ipprotocol'] ?? '') !== $family || !is_string($ingress) ||
		    !isset($native['interfaces'][$ingress]['enable']) || !is_string($device) || $device === '' ||
		    preg_match('/^(?:ipsec|enc|lo[0-9]|pflog|pfsync)/', $device) || isset($uplinks[$ingress]) ||
		    !in_array($rule['statetype'] ?? '', ['', 'keep state'], true)) {
			return sdwan_preflight_error("Rule {$tracker} must be an enabled, stateful interface ingress pass rule for the group family, independent of NAT and ingress WANs.");
		}
		if (!in_array($rule['sched'] ?? '', ['', 'none'], true) ||
		    !sdwan_preflight_endpoint($rule['source'] ?? null, $family, $ingress) ||
		    !sdwan_preflight_endpoint($rule['destination'] ?? null, $family, $ingress)) {
			return sdwan_preflight_error("Rule {$tracker} requires an unscheduled match with literal addresses, the ingress subnet or any, and numeric ports.");
		}
		if (sdwan_preflight_unrestricted($rule['source']) && sdwan_preflight_unrestricted($rule['destination'])) {
			return sdwan_preflight_error("Rule {$tracker} requires a specific source or destination.");
		}
		$guard = $rules[$index + 1] ?? null;
		$guard_id = $guard['tracker'] ?? null;
		if (!is_array($guard) || !in_array($guard['type'] ?? '', ['block', 'reject'], true) ||
		    (!is_int($guard_id) && !is_string($guard_id)) ||
		    !preg_match('/^[1-9][0-9]{0,9}$/D', (string)$guard_id) || (float)$guard_id > 4294967295 ||
		    ($counts[(string)$guard_id] ?? 0) !== 1 || !empty($guard['gateway']) ||
		    isset($guard['disabled']) || isset($guard['floating']) || isset($guard['force_category']) ||
		    isset($guard['associated-rule-id']) || isset($guard['nat']) ||
		    sdwan_preflight_guard_match($rule) !== sdwan_preflight_guard_match($guard)) {
			return sdwan_preflight_error("Place a permanent native block or reject directly after rule {$tracker}, with the same match, its own tracker and no gateway.");
		}
		$trackers[] = $tracker;
		unset($rule['created'], $rule['updated'], $rule['descr']);
		$rule['tracker'] = $tracker;
		$scope[] = [$rule, $device, (string)$guard_id, $guard['type']];
	}
	if (!$trackers) {
		return sdwan_preflight_error('Select a dedicated group already referenced by an enabled ingress pass rule.');
	}
	return ['errors' => [], 'trackers' => $trackers, 'scope' => $scope];
}

function sdwan_steering_preflight(array $config, string $policy, string $group, array $native): array {
	foreach (['groups', 'rules', 'gateways', 'interfaces', 'phase1', 'phase2', 'vips',
	    'openvpn_servers', 'openvpn_clients', 'dyndns', 'dnsupdates'] as $field) {
		if (!isset($native[$field]) || !is_array($native[$field])) {
			return sdwan_preflight_error('Native firewall inventory is incomplete.');
		}
	}
	foreach (['default4', 'default6', 'filtermode'] as $field) {
		if (!array_key_exists($field, $native) || !is_string($native[$field])) {
			return sdwan_preflight_error('Native routing or IPsec settings are unavailable.');
		}
	}
	$policies = array_values(array_filter($config['policies'] ?? [],
	    static fn($row) => ($row['name'] ?? '') === $policy));
	$groups = array_values(array_filter($native['groups'],
	    static fn($row) => ($row['name'] ?? '') === $group));
	if (!sdwan_valid_name($policy) || !sdwan_valid_name($group) || count($policies) !== 1 ||
	    count($groups) !== 1 || isset($native['gateways'][$group]) ||
	    isset($native['interfaces'][$group])) {
		return sdwan_preflight_error('Select a unique policy and a dedicated native gateway group.');
	}
	if ($native['default4'] === $group || $native['default6'] === $group) {
		return sdwan_preflight_error('The system default gateway group cannot be used for steering.');
	}
	foreach (['phase1', 'openvpn_servers', 'openvpn_clients', 'dyndns', 'dnsupdates'] as $field) {
		foreach ($native[$field] as $consumer) {
			if (($consumer['interface'] ?? '') === $group) {
				return sdwan_preflight_error("The group is also used by a native service ({$field}).");
			}
		}
	}

	$group_members = [];
	foreach ($groups[0]['item'] ?? [] as $item) {
		$parts = is_string($item) ? explode('|', $item) : [];
		if (count($parts) < 2 || count($parts) > 3 || $parts[0] === '' ||
		    !in_array($parts[1], ['1', '2', '3', '4', '5'], true) || isset($group_members[$parts[0]])) {
			return sdwan_preflight_error('The native group contains an invalid or duplicate gateway entry.');
		}
		$group_members[$parts[0]] = true;
	}
	$members = array_column($config['members'] ?? [], 'gateway', 'name');
	$paths = [];
	$family = null;
	$kind = null;
	$transports = [];
	$vti = sdwan_preflight_vti_transports($native);
	$uplinks = [];
	foreach ($native['gateways'] as $gateway) {
		if (is_string($gateway['interface'] ?? null)) {
			$uplinks[$gateway['interface']] = true;
		}
	}
	foreach ($policies[0]['members'] ?? [] as $member) {
		$name = is_string($member) ? ($members[$member] ?? '') : '';
		$gateway = $native['gateways'][$name] ?? [];
		$if = $gateway['interface'] ?? '';
		$device = $native['interfaces'][$if]['if'] ?? '';
		if (!isset($group_members[$name]) || isset($paths[$name]) ||
		    !isset($native['interfaces'][$if]['enable']) || !is_string($device) || $device === '' ||
		    ($gateway['monitor_disabled'] ?? true) || ($gateway['action_disabled'] ?? true) ||
		    !in_array($gateway['family'] ?? '', ['inet', 'inet6'], true)) {
			return sdwan_preflight_error('The policy must match enabled, monitored group gateways with gateway actions enabled.');
		}
		$is_vti = str_starts_with($device, 'ipsec');
		$transport = $is_vti ? ($vti[$device] ?? '') : $if;
		if (!$is_vti && preg_match('/^(?:ovpn|wg|tun|tap|gre|gif|vxlan|ipip|enc|lo[0-9]|pflog|pfsync)/', $device)) {
			return sdwan_preflight_error('The group contains an unsupported tunnel or local device.');
		}
		$physical = $native['interfaces'][$transport]['if'] ?? '';
		if (!is_string($physical) || $physical === '' || isset($transports[$physical])) {
			return sdwan_preflight_error('Each candidate requires a distinct identifiable transport interface.');
		}
		$paths[$name] = [$if, $device, $transport, $physical, $gateway['family'],
		    $gateway['address'] ?? '', $gateway['monitor'] ?? ''];
		if ($is_vti) {
			$peer = sdwan_preflight_vti_peer($native, $device);
			if ($peer === null) {
				return sdwan_preflight_error('The assigned VTI does not identify a unique Phase 1 peer.');
			}
			$paths[$name][] = $peer;
		}
		$transports[$physical] = true;
		$uplinks[$transport] = true;
		if (($family !== null && $family !== $gateway['family']) || ($kind !== null && $kind !== $is_vti)) {
			return sdwan_preflight_error('Keep one address family and one type of path in each group. Direct WAN and encrypted VTI cannot substitute for one another.');
		}
		$family = $gateway['family'];
		$kind = $is_vti;
	}
	if (count($paths) < 2 || count($paths) !== count($group_members)) {
		return sdwan_preflight_error('Active steering requires at least two distinct gateways and exactly the native group membership.');
	}
	if ($kind && $native['filtermode'] !== 'if_ipsec') {
		return sdwan_preflight_error('VTI steering requires a topology already filtering on assigned IPsec interfaces. Check compatibility with other VPNs before changing any global setting.');
	}
	if ($kind) {
		$enabled_peers = [];
		foreach ($native['phase1'] as $peer) {
			if (!isset($peer['disabled']) && isset($peer['ikeid'])) {
				if (isset($peer['mobile'])) {
					return sdwan_preflight_error('The current assigned-interface filtering mode conflicts with an enabled mobile IPsec peer.');
				}
				$enabled_peers[$peer['ikeid']] = true;
			}
		}
		foreach ($native['phase2'] as $child) {
			if (!isset($child['disabled']) && isset($enabled_peers[$child['ikeid'] ?? '']) &&
			    !in_array($child['mode'] ?? '', ['vti', 'transport'], true)) {
				return sdwan_preflight_error('The current assigned-interface filtering mode conflicts with an enabled policy-based IPsec tunnel.');
			}
		}
	}
	$rules = sdwan_preflight_native_rules($native, $group, $family, $uplinks);
	if ($rules['errors']) {
		return $rules;
	}
	$group_config = array_intersect_key($groups[0], array_flip(['name', 'item', 'trigger', 'keep_failover_states']));
	$scope = sdwan_preflight_canonical([$group_config, $rules['scope'], $paths]);
	return ['errors' => [], 'binding' => [
		'rules_revision' => hash('sha256', json_encode($scope, JSON_THROW_ON_ERROR)),
		'group' => $group, 'policy' => $policy, 'gateways' => array_map('strval', array_keys($paths)),
		'trackers' => $rules['trackers'],
	]];
}
