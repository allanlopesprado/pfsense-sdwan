<?php
/* The ABI 1 core adapter applies a choice only to explicitly bound rule trackers. */
require_once(__DIR__ . '/sdwan.inc');
require_once(__DIR__ . '/sdwan_engine.inc');
require_once(__DIR__ . '/sdwan_preflight.inc');
require_once(__DIR__ . '/sdwan_log.inc');

const SDWAN_BINDINGS_PATH = 'gateways/sdwan_bindings';
const SDWAN_STEERING_HOLD = 30;

function sdwan_steering_abi(): int {
	if (!function_exists('filter_sdwan_binding_api') && stream_resolve_include_path('filter.inc')) {
		require_once('filter.inc');
	}
	return function_exists('filter_sdwan_binding_api') ? filter_sdwan_binding_api() : 0;
}

function sdwan_steering_supported(): bool {
	return in_array(sdwan_steering_abi(), [1, 2], true);
}

/* Native send_event() logs a rejected request but does not report it to its
 * caller. The observer needs the queue's acknowledgement to decide when to retry. */
function sdwan_steering_request_reload(): bool {
	$address = g_get('event_address', 'unix:///var/run/check_reload_status');
	if (!is_string($address) || !str_starts_with($address, 'unix:///')) {
		return false;
	}
	$socket = @stream_socket_client($address, $errno, $error, 0.5);
	if ($socket === false) {
		return false;
	}
	try {
		$request = 'filter reload';
		return stream_set_timeout($socket, 0, 500000) &&
		    @fwrite($socket, $request) === strlen($request) && @fgets($socket, 4) === "OK\n";
	} finally {
		fclose($socket);
	}
}

/* A routed WAN rule must never take precedence over an overlapping policy-mode
 * full tunnel. pfSense omits /0 selectors from its automatic negate table. */
function sdwan_steering_full_tunnel_sources(array $phases, array $children): array {
	$sources = [];
	$peers = [];
	foreach ($phases as $phase) {
		if (isset($phase['ikeid']) && !isset($phase['disabled']) && !isset($phase['mobile'])) {
			$peers[$phase['ikeid']] = true;
		}
	}
	foreach ($children as $child) {
		$mode = $child['mode'] ?? '';
		$remote = $child['remoteid'] ?? [];
		if (!isset($peers[$child['ikeid'] ?? '']) || isset($child['disabled']) || isset($child['mobile']) ||
		    !in_array($mode, ['tunnel', 'tunnel6'], true) || !isset($remote['type'])) {
			continue;
		}
		if (!str_ends_with((string)ipsec_idinfo_to_cidr($remote, true, $mode), '/0')) {
			continue;
		}
		$local = $child['localid'] ?? [];
		$family = $mode === 'tunnel6' ? 'inet6' : 'inet';
		try {
			$sources[$family][] = isset($local['type']) ? ipsec_idinfo_to_cidr($local, true, $mode) : null;
		} catch (Throwable) {
			$sources[$family][] = null;
		}
	}
	return $sources;
}

function sdwan_steering_native(?array $inventory = null): array {
	$paths = [
		'groups' => 'gateways/gateway_group', 'rules' => 'filter/rule',
		'phase1' => 'ipsec/phase1', 'phase2' => 'ipsec/phase2', 'vips' => 'virtualip/vip',
		'openvpn_servers' => 'openvpn/openvpn-server', 'openvpn_clients' => 'openvpn/openvpn-client',
		'dyndns' => 'dyndnses/dyndns', 'dnsupdates' => 'dnsupdates/dnsupdate', 'interfaces' => 'interfaces',
		'interface_groups' => 'ifgroups/ifgroupentry', 'aliases' => 'aliases/alias',
	];
	$native = ['steering_abi' => sdwan_steering_abi()];
	foreach ($paths as $key => $path) {
		$native[$key] = config_get_path($path, []);
	}
	$native['links'] = sdwan_preflight_link_graph($native['interfaces']);
	$native['gateways'] = $inventory ?? sdwan_gateways();
	foreach ($native['gateways'] as &$gateway) {
		if (!$gateway['monitor_disabled'] && $gateway['monitor'] === 'dynamic') {
			$gateway['resolved_monitor'] = sdwan_gateway_monitor($gateway);
		}
		if (($gateway['family'] ?? '') === 'inet6' && function_exists('get_real_interface') &&
		    (str_contains($gateway['address'] ?? '', '%') || str_contains($gateway['monitor'] ?? '', '%'))) {
			$device = get_real_interface($gateway['interface'], 'inet6', false, false);
			if (is_string($device) && $device !== '') {
				$gateway['route_device'] = $device;
			}
		}
	}
	unset($gateway);
	$native['default4'] = config_get_path('gateways/defaultgw4', '');
	$native['default6'] = config_get_path('gateways/defaultgw6', '');
	$native['statepolicy'] = config_get_path('system/statepolicy', 'if-bound');
	$native['filtermode'] = config_get_path('ipsec/filtermode', '');
	$policy_children = array_filter($native['phase2'], static fn($child) =>
	    in_array($child['mode'] ?? '', ['tunnel', 'tunnel6'], true));
	if ($policy_children) {
		require_once('ipsec.inc');
		if (ipsec_enabled()) {
			$native['full_tunnel_sources'] = sdwan_steering_full_tunnel_sources($native['phase1'], $policy_children);
		}
	}
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

/* pfSense treats <group> as a repeatable tag throughout config.xml. */
function sdwan_steering_group($value): ?string {
	if (is_array($value) && array_keys($value) === [0]) {
		$value = $value[0];
	}
	return is_string($value) ? $value : null;
}

function sdwan_steering_decode(array $row): ?array {
	$group = sdwan_steering_group($row['group'] ?? null);
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

function sdwan_steering_probe_path_available(string $value, array $gateway, string $name): bool {
	require_once(__DIR__ . '/sdwan_probe.inc');
	$target = sdwan_probe_target($value);
	if ($target === null || $target['family'] !== $gateway['family']) {
		return false;
	}
	if (isset($target['fib'])) {
		return sdwan_probe_path($target, $gateway) !== null;
	}
	$routes = sdwan_probe_host_routes([['probe_primary' => $value]]);
	$enabled = array_values(array_filter($routes, static fn($route) => !$route[2]));
	$planned = $enabled === [[$target['address'], $name, false]];
	if ($enabled && !$planned) {
		// An old live route may still be visible until native changes are applied.
		return false;
	}
	if (sdwan_probe_path($target, $gateway) !== null) {
		return true;
	}
	/* An offline interface or pending lease can have a correct native route
	 * saved for when its source and next hop become available. */
	[$device, $source, $hop] = sdwan_dynamic_gateway_identity($gateway);
	return $planned && (!$device || !$source || !$hop);
}

/* Update policy inputs and their bound revisions in the caller's single XML
 * write. A settings edit never expands the approved native forwarding scope. */
function sdwan_steering_policy_edit(array $current, array $candidate, bool $allowed): array {
	$updated = [];
	$native = null;
	foreach (sdwan_steering_bindings() as $group => $binding) {
		$old = sdwan_steering_policy_revision($current, $binding['policy']);
		$new = sdwan_steering_policy_revision($candidate, $binding['policy']);
		if ($new === $old) {
			continue;
		}
		if (!$allowed) {
			return ['errors' => ['Editing an active forwarding policy requires access to edit firewall rules and gateway groups.'], 'rows' => null];
		}
		if (!sdwan_steering_supported()) {
			return ['errors' => ['The native forwarding integration is unavailable. Review the binding under Forwarding.'], 'rows' => null];
		}
		$native ??= sdwan_steering_native();
		$check = sdwan_steering_preflight($candidate, $binding['policy'], $group, $native);
		$approved = $check['binding'];
		if ($new === null || $old !== $binding['policy_revision'] || $approved === null ||
		    $approved['rules_revision'] !== $binding['rules_revision'] || $approved['trackers'] !== $binding['trackers'] ||
		    count($approved['gateways']) !== count($binding['gateways']) ||
		    array_diff($approved['gateways'], $binding['gateways'])) {
			return ['errors' => ["Review the {$group} binding under Forwarding before changing its policy members or native scope.", ...$check['errors']],
			    'rows' => null];
		}
		$probe_errors = sdwan_preflight_probe_paths($candidate, $binding['policy'], $native['gateways'],
		    'sdwan_steering_probe_path_available', $current);
		if ($probe_errors) {
			return ['errors' => $probe_errors, 'rows' => null];
		}
		$updated[$group] = ['policy_revision' => $new, 'gateways' => ['item' => $approved['gateways']]];
	}
	if (!$updated) {
		return ['errors' => [], 'rows' => null];
	}
	$rows = sdwan_steering_rows();
	foreach ($rows as &$row) {
		$group = sdwan_steering_group($row['group'] ?? null);
		if (isset($updated[$group])) {
			$row = array_replace($row, $updated[$group]);
		}
	}
	unset($row);
	return ['errors' => [], 'rows' => $rows];
}

function sdwan_steering_revision(): string {
	return sdwan_config_revision([sdwan_get_config(), sdwan_steering_rows(), sdwan_steering_native()]);
}

function sdwan_steering_preview(array $config, string $policy, string $group): array {
	$native = sdwan_steering_native();
	$preview = sdwan_steering_preflight($config, $policy, $group, $native);
	if ($preview['binding'] !== null && sdwan_steering_supported() && !isset(sdwan_steering_bindings()[$group])) {
		$errors = sdwan_preflight_probe_paths($config, $policy, $native['gateways'],
		    'sdwan_steering_probe_path_available');
		if ($errors) {
			$preview = ['errors' => $errors, 'binding' => null];
		}
	}
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

/* Preserve a bound tracker until its enabled pass rule has a native route. */
function sdwan_steering_withdrawal_errors(array $binding, array $native): array {
	$targets = array_map(static fn($gateway) => [$gateway['family']], $native['gateways']);
	foreach ($native['groups'] as $group) {
		foreach ((array)($group['item'] ?? []) as $item) {
			[$member, $tier] = array_pad(is_string($item) ? explode('|', $item, 3) : [], 2, '');
			if (isset($native['gateways'][$member], $group['name']) && in_array($tier, ['1', '2', '3', '4', '5'], true)) {
				$targets[$group['name']][] = $native['gateways'][$member]['family'];
			}
		}
	}
	$errors = [];
	foreach ($native['rules'] as $rule) {
		$tracker = $rule['tracker'] ?? '';
		if ((!is_string($tracker) && !is_int($tracker)) || !in_array((string)$tracker, $binding['trackers'], true) ||
		    isset($rule['disabled']) || ($rule['type'] ?? '') !== 'pass') {
			continue;
		}
		$gateway = $rule['gateway'] ?? null;
		if (!is_string($gateway) || !in_array($rule['ipprotocol'] ?? null, $targets[$gateway] ?? [], true)) {
			$errors[] = "Firewall rule {$tracker} has no valid native gateway for its address family. Assign one or disable the rule before removing the binding.";
		}
	}
	return $errors;
}

function sdwan_steering_edit(string $group, ?string $policy, string $expected_revision): array {
	if ($policy !== null && !sdwan_steering_supported()) {
		return ['Forwarding requires a supported native pfSense steering integration.'];
	}
	$lock = sdwan_lock('sdwan-settings', 5);
	if (!is_resource($lock)) {
		return ['SD-WAN settings are busy. Reload the page and try again.'];
	}
	$observation_lock = null;
	$receipt_before_edit = null;
	try {
		if (!config_read_file(false, false) || !is_array($config_before = config_get_path(''))) {
			return ['The current pfSense configuration could not be read.'];
		}
		$config = sdwan_get_config();
		$rows = sdwan_steering_rows();
		$native = sdwan_steering_native();
		if (!hash_equals(sdwan_config_revision([$config, $rows, $native]), $expected_revision)) {
			return ['Settings changed. Review the current preview before applying.'];
		}
		$active = sdwan_steering_bindings();
		if ($policy === null) {
			$binding = $active[$group] ?? null;
			if ($binding === null) {
				return ['This group has no saved binding.'];
			}
			$errors = sdwan_steering_withdrawal_errors($binding, $native);
			if ($errors) {
				return $errors;
			}
			$updated = array_values(array_filter($rows, static fn($row) =>
			    sdwan_steering_group($row['group'] ?? null) !== $group));
			if (sdwan_steering_supported()) {
				$observation_lock = @fopen(SDWAN_SNAPSHOT_PATH . '.lock', 'c');
				if (!is_resource($observation_lock) || !flock($observation_lock, LOCK_EX | LOCK_NB)) {
					return ['An SD-WAN observation is in progress. Retry the withdrawal.'];
				}
				$path = SDWAN_SNAPSHOT_PATH . '.forwarded';
				$receipt_before_edit = sdwan_steering_read_receipt($path);
				$receipt = $receipt_before_edit + [
				    'signature' => sdwan_config_revision([]), 'attempts' => 0, 'requested_at' => 0,
				    'accepted' => false, 'confirmed' => false,
				];
				$known = [...($receipt['trackers'] ?? []), ...sdwan_steering_trackers($active)];
				$receipt['trackers'] = array_values(array_unique($known));
				sort($receipt['trackers'], SORT_STRING);
				unset($active[$group]);
				$receipt['withdrawal'] = sdwan_steering_withdrawal($receipt, sdwan_steering_trackers($active));
				$receipt = array_replace($receipt, ['attempts' => 0, 'requested_at' => 0,
				    'accepted' => false, 'confirmed' => false]);
				if (!sdwan_steering_write_receipt($path, $receipt)) {
					return ['Could not record withdrawal for PF verification.'];
				}
			}
		} else {
			$preview = sdwan_steering_preflight($config, $policy, $group, $native);
			if ($preview['errors']) {
				return $preview['errors'];
			}
			$errors = sdwan_preflight_probe_paths($config, $policy, $native['gateways'],
			    'sdwan_steering_probe_path_available');
			if ($errors) {
				return $errors;
			}
			$row = $preview['binding'];
			$row['policy_revision'] = sdwan_steering_policy_revision($config, $policy);
			foreach ($active as $saved) {
				if ($saved['group'] === $group || array_intersect($row['trackers'], $saved['trackers'])) {
					return ['Roll back the existing binding before binding these rules.'];
				}
			}
			foreach (['trackers', 'gateways'] as $list) {
				$row[$list] = ['item' => $row[$list]];
			}
			$updated = [...$rows, $row];
		}
		$config_changed = sdwan_config_changed_since($config_before);
		if ($config_changed || !is_array(config_set_path(SDWAN_BINDINGS_PATH, ['item' => $updated])) ||
		    !is_array(write_config($policy === null ? 'Returned SD-WAN rules to native gateway selection' : 'Bound SD-WAN forwarding policy to native firewall rules'))) {
			if (!$config_changed) {
				config_read_file(false, false);
			}
			if ($receipt_before_edit !== null) {
				if ($receipt_before_edit) {
					sdwan_steering_write_receipt($path, $receipt_before_edit);
				} else {
					@unlink($path);
				}
			}
			if ($config_changed) {
				return ['Settings changed. Review the current preview before applying.'];
			}
			sdwan_log_event('binding_error');
			return ['pfSense could not save the forwarding binding.'];
		}
	} catch (UnexpectedValueException $error) {
		return [$error->getMessage()];
	} finally {
		if (is_resource($observation_lock)) {
			fclose($observation_lock);
		}
		sdwan_unlock($lock);
	}
	$label = sdwan_log_label($group);
	sdwan_log_emit(LOG_NOTICE, $policy === null ? "Group {$label}: forwarding binding removed." :
	    "Group {$label}: forwarding binding saved for policy " . sdwan_log_label($policy) . '.');
	if (sdwan_steering_supported()) {
		filter_configure();
	}
	return [];
}

/* Quarantine loss immediately. Keep a healthy incumbent while a better path settles. */
function sdwan_steering_step(array $previous, array $eligible, ?string $best, int $now, int $hold = SDWAN_STEERING_HOLD): array {
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
		    is_int($previous['since'] ?? null) && $previous['since'] >= 0 &&
		    $previous['since'] <= $now ? $previous['since'] : $now;
		$chosen = $incumbent;
		if ($now - $since >= $hold) {
			$chosen = $best;
			$candidate = $since = null;
		}
	}
	return ['gateway' => $chosen, 'candidate' => $candidate, 'since' => $since];
}

function sdwan_steering_state(array $config, array $binding, array $result, array $old, int $now,
    bool $prior_applied = false): array {
	$eligible = [];
	$best = null;
	$policy = array_column($config['policies'], null, 'name')[$binding['policy']] ?? [];
	$revision = sdwan_config_revision($binding);
	$prior = ($old['revision'] ?? null) === $revision ? $old : [];
	$degraded = [];
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
		$limit = (int)($policy['degrade_samples'] ?? 1);
		$previous_sample = $prior['degraded_at'] ?? null;
		if ($prior_applied && $limit > 1 && ($previous_sample === null || $previous_sample <= $now)) {
			$active = $prior['pool'] ?? [$prior['gateway'] ?? null];
			foreach ($result['soft'] ?? [] as $member) {
				$gateway = $members[$member] ?? null;
				if ($gateway === null || !in_array($gateway, $active, true) ||
				    !in_array($gateway, $binding['gateways'], true)) {
					continue;
				}
				$count = (int)($prior['degraded'][$gateway] ?? 0);
				if ($count === 0 || $previous_sample !== $now) {
					$count++;
				}
				if ($count < $limit) {
					$degraded[$gateway] = $count;
					$eligible[] = $gateway;
				}
			}
		}
	}
	$metadata = ['revision' => $revision];
	if ($degraded) {
		$metadata += ['degraded' => $degraded, 'degraded_at' => $now];
	}
	if (($policy['strategy'] ?? null) === 'balance') {
		$pool = array_intersect($binding['gateways'], $eligible);
		$hold = (int)($policy['recover_seconds'] ?? 0);
		$retained = array_intersect($pool, $prior['pool'] ?? []);
		// A surviving healthy path allows other members to wait without delaying recovery of the pool.
		if ($hold > 0 && array_diff($retained, array_keys($degraded))) {
			foreach (array_diff($pool, $retained) as $index => $gateway) {
				$since = $prior['recovering'][$gateway] ?? null;
				$since = is_int($since) && $since >= 0 && $since <= $now ? $since : $now;
				if ($now - $since < $hold) {
					$metadata['recovering'][$gateway] = $since;
					unset($pool[$index]);
				}
			}
		}
		$pool = array_values($pool);
		return $metadata + ['gateway' => $pool[0] ?? null, 'pool' => $pool];
	}
	if (isset($degraded[$prior['gateway'] ?? ''])) {
		$best = $prior['gateway'];
	}
	return $metadata + sdwan_steering_step($prior, $eligible, $best, $now,
	    (int)($policy['recover_seconds'] ?? SDWAN_STEERING_HOLD));
}

function sdwan_steering_preflight_matches(array $binding, array $check): bool {
	return !$check['errors'] && $binding['rules_revision'] === $check['binding']['rules_revision'] &&
	    $binding['gateways'] === $check['binding']['gateways'] && $binding['trackers'] === $check['binding']['trackers'];
}

/* Run in the observer process. Recheck native membership/ACL drift on each
 * sample so a subsequent reload can close a binding that is no longer valid. */
function sdwan_steering_observations(array $config, array $snapshot, array $previous, array &$rule_pairs = []): array {
	$states = [];
	$rule_pairs = [];
	$native = sdwan_steering_native();
	$loaded = null;
	$read_filter = false;
	foreach (sdwan_steering_bindings() as $group => $binding) {
		$check = sdwan_steering_preflight($config, $binding['policy'], $group, $native);
		$approved = sdwan_steering_preflight_matches($binding, $check);
		if ($approved) {
			$rule_pairs[$group] = $check['rule_pairs'];
		}
		$result = $approved ? ($snapshot['policies'][$binding['policy']] ?? []) : [];
		$old = $previous[$group] ?? [];
		$applied = false;
		if (!empty($result['soft']) && isset($old['gateway'])) {
			if (!$read_filter) {
				$loaded = sdwan_steering_pf_rules();
				$read_filter = true;
			}
			$applied = sdwan_steering_pf_status($binding, $old, $native['gateways'], $loaded, $check['rule_pairs']) === 'applied';
		}
		$states[$group] = sdwan_steering_state($config, $binding, $result, $old, sdwan_snapshot_clock($snapshot), $applied);
	}
	return $states;
}

function sdwan_steering_sticky_paths(array $gateways): bool {
	return count($gateways) > 1 && function_exists('config_path_enabled') &&
	    config_path_enabled('system', 'lb_use_sticky');
}

function sdwan_steering_loaded_path_matches(string $rule, array $gateways): bool {
	if (!preg_match('/^pass in (?:log(?: \([^)]*\))? )?quick on /', $rule) ||
	    !preg_match('/\broute-to\s+(\{[^}]+\}\s+round-robin(?:\s+sticky-address)?|\([^()]+\))/', $rule, $route)) {
		return false;
	}
	preg_match_all('/\(\s*([^\s()]+)\s+([^\s()]+)\s*\)/', $route[1], $paths, PREG_SET_ORDER);
	$balanced = count($gateways) > 1;
	if (!$paths || $balanced !== str_starts_with($route[1], '{') ||
	    sdwan_steering_sticky_paths($gateways) !== str_ends_with($route[1], 'sticky-address')) {
		return false;
	}
	$seen = [];
	foreach ($paths as [, $device, $address]) {
		$gateway = $gateways[$device] ?? null;
		if ($gateway === null || !sdwan_next_hop_matches($address, $gateway['address'], $device)) {
			return false;
		}
		$seen[$device] = ($seen[$device] ?? 0) + 1;
	}
	$weights = array_map(static fn($gateway) => max(1, min(30, (int)($gateway['weight'] ?? 1))), $gateways);
	$scale = count($weights) > 1 && min($weights) === 1 && max($weights) > 1 ? 2 : 1;
	foreach ($weights as $device => $weight) {
		if (($seen[$device] ?? 0) !== (count($weights) === 1 ? 1 : $weight * $scale)) {
			return false;
		}
	}
	return true;
}

/* Read only the rule descriptions required to verify an approved tracker.
 * The WebGUI never displays the raw output. */
function sdwan_steering_pf_rules(): ?array {
	if (!function_exists('exec') || !is_executable('/sbin/pfctl') || !is_executable('/bin/timeout')) {
		return null;
	}
	exec("/bin/timeout 2 /bin/sh -c '/sbin/pfctl -si && /sbin/pfctl -P -sr' 2>/dev/null", $lines, $status);
	return $status === 0 && preg_match('/^Status:\s+Enabled(?:\s|$)/', $lines[0] ?? '') ? $lines : null;
}

/* Use the filter generator's device selection and the current next hop. */
function sdwan_steering_resolve_path(array $gateway): ?array {
	$interface = $gateway['interface'] ?? null;
	$family = $gateway['family'] ?? null;
	$address = $gateway['address'] ?? null;
	$lookup = match ($family) {
		'inet' => 'get_interface_gateway',
		'inet6' => 'get_interface_gateway_v6',
		default => null,
	};
	if ($lookup === null || !is_string($interface) || $interface === '') {
		return null;
	}
	if (!function_exists('get_real_interface') || ($address === 'dynamic' && !function_exists($lookup))) {
		require_once('gwlb.inc');
	}
	$device = get_real_interface($interface, $family, false, false);
	if ($address === 'dynamic') {
		$address = $lookup($interface);
	}
	return is_string($device) && $device !== '' && is_string($address) && $address !== '' ?
	    ['device' => $device, 'address' => $address] : null;
}

const SDWAN_RELOAD_MAX_ATTEMPTS = 3;
const SDWAN_RELOAD_RETRY_INTERVAL = 30;
const SDWAN_STARTUP_RETRY_WINDOW = 300;

function sdwan_steering_trackers(array $bindings): array {
	$trackers = [];
	foreach ($bindings as $binding) {
		foreach ($binding['trackers'] as $tracker) {
			$trackers[$tracker] = true;
		}
	}
	$ids = array_map('strval', array_keys($trackers));
	sort($ids, SORT_STRING);
	return $ids;
}

function sdwan_steering_tracker_list_valid(mixed $list): bool {
	if (!is_array($list) || !array_is_list($list) || count($list) > 4096) {
		return false;
	}
	$last = '';
	foreach ($list as $tracker) {
		if (!is_string($tracker) || !preg_match('/\A[1-9][0-9]{0,9}\z/', $tracker) ||
		    strcmp($tracker, $last) <= 0) {
			return false;
		}
		$last = $tracker;
	}
	return true;
}

function sdwan_steering_withdrawal(array $previous, array $trackers): ?array {
	$pending = $previous['withdrawal'] ?? null;
	$removed = array_diff($previous['trackers'] ?? [], $trackers);
	$unknown = $pending['unknown'] ?? ($previous && !$trackers && !isset($previous['trackers']));
	$affected = array_values(array_unique(array_diff([...($pending['trackers'] ?? []), ...$removed], $trackers)));
	sort($affected, SORT_STRING);
	if (!$affected && !$unknown) {
		return null;
	}
	if (($pending['trackers'] ?? null) === $affected && ($pending['unknown'] ?? null) === $unknown) {
		return $pending;
	}
	return ['trackers' => $affected, 'unknown' => $unknown, 'since_ns' => hrtime(true)];
}

function sdwan_steering_withdrawal_confirmed(array $withdrawal, array $trackers, ?array $rules): bool {
	if ($rules === null) {
		return false;
	}
	if (!$withdrawal['unknown']) {
		$still_present = false;
		foreach ($rules as $rule) {
			if (in_array(sdwan_steering_rule_tracker($rule), $withdrawal['trackers'], true)) {
				$still_present = true;
				break;
			}
		}
		if (!$still_present) {
			return true;
		}
	}
	/* On older adapters, a native rule may reuse the tracker and route. Its
	 * presence alone cannot identify the generation that produced it. */
	if (!function_exists('filter_sdwan_withdrawal_proof_api') || filter_sdwan_withdrawal_proof_api() !== 1 ||
	    !function_exists('filter_sdwan_ruleset_hash')) {
		return false;
	}
	$path = g_get('varrun_path', '/var/run') . '/sdwan-filter-commit.json';
	$raw = @file_get_contents($path, false, null, 0, 65537);
	$proof = is_string($raw) && strlen($raw) <= 65536 ? json_decode($raw, true, 8) : null;
	$started = $proof['started_ns'] ?? null;
	$hash = filter_sdwan_ruleset_hash($rules);
	return is_int($started) && $started >= $withdrawal['since_ns'] && $started <= hrtime(true) &&
	    ($proof['trackers'] ?? null) === $trackers && $hash !== null && ($proof['ruleset'] ?? null) === $hash;
}

function sdwan_steering_runtime_signature(array $snapshot, array $inventory): string {
	$paths = [];
	$sticky = false;
	foreach ($snapshot['steering'] as $state) {
		$pool = $state['pool'] ?? array_filter([$state['gateway']]);
		$sticky = $sticky || sdwan_steering_sticky_paths($pool);
		foreach ($pool as $name) {
			if (isset($inventory[$name])) {
				$paths[$name] = sdwan_steering_resolve_path($inventory[$name]);
				if ($paths[$name] !== null && ($inventory[$name]['address'] === 'dynamic' || !empty($inventory[$name]['dynamic_source']))) {
					$paths[$name]['dynamic_identity'] = sdwan_dynamic_gateway_identity($inventory[$name], $paths[$name]['device']);
				}
			}
		}
	}
	ksort($paths, SORT_STRING);
	return sdwan_config_revision([
	    $snapshot['config_revision'], $snapshot['gateway_inventory_revision'],
	    sdwan_steering_signature($snapshot['steering']), $paths, $sticky,
	]);
}

/* An old-format acknowledgement or a damaged receipt cannot confirm PF. */
function sdwan_steering_read_receipt(string $path): array {
	$raw = @file_get_contents($path, false, null, 0, 131073);
	$data = is_string($raw) && strlen($raw) <= 131072 ? json_decode($raw, true, 8) : null;
	if (!is_array($data) || !is_string($data['signature'] ?? null) ||
	    !preg_match('/\A[a-f0-9]{64}\z/', $data['signature']) ||
	    !is_int($data['attempts'] ?? null) || $data['attempts'] < 0 ||
	    $data['attempts'] > SDWAN_RELOAD_MAX_ATTEMPTS ||
	    !is_int($data['requested_at'] ?? null) || $data['requested_at'] < 0 ||
	    !is_bool($data['accepted'] ?? null) || !is_bool($data['confirmed'] ?? null)) {
		return [];
	}
	if (isset($data['trackers']) && !sdwan_steering_tracker_list_valid($data['trackers'])) {
		return [];
	}
	if (isset($data['withdrawal'])) {
		$withdrawal = $data['withdrawal'];
		if (!is_array($withdrawal) || !sdwan_steering_tracker_list_valid($withdrawal['trackers'] ?? null) ||
		    !is_bool($withdrawal['unknown'] ?? null) || !is_int($withdrawal['since_ns'] ?? null) ||
		    $withdrawal['since_ns'] <= 0 || (!$withdrawal['trackers'] && !$withdrawal['unknown'])) {
			return [];
		}
	}
	return $data;
}

function sdwan_steering_write_receipt(string $path, array $receipt): bool {
	$data = json_encode($receipt, JSON_THROW_ON_ERROR);
	$temp = @tempnam(dirname($path), '.sdwan-reload-');
	if ($temp === false) {
		return false;
	}
	try {
		return @file_put_contents($temp, $data) === strlen($data) &&
		    @chmod($temp, 0644) && @rename($temp, $path);
	} finally {
		if (file_exists($temp)) {
			@unlink($temp);
		}
	}
}

/* pfctl prints dummynet and queue modifiers after the tracker. Labels may
 * contain administrator text, so look for the identifier outside quotes. */
function sdwan_steering_rule_tracker(string $rule): ?string {
	return preg_match('/"(?:[^"\\\\]|\\\\.)*"(*SKIP)(*F)|\bridentifier ([0-9]{1,10})(?=\s|$)/', $rule, $match)
	    ? $match[1] : null;
}

/* An empty result means no reconciliation is needed. Keep inferred withdrawal
 * evidence across reads so a later native proof can confirm the same removal. */
function sdwan_steering_watchdog_pending(?array &$seen_withdrawal, array $verify = [], int $verify_after = 0): ?array {
	if (!config_read_file(false, true)) {
		return null;
	}
	$path = SDWAN_SNAPSHOT_PATH . '.forwarded';
	clearstatcache(true, $path);
	$receipt = sdwan_steering_read_receipt($path);
	$has_receipt = $receipt || is_file($path);
	if (!config_get_path(SDWAN_BINDINGS_PATH . '/item', []) && !$has_receipt && !$verify_after) {
		$seen_withdrawal = null;
		return [];
	}
	if (!sdwan_steering_supported()) {
		return null;
	}
	if (is_platform_booting() || config_path_enabled('system', 'disablefilter')) {
		$seen_withdrawal = null;
		return $verify_after ? null : [];
	}
	try {
		$bindings = sdwan_steering_bindings();
	} catch (UnexpectedValueException) {
		return null;
	}
	$trackers = sdwan_steering_trackers($bindings);
	$invalid_receipt = $has_receipt && !$receipt;
	if ($verify_after) {
		/* Config and receipt may change while the native filter lock is busy. */
		$receipt['trackers'] = [...($receipt['trackers'] ?? []), ...$verify, ...($seen_withdrawal['trackers'] ?? [])];
		$receipt['withdrawal'] ??= $seen_withdrawal;
	}
	$recorded = $receipt['withdrawal'] ?? null;
	$withdrawal = sdwan_steering_withdrawal($receipt, $trackers);
	if ($invalid_receipt || ($verify_after && !empty($seen_withdrawal['unknown']))) {
		$withdrawal = ['trackers' => $withdrawal['trackers'] ?? [], 'unknown' => true,
		    'since_ns' => $withdrawal['since_ns'] ?? hrtime(true)];
	}
	if ($withdrawal !== null && $withdrawal !== $recorded) {
		if ($verify_after) {
			$withdrawal['since_ns'] = max($verify_after, $recorded['since_ns'] ?? 0, $seen_withdrawal['since_ns'] ?? 0);
		} elseif ($seen_withdrawal !== null && $withdrawal['trackers'] === $seen_withdrawal['trackers'] &&
		    $withdrawal['unknown'] === $seen_withdrawal['unknown']) {
			$withdrawal['since_ns'] = max($seen_withdrawal['since_ns'], $recorded['since_ns'] ?? 0);
		}
	}
	$seen_withdrawal = $withdrawal;
	$rules = null;
	if ($withdrawal !== null || $verify_after) {
		$rules = sdwan_steering_pf_rules();
		if ($rules === null) {
			return null;
		}
	}
	$candidates = $bindings ? sdwan_steering_watchdog_stale_trackers($bindings, $rules, $verify) : [];
	if ($rules === null && $candidates) {
		$rules = sdwan_steering_pf_rules();
		if ($rules === null) {
			return null;
		}
	}
	$stale = $candidates ? sdwan_steering_pass_trackers($candidates, $rules) : [];
	$pending = $withdrawal !== null && !sdwan_steering_withdrawal_confirmed($withdrawal, $trackers, $rules);
	return $stale || $pending ? ['passes' => $stale, 'withdrawal' => $pending ? $withdrawal : null] : [];
}

/* Evaluate authorization first so the healthy poll does not dump the PF ruleset. */
function sdwan_steering_watchdog_stale_trackers(array $bindings, ?array $rules, array $verify): array {
	$config = sdwan_get_config();
	$inventory = sdwan_gateways();
	$snapshot = sdwan_current_snapshot($config, $inventory);
	if ($snapshot === null) {
		return sdwan_steering_trackers($bindings);
	}
	$native = sdwan_steering_native($inventory);
	$stale = [];
	foreach ($bindings as $group => $binding) {
		$chosen = sdwan_steering_binding_gateways($binding, $config, $snapshot, $native, $rule_pairs);
		if (!$chosen || (array_intersect($binding['trackers'], $verify) &&
		    sdwan_steering_pf_status($binding, $snapshot['steering'][$group], $inventory, $rules, $rule_pairs) !== 'applied')) {
			$stale = [...$stale, ...$binding['trackers']];
		}
	}
	sort($stale, SORT_STRING);
	return $stale;
}

function sdwan_steering_pass_trackers(array $trackers, array $rules): array {
	$approved = array_fill_keys($trackers, true);
	$present = [];
	foreach ($rules as $rule) {
		if (str_starts_with($rule, 'pass ')) {
			$tracker = sdwan_steering_rule_tracker($rule);
			if ($tracker !== null && isset($approved[$tracker])) {
				$present[$tracker] = true;
			}
		}
	}
	return array_values(array_filter($trackers, static fn($tracker) => isset($present[$tracker])));
}

/* Require the running native adapter on every attempt. Never edit rules or
 * states directly, and skip the native global down-gateway state flush. */
function sdwan_steering_reconcile_expiry(): bool {
	$started = hrtime(true);
	$withdrawal = null;
	$pending = sdwan_steering_watchdog_pending($withdrawal);
	if ($pending === null) {
		return false;
	}
	if (!$pending) {
		return true;
	}
	if (!function_exists('filter_configure_sync')) {
		return false;
	}
	filter_configure_sync(false);
	if (sdwan_steering_watchdog_pending($withdrawal, $pending['passes'], $started) !== []) {
		return false;
	}
	if ($pending['passes']) {
		sdwan_log_event('filter_expiry_applied');
	}
	if ($pending['withdrawal'] !== null) {
		sdwan_log_event('filter_withdrawal_confirmed');
	}
	return true;
}

/* A restarted observer withdraws the interrupted decision before sampling. A
 * loaded pass rule can survive its publisher and the expiration of its file. */
function sdwan_steering_retire_on_start(): bool {
	if (!sdwan_steering_supported() || is_platform_booting() ||
	    config_path_enabled('system', 'disablefilter')) {
		return true;
	}
	return sdwan_steering_retire_observation(true);
}

/* Ordinary stop waits for an in-flight observation before withdrawing the
 * snapshot. Keep the receipt until the loaded bound passes are gone. */
function sdwan_steering_retire_observation(bool $startup = false): bool {
	$lock = @fopen(SDWAN_SNAPSHOT_PATH . '.lock', 'c');
	if ($lock === false) {
		return false;
	}
	try {
		clearstatcache();
		if (!flock($lock, $startup ? LOCK_EX | LOCK_NB : LOCK_EX)) {
			return false;
		}
		$path = SDWAN_SNAPSHOT_PATH . '.forwarded';
		if (!$startup && is_file(SDWAN_SNAPSHOT_PATH) && !unlink(SDWAN_SNAPSHOT_PATH)) {
			return false;
		}
		if (!config_read_file(false, true)) {
			return false;
		}
		$trackers = [];
		$bindings = config_get_path(SDWAN_BINDINGS_PATH . '/item', []);
		foreach ($bindings && sdwan_steering_supported() ? (array)$bindings : [] as $binding) {
			foreach ((array)($binding['trackers']['item'] ?? []) as $tracker) {
				if ((is_int($tracker) || is_string($tracker)) && preg_match('/^[1-9][0-9]{0,9}$/D', (string)$tracker)) {
					$trackers[$tracker] = true;
				}
			}
		}
		$receipt = sdwan_steering_read_receipt($path);
		$pending_withdrawal = isset($receipt['withdrawal']) || (!$trackers && !empty($receipt['trackers']));
		if (!$trackers) {
			return $startup || (!$pending_withdrawal && (!is_file($path) || unlink($path)));
		}
		if ($startup && is_file(SDWAN_SNAPSHOT_PATH)) {
			sdwan_read_snapshot($expired);
			if ($expired) {
				sdwan_log_event('sample_expired');
			}
		}
		if (is_file(SDWAN_SNAPSHOT_PATH) && !unlink(SDWAN_SNAPSHOT_PATH)) {
			return false;
		}
		$closed = static function () use ($trackers): bool {
			$rules = sdwan_steering_pf_rules();
			if ($rules === null) {
				return false;
			}
			foreach ($rules as $rule) {
				if (str_starts_with($rule, 'pass ') && isset($trackers[sdwan_steering_rule_tracker($rule)])) {
					return false;
				}
			}
			return true;
		};
		if ($closed()) {
			return $pending_withdrawal ? $startup : (!is_file($path) || unlink($path));
		}
		/* Reuse the startup signature so stop and restart share the retry budget. */
		$signature = sdwan_config_revision(['startup', array_keys($trackers)]);
		$now = time();
		if (($receipt['signature'] ?? null) !== $signature || $receipt['requested_at'] > $now ||
		    $now - $receipt['requested_at'] >= SDWAN_STARTUP_RETRY_WINDOW) {
			$receipt = ['signature' => $signature, 'attempts' => 0, 'requested_at' => 0,
			    'accepted' => false, 'confirmed' => false] + array_intersect_key($receipt,
			        ['trackers' => true, 'withdrawal' => true]);
		}
		if ($receipt['attempts'] >= SDWAN_RELOAD_MAX_ATTEMPTS ||
		    $now - $receipt['requested_at'] < SDWAN_RELOAD_RETRY_INTERVAL) {
			return false;
		}
		$receipt['attempts']++;
		$receipt['requested_at'] = $now;
		if (!sdwan_steering_write_receipt($path, $receipt) || !sdwan_steering_request_reload()) {
			return false;
		}
		$receipt['accepted'] = true;
		if (!sdwan_steering_write_receipt($path, $receipt)) {
			return false;
		}
		$deadline = hrtime(true) + 5_000_000_000;
		do {
			if ($closed()) {
				return $pending_withdrawal ? $startup : (!is_file($path) || unlink($path));
			}
			usleep(250000);
		} while (hrtime(true) < $deadline);
		return false;
	} finally {
		fclose($lock);
	}
}

/* Compare the packet selectors reflected by PF on a bound rule and its native
 * fallback, independent of action, logging, route selection and TCP state. */
function sdwan_steering_loaded_scope(string $rule): ?string {
	if (!preg_match('/^(?:pass|block(?: (?:drop|return\S*(?: \([^)]*\))?))?) in (?:log(?: \([^)]*\))? )?quick on ([A-Za-z0-9_.-]+) (.+)$/D',
	    $rule, $parts)) {
		return null;
	}
	$match = preg_replace('/^route-to\s+(?:\{[^}]+\}\s+round-robin(?:\s+sticky-address)?|\([^()]+\))\s+/', '', $parts[2]);
	[$selectors] = preg_split('/\s+(?:flags|keep state|no state|modulate state|synproxy state|ridentifier|dnpipe|queue)(?=\s)/',
	    $match, 2);
	return preg_match('/^inet6?\s/', $selectors) ? $parts[1] . ' ' . trim(preg_replace('/\s+/', ' ', $selectors)) : null;
}

function sdwan_steering_scope_fields(string $scope, bool $options = false): ?array {
	if (!preg_match('/^([A-Za-z0-9_.-]+) (inet6?)(?: proto ([a-z0-9_-]+))? (.*)$/D', $scope, $head)) {
		return null;
	}
	[, $device, $family, $protocol, $match] = $head;
	if ($protocol === 'icmp6') {
		$protocol = 'ipv6-icmp';
	}
	if ($match === 'all') {
		$match = 'from any to any';
	}
	$port = '(?: port ((?:[<>=]{1,2} )?[0-9]{1,5}(?:(?: >< |:)[0-9]{1,5})?))?';
	$qualifier = $options ? '(?: (?:icmp6?-type|tos|prio)\b.*)?' : '';
	if (!preg_match("/^from (\\S+){$port} to (\\S+){$port}{$qualifier}$/D", $match, $endpoints)) {
		return null;
	}
	$endpoint = static function (string $address, string $port): array {
		if (preg_match('/^<([A-Z0-9]+)__NETWORK(?::[0-9]+)?>$/D', $address, $table)) {
			$result = ['network' => strtolower($table[1])];
		} else {
			$result = $address === 'any' ? ['any' => ''] : ['address' => $address];
		}
		if ($port === '') {
			return $result;
		}
		if (preg_match('/^([0-9]+) >< ([0-9]+)$/D', $port, $range)) {
			$port = ((int)$range[1] + 1) . '-' . ((int)$range[2] - 1);
		} elseif (preg_match('/^(<=|>=|=) ([0-9]+)$/D', $port, $limit)) {
			$port = match ($limit[1]) {
				'<=' => '1-' . $limit[2],
				'>=' => $limit[2] . '-65535',
				'=' => $limit[2],
			};
		}
		return $result + ['port' => $port];
	};
	return ['device' => $device, 'family' => $family, 'protocol' => $protocol,
	    'source' => $endpoint($endpoints[1], $endpoints[2] ?? ''),
	    'destination' => $endpoint($endpoints[3], $endpoints[4] ?? '')];
}

function sdwan_steering_scope_endpoint(array $endpoint): array {
	$endpoint = array_intersect_key($endpoint, ['any' => true, 'address' => true, 'network' => true, 'port' => true]);
	if (sdwan_preflight_unrestricted($endpoint)) {
		$endpoint = ['any' => ''] + array_intersect_key($endpoint, ['port' => true]);
	}
	if (in_array($endpoint['port'] ?? null, ['1-65535', '1:65535'], true)) {
		unset($endpoint['port']);
	}
	return $endpoint;
}

function sdwan_steering_scope_matches(array $actual, array $expected): bool {
	if ($actual['device'] !== $expected['device'] || $actual['family'] !== $expected['family'] ||
	    !in_array($actual['protocol'], $expected['protocols'], true)) {
		return false;
	}
	foreach (['source', 'destination'] as $field) {
		$loaded = sdwan_steering_scope_endpoint($actual[$field]);
		$configured = sdwan_steering_scope_endpoint($expected[$field]);
		$alias = $field === 'destination' ? ($expected['destination_alias'] ?? null) : null;
		if ($alias !== null) {
			if (!preg_match('/\A<' . preg_quote($alias, '/') . '(?::[0-9]+)?>\z/', $loaded['address'] ?? '')) {
				return false;
			}
			$loaded['address'] = $alias;
		}
		if ($expected['family'] === 'inet6' && str_starts_with($configured['address'] ?? '', '::')) {
			$interface = $expected['interface'] ?? '';
			if ($interface === '' || !function_exists('merge_ipv6_delegated_prefix') ||
			    !function_exists('get_interface_ipv6') || !function_exists('get_interface_subnetv6')) {
				return false;
			}
			/* The native generator expands an IPv6 host suffix using the ingress prefix. */
			$address = merge_ipv6_delegated_prefix(get_interface_ipv6($interface),
			    $configured['address'], get_interface_subnetv6($interface));
			if (!is_string($address) || $address === '') {
				return false;
			}
			$configured['address'] = $address;
		}
		$ingress = $configured['network'] ?? '';
		if (!sdwan_preflight_endpoint($loaded, $expected['family'], $ingress, $alias) ||
		    !sdwan_preflight_endpoint_covers($configured, $loaded) ||
		    !sdwan_preflight_endpoint_covers($loaded, $configured)) {
			return false;
		}
	}
	return true;
}

function sdwan_steering_loaded_tcp_flags(string $rule): ?string {
	return preg_match('/\bflags\s+(any|[A-Za-z]*\/[A-Za-z]+)(?=\s|$)/', $rule, $flags) ?
	    sdwan_tcp_flags_canonical($flags[1]) : 'any';
}

/* Prove full coverage for plain quick rules. Distinct tables, anchors,
 * and partial overlaps still require a traffic test. */
function sdwan_steering_loaded_shadow(array $lines, int $position, string $scope, array $interface_groups = []): bool {
	$bound = sdwan_steering_scope_fields($scope);
	if ($bound === null) {
		return false;
	}
	$devices = [$bound['device'], ...$interface_groups];
	$destination = $bound['destination']['address'] ?? '';
	$same_table = preg_match('/\A<[A-Za-z][A-Za-z0-9_]{0,31}(?::[0-9]+)?>\z/', $destination) ? $destination : null;
	[$bound_rule] = explode(' label "', $lines[$position], 2);
	$bound_flags = sdwan_steering_loaded_tcp_flags($bound_rule);
	for ($i = 0; $i < $position; $i++) {
		$rule = preg_replace('/\s+label "(?:[^"\\\\]|\\\\.)*"/', '', $lines[$i]);
		$flags = sdwan_steering_loaded_tcp_flags($rule);
		if ($flags === null || ($flags !== 'any' && $flags !== $bound_flags)) {
			continue;
		}
		$rule = preg_replace('/(?: flags (?:any|[A-Za-z]*\/[A-Za-z]+))?(?:(?: keep state(?: \((?:if-bound|floating)\))?)| no state)?' .
		    '(?: ridentifier [0-9]+)?$/D', '', $rule);
		if (!preg_match('/^(?:pass|block(?: (?:drop|return\S*(?: \([^)]*\))?))?) (?:in )?(?:log(?: \([^)]*\))? )?quick ' .
		    '(?:on ([A-Za-z0-9_.-]+) )?(?:(inet6?) )?((?:proto [a-z0-9_-]+ )?(?:all|from .+))$/D', $rule, $match)) {
			continue;
		}
		$prior = sdwan_steering_scope_fields(($match[1] ?: $bound['device']) . ' ' .
		    ($match[2] ?: $bound['family']) . ' ' . $match[3]);
		if ($prior !== null && in_array($prior['device'], $devices, true) && $prior['family'] === $bound['family'] &&
		    ($prior['protocol'] === '' || $prior['protocol'] === $bound['protocol']) &&
		    sdwan_preflight_endpoint($prior['source'], $prior['family'], $bound['source']['network'] ?? '') &&
		    sdwan_preflight_endpoint($prior['destination'], $prior['family'], $bound['destination']['network'] ?? '', $same_table) &&
		    sdwan_preflight_endpoint_covers($prior['source'], $bound['source']) &&
		    sdwan_preflight_endpoint_covers($prior['destination'], $bound['destination'])) {
			return true;
		}
	}
	return false;
}

function sdwan_steering_loaded_pass_metadata(string $line, string $rule, array $pair, array $pool, string $group): bool {
	if (isset($pair['gateway_tiers'])) {
		$tier = $pair['gateway_tiers'][$pool[0]] ?? null;
		preg_match_all('/\blabel "((?:[^"\\\\]|\\\\.)*)"/', $line, $labels);
		$gateway_labels = array_values(array_filter($labels[1], static fn($label) => str_starts_with($label, 'gw=')));
		if ($tier === null || $gateway_labels !== ["gw={$tier}:{$group}"]) {
			return false;
		}
	}
	if (isset($pair['state_policy']) && preg_match('/\bkeep state\s+\(([^)]*)\)/', $rule, $options)) {
		foreach (array_map('trim', explode(',', $options[1])) as $option) {
			if (in_array($option, ['if-bound', 'floating'], true) && $option !== $pair['state_policy']) {
				return false;
			}
		}
	}
	return true;
}

function sdwan_steering_pf_status(array $binding, array $state, array $inventory, ?array $lines,
    ?array $rule_pairs = null): string {
	if ($lines === null) {
		return 'unavailable';
	}
	if (!array_key_exists('gateway', $state) || ($state['revision'] ?? null) !== sdwan_config_revision($binding)) {
		return 'pending';
	}
	$target = $state['gateway'];
	$pool = $state['pool'] ?? ($target === null ? [] : [$target]);
	if (!is_array($pool) || !array_is_list($pool) || ($pool[0] ?? null) !== $target) {
		return 'pending';
	}
	$gateways = [];
	foreach ($pool as $name) {
		if (!is_string($name) || !in_array($name, $binding['gateways'], true) ||
		    !isset($inventory[$name])) {
			return 'pending';
		}
		$gateway = $inventory[$name];
		$path = sdwan_steering_resolve_path($gateway);
		if ($path === null) {
			return 'pending';
		}
		$gateways[$path['device']] = array_replace($gateway, $path);
	}
	if (count($gateways) !== count($pool)) {
		return 'pending';
	}
	$matched = [];
	$guards = [];
	$guard_pairs = [];
	$expected_count = 0;
	foreach ($binding['trackers'] as $tracker) {
		$pair = $rule_pairs[$tracker] ?? [];
		$expected_count += count($pair['scope']['protocols'] ?? ['']);
		if (isset($pair['guard'])) {
			$guard_pairs[$pair['guard']] = $pair;
		}
	}
	$lines = array_values($lines);
	foreach ($lines as $position => $line) {
		$identifier = sdwan_steering_rule_tracker($line);
		$is_bound = in_array($identifier, $binding['trackers'], true);
		$pair = $is_bound ? ($rule_pairs[$identifier] ?? []) : ($guard_pairs[$identifier] ?? null);
		if ($pair === null) {
			continue;
		}
		[$rule] = explode(' label "', $line, 2);
		$scope = $rule_pairs === null ? null : sdwan_steering_loaded_scope($rule);
		$protocol = '';
		if (isset($pair['scope'])) {
			$actual = $scope === null ? null : sdwan_steering_scope_fields($scope, true);
			if ($actual === null || !sdwan_steering_scope_matches($actual, $pair['scope'])) {
				return 'pending';
			}
			$protocol = $actual['protocol'];
		}
		$flags_role = !$is_bound ? 'guard' : ($target === null ? 'blocked' : 'pass');
		$expected_flags = $pair['tcp_flags'][$flags_role] ?? null;
		if ($expected_flags !== null && in_array($protocol, ['', 'tcp'], true) &&
		    sdwan_steering_loaded_tcp_flags($rule) !== $expected_flags) {
			return 'pending';
		}
		$key = $identifier . ':' . $protocol;
		if (!$is_bound) {
			if (isset($guards[$key]) || !str_starts_with($rule, 'block ')) {
				return 'pending';
			}
			$guards[$key] = [$position, $scope];
			continue;
		}
		if ($rule_pairs !== null && isset($matched[$key])) {
			return 'pending';
		}
		if ($target === null) {
			if (!preg_match('/^block (?:drop |return\S*(?: \([^)]*\))? )?in (?:log(?: \([^)]*\))? )?quick on /', $rule)) {
				return 'pending';
			}
		} elseif (!sdwan_steering_loaded_path_matches($rule, $gateways) || ($rule_pairs !== null &&
		    (preg_match('/\b(?:no|modulate|synproxy) state(?:\s|$)/', $rule) ||
		    !sdwan_steering_loaded_pass_metadata($line, $rule, $pair, $pool, $binding['group'] ?? '')))) {
			return 'pending';
		}
		$matched[$key] = [$position, $scope, ($pair['guard'] ?? '') . ':' . $protocol, $pair['interface_groups'] ?? []];
	}
	if (count($matched) !== $expected_count) {
		return 'pending';
	}
	if ($rule_pairs !== null) {
		foreach ($matched as [$position, $scope, $guard, $interface_groups]) {
			if (!isset($guards[$guard]) || $scope === null || $guards[$guard][0] <= $position ||
			    $guards[$guard][1] !== $scope || sdwan_steering_loaded_shadow($lines, $position, $scope, $interface_groups)) {
				return 'pending';
			}
		}
	}
	return $target === null ? 'blocked' : 'applied';
}


/* The native state dump includes the originating rule identifier as well as
 * the next hop. Rule ordinals are transient across filter reloads. */
function sdwan_steering_state_ids(iterable $lines, array $trackers, string $device, string $address, int $limit = 64): array {
	$ids = [];
	$record = [];
	$finish = static function (array $state) use ($trackers, $device, $address, $limit, &$ids): void {
		if (count($ids) < $limit && isset($state['tracker'], $state['id'], $state['hop']) &&
		    in_array($state['tracker'], $trackers, true) && $state['hop'][1] === $device &&
		    sdwan_next_hop_matches($state['hop'][0], $address, $device)) {
			$ids[$state['id']] = true;
		}
	};
	foreach ($lines as $line) {
		if (preg_match('/^\S/', $line)) {
			$finish($record);
			$record = [];
		}
		$tracker = sdwan_steering_rule_tracker($line);
		if ($tracker !== null) {
			$record['tracker'] = $tracker;
		}
		if (preg_match('/\bid:\s*([a-f0-9]{1,16})\s+creatorid:\s*([a-f0-9]{1,8})\b/i', $line, $id)) {
			$record['id'] = $id[1] . '/' . $id[2];
		}
		if (preg_match('/\b(?:route-to|rt):\s*([a-f0-9:.]+(?:%[a-z0-9_.-]+)?)@([a-z0-9_.-]+)(?:\s|$)/i', $line, $hop)) {
			$record['hop'] = [$hop[1], $hop[2]];
		}
	}
	$finish($record);
	return array_keys($ids);
}

const SDWAN_AUTO_RECONNECT_STATES = 8;
const SDWAN_AUTO_RECONNECT_WINDOW_NS = 45_000_000_000;
const SDWAN_AUTO_RECONNECT_KILL_BUDGET_NS = 2_000_000_000;

function sdwan_steering_reconnect_timeout(int $remaining_ns): ?string {
	$milliseconds = intdiv(min($remaining_ns, 500_000_000), 1_000_000);
	// A zero FreeBSD timeout duration means no deadline.
	return $milliseconds > 0 ? sprintf('0.%03d', $milliseconds) : null;
}

function sdwan_steering_reconnect_retained(string $group_mode, bool $keep_failover, string $gateway_mode,
    string $failure_mode): bool {
	return ($group_mode !== 'kill' && ($group_mode !== '' || $keep_failover)) ||
	    ($gateway_mode !== 'down' && ($gateway_mode !== '' || ($failure_mode !== '' && $failure_mode !== 'down' &&
	        $failure_mode !== 'all')));
}

function sdwan_steering_auto_reconnect_path(array $gateway): ?array {
	$path = sdwan_steering_resolve_path($gateway);
	return $path !== null &&
	    !preg_match('/^(?:ipsec|ovpn|wg|tun|tap|gre|gif|vxlan|ipip|enc|lo[0-9]|pflog|pfsync)/', $path['device']) &&
	    sdwan_monitor_address($path['address'], $gateway['family'], $path['device'], true) !== null ? $path : null;
}

function sdwan_steering_auto_reconnect_failed(array $config, array $snapshot, array $binding, string $retired,
    string $replacement): bool {
	$policy = array_column($config['policies'], null, 'name')[$binding['policy']] ?? [];
	$members = array_column($config['members'], 'name', 'gateway');
	$candidates = $snapshot['policies'][$binding['policy']]['candidates'] ?? [];
	return ($policy['auto_reconnect'] ?? null) === 'enabled' &&
	    in_array($policy['strategy'] ?? null, ['cost', 'latency'], true) &&
	    $retired !== $replacement &&
	    in_array($retired, $binding['gateways'], true) && in_array($replacement, $binding['gateways'], true) &&
	    in_array($candidates[$members[$retired] ?? ''] ?? null, ['Gateway is down', 'Required service check failed'], true) &&
	    ($candidates[$members[$replacement] ?? ''] ?? null) === 'Eligible';
}

function sdwan_steering_auto_reconnect_transition(?array $before, array $after, array $config, array $snapshot,
    array $binding): bool {
	return $before !== null && $before['revision'] === $after['revision'] &&
	    $after['seen'] >= $before['seen'] && $after['seen'] - $before['seen'] <= SDWAN_AUTO_RECONNECT_WINDOW_NS &&
	    $before['path']['device'] !== $after['path']['device'] &&
	    sdwan_steering_auto_reconnect_failed($config, $snapshot, $binding, $before['gateway'], $after['gateway']);
}

/* A worker retains the most recent applied route while a replacement reload
 * is pending. Only a live PF readback can advance that baseline. */
function sdwan_steering_auto_reconnect(array &$baseline, array $config, array $inventory, array $bindings,
    array $confirmed, array $snapshot, bool $first_confirmation): void {
	$policies = array_column($config['policies'], null, 'name');
	$transition = null;
	$next = [];
	$now = hrtime(true);
	foreach ($bindings as $group => $binding) {
		if (($policies[$binding['policy']]['auto_reconnect'] ?? null) !== 'enabled') {
			continue;
		}
		$revision = sdwan_config_revision($binding);
		$before = $baseline[$group] ?? null;
		if (($before['revision'] ?? null) !== $revision || $now - $before['seen'] > SDWAN_AUTO_RECONNECT_WINDOW_NS) {
			$before = null;
		}
		if (!isset($confirmed[$group])) {
			if ($before !== null) {
				$next[$group] = $before;
			}
			continue;
		}
		$state = $confirmed[$group]['state'];
		$gateway = $state['gateway'] ?? null;
		if ($confirmed[$group]['status'] !== 'applied' || !is_string($gateway) || isset($state['pool']) ||
		    !isset($inventory[$gateway]) || ($path = sdwan_steering_auto_reconnect_path($inventory[$gateway])) === null) {
			continue;
		}
		$after = ['gateway' => $gateway, 'path' => $path, 'revision' => $revision, 'seen' => $now];
		$next[$group] = $after;
		if ($first_confirmation && $transition === null &&
		    sdwan_steering_auto_reconnect_transition($before, $after, $config, $snapshot, $binding)) {
			$transition = [$group, $before, $after];
		}
	}
	// Consume all observed transitions before attempting a single bounded batch.
	$baseline = $next;
	if ($transition !== null) {
		[$group, $before, $after] = $transition;
		$result = sdwan_steering_reconnect($group, $before['gateway'], sdwan_steering_revision(),
		    ['before' => $before, 'after' => $after]);
		if ($result['errors']) {
			sdwan_log_emit(LOG_WARNING, 'Automatic reconnection skipped or incomplete for group ' . sdwan_log_label($group) .
			    '. Confirmed state removals: ' . ($result['count'] ?? 0));
		} elseif ($result['count'] > 0) {
			sdwan_log_emit(LOG_NOTICE, 'Automatic reconnection retired ' . $result['count'] .
			    ' state(s) for group ' . sdwan_log_label($group));
		}
	}
}

function sdwan_steering_reconnect(string $group, string $gateway, string $revision, ?array $transition = null): array {
	$lock = sdwan_lock('sdwan-settings', $transition === null ? 5 : 0);
	if (!is_resource($lock)) {
		return ['errors' => ['SD-WAN settings are busy. Review the current policy and try again.']];
	}
	$filter_lock = null;
	try {
		if ($transition !== null && (!function_exists('try_lock') || !function_exists('unlock') ||
		    !is_resource($filter_lock = try_lock('filter', 0)))) {
			return ['errors' => ['The native filter is busy. Automatic reconnection was skipped.']];
		}
		if (!config_read_file(false, false) || !hash_equals(sdwan_steering_revision(), $revision)) {
			return ['errors' => ['Settings changed. Review the current policy before reconnecting sessions.']];
		}
		$before_config = $transition === null ? null : config_get_path('');
		if ($transition !== null && !is_array($before_config)) {
			return ['errors' => ['The native settings could not be identified.']];
		}
		$binding = sdwan_steering_bindings()[$group] ?? null;
		if ($binding === null || !in_array($gateway, $binding['gateways'], true)) {
			return ['errors' => ['This gateway is outside the active forwarding binding.']];
		}
		$config = sdwan_get_config();
		$inventory = sdwan_gateways();
		$native = sdwan_steering_native($inventory);
		$preview = sdwan_steering_preflight($config, $binding['policy'], $group, $native);
		if ($preview['errors'] || $preview['binding']['rules_revision'] !== $binding['rules_revision'] ||
		    $binding['policy_revision'] !== sdwan_steering_policy_revision($config, $binding['policy'])) {
			return ['errors' => ['The native rules or policy changed. Review the binding before reconnecting sessions.']];
		}
		$snapshot = sdwan_current_snapshot($config, $inventory);
		$state = $snapshot['steering'][$group] ?? [];
		$member = array_column($config['members'], 'name', 'gateway')[$gateway] ?? '';
		$reason = $snapshot['policies'][$binding['policy']]['candidates'][$member] ?? null;
		$pool = $state['pool'] ?? array_filter([$state['gateway'] ?? null]);
		if ($reason === null || $reason === 'Eligible' || in_array($gateway, $pool, true) ||
		    sdwan_steering_pf_status($binding, $state, $inventory, sdwan_steering_pf_rules(), $preview['rule_pairs']) !== 'applied') {
			return ['errors' => ['Reconnect is available after the filter has applied a different eligible gateway.']];
		}
		$metadata = $inventory[$gateway] ?? [];
		$path = sdwan_steering_resolve_path($metadata);
		if ($path === null ||
		    sdwan_monitor_address($path['address'], $metadata['family'], $path['device'], true) === null ||
		    !function_exists('popen') || !function_exists('pclose') || !function_exists('exec')) {
			return ['errors' => ['The previous native next hop cannot be identified.']];
		}
		if ($transition !== null) {
			$before = $transition['before'];
			$after = $transition['after'];
			$group_mode = array_column($native['groups'], 'keep_failover_states', 'name')[$group] ?? '';
			$gateway_mode = array_column(config_get_path('gateways/gateway_item', []), 'gw_down_kill_states', 'name')[$gateway] ?? '';
			$replacement = $inventory[$after['gateway']] ?? [];
			if ($snapshot === null || !isset($snapshot['observed_at_ns']) || isset($state['pool']) ||
			    hrtime(true) - $after['seen'] > 2_000_000_000 ||
			    $state['gateway'] !== $after['gateway'] || $before['gateway'] !== $gateway ||
			    $after['revision'] !== sdwan_config_revision($binding) ||
			    $before['path'] !== sdwan_steering_auto_reconnect_path($metadata) ||
			    $after['path'] !== sdwan_steering_auto_reconnect_path($replacement) ||
			    !sdwan_steering_auto_reconnect_transition($before, $after, $config, $snapshot, $binding) ||
			    sdwan_steering_reconnect_retained((string)$group_mode, config_path_enabled('system', 'keep_failover_states'),
			        (string)$gateway_mode, (string)config_get_path('system/gw_down_kill_states', ''))) {
				return ['errors' => ['The transition or native state policy does not permit automatic reconnection.']];
			}
		}
		$stream = @popen('/bin/timeout 3 /sbin/pfctl -vvss 2>/dev/null', 'r');
		if (!is_resource($stream)) {
			return ['errors' => ['Unable to inspect the active state table.']];
		}
		$lines = static function () use ($stream): Generator {
			while (($line = fgets($stream)) !== false) {
				yield $line;
			}
		};
		$ids = sdwan_steering_state_ids($lines(), $binding['trackers'], $path['device'], $path['address'],
		    $transition === null ? 64 : SDWAN_AUTO_RECONNECT_STATES);
		if (pclose($stream) !== 0) {
			return ['errors' => ['Unable to read the full state table. No states were removed.']];
		}
		$deadline = $transition === null ? null : hrtime(true) + SDWAN_AUTO_RECONNECT_KILL_BUDGET_NS;
		if ($ids && $before_config !== null && sdwan_config_changed_since($before_config)) {
			return ['errors' => ['Native settings changed during the state scan. Automatic reconnection was skipped.']];
		}
		$count = 0;
		foreach ($ids as $id) {
			$lines = [];
			$command = '/bin/timeout 1';
			if ($deadline !== null) {
				$duration = sdwan_steering_reconnect_timeout($deadline - hrtime(true));
				if ($duration === null) {
					return ['errors' => ['Automatic reconnection reached its time limit.'], 'count' => $count];
				}
				$command = '/bin/timeout -s KILL ' . $duration;
			}
			exec($command . ' /sbin/pfctl -k id -k ' . escapeshellarg($id) . ' 2>&1', $lines, $status);
			if ($status !== 0 || !preg_match('/\bkilled\s+([01])\s+states?\b/i', implode("\n", $lines), $match)) {
				$error = ['errors' => ['State recovery could not finish. Review the active states before retrying.']];
				return $deadline === null ? $error : $error + ['count' => $count];
			}
			$count += (int)$match[1];
		}
		return ['errors' => [], 'count' => $count];
	} catch (UnexpectedValueException $error) {
		return ['errors' => [$error->getMessage()]];
	} finally {
		if (is_resource($filter_lock)) {
			unlock($filter_lock);
		}
		sdwan_unlock($lock);
	}
}

/* Exclude ongoing preference timers from the native filter reload signature. */
function sdwan_steering_signature(array $states): string {
	$effective = [];
	foreach ($states as $group => $state) {
		$effective[$group] = [$state['revision'], $state['pool'] ?? $state['gateway']];
	}
	ksort($effective, SORT_STRING);
	return sdwan_config_revision($effective);
}

function sdwan_steering_gateways_for_rule(array $raw, array $rule): array {
	$binding = sdwan_steering_decode($raw);
	if ($binding === null || $binding['group'] !== ($rule['gateway'] ?? null) ||
	    !in_array((string)($rule['tracker'] ?? ''), $binding['trackers'], true)) {
		return [];
	}
	$config = sdwan_get_config();
	$inventory = sdwan_gateways();
	$snapshot = sdwan_current_snapshot($config, $inventory);
	return $snapshot === null ? [] : sdwan_steering_binding_gateways($binding, $config, $snapshot,
	    sdwan_steering_native($inventory));
}

/* The compiler and watchdog use the same approval and decision checks. */
function sdwan_steering_binding_gateways(array $binding, array $config, array $snapshot, array $native,
    ?array &$rule_pairs = null): array {
	$rule_pairs = null;
	if ($binding['policy_revision'] !== sdwan_steering_policy_revision($config, $binding['policy'])) {
		return [];
	}
	$preflight = sdwan_steering_preflight($config, $binding['policy'], $binding['group'], $native);
	if (!sdwan_steering_preflight_matches($binding, $preflight)) {
		return [];
	}
	$rule_pairs = $preflight['rule_pairs'];
	$state = $snapshot['steering'][$binding['group']] ?? [];
	if (($state['revision'] ?? null) !== sdwan_config_revision($binding)) {
		return [];
	}
	$policy = array_column($config['policies'], null, 'name')[$binding['policy']] ?? [];
	$chosen = ($policy['strategy'] ?? null) === 'balance' ? ($state['pool'] ?? []) : [$state['gateway'] ?? null];
	if (!is_array($chosen) || !array_is_list($chosen)) {
		return [];
	}
	$members = array_column($config['members'], null, 'gateway');
	$slas = array_column($config['slas'], null, 'name');
	$sla = $slas[$policy['sla'] ?? ''] ?? null;
	$overrides = array_column($policy['probe_requirements'] ?? [], null, 'member');
	$result = $snapshot['policies'][$binding['policy']] ?? [];
	foreach ($chosen as $gateway) {
		if (!is_string($gateway) || !in_array($gateway, $binding['gateways'], true)) {
			return [];
		}
		$member = $members[$gateway] ?? null;
		$name = $member['name'] ?? '';
		$reason = $result['candidates'][$name] ?? null;
		if ($reason === 'Eligible') {
			continue;
		}
		$degraded = $state['degraded'][$gateway] ?? null;
		$sample = $snapshot['members'][$name] ?? null;
		$checks = $sample['checks'] ?? [];
		if (!is_int($degraded) || $degraded < 1 || $degraded >= (int)($policy['degrade_samples'] ?? 1) ||
		    !in_array($name, $result['soft'] ?? [], true) || !is_string($reason) ||
		    $member === null || $sample === null || $sla === null || !is_array($checks)) {
			return [];
		}
		$requirements = sdwan_policy_probe_requirements($policy, $member, $overrides[$name] ?? []);
		if ($reason !== sdwan_candidate_reason($member, $sample, $sla, $requirements) ||
		    !sdwan_is_wan_quality_breach($reason, $sample, $sla) ||
		    sdwan_service_reason($checks, $requirements) !== 'Eligible') {
			return [];
		}
	}
	return $chosen === array_values(array_unique($chosen)) ? $chosen : [];
}

/* ABI 1 only accepts one gateway and preflight refuses a balancing policy. */
function sdwan_steering_gateway_for_rule(array $raw, array $rule): ?string {
	$chosen = sdwan_steering_gateways_for_rule($raw, $rule);
	return count($chosen) === 1 ? $chosen[0] : null;
}
