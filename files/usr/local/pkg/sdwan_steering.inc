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
		return ['Forwarding requires a supported native pfSense steering integration.'];
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
			$updated = array_values(array_filter($rows, static fn($row) =>
			    sdwan_steering_group($row['group'] ?? null) !== $group));
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
			sdwan_log_event('binding_error');
			return ['pfSense could not save the forwarding binding.'];
		}
	} finally {
		unlock($lock);
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
	$policies = array_column($config['policies'], 'strategy', 'name');
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
	if (($policies[$binding['policy']] ?? null) === 'balance') {
		$pool = array_values(array_intersect($binding['gateways'], $eligible));
		return ['revision' => $revision, 'gateway' => $pool[0] ?? null, 'pool' => $pool];
	}
	$step = sdwan_steering_step(($old['revision'] ?? null) === $revision ? $old : [], $eligible, $best, $now);
	return ['revision' => $revision] + $step;
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
	foreach (sdwan_steering_bindings() as $group => $binding) {
		$check = sdwan_steering_preflight($config, $binding['policy'], $group, $native);
		$approved = sdwan_steering_preflight_matches($binding, $check);
		if ($approved) {
			$rule_pairs[$group] = $check['rule_pairs'];
		}
		$result = $approved ? ($snapshot['policies'][$binding['policy']] ?? []) : [];
		$states[$group] = sdwan_steering_state($config, $binding, $result, $previous[$group] ?? [], $snapshot['generated_at']);
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
	exec("/bin/timeout 2 /bin/sh -c '/sbin/pfctl -si && /sbin/pfctl -sr' 2>/dev/null", $lines, $status);
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
	$raw = @file_get_contents($path, false, null, 0, 1024);
	$data = is_string($raw) ? json_decode($raw, true) : null;
	if (!is_array($data) || !is_string($data['signature'] ?? null) ||
	    !preg_match('/\A[a-f0-9]{64}\z/', $data['signature']) ||
	    !is_int($data['attempts'] ?? null) || $data['attempts'] < 0 ||
	    $data['attempts'] > SDWAN_RELOAD_MAX_ATTEMPTS ||
	    !is_int($data['requested_at'] ?? null) || $data['requested_at'] < 0 ||
	    !is_bool($data['accepted'] ?? null) || !is_bool($data['confirmed'] ?? null)) {
		return [];
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
		if (!$trackers) {
			return $startup || !is_file($path) || unlink($path);
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
			return !is_file($path) || unlink($path);
		}
		/* Reuse the startup signature so stop and restart share the retry budget. */
		$signature = sdwan_config_revision(['startup', array_keys($trackers)]);
		$receipt = sdwan_steering_read_receipt($path);
		$now = time();
		if (($receipt['signature'] ?? null) !== $signature || $receipt['requested_at'] > $now ||
		    $now - $receipt['requested_at'] >= SDWAN_STARTUP_RETRY_WINDOW) {
			$receipt = ['signature' => $signature, 'attempts' => 0, 'requested_at' => 0,
			    'accepted' => false, 'confirmed' => false];
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
				return !is_file($path) || unlink($path);
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
	if (!preg_match('/^(?:pass|block(?: (?:drop|return\S*(?: \([^)]*\))?))?) in (?:log(?: \([^)]*\))? )?quick on ([a-z0-9_.-]+) (.+)$/D',
	    $rule, $parts)) {
		return null;
	}
	$match = preg_replace('/^route-to\s+(?:\{[^}]+\}\s+round-robin(?:\s+sticky-address)?|\([^()]+\))\s+/', '', $parts[2]);
	[$selectors] = preg_split('/\s+(?:flags|keep state|no state|modulate state|synproxy state|ridentifier|dnpipe|queue)(?=\s)/',
	    $match, 2);
	return preg_match('/^inet6?\s/', $selectors) ? $parts[1] . ' ' . trim(preg_replace('/\s+/', ' ', $selectors)) : null;
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
	$guard_ids = array_column($rule_pairs ?? [], 'guard');
	foreach (array_values($lines) as $position => $line) {
		$identifier = sdwan_steering_rule_tracker($line);
		if (!in_array($identifier, $binding['trackers'], true)) {
			if (in_array($identifier, $guard_ids, true)) {
				[$rule] = explode(' label "', $line, 2);
				if (isset($guards[$identifier]) || !str_starts_with($rule, 'block ')) {
					return 'pending';
				}
				$guards[$identifier] = [$position, sdwan_steering_loaded_scope($rule)];
			}
			continue;
		}
		if ($rule_pairs !== null && isset($matched[$identifier])) {
			return 'pending';
		}
		[$rule] = explode(' label "', $line, 2);
		if ($target === null) {
			if (!preg_match('/^block (?:drop |return\S*(?: \([^)]*\))? )?in (?:log(?: \([^)]*\))? )?quick on /', $rule) ||
			    ($rule_pairs !== null && empty($rule_pairs[$identifier]['explicit_tcp_flags']) &&
			    preg_match('/\bflags\s+(?!any(?:\s|$))\S+/', $rule))) {
				return 'pending';
			}
		} elseif (!sdwan_steering_loaded_path_matches($rule, $gateways) || ($rule_pairs !== null &&
		    (preg_match('/\b(?:no|modulate|synproxy) state(?:\s|$)/', $rule) ||
		    !sdwan_steering_loaded_pass_metadata($line, $rule, $rule_pairs[$identifier] ?? [], $pool, $binding['group'] ?? '')))) {
			return 'pending';
		}
		$matched[$identifier] = [$position, $rule_pairs === null ? null : sdwan_steering_loaded_scope($rule)];
	}
	if (count($matched) !== count($binding['trackers'])) {
		return 'pending';
	}
	if ($rule_pairs !== null) {
		foreach ($matched as $identifier => [$position, $scope]) {
			$guard = $rule_pairs[$identifier]['guard'] ?? '';
			if (!isset($guards[$guard]) || $scope === null || $guards[$guard][0] <= $position ||
			    $guards[$guard][1] !== $scope) {
				return 'pending';
			}
		}
	}
	return $target === null ? 'blocked' : 'applied';
}


/* The native state dump includes the originating rule identifier as well as
 * the next hop. Rule ordinals are transient across filter reloads. */
function sdwan_steering_state_ids(iterable $lines, array $trackers, string $device, string $address): array {
	$ids = [];
	$record = [];
	$finish = static function (array $state) use ($trackers, $device, $address, &$ids): void {
		if (count($ids) < 64 && isset($state['tracker'], $state['id'], $state['hop']) &&
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

function sdwan_steering_reconnect(string $group, string $gateway, string $revision): array {
	$lock = try_lock('sdwan-settings', 5);
	if (!is_resource($lock)) {
		return ['errors' => ['SD-WAN settings are busy. Review the current policy and try again.']];
	}
	try {
		if (!config_read_file(false, false) || !hash_equals(sdwan_steering_revision(), $revision)) {
			return ['errors' => ['Settings changed. Review the current policy before reconnecting sessions.']];
		}
		$binding = sdwan_steering_bindings()[$group] ?? null;
		if ($binding === null || !in_array($gateway, $binding['gateways'], true)) {
			return ['errors' => ['This gateway is outside the active forwarding binding.']];
		}
		$config = sdwan_get_config();
		$inventory = sdwan_gateways();
		$preview = sdwan_steering_preflight($config, $binding['policy'], $group, sdwan_steering_native($inventory));
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
		$stream = @popen('/bin/timeout 3 /sbin/pfctl -vvss 2>/dev/null', 'r');
		if (!is_resource($stream)) {
			return ['errors' => ['Unable to inspect the active state table.']];
		}
		$lines = static function () use ($stream): Generator {
			while (($line = fgets($stream)) !== false) {
				yield $line;
			}
		};
		$ids = sdwan_steering_state_ids($lines(), $binding['trackers'], $path['device'], $path['address']);
		if (pclose($stream) !== 0) {
			return ['errors' => ['Unable to read the full state table. No states were removed.']];
		}
		$count = 0;
		foreach ($ids as $id) {
			$lines = [];
			exec('/bin/timeout 1 /sbin/pfctl -k id -k ' . escapeshellarg($id) . ' 2>&1', $lines, $status);
			if ($status !== 0 || !preg_match('/\bkilled\s+([01])\s+states?\b/i', implode("\n", $lines), $match)) {
				return ['errors' => ['State recovery could not finish. Review the active states before retrying.']];
			}
			$count += (int)$match[1];
		}
		return ['errors' => [], 'count' => $count];
	} finally {
		unlock($lock);
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
	if ($snapshot === null || $binding['policy_revision'] !== sdwan_steering_policy_revision($config, $binding['policy'])) {
		return [];
	}
	$preflight = sdwan_steering_preflight($config, $binding['policy'], $binding['group'], sdwan_steering_native($inventory));
	if ($preflight['errors'] || $preflight['binding']['rules_revision'] !== $binding['rules_revision'] ||
	    $preflight['binding']['gateways'] !== $binding['gateways'] ||
	    $preflight['binding']['trackers'] !== $binding['trackers']) {
		return [];
	}
	$state = $snapshot['steering'][$binding['group']] ?? [];
	if (($state['revision'] ?? null) !== sdwan_config_revision($binding)) {
		return [];
	}
	$strategy = array_column($config['policies'], 'strategy', 'name')[$binding['policy']] ?? null;
	$chosen = $strategy === 'balance' ? ($state['pool'] ?? []) : [$state['gateway'] ?? null];
	if (!is_array($chosen) || !array_is_list($chosen)) {
		return [];
	}
	$members = array_column($config['members'], 'name', 'gateway');
	$reasons = $snapshot['policies'][$binding['policy']]['candidates'] ?? [];
	foreach ($chosen as $gateway) {
		if (!is_string($gateway) || !in_array($gateway, $binding['gateways'], true) ||
		    ($reasons[$members[$gateway] ?? ''] ?? null) !== 'Eligible') {
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
