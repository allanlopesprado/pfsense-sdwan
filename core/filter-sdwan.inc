<?php
// Core-side interface for a laboratory pfSense build. This file is not a package payload.

const SDWAN_FILTER_PROVIDER = '/usr/local/pkg/sdwan_steering.inc';

function filter_sdwan_binding_api(): int {
	return 2;
}

function filter_sdwan_withdrawal_proof_api(): int {
	return 1;
}

/* Derive route-to solely from the gateway inventory used by this filter reload.
 * An address or interface from a package snapshot must never enter PF syntax. */
function filter_sdwan_gateway_route(array $gateway, mixed $address): ?array {
	$interface = $gateway['interface'] ?? null;
	$family = $gateway['ipprotocol'] ?? null;
	if (!is_string($interface) || !preg_match('/\A[a-zA-Z][a-zA-Z0-9_.-]{0,14}\z/', $interface) ||
	    !in_array($family, ['inet', 'inet6'], true) || !is_string($address) ||
	    isset($gateway['monitor_disable']) || isset($gateway['action_disable']) || isset($gateway['force_down'])) {
		return null;
	}
	$parts = explode('%', $address, 2);
	$ip = $parts[0];
	$flags = $family === 'inet' ? FILTER_FLAG_IPV4 : FILTER_FLAG_IPV6;
	if (filter_var($ip, FILTER_VALIDATE_IP, $flags) === false) {
		return null;
	}
	$packed = inet_pton($ip);
	if (trim($packed, "\0") === '' || ($family === 'inet' &&
	    (ord($packed[0]) === 0 || ord($packed[0]) === 127 || ord($packed[0]) >= 224)) ||
	    ($family === 'inet6' && ($packed === inet_pton('::1') || ord($packed[0]) === 255))) {
		return null;
	}
	$linklocal = $family === 'inet6' && ord($packed[0]) === 0xfe && (ord($packed[1]) & 0xc0) === 0x80;
	if (isset($parts[1]) && (!$linklocal || $parts[1] !== $interface)) {
		return null;
	}
	$next = inet_ntop($packed) . ($linklocal ? '%' . $interface : '');
	return ['family' => $family, 'route' => " route-to ({$interface} {$next}) ",
	    'hop' => "({$interface} {$next})", 'weight' => max(1, min(30, (int)($gateway['weight'] ?? 1)))];
}

function filter_sdwan_pool_route(array $paths, bool $sticky = false): ?string {
	if (!$paths) {
		return null;
	}
	foreach ($paths as $path) {
		if (!is_string($path['hop'] ?? null) || !is_string($path['route'] ?? null) ||
		    !is_int($path['weight'] ?? null) || $path['weight'] < 1 || $path['weight'] > 30) {
			return null;
		}
	}
	if (count($paths) === 1) {
		return reset($paths)['route'];
	}
	$weights = array_column($paths, 'weight');
	$multiplier = min($weights) === 1 && max($weights) > 1 ? 2 : 1;
	if (array_sum($weights) * $multiplier > 384) {
		return null;
	}
	$hops = [];
	foreach ($paths as $path) {
		$hops[] = str_repeat($path['hop'] . ' ', $path['weight'] * $multiplier);
	}
	return ' route-to { ' . implode('', $hops) . '} round-robin ' . ($sticky ? 'sticky-address ' : '');
}

/* An index belongs to a single native generation. Conflicting tracker entries
 * are denied instead of depending on XML order. */
function filter_sdwan_tracker_index(?array $rows = null): array {
	$index = [];
	$rows ??= (array)config_get_path('gateways/sdwan_bindings/item', []);
	foreach ($rows as $binding) {
		$trackers = $binding['trackers']['item'] ?? [];
		$valid = is_array($trackers) && array_is_list($trackers);
		foreach ((array)$trackers as $id) {
			if (is_string($id) || is_int($id)) {
				$key = (string)$id;
				$index[$key] = !$valid || array_key_exists($key, $index) ? false : $binding;
			}
		}
	}
	return $index;
}

/* The native parser reads the persisted file without replacing the current
 * caller's config. Restore its scratch globals after taking the sample. */
function filter_sdwan_read_persisted_bindings(): ?array {
	$keys = ['listtags', 'parsedcfg', 'curpath', 'depth', 'havedata'];
	$state = [];
	foreach ($keys as $key) {
		if (array_key_exists($key, $GLOBALS)) {
			$state[$key] = $GLOBALS[$key];
		}
	}
	try {
		$config = parse_xml_config(g_get('cf_conf_path') . '/config.xml', [g_get('xml_rootobj')]);
	} catch (Throwable) {
		return null;
	} finally {
		foreach ($keys as $key) {
			if (array_key_exists($key, $state)) {
				$GLOBALS[$key] = $state[$key];
			} else {
				unset($GLOBALS[$key]);
			}
		}
	}
	if (!is_array($config) || !$config) {
		return null;
	}
	$section = $config['gateways']['sdwan_bindings'] ?? [];
	if ($section === '' || $section === []) {
		return [];
	}
	$rows = $section['item'] ?? null;
	if (!is_array($rows) || !array_is_list($rows)) {
		return null;
	}
	foreach ($rows as $binding) {
		$trackers = $binding['trackers']['item'] ?? null;
		if (!is_array($trackers) || !array_is_list($trackers) || !$trackers) {
			return null;
		}
		foreach ($trackers as $tracker) {
			if (!is_string($tracker) || !preg_match('/\A[1-9][0-9]{0,9}\z/', $tracker)) {
				return null;
			}
		}
	}
	return $rows;
}

function filter_sdwan_matching_binding(array $memory, array $saved): bool {
	// Native XML represents a single <group> as a list; its editor may use a scalar.
	$normalize = static function (array $binding): array {
		$group = $binding['group'] ?? null;
		if (is_array($group) && array_keys($group) === [0]) {
			$binding['group'] = $group[0];
		}
		ksort($binding, SORT_STRING);
		return $binding;
	};
	return $normalize($memory) === $normalize($saved);
}

function filter_sdwan_begin_reload(?array $persisted_rows = null): void {
	$started = hrtime(true);
	$bindings = filter_sdwan_tracker_index();
	if ($persisted_rows !== null) {
		$saved = filter_sdwan_tracker_index($persisted_rows);
		foreach ($bindings + $saved as $tracker => $_) {
			$current = $bindings[$tracker] ?? null;
			$persisted = $saved[$tracker] ?? null;
			if (!is_array($current) || !is_array($persisted) || !filter_sdwan_matching_binding($current, $persisted)) {
				$bindings[$tracker] = false;
			}
		}
	}
	$trackers = array_map('strval', array_keys($bindings));
	sort($trackers, SORT_STRING);
	$GLOBALS['sdwan_filter_cycle'] = [
	    'bindings' => $bindings, 'choices' => [], 'started_ns' => $started, 'trackers' => $trackers,
	    'persisted_rows' => $persisted_rows,
	];
}

/* Recheck the saved approvals immediately before each PF load, including
 * a retry after the kernel reported a busy transaction. */
function filter_sdwan_precommit(?string $generated_hash): bool {
	$cycle = $GLOBALS['sdwan_filter_cycle'] ?? [];
	$captured = $cycle['persisted_rows'] ?? null;
	$current = filter_sdwan_read_persisted_bindings();
	$trackers = $cycle['trackers'] ?? [];
	$valid = $current !== null && ($current === $captured ||
	    ($current === [] && $captured === null && !$trackers && !filter_sdwan_tracker_index()));
	$label = is_string($generated_hash) && preg_match('/\A[a-f0-9]{16}\z/', $generated_hash) ? $generated_hash : 'unknown';
	$metadata = sprintf('SD-WAN PF load %s pid=%d generation=%d ruleset=%s trackers=%d captured=%d saved=%d.',
	    $valid ? 'approved' : 'rejected', getmypid(), $cycle['started_ns'] ?? 0, $label, count($trackers),
	    $captured === null ? -1 : count($captured), $current === null ? -1 : count($current));
	update_filter_reload_status($metadata);
	if (!$valid || $trackers || $current) {
		logger($valid ? LOG_INFO : LOG_ERR, $metadata, LOG_PREFIX_FILTER);
	}
	return $valid;
}

/* A failed PF transaction can preserve its active rules. An older rules file
 * has no current approval proof for a bound tracker. */
function filter_sdwan_native_fallback_allowed(): bool {
	return empty($GLOBALS['sdwan_filter_cycle']['trackers']) && filter_sdwan_tracker_index() === [] &&
	    filter_sdwan_read_persisted_bindings() === [];
}

/* The native generator labels its default deny rules with the ruleset hash. */
function filter_sdwan_ruleset_hash(array $rules): ?string {
	$hash = null;
	foreach ($rules as $rule) {
		if (!str_starts_with($rule, 'block ') ||
		    !preg_match('/(?:^|\s)label "descr=Default deny rule IPv[46]"(?:\s|$)/', $rule)) {
			continue;
		}
		foreach (get_label_tags_from_rule_string($rule) as $tag) {
			if (!str_starts_with($tag, 'ruleset:')) {
				continue;
			}
			if (!preg_match('/\Aruleset:([a-f0-9]{16})\z/', $tag, $matches) ||
			    ($hash !== null && $hash !== $matches[1])) {
				return null;
			}
			$hash = $matches[1];
		}
	}
	return $hash;
}

function filter_sdwan_withdrawal_proof(?array $reload_result, ?string $generated_hash, array $active_rules): ?array {
	$cycle = $GLOBALS['sdwan_filter_cycle'] ?? [];
	$started = $cycle['started_ns'] ?? null;
	if (($reload_result !== null && $reload_result !== [true, '']) ||
	    !is_int($started) || $started <= 0 || $generated_hash === null ||
	    !preg_match('/\A[a-f0-9]{16}\z/', $generated_hash) ||
	    !preg_match('/^Status:\s+Enabled(?:\s|$)/', $active_rules[0] ?? '') ||
	    filter_sdwan_ruleset_hash($active_rules) !== $generated_hash) {
		return null;
	}
	$trackers = $cycle['trackers'];
	foreach ($trackers as $tracker) {
		if (!preg_match('/\A[1-9][0-9]{0,9}\z/', $tracker)) {
			return null;
		}
	}
	return ['started_ns' => $started, 'trackers' => $trackers, 'ruleset' => $generated_hash];
}

function filter_sdwan_write_withdrawal_proof(string $path, array $proof): void {
	$data = json_encode($proof);
	if ($data === false) {
		return;
	}
	$temp = @tempnam(dirname($path), '.sdwan-filter-');
	if ($temp === false) {
		return;
	}
	try {
		if (@file_put_contents($temp, $data) === strlen($data) && @chmod($temp, 0644)) {
			@rename($temp, $path);
		}
	} finally {
		if (is_file($temp)) {
			@unlink($temp);
		}
	}
}

/* Invoked while the native filter lock is held. Keep this readback independent
 * of the observer lock and leave the native reload outcome intact. */
function filter_sdwan_publish_withdrawal_proof(?array $reload_result, ?string $generated_hash): void {
	if (($reload_result !== null && $reload_result !== [true, '']) || $generated_hash === null ||
	    !is_file(SDWAN_FILTER_PROVIDER) || !function_exists('exec') ||
	    !is_executable('/bin/timeout') || !is_executable('/sbin/pfctl')) {
		return;
	}
	exec("/bin/timeout 2 /bin/sh -c '/sbin/pfctl -si && /sbin/pfctl -sr' 2>/dev/null", $rules, $status);
	if ($status === 0 && ($proof = filter_sdwan_withdrawal_proof($reload_result, $generated_hash, $rules)) !== null) {
		filter_sdwan_write_withdrawal_proof('/var/run/sdwan-filter-commit.json', $proof);
	}
}

/* Look up by tracker even after the regular gateway group editor has removed the
 * gateway field from a rule. Unmatched rules retain the native generator path.
 * false means block. A selected route includes its actual native failover tier. */
function filter_sdwan_rule_route(array $rule, array $routes): array|false|null {
	global $sdwan_filter_cycle;
	$tracker = $rule['tracker'] ?? null;
	if ((!is_int($tracker) && !is_string($tracker)) ||
	    !preg_match('/^[1-9][0-9]{0,9}$/D', (string)$tracker)) {
		return null;
	}
	$bindings = $sdwan_filter_cycle['bindings'] ?? filter_sdwan_tracker_index();
	$match = $bindings[(string)$tracker] ?? null;
	if ($match === false) {
		return false;
	}
	if ($match === null) {
		return null;
	}
	$group = $match['group'] ?? null;
	// The native XML parser represents even a single <group> as a list.
	if (is_array($group) && array_keys($group) === [0]) {
		$group = $group[0];
	}
	$allowed = $match['gateways']['item'] ?? null;
	if (!is_string($group) || $group === '' || ($rule['gateway'] ?? null) !== $group ||
	    !is_array($allowed) || !array_is_list($allowed) || count($allowed) < 2 ||
	    isset($rule['floating']) || !in_array($rule['ipprotocol'] ?? '', ['inet', 'inet6'], true)) {
		return false;
	}
	try {
		if (!is_file(SDWAN_FILTER_PROVIDER)) {
			return false;
		}
		if (!function_exists('sdwan_steering_gateway_for_rule')) {
			require_once(SDWAN_FILTER_PROVIDER);
		}
		/* Snapshot publication may race a reload. Keep all trackers in one
		 * binding on the same choice for this ruleset, including a denial. */
		$key = hash('sha256', serialize($match));
		if ($sdwan_filter_cycle !== null && array_key_exists($key, $sdwan_filter_cycle['choices'])) {
			$chosen = $sdwan_filter_cycle['choices'][$key];
		} else {
			$chosen = function_exists('sdwan_steering_gateways_for_rule')
			    ? sdwan_steering_gateways_for_rule($match, $rule)
			    : array_values(array_filter([sdwan_steering_gateway_for_rule($match, $rule)], 'is_string'));
			if ($sdwan_filter_cycle !== null) {
				$sdwan_filter_cycle['choices'][$key] = $chosen;
			}
		}
		if (!is_array($chosen) || !$chosen) {
			return false;
		}
		$native = array_filter(config_get_path('gateways/gateway_group', []),
		    static fn($entry) => ($entry['name'] ?? null) === $group);
		if (count($native) !== 1) {
			return false;
		}
		$tiers = [];
		foreach (reset($native)['item'] ?? [] as $entry) {
			$parts = is_string($entry) ? explode('|', $entry, 3) : [];
			if (in_array($parts[1] ?? null, ['1', '2', '3', '4', '5'], true)) {
				$tiers[$parts[0]] = $parts[1];
			}
		}
		$tier = null;
		$paths = [];
		foreach ($chosen as $gateway) {
			if (!is_string($gateway) || !in_array($gateway, $allowed, true) || !isset($tiers[$gateway]) ||
			    isset($paths[$gateway]) || ($routes[$gateway]['family'] ?? '') !== $rule['ipprotocol'] ||
			    ($tier !== null && $tier !== $tiers[$gateway])) {
				return false;
			}
			$tier = $tiers[$gateway];
			$paths[$gateway] = $routes[$gateway];
		}
		$route = filter_sdwan_pool_route($paths, config_path_enabled('system', 'lb_use_sticky'));
		return $route === null ? false : ['route' => $route, 'tier' => $tier];
	} catch (Throwable $e) {
		error_log('SD-WAN: bound rule ' . $tracker . ' blocked during filter generation: ' . $e->getMessage());
	}
	return false;
}
