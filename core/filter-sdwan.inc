<?php
// Core-side interface for a laboratory pfSense build. This file is not a package payload.

function filter_sdwan_binding_api(): int {
	return 2;
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

function filter_sdwan_pool_route(array $paths): ?string {
	if (count($paths) === 1) {
		return reset($paths)['route'];
	}
	if (!$paths) {
		return null;
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
	return ' route-to { ' . implode('', $hops) . '} round-robin ';
}

/* An index belongs to a single native generation. Conflicting tracker entries
 * are denied instead of depending on XML order. */
function filter_sdwan_tracker_index(): array {
	$index = [];
	foreach ((array)config_get_path('gateways/sdwan_bindings/item', []) as $binding) {
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

function filter_sdwan_begin_reload(): void {
	$GLOBALS['sdwan_filter_cycle'] = ['bindings' => filter_sdwan_tracker_index(), 'choices' => []];
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
		$provider = '/usr/local/pkg/sdwan_steering.inc';
		if (!is_file($provider)) {
			return false;
		}
		if (!function_exists('sdwan_steering_gateway_for_rule')) {
			require_once($provider);
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
		$route = filter_sdwan_pool_route($paths);
		return $route === null ? false : ['route' => $route, 'tier' => $tier];
	} catch (Throwable $e) {
		error_log('SD-WAN: bound rule ' . $tracker . ' blocked during filter generation: ' . $e->getMessage());
	}
	return false;
}
