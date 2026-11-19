<?php
// Core-side interface for a laboratory pfSense build. This file is not a package payload.

function filter_sdwan_binding_api(): int {
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
	return ['family' => $family, 'route' => " route-to ({$interface} {$next}) "];
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
			$chosen = sdwan_steering_gateway_for_rule($match, $rule);
			if ($sdwan_filter_cycle !== null) {
				$sdwan_filter_cycle['choices'][$key] = $chosen;
			}
		}
		if (!is_string($chosen) || !in_array($chosen, $allowed, true) ||
		    ($routes[$chosen]['family'] ?? '') !== $rule['ipprotocol']) {
			return false;
		}
		$native = array_filter(config_get_path('gateways/gateway_group', []),
		    static fn($entry) => ($entry['name'] ?? null) === $group);
		if (count($native) !== 1) {
			return false;
		}
		foreach (reset($native)['item'] ?? [] as $entry) {
			$parts = is_string($entry) ? explode('|', $entry, 3) : [];
			if (($parts[0] ?? null) === $chosen && in_array($parts[1] ?? null, ['1', '2', '3', '4', '5'], true)) {
				return ['route' => $routes[$chosen]['route'], 'tier' => $parts[1]];
			}
		}
	} catch (Throwable $e) {
		error_log('SD-WAN: bound rule ' . $tracker . ' blocked during filter generation: ' . $e->getMessage());
	}
	return false;
}
