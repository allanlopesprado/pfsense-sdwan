<?php

/* Every probe uses an explicitly routed destination IP. */
function sdwan_probe_target($value): ?array {
	if (!is_string($value) || strlen($value) > 512) {
		return null;
	}
	$fib = [];
	if (preg_match('/\Afib=([1-9][0-9]{0,4}) (.+)\z/D', $value, $prefix)) {
		if ((int)$prefix[1] > 65535) {
			return null;
		}
		$fib = ['fib' => (int)$prefix[1]];
		$value = $prefix[2];
	}
	if (preg_match('~\Atcp://(\[[A-Fa-f0-9:.]+\]|[0-9.]+):([1-9][0-9]{0,4})\z~D', $value, $parts)) {
		$address = trim($parts[1], '[]');
		$port = (int) $parts[2];
		if ($port > 65535 || str_starts_with($parts[1], '[') !== str_contains($address, ':')) {
			return null;
		}
		$target = ['protocol' => 'tcp', 'port' => $port];
	} elseif (preg_match('~\A(https|dns)://([A-Za-z0-9.-]+)(/[^ \x00-\x20\x7f#]*)? ([A-Fa-f0-9:.]+)(?: expect=([A-Za-z0-9._:-]{1,64}))?\z~D', $value, $parts)) {
		[, $protocol, $host, $path, $address] = $parts;
		if (strlen($host) > 253 || !preg_match('/\A(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?\z/iD', $host) ||
		    ($protocol === 'dns' && ($path !== '' || isset($parts[5]))) ||
		    ($protocol === 'https' && !sdwan_probe_https_path_valid($path))) {
			return null;
		}
		$target = ['protocol' => $protocol, 'host' => strtolower($host), 'path' => $path ?: '/'];
		if (isset($parts[5])) {
			$target['expect'] = $parts[5];
		}
	} else {
		return null;
	}
	if (filter_var($address, FILTER_VALIDATE_IP) === false) {
		return null;
	}
	$packed = inet_pton($address);
	$ipv6 = strlen($packed) === 16;
	if ($ipv6 ? ($packed === inet_pton('::') || $packed === inet_pton('::1') || ord($packed[0]) === 255 ||
	    str_starts_with($packed, str_repeat("\0", 10) . "\xff\xff") ||
	    (ord($packed[0]) === 254 && (ord($packed[1]) & 192) === 128)) :
	    (ord($packed[0]) === 0 || ord($packed[0]) === 127 || ord($packed[0]) >= 224 ||
	    (ord($packed[0]) === 169 && ord($packed[1]) === 254))) {
		return null;
	}
	return $target + ['address' => inet_ntop($packed), 'family' => $ipv6 ? 'inet6' : 'inet'] + $fib;
}

function sdwan_probe_https_path_valid(string $value): bool {
	if (preg_match('~[^\x21-\x7e]|%(?![0-9a-f]{2})~i', $value) ||
	    str_contains($value, '\\') || preg_match('~[\x00-\x1f\x7f]~', rawurldecode($value))) {
		return false;
	}
	[$path] = explode('?', $value, 2);
	/* Reject encoded separators and double encoding before checking segments. */
	return !str_starts_with($path, '//') &&
	    !preg_match('~%(?:25|2f|3f|23|5c)~i', $path) &&
	    !preg_match('~(?:^|/)\.{1,2}(?:/|;|$)~', rawurldecode($path));
}

function sdwan_probe_https_marker_matches(string $body, string $marker): bool {
	return $body === $marker || $body === $marker . "\n" || $body === $marker . "\r\n";
}

/* A writable asynchronous socket can signal either a connection or a refusal. */
function sdwan_probe_tcp_status($socket): ?bool {
	$read = null;
	$write = $except = [$socket];
	$ready = @stream_select($read, $write, $except, 0, 0);
	return $ready === 0 ? null : ($ready !== false && !$except && $write &&
	    @stream_socket_get_name($socket, true) !== false);
}

function sdwan_probe_route_matches(string $output, string $device, string $next_hop, ?string $direct_target = null): bool {
	if (!preg_match('/^[ \t]*flags:[ \t]*<([^>\r\n]+)>/m', $output, $route_flags)) {
		return false;
	}
	$flags = array_map('trim', explode(',', $route_flags[1]));
	if (!in_array('UP', $flags, true) || !in_array('HOST', $flags, true) ||
	    in_array('REJECT', $flags, true) || in_array('BLACKHOLE', $flags, true)) {
		return false;
	}
	if (!preg_match('/^[ \t]*interface:[ \t]*(\S+)[ \t]*\r?$/m', $output, $route_device) || $route_device[1] !== $device) {
		return false;
	}
	if (preg_match('/^[ \t]*gateway:([^\r\n]*)/m', $output, $route_gateway)) {
		return sdwan_next_hop_matches(trim($route_gateway[1]), $next_hop, $device);
	}
	/* route(8) omits the gateway field for interface routes. Only a live PPP
	 * device can use this form, and the route must pin the exact destination. */
	return $direct_target !== null && !in_array('GATEWAY', $flags, true) &&
	    preg_match('/^[ \t]*destination:[ \t]*(\S+)[ \t]*\r?$/m', $output, $route_destination) &&
	    sdwan_next_hop_matches($route_destination[1], $direct_target, $device);
}

function sdwan_probe_dns_question(string $name): string {
	$question = '';
	foreach (explode('.', $name) as $label) {
		$question .= chr(strlen($label)) . $label;
	}
	return $question . "\0" . pack('nn', 1, 1);
}

/* Expand a bounded DNS name, retaining label boundaries for comparisons. */
function sdwan_probe_dns_name(string $packet, int &$offset): ?string {
	$size = strlen($packet);
	$cursor = $offset;
	$end = null;
	$jumps = 0;
	$name = '';
	while ($cursor < $size && strlen($name) < 255) {
		$length = ord($packet[$cursor]);
		if (($length & 0xc0) === 0xc0) {
			if ($cursor + 1 >= $size) {
				return null;
			}
			$pointer = (($length & 0x3f) << 8) | ord($packet[$cursor + 1]);
			if ($pointer < 12 || $pointer >= $cursor || ++$jumps > 32) {
				return null;
			}
			$end ??= $cursor + 2;
			$cursor = $pointer;
			continue;
		}
		if ($length > 63 || $cursor + 1 + $length > $size) {
			return null;
		}
		if ($length === 0) {
			$offset = $end ?? ($cursor + 1);
			return $name . "\0";
		}
		$name .= chr($length) . strtolower(substr($packet, $cursor + 1, $length));
		$cursor += $length + 1;
	}
	return null;
}

function sdwan_probe_dns_answer(string $reply, int $id, string $question): bool {
	$size = strlen($reply);
	$offset = 12 + strlen($question);
	if ($size <= $offset) {
		return false;
	}
	$header = unpack('nid/nflags/nquestions/nanswers', $reply);
	if ($header['id'] !== $id || ($header['flags'] & 0xfa0f) !== 0x8000 ||
	    $header['questions'] !== 1 || $header['answers'] > 128 ||
	    substr($reply, 12, strlen($question)) !== $question) {
		return false;
	}
	$addresses = $aliases = [];
	for ($i = 0; $i < $header['answers']; $i++) {
		$owner = sdwan_probe_dns_name($reply, $offset);
		if ($owner === null || $offset + 10 > $size) {
			return false;
		}
		$rr = unpack('ntype/nclass/Nttl/nlength', $reply, $offset);
		$offset += 10;
		$end = $offset + $rr['length'];
		if ($end > $size) {
			return false;
		}
		if ($rr['class'] === 1 && $rr['type'] === 1 && $rr['length'] === 4) {
			$addresses[$owner] = true;
		} elseif ($rr['class'] === 1 && $rr['type'] === 5) {
			$alias = sdwan_probe_dns_name($reply, $offset);
			if ($alias === null || $offset !== $end || (isset($aliases[$owner]) && $aliases[$owner] !== $alias)) {
				return false;
			}
			$aliases[$owner] = $alias;
		}
		$offset = $end;
	}
	$name = strtolower(substr($question, 0, -4));
	while (isset($aliases[$name])) {
		$target = $aliases[$name];
		unset($aliases[$name]); // This also bounds a loop in a CNAME chain.
		if (isset($addresses[$name])) {
			return false;
		}
		$name = $target;
	}
	return isset($addresses[$name]);
}

function sdwan_probe_remaining_us(int $deadline): int {
	return max(0, intdiv($deadline - hrtime(true), 1000));
}

function sdwan_probe_fib_supported(): bool {
	return PHP_OS_FAMILY === 'BSD' && function_exists('proc_open') && is_executable('/usr/sbin/setfib') &&
	    is_executable('/usr/local/bin/php') && is_readable(__DIR__ . '/sdwan_probe_worker.php');
}

/* All sockets are bound to the live interface source. Require a native host
 * route pinned to the gateway or its PPP link, and check it again before accepting results. */
function sdwan_probe_path(array $target, array $gateway, ?int $deadline = null): ?array {
	$family = $target['family'];
	$fib = $target['fib'] ?? 0;
	if (($deadline !== null && hrtime(true) >= $deadline) ||
	    !in_array($family, ['inet', 'inet6'], true) || $family !== ($gateway['family'] ?? null) ||
	    !is_int($fib) || $fib < 0 || $fib > 65535 || ($fib > 0 && !sdwan_probe_fib_supported()) ||
	    !function_exists('exec') ||
	    !is_executable('/sbin/route') || !is_executable('/bin/timeout')) {
		return null;
	}
	$interface = $gateway['interface'];
	$device = get_real_interface($interface, $family, false, true);
	if (!is_string($device) || $device === '') {
		return null;
	}
	$source = $family === 'inet' ? find_interface_ip($device, true) : find_interface_ipv6($device, true);
	$source = is_string($source) ? sdwan_monitor_address($source, $family, $device, false) : null;
	if ($source === null || in_array($source, ['0.0.0.0', '::'], true) || str_contains($source, '%')) {
		return null;
	}
	$next = $gateway['address'];
	if ($next === 'dynamic') {
		$next = $family === 'inet' ? get_interface_gateway($interface) : get_interface_gateway_v6($interface);
	}
	$next = is_string($next) ? sdwan_monitor_address($next, $family, $device, true) : null;
	if ($next === null) {
		return null;
	}
	$timeout = $deadline === null ? 300000 : min(300000, sdwan_probe_remaining_us($deadline));
	if ($timeout === 0) {
		return null;
	}
	$seconds = sprintf('%.6F', $timeout / 1000000);
	exec('/bin/timeout ' . $seconds . ' /sbin/route -n get -' . $family . ' ' .
	    escapeshellarg($target['address']) . ($fib > 0 ? " -fib {$fib}" : '') . ' 2>/dev/null', $lines, $result);
	if ($result !== 0) {
		return null;
	}
	$output = implode("\n", $lines);
	$direct_target = null;
	if (function_exists('interface_isppp_type') && interface_isppp_type($interface) && function_exists('pfSense_get_ifaddrs')) {
		$interface_data = pfSense_get_ifaddrs($device);
		if (($interface_data['pointtopoint'] ?? null) === 1 && ($interface_data['status'] ?? null) === 'up') {
			$direct_target = $target['address'];
		}
	}
	return sdwan_probe_route_matches($output, $device, $next, $direct_target) &&
	    ($deadline === null || hrtime(true) <= $deadline)
	    ? ['device' => $device, 'source' => $source, 'next_hop' => $next] : null;
}

function sdwan_probe_result(array $job, bool $replied, string $failure, int $deadline): string {
	if (sdwan_probe_path($job['target'], $job['gateway'], $deadline) !== $job['path']) {
		return 'Path not verified';
	}
	return $replied ? 'Passed' : $failure;
}

/* Keep per-socket FIB selection out of the observer process. The worker
 * creates and verifies its own sockets after setfib has selected the table. */
function sdwan_probe_fib_start(int $fib, string $value, array $gateway, int $deadline): ?array {
	if (!sdwan_probe_fib_supported()) {
		return null;
	}
	$query = json_encode([$value, array_intersect_key($gateway, ['interface' => true, 'family' => true,
	    'address' => true]), $deadline], JSON_THROW_ON_ERROR);
	if (strlen($query) > 4096) {
		return null;
	}
	$worker = @proc_open(['/usr/sbin/setfib', '-F', (string)$fib, '/usr/local/bin/php',
	    __DIR__ . '/sdwan_probe_worker.php'], [['pipe', 'r'], ['pipe', 'w'], ['file', '/dev/null', 'w']], $pipes);
	if (!is_resource($worker)) {
		return null;
	}
	$written = @fwrite($pipes[0], $query);
	fclose($pipes[0]);
	if ($written !== strlen($query) || !stream_set_blocking($pipes[1], false)) {
		sdwan_probe_fib_close($worker, $pipes[1], true);
		return null;
	}
	return ['worker' => $worker, 'worker_output' => $pipes[1]];
}

function sdwan_probe_fib_close($worker, $output, bool $running): void {
	if ($running) {
		proc_terminate($worker, 9);
	}
	fclose($output);
	proc_close($worker);
}

/* Start pending HTTPS work and consume ready replies without waiting for I/O. */
function sdwan_probe_collect_ready(array &$jobs, array &$results, $curl, int $deadline): void {
	if (!$jobs || hrtime(true) >= $deadline) {
		return;
	}
	if ($curl !== null) {
		curl_multi_exec($curl, $running);
	}
	foreach ($jobs as $index => $job) {
		if (hrtime(true) >= $deadline) {
			return;
		}
		if (isset($job['worker'])) {
			$status = proc_get_status($job['worker']);
			if ($status['running']) {
				continue;
			}
			$reply = stream_get_contents($job['worker_output'], 64);
			sdwan_probe_fib_close($job['worker'], $job['worker_output'], false);
			$results[$job['member']][$job['field']] = $status['exitcode'] === 0 && is_string($reply) &&
			    in_array($reply, ["Passed\n", "Unavailable\n", "No matching host route or source\n",
			    "Path not verified\n", "TCP check failed\n", "DNS check failed\n", "HTTPS check failed\n",
			    "HTTPS response marker mismatch\n", "Timed out\n"], true)
			    ? rtrim($reply, "\n") : 'Routing table unavailable';
			unset($jobs[$index]);
			continue;
		}
		if (!isset($job['socket'])) {
			continue;
		}
		if ($job['target']['protocol'] === 'tcp') {
			$replied = sdwan_probe_tcp_status($job['socket']);
			if ($replied === null) {
				continue;
			}
			$failure = 'TCP check failed';
		} else {
			$reply = @fread($job['socket'], 4096);
			if (!is_string($reply) || $reply === '') {
				continue;
			}
			$replied = sdwan_probe_dns_answer($reply, $job['id'], $job['question']);
			$failure = 'DNS check failed';
		}
		$results[$job['member']][$job['field']] = sdwan_probe_result($job, $replied, $failure, $deadline);
		fclose($job['socket']);
		unset($jobs[$index]);
	}
	while ($curl !== null && hrtime(true) < $deadline && ($done = curl_multi_info_read($curl))) {
		foreach ($jobs as $index => $job) {
			if (($job['curl'] ?? null) !== $done['handle']) {
				continue;
			}
			$status = curl_getinfo($job['curl'], CURLINFO_RESPONSE_CODE);
			$peer = curl_getinfo($job['curl'], CURLINFO_PRIMARY_IP);
			$source = curl_getinfo($job['curl'], CURLINFO_LOCAL_IP);
			$replied = $done['result'] === CURLE_OK && $status >= 200 && $status < 300 &&
			    is_string($peer) && filter_var($peer, FILTER_VALIDATE_IP) !== false &&
			    inet_pton($peer) === inet_pton($job['target']['address']) &&
			    is_string($source) && filter_var($source, FILTER_VALIDATE_IP) !== false &&
			    inet_pton($source) === inet_pton($job['path']['source']);
			$failure = 'HTTPS check failed';
			if ($replied && isset($job['target']['expect']) &&
			    ($job['body']->oversized || !sdwan_probe_https_marker_matches($job['body']->value, $job['target']['expect']))) {
				$replied = false;
				$failure = 'HTTPS response marker mismatch';
			}
			$results[$job['member']][$job['field']] = sdwan_probe_result($job, $replied, $failure, $deadline);
			curl_multi_remove_handle($curl, $job['curl']);
			unset($jobs[$index]);
			break;
		}
	}
}

function sdwan_probe_secondary_first(array $config): array {
	$members = array_column($config['members'], null, 'name');
	$required = [];
	foreach ($config['policies'] as $policy) {
		$overrides = array_column($policy['probe_requirements'] ?? [], null, 'member');
		foreach ($policy['members'] as $name) {
			$member = $members[$name] ?? null;
			if ($member === null) {
				continue;
			}
			$slots = sdwan_policy_probe_requirements($policy, $member, $overrides[$name] ?? []);
			$required[$name] = ($required[$name] ?? []) + array_filter($slots, static fn($mode) => $mode === 'required');
		}
	}
	return array_filter($required, static fn($slots) => isset($slots['probe_secondary']) && !isset($slots['probe_primary']));
}

function sdwan_probe_observe(array $members, array $inventory, array $observations, array $secondary_first = [],
    ?int $deadline = null, int $active_fib = 0): array {
	$results = $jobs = [];
	$curl = function_exists('curl_multi_init') ? curl_multi_init() : null;
	$deadline ??= hrtime(true) + 2500000000;
	/* Give every member a chance at one result before running backups. */
	$fields = ['probe_primary', 'probe_secondary'];
	foreach ([0, 1] as $position) {
		foreach ($members as $member) {
			$name = $member['name'];
			$field = $fields[isset($secondary_first[$name]) ? 1 - $position : $position];
			if (!isset($member[$field])) {
				continue;
			}
			sdwan_probe_collect_ready($jobs, $results, $curl, $deadline);
			$gateway = $inventory[$member['gateway']] ?? null;
			$target = sdwan_probe_target($member[$field]);
			$results[$name][$field] = 'Unavailable';
			if ($target === null || $gateway === null ||
			    ($observations[$member['gateway']]['status'] ?? null) !== 'online' || hrtime(true) >= $deadline) {
				continue;
			}
			$fib = $target['fib'] ?? 0;
			if ($fib !== $active_fib) {
				if ($active_fib !== 0) {
					continue;
				}
				$worker = sdwan_probe_fib_start($fib, $member[$field], $gateway, $deadline);
				if ($worker === null) {
					$results[$name][$field] = 'Routing table unavailable';
				} else {
					$jobs[] = ['member' => $name, 'field' => $field] + $worker;
				}
				continue;
			}
			$path = sdwan_probe_path($target, $gateway, $deadline);
			$remaining = sdwan_probe_remaining_us($deadline);
			if ($remaining === 0) {
				continue;
			}
			if ($path === null) {
				$results[$name][$field] = 'No matching host route or source';
				continue;
			}
			$source = $path['source'];
			$ipv6 = $target['family'] === 'inet6';
			$destination = $ipv6 ? '[' . $target['address'] . ']' : $target['address'];
			$job = ['member' => $name, 'field' => $field, 'target' => $target, 'gateway' => $gateway, 'path' => $path];
			if ($target['protocol'] === 'tcp' || $target['protocol'] === 'dns') {
				$bind = ($ipv6 ? "[{$source}]" : $source) . ':0';
				$context = stream_context_create(['socket' => ['bindto' => $bind]]);
				if ($target['protocol'] === 'tcp') {
					$socket = @stream_socket_client("tcp://{$destination}:{$target['port']}", $error, $message, 0,
					    STREAM_CLIENT_CONNECT | STREAM_CLIENT_ASYNC_CONNECT, $context);
					if ($socket !== false) {
						$jobs[] = $job + ['socket' => $socket];
					}
					continue;
				}
				$socket = @stream_socket_client("udp://{$destination}:53", $error, $message,
				    min(100000, $remaining) / 1000000, STREAM_CLIENT_CONNECT, $context);
				if ($socket === false) {
					continue;
				}
				stream_set_blocking($socket, false);
				$id = random_int(0, 65535);
				$question = sdwan_probe_dns_question($target['host']);
				$request = pack('nnnnnn', $id, 0x0100, 1, 0, 0, 0) . $question;
				if (@fwrite($socket, $request) !== strlen($request)) {
					fclose($socket);
					continue;
				}
				$jobs[] = $job + ['socket' => $socket, 'id' => $id, 'question' => $question];
			} elseif ($curl !== null && $remaining >= 1000) {
				$host = $target['host'];
				$body = isset($target['expect']) ? (object)['value' => '', 'oversized' => false] : null;
				$marker_limit = $body === null ? 0 : strlen($target['expect']) + 2;
				$handle = curl_init('https://' . $host . ':443' . $target['path']);
				if ($handle === false) {
					continue;
				}
				if (!curl_setopt_array($handle, [
					CURLOPT_INTERFACE => $source,
					CURLOPT_CONNECT_TO => ["{$host}:443:{$destination}:443"],
					CURLOPT_FRESH_CONNECT => true, CURLOPT_FORBID_REUSE => true,
					CURLOPT_PROXY => '', CURLOPT_FOLLOWLOCATION => false,
					CURLOPT_SSL_VERIFYPEER => true, CURLOPT_SSL_VERIFYHOST => 2,
					CURLOPT_CONNECTTIMEOUT_MS => min(900, intdiv($remaining, 1000)),
					CURLOPT_TIMEOUT_MS => min(1800, intdiv($remaining, 1000)),
					CURLOPT_NOPROGRESS => true, CURLOPT_NOSIGNAL => true,
					CURLOPT_WRITEFUNCTION => static function ($handle, string $chunk) use ($body, $marker_limit): int {
						static $bytes = 0;
						$bytes += strlen($chunk);
						if ($body !== null) {
							if ($bytes <= $marker_limit) {
								$body->value .= $chunk;
							} else {
								$body->oversized = true;
							}
						}
						return $bytes <= 65536 ? strlen($chunk) : 0;
					},
				]) || curl_multi_add_handle($curl, $handle) !== CURLM_OK) {
					continue;
				}
				$jobs[] = $job + ['curl' => $handle, 'body' => $body];
			}
		}
	}
	while ($jobs && hrtime(true) < $deadline) {
		sdwan_probe_collect_ready($jobs, $results, $curl, $deadline);
		$remaining = sdwan_probe_remaining_us($deadline);
		if ($remaining === 0) {
			break;
		}
		if ($jobs) {
			usleep(min(25000, $remaining));
		}
	}
	foreach ($jobs as $job) {
		$results[$job['member']][$job['field']] = 'Timed out';
		if (isset($job['worker'])) {
			sdwan_probe_fib_close($job['worker'], $job['worker_output'], true);
		} elseif (isset($job['socket'])) {
			fclose($job['socket']);
		} else {
			curl_multi_remove_handle($curl, $job['curl']);
		}
	}
	return $results;
}
