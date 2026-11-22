<?php

/* Every probe uses an explicitly routed destination IP. */
function sdwan_probe_target($value): ?array {
	if (!is_string($value) || strlen($value) > 512) {
		return null;
	}
	if (preg_match('~\Atcp://(\[[A-Fa-f0-9:.]+\]|[0-9.]+):([1-9][0-9]{0,4})\z~D', $value, $parts)) {
		$address = trim($parts[1], '[]');
		$port = (int) $parts[2];
		if ($port > 65535 || str_starts_with($parts[1], '[') !== str_contains($address, ':')) {
			return null;
		}
		$target = ['protocol' => 'tcp', 'port' => $port];
	} elseif (preg_match('~\A(https|dns)://([A-Za-z0-9.-]+)(/[^ \x00-\x20\x7f#]*)? ([A-Fa-f0-9:.]+)\z~D', $value, $parts)) {
		[, $protocol, $host, $path, $address] = $parts;
		if (strlen($host) > 253 || !preg_match('/\A(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?\z/iD', $host) ||
		    ($protocol === 'dns' && $path !== '')) {
			return null;
		}
		$target = ['protocol' => $protocol, 'host' => strtolower($host), 'path' => $path ?: '/'];
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
	    (ord($packed[0]) === 0 || ord($packed[0]) === 127 || ord($packed[0]) >= 224)) {
		return null;
	}
	return $target + ['address' => inet_ntop($packed), 'family' => $ipv6 ? 'inet6' : 'inet'];
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

/* All sockets are bound to the live interface source. Require a native host
 * route pinned to the gateway or its PPP link, and check it again before accepting results. */
function sdwan_probe_path(array $target, array $gateway, ?int $deadline = null): ?array {
	$family = $target['family'];
	if (($deadline !== null && hrtime(true) >= $deadline) ||
	    $family !== $gateway['family'] || !function_exists('exec') ||
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
	    escapeshellarg($target['address']) . ' 2>/dev/null', $lines, $result);
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
			$replied = $done['result'] === CURLE_OK && $status >= 200 && $status < 300;
			$results[$job['member']][$job['field']] = sdwan_probe_result($job, $replied, 'HTTPS check failed', $deadline);
			curl_multi_remove_handle($curl, $job['curl']);
			unset($jobs[$index]);
			break;
		}
	}
}

function sdwan_probe_observe(array $members, array $inventory, array $observations): array {
	$results = $jobs = [];
	$curl = function_exists('curl_multi_init') ? curl_multi_init() : null;
	$deadline = hrtime(true) + 2500000000;
	/* Give every member a chance at one result before running backups. */
	foreach (['probe_primary', 'probe_secondary'] as $field) {
		foreach ($members as $member) {
			if (!isset($member[$field])) {
				continue;
			}
			sdwan_probe_collect_ready($jobs, $results, $curl, $deadline);
			$name = $member['name'];
			$gateway = $inventory[$member['gateway']] ?? null;
			$target = sdwan_probe_target($member[$field]);
			$results[$name][$field] = 'Unavailable';
			if ($target === null || $gateway === null ||
			    ($observations[$member['gateway']]['status'] ?? null) !== 'online' || hrtime(true) >= $deadline) {
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
				$handle = curl_init('https://' . $host . $target['path']);
				if ($handle === false) {
					continue;
				}
				if (!curl_setopt_array($handle, [
					CURLOPT_INTERFACE => $source, CURLOPT_RESOLVE => ["{$host}:443:{$destination}"],
					CURLOPT_PROXY => '', CURLOPT_FOLLOWLOCATION => false,
					CURLOPT_SSL_VERIFYPEER => true, CURLOPT_SSL_VERIFYHOST => 2,
					CURLOPT_CONNECTTIMEOUT_MS => min(900, intdiv($remaining, 1000)),
					CURLOPT_TIMEOUT_MS => min(1800, intdiv($remaining, 1000)),
					CURLOPT_NOPROGRESS => true, CURLOPT_NOSIGNAL => true,
					CURLOPT_WRITEFUNCTION => static function ($handle, string $chunk): int {
						static $bytes = 0;
						$bytes += strlen($chunk);
						return $bytes <= 65536 ? strlen($chunk) : 0;
					},
				]) || curl_multi_add_handle($curl, $handle) !== CURLM_OK) {
					continue;
				}
				$jobs[] = $job + ['curl' => $handle];
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
		if (isset($job['socket'])) {
			fclose($job['socket']);
		} else {
			curl_multi_remove_handle($curl, $job['curl']);
		}
	}
	return $results;
}
