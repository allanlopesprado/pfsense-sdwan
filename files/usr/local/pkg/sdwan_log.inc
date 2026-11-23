<?php
/* Syslogd applies the administrator's system.log severity, local and remote
 * settings. No package-specific facility registration, log file or rotator. */
function sdwan_log_emit(int $priority, string $message): void {
	if (!in_array($priority, [LOG_NOTICE, LOG_WARNING, LOG_ERR], true)) {
		return;
	}
	/* This API receives event descriptions, never config arrays or exceptions.
	 * The native logger() may include a backtrace with arguments in debug mode. */
	$line = preg_replace('/[[:cntrl:]]+/', ' ', substr($message, 0, 320));
	try {
		if (openlog('sdwan', LOG_PID, LOG_DAEMON)) {
			try {
				syslog(LOG_DAEMON | $priority, 'SD-WAN ' . $line);
			} finally {
				if (PHP_SAPI === 'cli' && defined('SDWAN_LOG_DEDICATED_CLI') && SDWAN_LOG_DEDICATED_CLI === true) {
					/* FreeBSD can discard unread datagrams when a connected
					 * sender closes while the receiver's shared queue contains
					 * data. Keep one socket until this worker exits. Reset its
					 * identity so native routines log under PHP's own settings. */
					$facility = strtoupper((string)ini_get('syslog.facility'));
					if (!str_starts_with($facility, 'LOG_')) {
						$facility = 'LOG_' . $facility;
					}
					openlog((string)ini_get('syslog.ident'), 0,
					    defined($facility) ? constant($facility) : LOG_USER);
				} else {
					closelog();
				}
			}
		}
	} catch (Throwable $ignored) {
		/* A local logging outage must not interrupt measurement or forwarding. */
	}
}

function sdwan_log_label($value): string {
	return is_string($value) && preg_match('/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/D', $value) ? $value : '[unnamed]';
}

function sdwan_log_forwarding_choice(array $binding): array {
	$choice = $binding['gateway'] ?? null;
	$entry = ['choice' => $choice === null ? null : sdwan_log_label($choice)];
	$pool = $binding['pool'] ?? [];
	if (is_array($pool) && count($pool) > 1) {
		$pool = array_map('sdwan_log_label', $pool);
		$entry['pool'] = hash('sha256', implode("\0", $pool));
		$entry['choice'] = implode(', ', array_slice($pool, 0, 2));
		if (count($pool) > 2) {
			$entry['choice'] .= ' (+' . (count($pool) - 2) . ')';
		}
	}
	return $entry;
}

/* Keep the last reported choices. If several paths flap, publish at most 12
 * policy/forwarding events per minute and reconcile the final choices after it. */
function sdwan_log_plan(array $state, string $kind, array $snapshot, string $cause, int $now): array {
	$entries = [];
	if ($kind === 'binding_error') {
		$last = $state['binding_error_at'] ?? null;
		if ($last === null || $now < $last || $now - $last >= 300) {
			$entries[] = [LOG_ERR, 'pfSense could not save a forwarding binding change.'];
			$state['binding_error_at'] = $now;
		}
		return [$state, $entries];
	}
	$filter_event = match ($kind) {
		'filter_requested' => [LOG_NOTICE, 'Native filter reload requested. Waiting for PF confirmation.'],
		'filter_applied' => [LOG_NOTICE, 'Active PF rules confirmed the current forwarding decision.'],
		'filter_withdrawal_confirmed' => [LOG_NOTICE, 'Active PF rules confirmed withdrawal of the removed forwarding bindings.'],
		'filter_divergent' => [LOG_ERR, 'Persistent PF divergence. Automatic reload attempts for this decision have stopped.'],
		'filter_unavailable' => [LOG_WARNING, 'Active PF rules are unavailable after the native filter reload was accepted. Confirmation and retries are paused. See Status > Filter Reload.'],
		'filter_retirement_unconfirmed' => [LOG_ERR, 'Observer stopped without confirming withdrawal of the previous forwarding rules. Check Status > Filter Reload.'],
		'filter_expiry_requested' => [LOG_WARNING, 'Stale forwarding or a pending withdrawal requires an independent native filter reload.'],
		'filter_expiry_applied' => [LOG_NOTICE, 'Active PF rules confirmed reconciliation of stale forwarding.'],
		'filter_expiry_unconfirmed' => [LOG_ERR, 'The forwarding safeguard could not confirm the active PF rules. Check Status > Filter Reload.'],
		'filter_expiry_divergent' => [LOG_ERR, 'Persistent PF divergence. The forwarding safeguard has stopped retrying this change. Check Status > Filter Reload.'],
		'sample_expired' => [LOG_WARNING, 'Previous observation expired. Its result cannot be reused by the observer.'],
		default => null,
	};
	if ($filter_event !== null) {
		$last = $state['filter_event_at'][$kind] ?? null;
		$interval = $filter_event[0] === LOG_NOTICE ? 30 : 300;
		if ($last === null || $now < $last || $now - $last >= $interval) {
			$entries[] = $filter_event;
			$state['filter_event_at'][$kind] = $now;
		}
		return [$state, $entries];
	}
	if ($kind === 'start' || $kind === 'stop') {
		$was_running = $state['running'] ?? false;
		$state['running'] = $kind === 'start';
		$last = $state['service_at'][$kind] ?? null;
		if (($kind === 'start' || $was_running) &&
		    ($last === null || $now < $last || $now - $last >= 60)) {
			$entries[] = [LOG_NOTICE, $kind === 'start' ? 'Observer service started.' : 'Observer service stopped.'];
			$state['service_at'][$kind] = $now;
		}
		return [$state, $entries];
	}
	if ($kind === 'error') {
		/* Never interpolate arbitrary exception messages, which may contain
		 * endpoint credentials, config fragments or a backtrace. */
		$explanation = match ($cause) {
			'config' => 'Cannot read the current firewall or package configuration.',
			'status' => 'Cannot publish the observation snapshot.',
			'bindings' => 'Invalid forwarding bindings. No path was authorized for them.',
			'reload' => 'Cannot record the native filter reload request.',
			'startup_filter' => 'Cannot confirm withdrawal of the previous forwarding rule. Observer will retry starting.',
			default => 'Gateway observation failed.',
		};
		$last = $state['failure_at'] ?? null;
		if ($last === null || $now < $last || $now - $last >= 300) {
			$entries[] = [LOG_ERR, $explanation];
			$state['failure_at'] = $now;
			$state['failure_reported'] = true;
		}
		return [$state, $entries];
	}
	if ($kind !== 'observation') {
		return [$state, $entries];
	}
	if (!empty($state['failure_reported'])) {
		$entries[] = [LOG_NOTICE, 'Gateway observation recovered.'];
		unset($state['failure_reported']);
	}

	$current = [];
	foreach ($snapshot['policies'] ?? [] as $name => $policy) {
		$choice = $policy['selected'] ?? null;
		$current['Policy ' . sdwan_log_label((string)$name)] = [
		    'choice' => $choice === null ? null : sdwan_log_label($choice),
		    'status' => $policy['path_status'] ?? 'unknown',
		    'reason' => match ($policy['reason'] ?? null) {
			    'Lowest configured cost within SLA' => 'lowest configured cost within SLA',
			    'Lowest measured RTT within SLA' => 'lowest measured RTT within SLA',
			    'Weighted connections across eligible gateways' => 'weighted connections across eligible gateways',
			    default => null,
		    },
		];
	}
	foreach ($snapshot['steering'] ?? [] as $group => $binding) {
		$current['Group ' . sdwan_log_label((string)$group)] =
		    sdwan_log_forwarding_choice($binding) + ['status' => 'forwarding'];
	}
	foreach ($snapshot['pf_confirmed'] ?? [] as $group => $binding) {
		$current['PF ' . sdwan_log_label((string)$group)] = sdwan_log_forwarding_choice($binding['state']) + [
		    'status' => $binding['status'], 'policy' => sdwan_log_label($binding['policy']),
		    'group' => sdwan_log_label((string)$group),
		];
	}
	$reported = array_intersect_key($state['reported'] ?? [], $current);
	$cursor = array_search($state['transition_cursor'] ?? null, array_keys($current), true);
	if ($cursor !== false && ($state['count'] ?? 0) > 12) {
		$current = array_slice($current, $cursor + 1, null, true) + array_slice($current, 0, $cursor + 1, true);
	}
	foreach ($current as $name => $next) {
		$previous = $reported[$name] ?? null;
		if ($previous === $next) {
			continue;
		}
		$window = $state['window_at'] ?? null;
		if ($window === null || $now < $window || $now - $window >= 60) {
			$state['window_at'] = $now;
			$state['count'] = 0;
		}
		if ($state['count'] >= 12) {
			if ($state['count'] === 12) {
				$entries[] = [LOG_WARNING, 'Several paths changed. Further transitions are coalesced for this minute. See SD-WAN Status.'];
				$state['count']++;
			}
			break;
		}
		$old = $previous['choice'] ?? null;
		$new = $next['choice'];
		if (isset($next['policy'])) {
			$detail = $next['status'] === 'blocked' ? 'block for new connections' :
			    (isset($next['pool']) ? 'forwarding pool ' : 'gateway ') . $new;
			$entries[] = [$next['status'] === 'blocked' ? LOG_WARNING : LOG_NOTICE,
			    'Policy ' . $next['policy'] . ': PF confirmed ' . $detail . ' in group ' . $next['group'] . '.'];
			$reported[$name] = $next;
			$state['transition_cursor'] = $name;
			$state['count']++;
			continue;
		}
		$weighted = ($next['reason'] ?? null) === 'weighted connections across eligible gateways';
		if ($next['status'] === 'forwarding') {
			$text = $new === null ? 'no forwarding target for new flows' :
			    (isset($next['pool']) ? 'forwarding pool ' : 'forwarding target ') . $new;
			$text .= ' for the native filter to evaluate';
		} elseif ($new === null) {
			$text = 'no eligible path';
		} elseif ($weighted) {
			$text = 'weighted forwarding recommended';
		} elseif ($previous !== null && $old === null) {
			$text = 'eligible path restored, recommended member ' . $new;
		} else {
			$text = 'recommended member ' . $new;
		}
		if (!$weighted && $old !== null && $old !== $new) {
			$text .= ' (previously ' . $old . ')';
		}
		if ($next['status'] === 'degraded') {
			$text .= ', only one eligible member remains';
		} elseif ($previous !== null && $previous['status'] === 'degraded' && $next['status'] === 'alternatives') {
			$text .= ', alternatives available again';
		}
		if (!$weighted && $new !== null && isset($next['reason'])) {
			$text .= ', ' . $next['reason'];
		}
		$entries[] = [($new === null || $next['status'] === 'degraded') ? LOG_WARNING : LOG_NOTICE,
		    $name . ': ' . $text . '.'];
		$reported[$name] = $next;
		$state['transition_cursor'] = $name;
		$state['count']++;
	}
	$state['reported'] = $reported;
	return [$state, $entries];
}

/* Only read named policy entries written by the SD-WAN syslog identity.
 * Keep timestamps in the native log format, including older RFC 3164 rows. */
function sdwan_log_recent_policy_events(string $logfile, string $policy): ?array {
	if (sdwan_log_label($policy) !== $policy || is_link($logfile) || !is_file($logfile)) {
		return null;
	}
	$handle = @fopen($logfile, 'rb');
	if ($handle === false) {
		return null;
	}
	try {
		$stat = fstat($handle);
		if ($stat === false || ($stat['mode'] & 0170000) !== 0100000) {
			return null;
		}
		$limit = 262144;
		$offset = max(0, $stat['size'] - $limit);
		if (fseek($handle, $offset) !== 0) {
			return null;
		}
		$tail = stream_get_contents($handle, $limit);
		if ($tail === false) {
			return null;
		}
	} finally {
		fclose($handle);
	}
	$lines = explode("\n", $tail);
	array_pop($lines); // Ignore a trailing partial line during concurrent append.
	if ($offset > 0) {
		array_shift($lines);
	}
	$prefix = 'SD-WAN Policy ' . $policy . ': ';
	$events = [];
	foreach (array_reverse($lines) as $line) {
		$line = rtrim($line, "\r");
		if (strlen($line) > 1024 || !str_contains($line, $prefix)) {
			continue;
		}
		if (!preg_match('/\A([A-Z][a-z]{2} {1,2}[0-9]{1,2} [0-9]{2}(?::[0-9]{2}){2}) \S+ sdwan\[[0-9]+\]: (.+)\z/D', $line, $match) &&
		    !preg_match('/\A<[0-9]{1,3}>1 ([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}(?::[0-9]{2}){2}(?:\.[0-9]{1,6})?(?:Z|[+-][0-9]{2}:[0-9]{2})) \S+ sdwan [0-9]+ - - (.+)\z/D', $line, $match)) {
			continue;
		}
		if (!str_starts_with($match[2], $prefix)) {
			continue;
		}
		$detail = substr($match[2], strlen($prefix));
		$type = match (true) {
			str_starts_with($detail, 'PF confirmed block ') => 'blocked',
			str_starts_with($detail, 'PF confirmed gateway '),
			str_starts_with($detail, 'PF confirmed forwarding pool ') => 'applied',
			str_starts_with($detail, 'no eligible path') => 'unavailable',
			str_starts_with($detail, 'recommended member '),
			str_starts_with($detail, 'weighted forwarding recommended'),
			str_starts_with($detail, 'eligible path restored, recommended member ') => 'recommended',
			default => null,
		};
		if ($type !== null) {
			$events[] = ['time' => $match[1], 'type' => $type, 'detail' => $detail];
			if (count($events) === 20) {
				break;
			}
		}
	}
	return $events;
}

function sdwan_log_event(string $kind, array $snapshot = [], string $cause = ''): void {
	/* The shared ledger deduplicates separate processes. On contention, a
	 * short retry falls back to this process's ledger instead of losing events. */
	static $fallback = [];
	$handle = null;
	try {
		$handle = @fopen(SDWAN_SNAPSHOT_PATH . '.events', 'c+');
		if (is_resource($handle)) {
			if (!flock($handle, LOCK_EX | LOCK_NB)) {
				usleep(2000);
				if (!flock($handle, LOCK_EX | LOCK_NB)) {
					fclose($handle);
					$handle = null;
				}
			}
		}
		if (is_resource($handle)) {
			$contents = stream_get_contents($handle);
			$old = is_string($contents) ? json_decode($contents, true) : null;
		}
		$old = is_array($old ?? null) ? $old : $fallback;
		[$next, $entries] = sdwan_log_plan($old, $kind, $snapshot, $cause, time());
		$fallback = $next;
		if ($old !== $next && is_resource($handle)) {
			$encoded = json_encode($next, JSON_THROW_ON_ERROR);
			if (rewind($handle) && ftruncate($handle, 0)) {
				fwrite($handle, $encoded);
			}
		}
		if (is_resource($handle)) {
			fclose($handle);
			$handle = null;
		}
		foreach ($entries as [$priority, $message]) {
			sdwan_log_emit($priority, $message);
		}
	} catch (Throwable $ignored) {
		/* Reporting must never veto an otherwise successful operation. */
	} finally {
		if (is_resource($handle)) {
			fclose($handle);
		}
	}
}
