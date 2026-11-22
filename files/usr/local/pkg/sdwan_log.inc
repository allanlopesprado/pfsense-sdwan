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
		];
	}
	foreach ($snapshot['steering'] ?? [] as $group => $binding) {
		$choice = $binding['gateway'] ?? null;
		$current['Group ' . sdwan_log_label((string)$group)] = [
		    'choice' => $choice === null ? null : sdwan_log_label($choice), 'status' => 'forwarding',
		];
	}
	$reported = array_intersect_key($state['reported'] ?? [], $current);
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
		if ($next['status'] === 'forwarding') {
			$text = $new === null ? 'no forwarding target for new flows' : 'forwarding target ' . $new;
			$text .= ' for the native filter to evaluate';
		} elseif ($new === null) {
			$text = 'no eligible path';
		} elseif ($previous !== null && $old === null) {
			$text = 'eligible path restored, recommended member ' . $new;
		} else {
			$text = 'recommended member ' . $new;
		}
		if ($old !== null && $old !== $new) {
			$text .= ' (previously ' . $old . ')';
		}
		if ($next['status'] === 'degraded') {
			$text .= ', only one eligible member remains';
		} elseif ($previous !== null && $previous['status'] === 'degraded' && $next['status'] === 'alternatives') {
			$text .= ', alternatives available again';
		}
		$entries[] = [($new === null || $next['status'] === 'degraded') ? LOG_WARNING : LOG_NOTICE,
		    $name . ': ' . $text . '.'];
		$reported[$name] = $next;
		$state['count']++;
	}
	$state['reported'] = $reported;
	return [$state, $entries];
}

function sdwan_log_event(string $kind, array $snapshot = [], string $cause = ''): void {
	/* Nonblocking private runtime state also deduplicates separate --once
	 * calls. A read-only /var/run falls back to this process's memory. */
	static $fallback = [];
	$handle = null;
	try {
		$handle = @fopen(SDWAN_SNAPSHOT_PATH . '.events', 'c+');
		if (is_resource($handle)) {
			if (!flock($handle, LOCK_EX | LOCK_NB)) {
				return;
			}
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
