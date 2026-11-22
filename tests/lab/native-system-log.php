<?php
/* Execute the pinned generator and the General page's file reader with a
 * disposable config. Only system startup/other appliance dependencies are stubbed. */
[$script, $mode, $source, $work, $format, $level] = $argv;
$shim = $work . '/shim';
set_include_path($shim);
function config_get_path(string $key, $default = null) {
	global $mode, $level;
	if ($key === 'syslog/default_log_level' && $level === 'warning') { return 'warning'; }
	if ($key === 'syslog/sourceip' && $mode === 'prepare') {
		// The native generator has finished writing pfSense.conf at this point.
		throw new RulesWritten();
	}
	return $key === 'syslog/logcompressiontype' ? 'none' : $default;
}
function config_path_enabled(string $section, string $key = 'enable'): bool { return false; }
function g_get(string $key) { return $GLOBALS['g'][$key] ?? false; }
function is_platform_booting(): bool { return false; }
function mwexec(string $command): void {
	if ($command !== '/etc/rc.d/hostid start') {
		throw new RuntimeException('Unexpected command in config generator');
	}
}
function safe_mkdir(string $path): void {
	if (!is_dir($path) && !mkdir($path, 0700, true)) { throw new RuntimeException('mkdir failed'); }
}
if (!function_exists('gettext')) {
	function gettext($message) { return $message; }
}
final class RulesWritten extends RuntimeException {}
$g = ['etc_path' => $work . '/etc', 'varetc_path' => $work . '/etc', 'varlog_path' => '/var/log',
    'conf_path' => $work . '/etc', 'debug' => false];
$system_log_compression_types = ['none' => ['cat' => '/bin/cat']];
require $source;
if ($mode === 'prepare') {
	try {
		system_syslogd_start();
		throw new RuntimeException('Unexpected generator completion');
	} catch (RulesWritten $done) {
	}
	// Include the upstream process selector and its exact routing expression,
	// for both General and the independent dpinger destination. Exclude all
	// unrelated service logs, terminal broadcasts, and any remote destinations.
	$rows = [];
	$selector = '';
	foreach (file($work . '/etc/syslog.d/pfSense.conf', FILE_IGNORE_NEW_LINES) as $line) {
		if (str_starts_with($line, '!')) { $selector = $line; }
		if (preg_match('~\s/var/log/(system|gateways)\.log$~D', $line, $matches)) {
			$rows[$matches[1]] = $selector . "\n" . $line;
		}
	}
	if (count($rows) !== 2 || !str_starts_with($rows['system'], '!-') ||
	    !str_starts_with($rows['gateways'], "!dpinger\n")) {
		throw new RuntimeException('Pinned source no longer generates the expected log destinations');
	}
	file_put_contents($work . '/etc/lab-syslog.conf', implode("\n", $rows) .
	    "\n!*\n*.*\t/var/log/fixture-input.log\n");
	return;
}
function demand(bool $condition, string $message): void {
	if (!$condition) { throw new RuntimeException($message); }
}
$file = $work . '/var/log/system.log';
$rows = conv_log_filter($file, 500, 500, '', '');
$events = array_values(array_filter($rows, static fn($entry) => $entry['process'] === 'sdwan'));
$messages = array_column($events, 'message');
$expected = [
	'SD-WAN Observer service started.',
	'SD-WAN Policy voice: recommended member A.',
	'SD-WAN Policy voice: recommended member B (previously A).',
	'SD-WAN Policy voice: no eligible path (previously B).',
	'SD-WAN Gateway observation failed.',
];
$forwarding = [
	'SD-WAN Native filter reload requested. Waiting for PF confirmation.',
	'SD-WAN Active PF rules confirmed the current forwarding decision.',
	'SD-WAN Active PF rules confirmed withdrawal of the removed forwarding bindings.',
	'SD-WAN Persistent PF divergence. Automatic reload attempts for this decision have stopped.',
	'SD-WAN Active PF rules are unavailable after the native filter reload was accepted. Confirmation and retries are paused. See Status > Filter Reload.',
	'SD-WAN Observer stopped without confirming withdrawal of the previous forwarding rules. Check Status > Filter Reload.',
	'SD-WAN Previous observation expired. Its result cannot be reused by the observer.',
];
if ($level === 'warning') {
	$expected = [...array_slice($expected, 3), ...array_slice($forwarding, 2)];
} else {
	$expected = [...$expected, ...$forwarding];
}
demand($messages === $expected, "Unexpected event stream from General ({$format}): " . json_encode($messages));
foreach ($events as $entry) {
	demand(preg_match('/^[0-9]+$/D', (string)$entry['pid']) === 1 && !empty($entry['time']), 'Missing parsed process metadata');
}
$text = file_get_contents($file);
demand(!str_contains($text, 'CREDENTIAL_CANARY') && !str_contains($text, 'below-default') &&
    !str_contains($text, 'separate-program'), 'Unexpected sensitive, below-threshold, or separately routed log data');
$gateways = file_get_contents($work . '/var/log/gateways.log');
$input = file_get_contents($work . '/var/log/fixture-input.log');
$nativeIdentity = $format === 'rfc5424'
    ? '/^<13>1 [^\n]* php [^\n]* native-ident-control$/m'
    : '/ php(?:\[[0-9]+\])?: native-ident-control$/m';
demand(preg_match($nativeIdentity, $input) === 1, 'Native PHP tag or facility was not restored');
foreach (['below-default', 'separate-program'] as $marker) {
	demand(str_contains($input, $marker), "Isolated syslogd input did not receive control {$marker}");
}
demand(str_contains($gateways, 'separate-program'), 'dpinger absent from native gateways.log');
if ($format === 'rfc5424') {
	$priorities = [28 => 'no eligible path', 27 => 'Gateway observation failed'];
	if ($level !== 'warning') { $priorities[29] = 'Observer service started'; }
	foreach ($priorities as $pri => $fragment) {
		demand(preg_match('/^<' . $pri . '>1 [^\n]*sdwan [^\n]*' . preg_quote($fragment, '/') . '/m', $text) === 1, 'Incorrect syslog PRI');
	}
}
echo "ok - FreeBSD syslogd {$format} ({$level}) delivered " . count($events) .
    " distinct package events to the native General reader with PID, thresholds and routing intact\n";
