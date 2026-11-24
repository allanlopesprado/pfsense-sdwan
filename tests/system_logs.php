<?php
declare(strict_types=1);
require __DIR__ . '/../files/usr/local/pkg/sdwan_log.inc';

function verify(bool $test, string $description): void {
	if (!$test) {
		throw new RuntimeException($description);
	}
	echo "ok - {$description}\n";
}
function snapshot(?string $name, string $status = 'alternatives'): array {
	return ['policies' => ['voice' => ['selected' => $name, 'path_status' => $status]]];
}
[$ledger, $logs] = sdwan_log_plan([], 'start', [], '', 100);
verify(count($logs) === 1 && $logs[0][0] === LOG_NOTICE, 'service start is notice severity accepted by the default system log');
[$ledger, $logs] = sdwan_log_plan($ledger, 'stop', [], '', 102);
verify(count($logs) === 1 && str_contains($logs[0][1], 'stopped'), 'clean service stop is reported');
foreach (['stop', 'start', 'stop'] as $kind) {
	[$ledger, $logs] = sdwan_log_plan($ledger, $kind, [], '', 105);
	verify($logs === [], 'duplicate or immediate restart is rate-limited: ' . $kind);
}

$first = snapshot('ISP_A');
[$ledger, $logs] = sdwan_log_plan($ledger, 'observation', $first, '', 110);
verify(count($logs) === 1 && str_contains($logs[0][1], 'ISP_A'), 'first observation reports the recommendation');
[$same, $logs] = sdwan_log_plan($ledger, 'observation', $first, '', 120);
verify($ledger === $same && $logs === [], 'same choice produces neither entry nor ledger write');
[$ledger, $logs] = sdwan_log_plan($ledger, 'observation', snapshot('ISP_B', 'degraded'), '', 130);
verify($logs[0][0] === LOG_WARNING && str_contains($logs[0][1], 'ISP_B') && str_contains($logs[0][1], 'ISP_A'), 'failover identifies prior and current choice and degraded redundancy');
$lost = snapshot(null, 'no_eligible');
$lost['steering']['Dedicated'] = ['gateway' => null];
[$ledger, $logs] = sdwan_log_plan($ledger, 'observation', $lost, '', 140);
verify(count($logs) === 2 && str_contains($logs[0][1], 'no eligible path') &&
    str_contains($logs[1][1], 'no forwarding target'), 'loss of all paths reports recommendation and scoped forwarding separately');
$restored = snapshot('ISP_B');
$restored['steering']['Dedicated'] = ['gateway' => 'GW_B'];
[$ledger, $logs] = sdwan_log_plan($ledger, 'observation', $restored, '', 145);
verify(count($logs) === 2 && str_contains($logs[0][1], 'restored') &&
    str_contains($logs[1][1], 'native filter to evaluate'), 'recovery distinguishes a requested target from delivery');

[$ledger, $logs] = sdwan_log_plan($ledger, 'error', [], 'password=SECRET', 150);
verify($logs === [[LOG_ERR, 'Gateway observation failed.']], 'exception data and private configuration never enter the system log');
[$ledger, $logs] = sdwan_log_plan($ledger, 'error', [], 'status', 152);
verify($logs === [], 'repeated collection errors are throttled');
[$ledger, $logs] = sdwan_log_plan($ledger, 'observation', $restored, '', 170);
verify(count($logs) === 1 && str_contains($logs[0][1], 'recovered'), 'one recovery is emitted for a reported error');
[$ledger, $logs] = sdwan_log_plan($ledger, 'error', [], 'config', 172);
[$ledger, $recovery] = sdwan_log_plan($ledger, 'observation', $restored, '', 174);
verify(!$logs && !$recovery, 'rapid service error/recovery loops do not flood');

[$ledger, $logs] = sdwan_log_plan($ledger, 'filter_retirement_unconfirmed', [], '', 175);
verify(count($logs) === 1 && $logs[0][0] === LOG_ERR && str_contains($logs[0][1], 'without confirming withdrawal'),
	'unconfirmed shutdown is logged even after a recent observation error');
[$ledger, $logs] = sdwan_log_plan($ledger, 'filter_retirement_unconfirmed', [], '', 176);
verify($logs === [], 'repeated unconfirmed shutdown messages are rate-limited');

[$ledger, $logs] = sdwan_log_plan($ledger, 'adapter_unavailable', [], '', 177);
verify(count($logs) === 1 && $logs[0][0] === LOG_ERR && str_contains($logs[0][1], 'saved bindings'),
	'a missing adapter with saved bindings is reported independently of filter failures');
[$ledger, $logs] = sdwan_log_plan($ledger, 'adapter_unavailable', [], '', 178);
verify($logs === [], 'repeated missing adapter alerts are rate-limited');

$many = ['policies' => []];
for ($i = 0; $i < 30; $i++) {
	$many['policies']['p' . $i] = ['selected' => 'path', 'path_status' => 'single'];
}
[$ledger, $logs] = sdwan_log_plan([], 'observation', $many, '', 200);
verify(count($logs) === 13 && str_contains($logs[12][1], 'coalesced'), 'a burst of paths emits a bounded collection and one suppression message');
[$ledger, $logs] = sdwan_log_plan($ledger, 'observation', $many, '', 202);
verify(!$logs, 'repeated snapshots within the burst window stay quiet');
[$ledger, $logs] = sdwan_log_plan($ledger, 'observation', $many, '', 260);
[$ledger, $logs] = sdwan_log_plan($ledger, 'observation', $many, '', 320);
verify(count($ledger['reported']) === 30 && count($logs) === 6, 'unreported final choices are reconciled after each window');
$busy = ['policies' => array_slice($many['policies'], 0, 13)];
[$ledger] = sdwan_log_plan([], 'observation', $busy, '', 330);
foreach (array_slice(array_keys($busy['policies']), 0, 12) as $name) {
	$busy['policies'][$name]['selected'] = 'backup';
}
[$ledger, $logs] = sdwan_log_plan($ledger, 'observation', $busy, '', 390);
verify(isset($ledger['reported']['Policy p12']) && str_starts_with($logs[0][1], 'Policy p12:'),
    'a busy set of policies cannot starve a deferred policy');
$balanced = ['steering' => ['WAN' => ['gateway' => 'A', 'pool' => ['A', 'B', 'C']]]];
[$ledger] = sdwan_log_plan([], 'observation', $balanced, '', 390);
$balanced['steering']['WAN']['pool'] = ['A', 'C'];
[, $logs] = sdwan_log_plan($ledger, 'observation', $balanced, '', 391);
verify(count($logs) === 1 && str_contains($logs[0][1], 'forwarding pool A, C'),
    'pool membership changes are recorded when the first gateway stays the same');
$malicious = ['policies' => ["bad\ncredential" => ['selected' => "PSK\nsecret", 'path_status' => 'single']]];
[, $logs] = sdwan_log_plan([], 'observation', $malicious, '', 400);
verify(!str_contains($logs[0][1], 'credential') && !str_contains($logs[0][1], 'secret'), 'malformed names cannot inject new messages or disclose additional text');

[$ledger, $logs] = sdwan_log_plan([], 'filter_unavailable', [], '', 600);
verify(count($logs) === 1 && $logs[0][0] === LOG_WARNING && str_contains($logs[0][1], 'Status > Filter Reload'),
    'an acknowledged reload with unreadable PF gets a distinct operational warning');
[$same, $logs] = sdwan_log_plan($ledger, 'filter_unavailable', [], '', 899);
verify($same === $ledger && $logs === [], 'PF read failures are rate-limited for five minutes');
[$ledger, $logs] = sdwan_log_plan($ledger, 'filter_unavailable', [], '', 900);
verify(count($logs) === 1, 'a prolonged PF read failure can be reported again');
[, $logs] = sdwan_log_plan($ledger, 'filter_applied', [], '', 901);
verify(count($logs) === 1 && $logs[0][0] === LOG_NOTICE, 'PF confirmation can be reported immediately when rules become readable');

$decision = snapshot('ISP_B', 'alternatives');
$decision['steering']['Group_B'] = ['gateway' => 'ISP_A', 'pool' => ['ISP_A', 'ISP_B']];
[$ledger, $logs] = sdwan_log_plan([], 'observation', $decision, '', 1000);
verify(count(array_filter($logs, static fn($entry) => str_contains($entry[1], 'PF confirmed'))) === 0,
    'recommendation and prospective steering do not imply confirmation in PF');
$policy_name = array_key_first($decision['policies']);
$decision['pf_confirmed']['Group_B'] = ['policy' => $policy_name, 'status' => 'applied',
    'state' => $decision['steering']['Group_B']];
[$ledger, $logs] = sdwan_log_plan($ledger, 'observation', $decision, '', 1001);
verify($logs === [[LOG_NOTICE, "Policy {$policy_name}: PF confirmed forwarding pool ISP_A, ISP_B in group Group_B."]],
    'confirmed forwarding is attributed to the policy at readback time');
[$ledger, $logs] = sdwan_log_plan($ledger, 'observation', $decision, '', 1002);
verify($logs === [], 'an unchanged PF confirmation stays quiet');
$decision['pf_confirmed']['Group_B'] = ['policy' => $policy_name, 'status' => 'blocked', 'state' => []];
[, $logs] = sdwan_log_plan($ledger, 'observation', $decision, '', 1003);
verify($logs === [[LOG_WARNING, "Policy {$policy_name}: PF confirmed block for new connections in group Group_B."]],
    'a confirmed scope block has a distinct policy event');

$history = tempnam(sys_get_temp_dir(), 'sdwan-history-');
try {
	$bsd = 'Apr  8 10:00:00 pfSense sdwan[27]: SD-WAN Policy ERP: ';
	$rfc5424 = '<29>1 2026-04-08T20:00:00.123456+00:00 pfSense sdwan 27 - - SD-WAN Policy ERP: ';
	file_put_contents($history, $bsd . "recommended member PREVIOUS-TIER.\n" . str_repeat(' ', 262144) . "\n" .
	    $bsd . "recommended member A.\n" . $rfc5424 . "PF confirmed block for new connections in group G.\n" .
	    str_replace('[27]', '[28]', str_replace('sdwan', 'other', $bsd)) . "recommended member FOREIGN.\n" .
	    str_replace('Policy ERP:', 'Policy ERP-extra:', $bsd) . "recommended member UNRELATED.\n" .
	    $rfc5424 . "PF confirmed gateway B in group G.");
	$events = sdwan_log_recent_policy_events($history, 'ERP');
	verify(array_column($events, 'type') === ['blocked', 'recommended'] &&
	    array_column($events, 'time') === ['2026-04-08T20:00:00.123456+00:00', 'Apr  8 10:00:00'],
	    'policy history reads complete records within the bounded active log tail in both native formats');
	verify(sdwan_log_recent_policy_events($history, 'OTHER') === [] &&
	    sdwan_log_recent_policy_events($history, '../system.log') === null,
	    'policy names are filtered literally and do not select log files');
	file_put_contents($history, str_repeat($bsd . "recommended member A.\n", 30));
	verify(count(sdwan_log_recent_policy_events($history, 'ERP')) === 20,
	    'the policy history response has a fixed record limit');
} finally {
	unlink($history);
}
