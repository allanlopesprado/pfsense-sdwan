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
$malicious = ['policies' => ["bad\ncredential" => ['selected' => "PSK\nsecret", 'path_status' => 'single']]];
[, $logs] = sdwan_log_plan([], 'observation', $malicious, '', 400);
verify(!str_contains($logs[0][1], 'credential') && !str_contains($logs[0][1], 'secret'), 'malformed names cannot inject new messages or disclose additional text');
