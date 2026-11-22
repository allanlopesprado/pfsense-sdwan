<?php
declare(strict_types=1);

/* Exercise the shipped package hook and immutable native bindings using a
 * temporary status path and a PHP implementation of pfSense's config boundary. */
$pkg = __DIR__ . '/../files/usr/local/pkg';
$dir = sys_get_temp_dir() . '/sdwan-steering-' . bin2hex(random_bytes(8));
mkdir($dir, 0700);
register_shutdown_function(static function () use ($dir) {
	foreach (glob($dir . '/*') as $path) { unlink($path); }
	rmdir($dir);
});
foreach (['sdwan.inc', 'sdwan_engine.inc', 'sdwan_steering.inc', 'sdwan_preflight.inc', 'sdwan_log.inc',
    'sdwan_probe.inc'] as $file) {
	$contents = file_get_contents($pkg . '/' . $file);
	if ($file === 'sdwan_engine.inc') {
		$contents = str_replace('/var/run/sdwan-observer.json', $dir . '/snapshot', $contents);
	}
	file_put_contents($dir . '/' . $file, $contents);
}
set_include_path(__DIR__ . '/fixtures/write');
require 'config.inc';
require $dir . '/sdwan_steering.inc';
function config_path_enabled($section, $key): bool {
	return isset(config_get_path($section, [])[$key]);
}
function filter_sdwan_binding_api(): int { global $abi; return $abi; }
function filter_configure(): void { global $pending; $pending++; }
function get_interface_gateway($interface): ?string {
	return config_get_path('fixture/dynamic/' . $interface);
}
function get_interface_gateway_v6($interface): ?string {
	return get_interface_gateway($interface);
}
function get_real_interface($interface, $family, $realv6iface, $flush): ?string {
	if ($realv6iface !== false || $flush !== false) {
		throw new RuntimeException('Steering must use the native filter generator interface lookup');
	}
	return config_get_path('fixture/devices/' . $family . '/' . $interface) ??
	    (config_get_path('interfaces', [])[$interface]['if'] ?? null);
}
function verify(bool $ok, string $label): void {
	if (!$ok) { throw new RuntimeException($label); }
	echo "ok - {$label}\n";
}
$abi = 0;
$pending = $writes = 0;
$busy = $fail = false;
$config = ['version' => '1', 'members' => [
	['name' => 'a', 'gateway' => 'A', 'cost' => '1'], ['name' => 'b', 'gateway' => 'B', 'cost' => '2']
], 'slas' => [['name' => 's', 'latency_ms' => '100', 'loss_pct' => '5']],
'policies' => [['name' => 'p', 'sla' => 's', 'strategy' => 'cost', 'members' => ['a', 'b']]]];
$rule = ['tracker' => '301', 'type' => 'pass', 'ipprotocol' => 'inet', 'gateway' => 'G',
    'interface' => 'lan', 'source' => ['address' => '10.23.0.0/24'], 'destination' => ['any' => '']];
$guard = array_replace($rule, ['tracker' => '302', 'type' => 'block']);
unset($guard['gateway']);
$current = $disk = [
	SDWAN_CONFIG_PATH => sdwan_encode_config($config),
	'gateways/gateway_group' => [['name' => 'G', 'item' => ['A|1|', 'B|2|']]],
	'filter/rule' => [$rule, $guard], 'interfaces' => [
		'wan' => ['enable' => '', 'if' => 'igb0'], 'opt1' => ['enable' => '', 'if' => 'igb1'],
		'lan' => ['enable' => '', 'if' => 'igb2']
	],
	'gateways/gateway_item' => [
		['name' => 'A', 'interface' => 'wan', 'gateway' => '192.0.2.1'],
		['name' => 'B', 'interface' => 'opt1', 'gateway' => '198.51.100.1'],
	]
];
$preview = sdwan_steering_preview($config, 'p', 'G');
verify(!$preview['errors'] && $preview['binding']['trackers'] === ['301'] && !$writes, 'preflight is read-only on stock CE');
$current['gateways/gateway_item'][1] += ['monitor' => 'dynamic'];
$current['fixture/dynamic/opt1'] = '192.0.2.1';
verify(str_contains(sdwan_steering_preview($config, 'p', 'G')['errors'][0] ?? '', 'shares its Monitor IP') &&
    !$writes && !$pending, 'a live DHCP target resolved by pfSense is checked before binding');
$current = $disk;
verify(sdwan_steering_bind('p', 'G', $preview['revision']) !== [] && !$writes && !$pending, 'stock CE cannot activate forwarding');
$abi = 1;
$preview = sdwan_steering_preview($config, 'p', 'G');
verify(sdwan_steering_bind('p', 'G', str_repeat('0', 64)) !== [] && !$writes, 'optimistic revision rejects an outdated binding');
$fail = true;
verify(sdwan_steering_bind('p', 'G', $preview['revision']) !== [] && !$pending && $current === $disk, 'failed persistence rolls back without a reload request');
$fail = false;
verify(sdwan_steering_bind('p', 'G', $preview['revision']) === [] && $writes === 1 && $pending === 1, 'opt-in binds verified native trackers and queues one native reload');
$bindings = sdwan_steering_bindings();
$raw = $disk[SDWAN_BINDINGS_PATH]['item'][0];
verify(sdwan_steering_decode($raw) === $bindings['G'] && $raw['gateways']['item'] === ['A', 'B'], 'binding persists outside the package in XML list form');
verify(sdwan_steering_bind('p', 'G', sdwan_steering_revision()) !== [] && $writes === 1, 'a bound rule cannot be bound again');
verify(sdwan_steering_gateway_for_rule($raw, $rule) === null, 'missing or stale snapshot never authorizes pass');
$sample = ['status' => 'online', 'substatus' => 'none', 'delay' => '12ms', 'stddev' => '1ms', 'loss' => '0%'];
$snapshot = sdwan_evaluate($config, ['A' => $sample, 'B' => $sample], time(), sdwan_gateways());
$snapshot['config_revision'] = sdwan_config_revision($config);
$snapshot['gateway_inventory_revision'] = sdwan_gateway_inventory_revision($config, sdwan_gateways());
$snapshot['steering'] = sdwan_steering_observations($config, $snapshot, []);
file_put_contents(SDWAN_SNAPSHOT_PATH, json_encode($snapshot));
verify(sdwan_steering_gateway_for_rule($raw, $rule) === 'A', 'fresh matching snapshot returns only the selected native gateway');
$current['gateways/gateway_item'][0]['interval'] = '1000';
verify(sdwan_steering_gateway_for_rule($raw, $rule) === null, 'a change to probing parameters requires a current observation');
unset($current['gateways/gateway_item'][0]['interval']);
$current['gateways/gateway_item'][] = ['name' => 'other', 'interface' => 'opt1', 'gateway' => '192.0.2.1'];
verify(sdwan_steering_gateway_for_rule($raw, $rule) === null &&
    sdwan_steering_observations($config, $snapshot, [])['G']['gateway'] === null,
    'a new duplicate native monitor retires the saved forwarding decision');
$current = $disk;
foreach ([time() + 60, time() - SDWAN_MAX_SNAPSHOT_AGE - 1] as $timestamp) {
	$mistimed = array_replace($snapshot, ['generated_at' => $timestamp]);
	file_put_contents(SDWAN_SNAPSHOT_PATH, json_encode($mistimed));
	verify(sdwan_steering_gateway_for_rule($raw, $rule) === null, 'a future-dated or expired observation cannot authorize a bound rule');
}
file_put_contents(SDWAN_SNAPSHOT_PATH, json_encode($snapshot));
verify(sdwan_steering_gateway_for_rule($raw, array_replace($rule, ['tracker' => '999'])) === null &&
    sdwan_steering_gateway_for_rule($raw, array_replace($rule, ['gateway' => 'other'])) === null, 'unbound tracker and changed group cannot inherit selection');
$before = $current;
$current['filter/rule'][0]['source'] = ['any' => ''];
verify(sdwan_steering_gateway_for_rule($raw, $current['filter/rule'][0]) === null &&
    sdwan_steering_observations($config, $snapshot, [])['G']['gateway'] === null, 'enlarged native match under an unchanged tracker requires new consent');
$current = $before;
$changed = $config;
$changed['members'][0]['cost'] = '50';
$current[SDWAN_CONFIG_PATH] = sdwan_encode_config($changed);
verify(sdwan_steering_gateway_for_rule($raw, $rule) === null, 'stale recommendation after a policy change cannot authorize forwarding');
$current = $disk;
$current['filter/rule'][0]['descr'] = 'updated comment';
verify(sdwan_steering_gateway_for_rule($raw, $rule) === 'A', 'native comment edits do not change traffic scope');
$current = $disk;
$old = ['gateway' => 'A'];
$pending_choice = sdwan_steering_step($old, ['A','B'], 'B', 100);
verify($pending_choice['gateway'] === 'A' && $pending_choice['since'] === 100, 'better healthy challenger starts hold timer');
verify(sdwan_steering_step($pending_choice, ['A','B'], 'B', 129)['gateway'] === 'A' &&
    sdwan_steering_step($pending_choice, ['A','B'], 'B', 130)['gateway'] === 'B', 'sustained better path takes over at the 30-second boundary');
$future_suggestion = array_replace($pending_choice, ['since' => 1000]);
verify(sdwan_steering_step($future_suggestion, ['A','B'], 'B', 110)['since'] === 110,
    'a clock rollback restarts the healthy challenger timer');
verify(sdwan_steering_step($pending_choice, ['B'], 'B', 101)['gateway'] === 'B' &&
    sdwan_steering_step($old, [], null, 101)['gateway'] === null, 'ineligible incumbent fails over immediately and total SLA loss denies new flows');
verify(sdwan_steering_step($old, ['A','B'], 'B', 100, 0)['gateway'] === 'B',
    'zero configured recovery hold returns immediately to the preferred path');
$tuned = $config;
$tuned['members'][0]['probe_primary'] = 'tcp://192.0.2.77:443';
$tuned['policies'][0] += ['degrade_samples' => '3', 'recover_seconds' => '5',
	'probe_requirements' => [['member' => 'a', 'primary_check' => 'required']]];
$tuned_raw = array_replace($raw, ['policy_revision' => sdwan_steering_policy_revision($tuned, 'p')]);
$tuned_binding = sdwan_steering_decode($tuned_raw);
$applied = ['revision' => sdwan_config_revision($tuned_binding), 'gateway' => 'A'];
$verification_time = time();
$wan_a = array_replace($sample, ['delay' => '600001ms']);
$inventory = sdwan_gateways();
$probe_ok = ['a' => ['probe_primary' => 'Passed']];
$soft_sample = sdwan_evaluate($tuned, ['A' => $wan_a, 'B' => $sample], $verification_time, $inventory, $probe_ok);
$quality = $soft_sample['policies']['p'];
verify($quality['selected'] === 'b' && $quality['soft'] === ['a'], 'a passing service check identifies a soft WAN SLA breach');
$first = sdwan_steering_state($tuned, $tuned_binding, $quality, $applied, $verification_time, true);
$replayed = sdwan_steering_state($tuned, $tuned_binding, $quality, $first, $verification_time, true);
$second = sdwan_steering_state($tuned, $tuned_binding, $quality, $first, $verification_time + 1, true);
$third = sdwan_steering_state($tuned, $tuned_binding, $quality, $second, $verification_time + 2, true);
verify($first['gateway'] === 'A' && $first['degraded'] === ['A' => 1] &&
    $replayed === $first && $second['degraded'] === ['A' => 2] && $third['gateway'] === 'B' &&
    !isset($third['degraded']), 'only fresh consecutive degraded samples consume the opt-in hold');
verify(sdwan_steering_state($tuned, $tuned_binding, $quality, $applied, $verification_time)['gateway'] === 'B',
    'an unverified incumbent cannot retain a degraded path');
$balanced = $tuned;
$balanced['policies'][0]['strategy'] = 'balance';
$balanced_binding = array_replace($tuned_binding, ['policy_revision' => sdwan_steering_policy_revision($balanced, 'p')]);
$only_b_applied = ['revision' => sdwan_config_revision($balanced_binding), 'gateway' => 'B', 'pool' => ['B']];
verify(sdwan_steering_state($balanced, $balanced_binding, $quality, $only_b_applied, $verification_time, true)['pool'] === ['B'],
    'a weighted pool cannot admit an out-of-SLA path that was not already applied');
$both_applied = array_replace($only_b_applied, ['gateway' => 'A', 'pool' => ['A', 'B']]);
$balanced_state = sdwan_steering_state($balanced, $balanced_binding, $quality, $both_applied, $verification_time, true);
verify($balanced_state['pool'] === ['A', 'B'] && $balanced_state['degraded'] === ['A' => 1],
    'an opt-in weighted pool retains only previously applied degrading members');
$weighted = $balanced;
$weighted['members'][] = ['name' => 'c', 'gateway' => 'C', 'cost' => '40'];
$weighted['policies'][0]['members'][] = 'c';
$weighted_binding = array_replace($balanced_binding, ['gateways' => ['A', 'B', 'C'],
	'policy_revision' => sdwan_steering_policy_revision($weighted, 'p')]);
$weighted_prior = ['revision' => sdwan_config_revision($weighted_binding), 'gateway' => 'A', 'pool' => ['A', 'B', 'C']];
$weighted_result = static fn($a, $b, $c) => ['candidates' => ['a' => $a, 'b' => $b, 'c' => $c]];
$removed = sdwan_steering_state($weighted, $weighted_binding,
    $weighted_result('Gateway is down', 'Eligible', 'Required service check failed'), $weighted_prior, 100);
verify($removed['pool'] === ['B'] && !isset($removed['recovering']), 'a weighted pool withdraws failed paths immediately');
$only_a_recovered = $weighted_result('Eligible', 'Eligible', 'Gateway is down');
$first_recovering = sdwan_steering_state($weighted, $weighted_binding, $only_a_recovered, $removed, 101);
$all_recovered = $weighted_result('Eligible', 'Eligible', 'Eligible');
$both_recovering = sdwan_steering_state($weighted, $weighted_binding, $all_recovered, $first_recovering, 103);
verify($both_recovering['pool'] === ['B'] && $both_recovering['recovering'] === ['A' => 101, 'C' => 103] &&
    sdwan_steering_signature(['G' => $removed]) === sdwan_steering_signature(['G' => $both_recovering]),
    'weighted recovery timers start independently and do not alter the effective rules while waiting');
$first_readmitted = sdwan_steering_state($weighted, $weighted_binding, $all_recovered, $both_recovering, 106);
$both_readmitted = sdwan_steering_state($weighted, $weighted_binding, $all_recovered, $first_readmitted, 108);
verify(sdwan_steering_state($weighted, $weighted_binding, $all_recovered, $both_recovering, 105) === $both_recovering &&
    $first_readmitted['pool'] === ['A', 'B'] && $first_readmitted['recovering'] === ['C' => 103] &&
    sdwan_steering_state($weighted, $weighted_binding, $all_recovered, $first_readmitted, 107) === $first_readmitted &&
    $both_readmitted['pool'] === ['A', 'B', 'C'] && !isset($both_readmitted['recovering']),
    'each eligible member rejoins the weighted pool exactly at its own recovery boundary');
$a_restarts = sdwan_steering_state($weighted, $weighted_binding,
    $weighted_result('No verified required service measurement', 'Eligible', 'Eligible'), $both_recovering, 104);
verify($a_restarts['recovering'] === ['C' => 103] &&
    sdwan_steering_state($weighted, $weighted_binding, $all_recovered, $a_restarts, 105)['recovering'] === ['A' => 105, 'C' => 103],
    'an interrupted service measurement restarts only that member’s recovery timer');
verify(sdwan_steering_state($weighted, $weighted_binding, $all_recovered, $both_recovering, 100)['recovering'] === ['A' => 100, 'C' => 100],
    'a clock rollback restarts any future-dated weighted timers');
$only_a_remains = sdwan_steering_state($weighted, $weighted_binding,
    $weighted_result('Eligible', 'Gateway is down', 'Gateway is down'), $both_recovering, 104);
verify($only_a_remains['pool'] === ['A'] && !isset($only_a_remains['recovering']),
    'a weighted recovery timer never delays the only eligible gateway');
$b_degraded = $weighted_result('Gateway is down', 'Loss exceeds the SLA', 'Eligible') + ['soft' => ['b']];
$healthy_after_degradation = sdwan_steering_state($weighted, $weighted_binding, $b_degraded, $both_recovering, 104, true);
verify($healthy_after_degradation['pool'] === ['B', 'C'] && !isset($healthy_after_degradation['recovering']),
    'an already applied degraded path does not delay a healthy member');
verify(sdwan_steering_state($weighted, $weighted_binding, $all_recovered, [], 104)['pool'] === ['A', 'B', 'C'],
    'a new or changed binding admits its healthy weighted paths immediately');
foreach (['0', null] as $hold) {
	$immediate = $weighted;
	if ($hold === null) {
		unset($immediate['policies'][0]['recover_seconds']);
	} else {
		$immediate['policies'][0]['recover_seconds'] = $hold;
	}
	$immediate_binding = array_replace($weighted_binding, ['policy_revision' => sdwan_steering_policy_revision($immediate, 'p')]);
	$immediate_prior = array_replace($removed, ['revision' => sdwan_config_revision($immediate_binding)]);
	$joined = sdwan_steering_state($immediate, $immediate_binding, $all_recovered, $immediate_prior, 104);
	verify($joined['pool'] === ['A', 'B', 'C'] && !isset($joined['recovering']),
	    'zero or omitted recovery hold preserves immediate weighted admission');
}
verify(sdwan_snapshot_steering_valid(['G' => $both_recovering], 103), 'snapshot reader accepts independent weighted recovery timers');
foreach ([
	['recovering' => ['C' => 104]],
	['recovering' => ['A' => -1]],
	['recovering' => ['A' => '101']],
	['recovering' => ['B' => 101]],
	['recovering' => []],
	['pool' => [], 'gateway' => null],
] as $malformed_hold) {
	verify(!sdwan_snapshot_steering_valid(['G' => array_replace($both_recovering, $malformed_hold)], 103),
	    'snapshot reader rejects malformed weighted recovery timers');
}
$not_weighted = $both_recovering;
unset($not_weighted['pool']);
verify(!sdwan_snapshot_steering_valid(['G' => $not_weighted], 103), 'snapshot reader requires a weighted pool for weighted timers');
$critical = sdwan_evaluate($tuned, ['A' => $wan_a, 'B' => $sample], $verification_time, $inventory, [
    'a' => ['probe_primary' => 'Timed out'],
])['policies']['p'];
verify(!isset($critical['soft']) &&
    sdwan_steering_state($tuned, $tuned_binding, $critical, $first, $verification_time + 1, true)['gateway'] === 'B',
    'a simultaneous required service failure bypasses the WAN degradation hold');
$unavailable = sdwan_evaluate($tuned, ['A' => array_replace($sample, ['status' => 'down'])],
    $verification_time, $inventory, $probe_ok)['policies']['p'];
verify(sdwan_steering_state($tuned, $tuned_binding, $unavailable, $first, $verification_time + 1, true)['gateway'] === null,
    'unambiguous outages take effect immediately even during a degradation hold');
$recovered = sdwan_evaluate($tuned, ['A' => $sample, 'B' => $sample], $verification_time, $inventory, $probe_ok)['policies']['p'];
$holding = sdwan_steering_state($tuned, $tuned_binding, $recovered, $third, $verification_time + 3, true);
verify($holding['gateway'] === 'B' &&
    sdwan_steering_state($tuned, $tuned_binding, $recovered, $holding, $verification_time + 7, true)['gateway'] === 'B' &&
    sdwan_steering_state($tuned, $tuned_binding, $recovered, $holding, $verification_time + 8, true)['gateway'] === 'A',
    'a healthy preferred gateway returns at the configured recovery boundary');
$current[SDWAN_CONFIG_PATH] = sdwan_encode_config($tuned);
$soft_sample['config_revision'] = sdwan_config_revision($tuned);
$soft_sample['gateway_inventory_revision'] = sdwan_gateway_inventory_revision($tuned, $inventory);
$soft_sample['steering']['G'] = $first;
file_put_contents(SDWAN_SNAPSHOT_PATH, json_encode($soft_sample));
verify(sdwan_steering_gateway_for_rule($tuned_raw, $rule) === 'A', 'native renderer permits the approved temporarily degraded gateway');
foreach ([
	'down gateway' => ['status' => 'down'],
	'failed required probe' => ['checks' => ['probe_primary' => 'Timed out']],
	'missing required probe' => ['checks' => []],
	'unreadable service results' => ['checks' => 'Unavailable'],
] as $condition => $replacement) {
	$contradictory = $soft_sample;
	$contradictory['members']['a'] = array_replace($contradictory['members']['a'], $replacement);
	file_put_contents(SDWAN_SNAPSHOT_PATH, json_encode($contradictory));
	verify(sdwan_steering_gateway_for_rule($tuned_raw, $rule) === null,
	    "native renderer rejects a degraded decision with {$condition}");
}
$soft_sample['steering']['G']['degraded_at']--;
file_put_contents(SDWAN_SNAPSHOT_PATH, json_encode($soft_sample));
verify(sdwan_steering_gateway_for_rule($tuned_raw, $rule) === null, 'native renderer rejects a degraded decision from another sample');
$current = $disk;
file_put_contents(SDWAN_SNAPSHOT_PATH, json_encode($snapshot));
$t1 = $snapshot['steering'];
$t2 = $t1;
$t2['G']['since'] = time();
$t2['G']['candidate'] = 'B';
verify(sdwan_steering_signature($t1) === sdwan_steering_signature($t2), 'pending preference does not enqueue a filter reload');
/* Flat write fixture exposes child lookups separately, as config_get_path does. */
$disk[SDWAN_BINDINGS_PATH . '/item'] = $disk[SDWAN_BINDINGS_PATH]['item'];
verify(sdwan_save_config($changed, sdwan_config_revision($config)) !== [] && $writes === 1, 'SD-WAN-only editors cannot change bound policy inputs');
$frozen = $disk;
$fail = true;
verify(sdwan_save_config($changed, sdwan_config_revision($config), true) !== [] &&
    $disk === $frozen && $current === $disk, 'failed save rolls back both policy and binding revision');
$fail = false;
$disk['filter/rule'][0]['source']['address'] = '10.23.1.0/24';
$disk['filter/rule'][1]['source']['address'] = '10.23.1.0/24';
verify(sdwan_save_config($changed, sdwan_config_revision($config), true) !== [] && $writes === 1,
    'editing policy inputs cannot approve native rule drift');
$disk = $frozen;
verify(sdwan_save_config($changed, sdwan_config_revision($config), true) === [] && $writes === 2 && $pending === 1,
    'authorized cost edit updates an active binding and policy in a single write');
$edited_binding = sdwan_steering_decode($disk[SDWAN_BINDINGS_PATH]['item'][0]);
verify($edited_binding === array_replace($bindings['G'], [
	'policy_revision' => sdwan_steering_policy_revision($changed, 'p'),
]) && $disk['filter/rule'] === $frozen['filter/rule'] && $disk['gateways/gateway_group'] === $frozen['gateways/gateway_group'],
    'cost revision changes with the native group and rule scope intact');
$disk[SDWAN_BINDINGS_PATH . '/item'] = $disk[SDWAN_BINDINGS_PATH]['item'];
$revision = sdwan_config_revision($changed);
$reordered = $changed;
$reordered['policies'][0]['members'] = ['b', 'a'];
verify(sdwan_save_config($reordered, $revision, true) === [] &&
    sdwan_steering_decode($disk[SDWAN_BINDINGS_PATH]['item'][0])['gateways'] === ['B', 'A'],
    'reordering the same gateways retains approval and keeps tie preference');
$disk[SDWAN_BINDINGS_PATH . '/item'] = $disk[SDWAN_BINDINGS_PATH]['item'];
$reduced = $reordered;
$reduced['policies'][0]['members'] = ['a'];
verify(sdwan_save_config($reduced, sdwan_config_revision($reordered), true) !== [] && $writes === 3,
    'removing an approved path still requires reviewing the binding');
unset($disk[SDWAN_BINDINGS_PATH . '/item']);

$runtime = ['revision' => sdwan_config_revision($edited_binding), 'gateway' => 'A'];
$inventory = ['A' => ['interface' => 'wan', 'family' => 'inet', 'device' => 'igb0', 'address' => '192.0.2.1']];
$loaded = ['pass in quick on igb2 route-to (igb0 192.0.2.1) inet all label "descr=Test" ridentifier 301'];
verify(sdwan_steering_pf_status($edited_binding, $runtime, $inventory, $loaded) === 'applied',
    'active PF verifies expected tracker and exact next hop');
verify(sdwan_steering_pf_status($edited_binding, $runtime, $inventory, [str_replace('192.0.2.1', '192.0.2.2', $loaded[0])]) === 'pending' &&
    sdwan_steering_pf_status($edited_binding, $runtime, $inventory, [$loaded[0] . '0']) === 'pending' &&
    sdwan_steering_pf_status($edited_binding, [], $inventory, $loaded) === 'pending' &&
    sdwan_steering_pf_status($edited_binding, $runtime, $inventory, [str_replace('in quick', 'out quick', $loaded[0])]) === 'pending',
    'wrong next hop, wrong tracker and stale samples are never shown as applied');
$logged = 'pass in log (all, to pflog0) quick on igb2 route-to (igb0 192.0.2.1) inet all ' .
    'label "descr=ridentifier 401" ridentifier 301 dnpipe 10';
verify(sdwan_steering_pf_status($edited_binding, $runtime, $inventory, [$logged]) === 'applied' &&
    sdwan_steering_pf_status($edited_binding, $runtime, $inventory, [str_replace('301 dnpipe', '401 dnpipe', $logged)]) === 'pending' &&
    sdwan_steering_rule_tracker('label "descr=escaped \" ridentifier 301" queue wan') === null,
    'logging and shaper modifiers do not hide the real tracker or match a label');
$dynamic = ['A' => ['device' => 'igb0', 'address' => 'dynamic', 'family' => 'inet', 'interface' => 'wan']];
$current['fixture/dynamic/wan'] = '192.0.2.1';
verify(sdwan_steering_pf_status($edited_binding, $runtime, $dynamic, $loaded) === 'applied',
    'active PF verifies a resolved dynamic next hop');
$publication = ['config_revision' => 'test', 'gateway_inventory_revision' => 'test', 'steering' => ['G' => $runtime]];
$before_renewal = sdwan_steering_runtime_signature($publication, $dynamic);
$current['fixture/dynamic/wan'] = '192.0.2.2';
verify(sdwan_steering_runtime_signature($publication, $dynamic) !== $before_renewal,
    'renewing a live next hop grants a new reconciliation budget without changing the stored gateway');
verify(sdwan_steering_pf_status($edited_binding, $runtime, $dynamic, $loaded) === 'pending',
    'a renewed dynamic gateway requires the new next hop in PF');
unset($current['fixture/dynamic/wan']);
verify(sdwan_steering_pf_status($edited_binding, $runtime, $dynamic, $loaded) === 'pending',
    'an unresolved dynamic gateway is not shown as applied');
$ipv6 = ['A' => ['interface' => 'wan', 'family' => 'inet6', 'device' => 'igb0', 'address' => '2001:db8::1']];
$loaded6rd = ['pass in quick on igb2 route-to (wan_stf 2001:db8::1) inet6 all ridentifier 301'];
$current['fixture/devices/inet6/wan'] = 'wan_stf';
$signature6rd = sdwan_steering_runtime_signature($publication, $ipv6);
verify(sdwan_steering_pf_status($edited_binding, $runtime, $ipv6, $loaded6rd) === 'applied',
    'IPv6 6rd PF verification uses the resolved tunnel device');
$current['fixture/devices/inet6/wan'] = 'igb0.42';
verify(sdwan_steering_runtime_signature($publication, $ipv6) !== $signature6rd &&
    sdwan_steering_pf_status($edited_binding, $runtime, $ipv6, $loaded6rd) === 'pending',
    'a live device change invalidates PF verification and the reconciliation fingerprint even with the same next hop');
$pppoe = ['A' => array_replace($ipv6['A'], ['device' => 'pppoe0', 'address' => 'dynamic'])];
$current['fixture/dynamic/wan'] = '2001:db8::1';
$loadedPppoe = ['pass in quick on igb2 route-to (igb0.42 2001:db8::1) inet6 all ridentifier 301'];
verify(sdwan_steering_pf_status($edited_binding, $runtime, $pppoe, $loadedPppoe) === 'applied',
    'IPv6 alongside PPPoE resolves the parent VLAN and live next hop');
$current['fixture/devices/inet6/wan'] = '';
verify(sdwan_steering_pf_status($edited_binding, $runtime, $pppoe, $loadedPppoe) === 'pending',
    'an unresolved live device is not accepted');
unset($current['fixture/dynamic/wan'], $current['fixture/devices/inet6/wan']);
$pooled = ['revision' => sdwan_config_revision($edited_binding), 'gateway' => 'A', 'pool' => ['A', 'B']];
$inventory['B'] = ['interface' => 'opt1', 'family' => 'inet', 'device' => 'igb1', 'address' => '192.0.2.2', 'weight' => 2];
$weighted = 'pass in quick on igb2 route-to { ' . str_repeat('(igb0 192.0.2.1), ', 2) .
    str_repeat('(igb1 192.0.2.2), ', 3) . '(igb1 192.0.2.2) } round-robin inet all ridentifier 301';
verify(sdwan_steering_pf_status($edited_binding, $pooled, $inventory, [$weighted]) === 'applied' &&
    sdwan_steering_pf_status($edited_binding, $pooled, $inventory, [str_replace('(igb0 192.0.2.1), ', '', $weighted)]) === 'pending',
    'loaded PF verification checks each balancing route and native weight');
$current['system']['lb_use_sticky'] = '';
$sticky = str_replace('round-robin', 'round-robin sticky-address', $weighted);
verify(sdwan_steering_pf_status($edited_binding, $pooled, $inventory, [$sticky]) === 'applied' &&
    sdwan_steering_pf_status($edited_binding, $pooled, $inventory, [$weighted]) === 'pending',
    'loaded PF verification checks the configured native sticky option');
unset($current['system']['lb_use_sticky']);
$runtime['gateway'] = null;
verify(sdwan_steering_pf_status($edited_binding, $runtime, $inventory, ['block drop in log quick on igb2 inet all ridentifier 301 queue shaped']) === 'blocked' &&
    sdwan_steering_pf_status($edited_binding, $runtime, $inventory, $loaded) === 'pending' &&
    sdwan_steering_pf_status($edited_binding, $runtime, $inventory, null) === 'unavailable',
    'blocking is verified from PF and missing output is explicit');
$states = [
	'all tcp first -> second ESTABLISHED:ESTABLISHED',
	'   age 00:00:04, anchor 1, rule 33',
	'   id: 000000010000000a creatorid: 12345678',
	'   route-to: 192.0.2.1@igb0',
	'   ridentifier 301',
	'all tcp third -> fourth ESTABLISHED:ESTABLISHED',
	'   id: 000000010000000b creatorid: 12345678',
	'   route-to: 192.0.2.1@igb0',
	'   ridentifier 999',
	'all tcp fifth -> sixth ESTABLISHED:ESTABLISHED',
	'   id: 000000010000000c creatorid: 12345678',
	'   route-to: 192.0.2.1@igb1',
	'   ridentifier 301',
];
verify(sdwan_steering_state_ids($states, ['301'], 'igb0', '192.0.2.1') === ['000000010000000a/12345678'],
    'state recovery matches the stable tracker, exact interface, next hop and unique state identity');
$before_unbind = $disk;
$receipt_path = SDWAN_SNAPSHOT_PATH . '.forwarded';
$before_requests = $pending;
$before_writes = $writes;
$current = $disk;
$fail = true;
verify(sdwan_steering_unbind('G', sdwan_steering_revision()) !== [] && $current === $disk &&
    !is_file($receipt_path) && $pending === $before_requests,
    'a failed binding save rolls back the withdrawal receipt without requesting native reload');
$fail = false;
verify(sdwan_steering_unbind('G', sdwan_steering_revision()) === [] && !sdwan_steering_bindings() &&
    $pending === $before_requests + 1, 'the binding editor requests native reload when removing a binding');
$withdrawal = sdwan_steering_read_receipt($receipt_path);
verify($withdrawal['trackers'] === ['301'] && $withdrawal['withdrawal']['trackers'] === ['301'] &&
    !$withdrawal['withdrawal']['unknown'] && !$withdrawal['confirmed'],
    'the editor retains removed trackers before the observer runs again');
verify(sdwan_steering_withdrawal($withdrawal, ['301']) === null &&
    !sdwan_steering_withdrawal_confirmed($withdrawal['withdrawal'], [], null),
    'reattached trackers cancel a pending withdrawal and unavailable PF cannot confirm it');
unlink($receipt_path);
$disk = $current = $before_unbind;
$pending = $before_requests;
$writes = $before_writes;
$abi = 0;
$current = $disk;
verify(sdwan_steering_unbind('G', sdwan_steering_revision()) === [] && !sdwan_steering_bindings() &&
    $pending === 1 && $writes === 4, 'stock firmware can remove orphaned binding metadata without PF operations');
