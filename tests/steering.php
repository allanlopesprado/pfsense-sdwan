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
foreach (['sdwan.inc', 'sdwan_engine.inc', 'sdwan_steering.inc', 'sdwan_preflight.inc', 'sdwan_log.inc'] as $file) {
	$contents = file_get_contents($pkg . '/' . $file);
	if ($file === 'sdwan_engine.inc') {
		$contents = str_replace('/var/run/sdwan-observer.json', $dir . '/snapshot', $contents);
	}
	file_put_contents($dir . '/' . $file, $contents);
}
set_include_path(__DIR__ . '/fixtures/write');
require 'config.inc';
require $dir . '/sdwan_steering.inc';
function filter_sdwan_binding_api(): int { global $abi; return $abi; }
function filter_configure(): void { global $pending; $pending++; }
function get_interface_gateway($interface): ?string {
	return config_get_path('fixture/dynamic/' . $interface);
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
$t1 = $snapshot['steering'];
$t2 = $t1;
$t2['G']['since'] = time();
$t2['G']['candidate'] = 'B';
verify(sdwan_steering_signature($t1) === sdwan_steering_signature($t2), 'pending preference does not enqueue a filter reload');
/* Flat write fixture exposes child lookups separately, as config_get_path does. */
$disk[SDWAN_BINDINGS_PATH . '/item'] = $disk[SDWAN_BINDINGS_PATH]['item'];
verify(sdwan_save_config($changed, sdwan_config_revision($config)) !== [] && $writes === 1, 'SD-WAN-only editors cannot change bound policy inputs');
unset($disk[SDWAN_BINDINGS_PATH . '/item']);
$abi = 0;
$current = $disk;
verify(sdwan_steering_unbind('G', sdwan_steering_revision()) === [] && !sdwan_steering_bindings() &&
    $pending === 1 && $writes === 2, 'stock firmware can remove orphaned binding metadata without PF operations');
