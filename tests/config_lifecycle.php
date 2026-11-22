<?php
/* Exercise normal configuration lifecycles against the in-memory pfSense write fixture. */
set_include_path(__DIR__ . '/fixtures/write');
require 'config.inc';
require __DIR__ . '/../files/usr/local/pkg/sdwan.inc';

$seed = filter_var($argv[1] ?? '172831', FILTER_VALIDATE_INT, ['options' => ['min_range' => 0, 'max_range' => 2147483647]]);
$sequences = filter_var($argv[2] ?? '2048', FILTER_VALIDATE_INT, ['options' => ['min_range' => 1, 'max_range' => 100000]]);
if ($argc > 3 || $seed === false || $sequences === false) {
	fwrite(STDERR, "Usage: php tests/config_lifecycle.php [seed] [sequences]\n");
	exit(2);
}
mt_srand($seed, MT_RAND_MT19937);

function lifecycle_edit(string $step, array $candidate, bool $allowed, ?string $revision = null, bool $can_edit_checks = true): void {
	global $disk, $current, $writes, $summary, $seed, $sequence;
	$old_disk = $disk;
	$old_config = sdwan_get_config();
	$old_writes = $writes;
	$errors = sdwan_save_config($candidate, $revision ?? sdwan_config_revision($old_config), $can_edit_checks);
	$operation = !$allowed ? 'rejected' : ($old_config === $candidate ? 'unchanged' : 'saved');
	if (($errors === []) !== $allowed || $writes - $old_writes !== (int)($operation === 'saved') ||
	    ($operation !== 'saved' && $disk !== $old_disk) || $current !== $disk ||
	    sdwan_get_config() !== ($allowed ? $candidate : $old_config) ||
	    array_diff_key($disk, [SDWAN_CONFIG_PATH => true]) !== array_diff_key($old_disk, [SDWAN_CONFIG_PATH => true])) {
		throw new RuntimeException("Seed {$seed}, sequence {$sequence}, {$step}: expected {$operation}; got " .
		    ($errors ? implode(' ', $errors) : 'success') . '; writes=' . ($writes - $old_writes));
	}
	$summary[$operation]++;
}

$native = [
	'interfaces' => ['wan' => ['enable' => ''], 'opt1' => ['enable' => ''], 'opt2' => ['enable' => '']],
	'gateways/gateway_item' => [
		['name' => 'GW1', 'interface' => 'wan', 'gateway' => '192.0.2.1'],
		['name' => 'GW2', 'interface' => 'opt1', 'gateway' => '198.51.100.1'],
		['name' => 'GWv6', 'interface' => 'opt2', 'gateway' => '2001:db8::1'],
	],
	'filter' => ['rule' => [['descr' => 'Existing native rule']]],
];
$summary = ['saved' => 0, 'rejected' => 0, 'unchanged' => 0];

for ($sequence = 1; $sequence <= $sequences; $sequence++) {
	$disk = $current = $native;
	$writes = 0;
	$fail = false;
	$empty = sdwan_empty_config();
	$first = ['name' => 'WAN1', 'gateway' => 'GW1', 'cost' => (string)mt_rand(0, 65534)];
	$second = ['name' => 'WAN2', 'gateway' => 'GW2', 'cost' => (string)mt_rand(0, 65535)];
	$third = ['name' => 'WANv6', 'gateway' => 'GWv6', 'cost' => (string)mt_rand(0, 65535)];
	$sla = ['name' => 'SLA', 'latency_ms' => (string)mt_rand(1, 600000), 'loss_pct' => (string)mt_rand(0, 100)];
	$member_order = mt_rand(0, 1) ? ['WAN1', 'WAN2'] : ['WAN2', 'WAN1'];
	$strategies = ['cost', 'latency', 'balance'];
	$policy = ['name' => 'Policy', 'sla' => 'SLA', 'members' => $member_order, 'strategy' => $strategies[mt_rand(0, 2)]];
	lifecycle_edit('open a fresh installation', $empty, true);
	lifecycle_edit('policy before its members and SLA', array_replace($empty, ['policies' => [$policy]]), false);
	lifecycle_edit('member for an absent gateway', array_replace($empty, ['members' => [array_replace($first, ['gateway' => 'Missing'])]]), false);

	$setup = $empty;
	$sections = mt_rand(0, 1) ? ['members', 'slas'] : ['slas', 'members'];
	foreach ($sections as $section) {
		$setup[$section] = $section === 'members' ? [$first, $second, $third] : [$sla];
		lifecycle_edit("create {$section}", $setup, true);
	}
	$setup['policies'][] = $policy;
	lifecycle_edit('save legacy policy without optional fields', $setup, true);
	$before_edit = sdwan_config_revision($setup);

	$invalid = $setup;
	$invalid['policies'][0]['members'][] = 'WANv6';
	lifecycle_edit('mix families in a policy', $invalid, false);
	$invalid['policies'][0]['members'] = [];
	lifecycle_edit('remove all members from a policy', $invalid, false);
	$orphaned = $setup;
	$orphaned['slas'] = [];
	lifecycle_edit('delete an SLA in use', $orphaned, false);
	$orphaned = $setup;
	array_shift($orphaned['members']);
	lifecycle_edit('delete a member in use', $orphaned, false);

	$with_checks = $setup;
	$with_checks['members'][0]['probe_primary'] = 'tcp://192.0.2.50:' . mt_rand(1, 65535);
	$with_checks['members'][1]['probe_primary'] = 'tcp://198.51.100.50:' . mt_rand(1, 65535);
	lifecycle_edit('change a service check without permission', $with_checks, false, null, false);
	$fail = true;
	lifecycle_edit('disk rejects a legitimate edit', $with_checks, false);
	$fail = false;
	lifecycle_edit('retry the legitimate edit', $with_checks, true);
	lifecycle_edit('stale editor attempts to erase newer probes', $setup, false, $before_edit);

	$required = $with_checks;
	$required['policies'][0]['degrade_samples'] = (string)mt_rand(1, 6);
	$required['policies'][0]['recover_seconds'] = (string)mt_rand(0, 300);
	$required['policies'][0]['probe_requirements'] = [['member' => 'WAN1', 'primary_check' => 'required']];
	lifecycle_edit('require a probe on one member', $required, true);
	$missing_check = $required;
	unset($missing_check['members'][0]['probe_primary']);
	lifecycle_edit('delete a mandatory probe', $missing_check, false);
	$missing_secondary = $required;
	$missing_secondary['policies'][0]['secondary_check'] = 'required';
	lifecycle_edit('require an absent secondary probe', $missing_secondary, false);

	/* The native administrator removes a gateway outside the package. */
	array_shift($disk['gateways/gateway_item']);
	$repair = $required;
	$repair['members'][0]['cost'] = (string)((int)$first['cost'] + 1);
	lifecycle_edit('allow repair of a restored policy with a missing gateway', $repair, true);
	$unavailable = $repair;
	$unavailable['policies'][] = array_replace($policy, ['name' => 'Other policy', 'members' => ['WAN1']]);
	lifecycle_edit('reject adding an unavailable member to a new policy', $unavailable, false);
	$disk['gateways/gateway_item'] = $native['gateways/gateway_item'];
	lifecycle_edit('retrieve the existing policy after gateway restoration', $repair, true);

	$repair['policies'] = [];
	lifecycle_edit('remove policy references before deleting dependencies', $repair, true);
	lifecycle_edit('delete now-unused members and SLA', $empty, true);
}

printf("seed=%d sequences=%d operations=%d saved=%d rejected=%d unchanged=%d\n", $seed, $sequences,
    array_sum($summary), $summary['saved'], $summary['rejected'], $summary['unchanged']);
