<?php
declare(strict_types=1);

if (PHP_SAPI !== 'cli' || !is_readable('/dev/gpt/pfsensece292lab') ||
    trim((string)file_get_contents('/etc/version')) !== '2.9.2-RELEASE' ||
    shell_exec('/bin/kenv -q smbios.system.maker') !== "QEMU\n" ||
    trim((string)shell_exec('/bin/hostname -s')) !== 'sdwan-ce292-lab') {
    fwrite(STDERR, "Requires isolated disposable CE 2.9.2 appliance.\n");
    exit(1);
}

require_once('config.inc');
require_once('filter.inc');
require_once('/usr/local/pkg/sdwan_steering.inc');

$operation = $argv[1] ?? '';
$groupName = 'LAB_SD';
$policyName = 'lab_policy';
$settings = sdwan_get_config();
$binding = sdwan_steering_bindings()[$groupName] ?? null;

if ($operation === 'configure') {
    if ($binding !== null ||
        count($settings['slas']) !== 1 || count($settings['members']) !== 2 ||
        count($settings['policies']) !== 1 || ($settings['policies'][0]['name'] ?? '') !== $policyName) {
        fwrite(STDERR, "Expected synthetic two-WAN scenario, with no bound rules.\n");
        exit(1);
    }
    $revised = $settings;
    $revised['slas'][0]['latency_ms'] = '40';
    $revised['slas'][0]['rttsd_ms'] = '30';
    $revised['slas'][0]['loss_pct'] = '5';
    $revised['policies'][0]['strategy'] = 'cost';
    foreach ($revised['members'] as &$member) {
        $member['cost'] = match ($member['gateway']) {
            'LAB_WAN1' => '2',
            'LAB_WAN2' => '1',
            default => throw new RuntimeException('Unexpected lab gateway'),
        };
    }
    unset($member);
    $problems = sdwan_save_config($revised, sdwan_config_revision($settings), true);
    if ($problems) {
        fwrite(STDERR, implode("\n", $problems) . PHP_EOL);
        exit(1);
    }

    $groups = config_get_path('gateways/gateway_group', []);
    foreach ($groups as &$group) {
        if ($group['name'] === $groupName) {
            $group['item'] = ['LAB_WAN2|1|', 'LAB_WAN1|2|'];
        }
    }
    unset($group);
    $groups[] = ['name' => 'LAB_DEFAULT', 'trigger' => 'down',
        'descr' => 'Separate default group with WAN1 preferred',
        'item' => ['LAB_WAN1|1|', 'LAB_WAN2|2|']];
    config_set_path('gateways/gateway_group', $groups);
    config_set_path('gateways/defaultgw4', 'LAB_DEFAULT');
    if (!is_array(write_config('Isolated matched two-WAN retune A/B scenario', true, true))) {
        fwrite(STDERR, "Unable to commit lab group priorities.\n");
        exit(1);
    }
    filter_configure();
} elseif ($operation === 'inspect') {
    $inventory = sdwan_gateways();
    $snapshot = sdwan_current_snapshot($settings, $inventory);
    $state = $snapshot['steering'][$groupName] ?? [];
    $receipt = sdwan_steering_read_receipt(SDWAN_SNAPSHOT_PATH . '.forwarded');
    $signature_matches = $snapshot &&
        ($receipt['signature'] ?? null) === sdwan_steering_runtime_signature($snapshot, $inventory);
    echo json_encode([
        'package_settings' => $settings,
        'binding' => $binding === null ? 'absent' : 'present',
        'generation' => $snapshot['generated_at'] ?? null,
        'members' => $snapshot['members'] ?? null,
        'candidates' => $snapshot['policies'][$policyName]['candidates'] ?? null,
        'gateway' => $state['gateway'] ?? null,
        'receipt_accepted' => $signature_matches && ($receipt['accepted'] ?? false),
        'receipt_confirmed' => $signature_matches && ($receipt['confirmed'] ?? false),
        'pf' => $binding === null ? 'native' :
            sdwan_steering_pf_status($binding, $state, $inventory, sdwan_steering_pf_rules()),
    ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES), PHP_EOL;
} else {
    fwrite(STDERR, "Usage: retune.php configure|inspect\n");
    exit(1);
}
