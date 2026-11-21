<?php
// Synthetic IPv4 scenario for the dedicated, isolated CE lab disk.
declare(strict_types=1);

const LAB_HOST = 'sdwan-ce292-lab';
const LAB_GROUP = 'LAB_SD';
const LAB_POLICY = 'lab_policy';
const LAB_PASS = '771292101';
const LAB_GUARD = '771292102';

function lab_fail(string $message): never {
    fwrite(STDERR, "$message\n");
    exit(1);
}

if (PHP_SAPI !== 'cli' || !is_readable('/dev/gpt/pfsensece292lab') || trim((string)file_get_contents('/etc/version')) !== '2.9.2-RELEASE' ||
    shell_exec('/bin/kenv -q smbios.system.maker') !== "QEMU\n") {
    lab_fail('This command requires the named disposable QEMU disk.');
}

require_once('config.inc');
require_once('gwlb.inc');
require_once('/usr/local/pkg/sdwan_steering.inc');
$mode = $argv[1] ?? '';
$hostname = config_get_path('system/hostname');

switch ($mode) {
    case 'topology':
        if (!is_file('/root/sdwan-lab-proof/config.stock.xml') || !sdwan_steering_supported() ||
            !in_array($hostname, ['pfSense', LAB_HOST], true) || config_get_path('gateways/sdwan_bindings/item', [])) {
            lab_fail('Complete the stock installation and backup before configuring this scenario.');
        }
        config_set_path('system/hostname', LAB_HOST);
        config_set_path('system/domain', 'lab.test');
        config_set_path('interfaces/wan', ['enable' => '', 'if' => 'em0', 'descr' => 'LAB_WAN1',
            'ipaddr' => '198.18.10.10', 'subnet' => '24', 'gateway' => 'LAB_WAN1']);
        config_set_path('interfaces/lan', ['enable' => '', 'if' => 'em1', 'descr' => 'LAB_LAN',
            'ipaddr' => '192.168.1.1', 'subnet' => '24']);
        config_set_path('interfaces/opt1', ['enable' => '', 'if' => 'em2', 'descr' => 'LAB_WAN2',
            'ipaddr' => '198.18.20.10', 'subnet' => '24', 'gateway' => 'LAB_WAN2']);
        config_set_path('dhcpd/lan', []);
        config_set_path('gateways/gateway_item', [
            ['interface' => 'wan', 'gateway' => '198.18.10.2', 'name' => 'LAB_WAN1',
                'ipprotocol' => 'inet', 'descr' => 'Lab WAN 1', 'monitor' => '198.18.10.2'],
            ['interface' => 'opt1', 'gateway' => '198.18.20.2', 'name' => 'LAB_WAN2',
                'ipprotocol' => 'inet', 'descr' => 'Lab WAN 2', 'monitor' => '198.18.20.2'],
        ]);
        config_set_path('gateways/defaultgw4', 'LAB_WAN1');
        config_set_path('gateways/gateway_group', [
            ['name' => LAB_GROUP, 'trigger' => 'down', 'descr' => 'Isolated SD-WAN test',
                'item' => ['LAB_WAN1|1|', 'LAB_WAN2|2|']],
        ]);
        $scope = ['interface' => 'lan', 'ipprotocol' => 'inet', 'protocol' => 'tcp',
            'source' => ['address' => '192.168.1.10'], 'destination' => ['any' => '', 'port' => '18080']];
        $pass = ['type' => 'pass', 'tracker' => LAB_PASS, 'descr' => 'Lab SD-WAN TCP 18080', 'gateway' => LAB_GROUP] + $scope;
        $guard = ['type' => 'block', 'tracker' => LAB_GUARD, 'descr' => 'Lab SD-WAN fallback block'] + $scope;
        $previous = array_filter(config_get_path('filter/rule', []),
            static fn(array $rule): bool => !in_array($rule['tracker'] ?? '', [LAB_PASS, LAB_GUARD], true));
        config_set_path('filter/rule', [$pass, $guard, ...array_values($previous)]);

        $candidate = sdwan_empty_config();
        $candidate['members'] = [
            ['name' => 'lab_a', 'gateway' => 'LAB_WAN1', 'cost' => '10'],
            ['name' => 'lab_b', 'gateway' => 'LAB_WAN2', 'cost' => '20'],
        ];
        $candidate['slas'] = [['name' => 'lab_health', 'latency_ms' => '250', 'loss_pct' => '25']];
        $candidate['policies'] = [['name' => LAB_POLICY, 'sla' => 'lab_health', 'strategy' => 'cost',
            'members' => ['lab_a', 'lab_b']]];
        $errors = sdwan_validate_config($candidate, null);
        if ($errors) {
            lab_fail(implode(' ', $errors));
        }
        config_set_path(SDWAN_CONFIG_PATH, sdwan_encode_config($candidate));
        if (!is_array(write_config('Isolated CE two-WAN scenario', true, true))) {
            lab_fail('Native write_config did not commit the scenario.');
        }
        echo "Synthetic topology written. Reboot before binding the policy.\n";
        break;

    case 'bind':
    case 'unbind':
        if ($hostname !== LAB_HOST) {
            lab_fail('Synthetic lab hostname does not match.');
        }
        $revision = sdwan_steering_revision();
        $errors = $mode === 'bind' ? sdwan_steering_bind(LAB_POLICY, LAB_GROUP, $revision) :
            sdwan_steering_unbind(LAB_GROUP, $revision);
        if ($errors) {
            lab_fail(implode(' ', $errors));
        }
        echo ($mode === 'bind' ? 'Bound' : 'Unbound') . " via the native config and reload path.\n";
        break;

    case 'proof':
        if ($hostname !== LAB_HOST) {
            lab_fail('Synthetic lab hostname does not match.');
        }
        $inventory = sdwan_gateways();
        $snapshot = sdwan_current_snapshot(sdwan_get_config(), $inventory);
        $binding = sdwan_steering_bindings()[LAB_GROUP] ?? null;
        $state = $snapshot['steering'][LAB_GROUP] ?? [];
        echo json_encode([
            'config_scope_sha256' => sdwan_config_revision([
                config_get_path('interfaces'), config_get_path('gateways'), config_get_path('filter'),
                sdwan_get_config(),
            ]),
            'binding' => $binding === null ? 'absent' : 'present',
            'snapshot_epoch' => $snapshot['generated_at'] ?? null,
            'gateway' => $state['gateway'] ?? null,
            'pf' => $binding === null ? 'native' :
                sdwan_steering_pf_status($binding, $state, $inventory, sdwan_steering_pf_rules()),
        ], JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR), PHP_EOL;
        break;

    default:
        lab_fail('Usage: php -f native-scenario.php -- topology|bind|unbind|proof');
}
