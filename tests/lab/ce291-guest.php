<?php
/* Scenario inputs for the isolated appliance. pfSense owns the reload and services. */
declare(strict_types=1);

function add_fields(SimpleXMLElement $parent, array $fields): void {
    foreach ($fields as $key => $value) {
        if (is_array($value)) {
            add_fields($parent->addChild($key), $value);
        } else {
            $parent->addChild($key, $value);
        }
    }
}

$action = $argv[1] ?? '';
if ($action === 'topology') {
    $config = simplexml_load_file('/conf.default/config.xml', SimpleXMLElement::class, LIBXML_NONET);
    unset($config->interfaces, $config->gateways, $config->staticroutes, $config->dhcpd, $config->dhcpdv6);
    $interfaces = $config->addChild('interfaces');
    foreach ([
        'wan' => ['vtnet0', '198.51.100.1', '30', 'GW_A'],
        'lan' => ['vtnet1', '192.0.2.1', '25', null],
        'opt1' => ['vtnet2', '203.0.113.1', '30', 'GW_B'],
    ] as $name => [$device, $address, $mask, $gateway]) {
        $interface = $interfaces->addChild($name);
        add_fields($interface, ['if' => $device, 'enable' => '', 'descr' => strtoupper($name),
            'ipaddr' => $address, 'subnet' => $mask]);
        if ($gateway !== null) {
            $interface->addChild('gateway', $gateway);
        }
    }
    $gateways = $config->addChild('gateways');
    foreach (['GW_A' => ['wan', '198.51.100.2'], 'GW_B' => ['opt1', '203.0.113.2']] as $name => [$iface, $hop]) {
        add_fields($gateways->addChild('gateway_item'), ['name' => $name, 'interface' => $iface,
            'gateway' => $hop, 'monitor' => $hop, 'ipprotocol' => 'inet',
            'interval' => '150', 'loss_interval' => '500', 'time_period' => '3000']);
    }
    $gateways->addChild('defaultgw4', 'GW_A');
    foreach (['G', 'B'] as $name) {
        $group = $gateways->addChild('gateway_group');
        $group->addChild('name', $name);
        $group->addChild('item', 'GW_A|1|address');
        $group->addChild('item', 'GW_B|2|address');
        $group->addChild('trigger', 'down');
    }
    $routes = $config->addChild('staticroutes');
    foreach (['164' => 'GW_A', '165' => 'GW_B', '166' => 'GW_A', '167' => 'GW_B'] as $last => $gateway) {
        add_fields($routes->addChild('route'), ['network' => "192.0.2.$last/32", 'gateway' => $gateway]);
    }
    unset($config->filter);
    $filter = $config->addChild('filter');
    foreach ([['ERP', 'G', '162', 41001], ['Backup', 'B', '163', 41003]] as [$name, $group, $target, $id]) {
        foreach (['pass', 'block'] as $type) {
            $rule = $filter->addChild('rule');
            add_fields($rule, ['type' => $type, 'ipprotocol' => 'inet', 'interface' => 'lan',
                'protocol' => 'tcp', 'tracker' => (string)($id + ($type === 'block' ? 1 : 0)),
                'descr' => "$name $type", 'source' => ['address' => '192.0.2.11'],
                'destination' => ['address' => "192.0.2.$target", 'port' => '7']]);
            if ($type === 'pass') {
                $rule->addChild('gateway', $group);
                $rule->addChild('log');
            }
        }
    }
    $native = $filter->addChild('rule');
    add_fields($native, ['type' => 'pass', 'ipprotocol' => 'inet', 'interface' => 'lan',
        'tracker' => '41005', 'descr' => 'Unrelated native LAN rule', 'source' => ['network' => 'lan'],
        'destination' => ['any' => '']]);
    $config->nat->outbound->mode = 'automatic';
    if ($config->asXML('/cf/conf/config.xml') === false) {
        throw new RuntimeException('Cannot write the disposable configuration');
    }
    exit;
}

require_once('config.inc');
require_once('/usr/local/pkg/sdwan_steering.inc');
if ($action === 'observations') {
    $config = sdwan_get_config();
    $inventory = sdwan_gateways();
    $snapshot = sdwan_current_snapshot($config, $inventory);
    $record = sdwan_steering_receipt(SDWAN_SNAPSHOT_PATH . '.forwarded');
    echo json_encode(['snapshot' => $snapshot, 'receipt' => $record], JSON_THROW_ON_ERROR), PHP_EOL;
    exit;
}
if ($action === 'settings') {
    $policies = [];
    foreach (['ERP' => ['required', 'ignored'], 'Backup' => ['ignored', 'required']] as $name => [$p, $s]) {
        $policies[] = ['name' => $name, 'sla' => 'lab', 'strategy' => 'cost',
            'primary_check' => $p, 'secondary_check' => $s, 'recover_seconds' => '0',
            'members' => ['item' => ['a','b']]];
    }
    config_set_path('installedpackages/sdwan', ['version' => '1',
        'members' => ['item' => [
            ['name' => 'a', 'gateway' => 'GW_A', 'cost' => '10', 'probe_primary' => 'tcp://192.0.2.164:7',
                'probe_secondary' => 'tcp://192.0.2.166:7'],
            ['name' => 'b', 'gateway' => 'GW_B', 'cost' => '20', 'probe_primary' => 'tcp://192.0.2.165:7',
                'probe_secondary' => 'tcp://192.0.2.167:7'],
        ]],
        'slas' => ['item' => [['name' => 'lab', 'latency_ms' => '80', 'loss_pct' => '5']]],
        'policies' => ['item' => $policies],
    ]);
    write_config('Configure the disposable SD-WAN two-service acceptance');
    exit;
}
if ($action === 'bind' || $action === 'unbind') {
    foreach (['G' => 'ERP', 'B' => 'Backup'] as $group => $policy) {
        if ($action === 'bind') {
            $errors = sdwan_steering_bind($policy, $group, sdwan_steering_revision());
        } else {
            $errors = sdwan_steering_unbind($group, sdwan_steering_revision());
        }
        if ($errors) {
            throw new RuntimeException("$group: " . implode('; ', $errors));
        }
    }
    exit;
}
if ($action === 'mode') {
    echo 'ABI=', sdwan_steering_abi(), PHP_EOL;
    exit;
}
throw new InvalidArgumentException('Unknown acceptance action');

