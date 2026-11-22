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
        'opt1' => ['vtnet2', 'dhcp', '29', null],
    ] as $name => [$device, $address, $mask, $gateway]) {
        $interface = $interfaces->addChild($name);
        add_fields($interface, ['if' => $device, 'enable' => '', 'descr' => strtoupper($name),
            'ipaddr' => $address, 'subnet' => $mask]);
        if ($gateway !== null) {
            $interface->addChild('gateway', $gateway);
        }
    }
    $gateways = $config->addChild('gateways');
    foreach (['GW_A' => ['wan', '198.51.100.2'], 'GW_B' => ['opt1', '203.0.113.2']] as $name => [$iface, $monitor]) {
        add_fields($gateways->addChild('gateway_item'), ['name' => $name, 'interface' => $iface,
            'gateway' => $iface === 'opt1' ? 'dynamic' : $monitor, 'monitor' => $monitor, 'ipprotocol' => 'inet',
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

if ($action === 'hold_renderer') {
    $adapter = '/etc/inc/filter-sdwan.inc';
    $original = file_get_contents($adapter);
    $head = 'function filter_sdwan_rule_route(array $rule, array $routes): array|false|null {';
    $test = 'if ((string)($rule["tracker"] ?? "") === "41001") { return null; }';
    $modified = str_replace($head, "$head\n\t$test", $original, $count);
    if ($count !== 1 || file_put_contents("$adapter.lab", $modified) !== strlen($modified) ||
        !rename("$adapter.lab", $adapter)) {
        throw new RuntimeException('Cannot arrange the disposable renderer failure');
    }
    exit;
}
if ($action === 'probe') {
    $context = stream_context_create(['socket' => ['bindto' => $argv[2] . ':0']]);
    $peer = stream_socket_client('tcp://192.0.2.168:7', $errno, $error, 4, STREAM_CLIENT_CONNECT, $context);
    if ($peer === false) {
        throw new RuntimeException($error);
    }
    stream_set_timeout($peer, 4);
    fwrite($peer, "same-target\n");
    echo fgets($peer);
    fclose($peer);
    exit;
}

require_once('config.inc');
require_once('/usr/local/pkg/sdwan_steering.inc');
if ($action === 'renew_wan2') {
    require_once('interfaces.inc');
    require_once('pfsense-utils.inc');
    interface_bring_down('opt1');
    restart_interface_services('opt1');
    interface_configure('opt1');
    exit;
}
if ($action === 'observations') {
    $package_settings = sdwan_get_config();
    $inventory = sdwan_gateways();
    $snapshot = sdwan_current_snapshot($package_settings, $inventory);
    $record = sdwan_steering_read_receipt(SDWAN_SNAPSHOT_PATH . '.forwarded');
    $signature = null;
    $filter_status = [];
    if (isset($snapshot['steering'])) {
        $signature = sdwan_steering_runtime_signature($snapshot, $inventory);
        $native = sdwan_steering_native($inventory);
        $rules = sdwan_steering_pf_rules();
        foreach (sdwan_steering_bindings() as $group => $binding) {
            $check = sdwan_steering_preflight($package_settings, $binding['policy'], $group, $native);
            $filter_status[$group] = sdwan_steering_preflight_matches($binding, $check)
                ? sdwan_steering_pf_status($binding, $snapshot['steering'][$group] ?? [], $inventory,
                    $rules, $check['rule_pairs'])
                : 'binding_changed';
        }
    }
    echo json_encode(['snapshot' => $snapshot, 'receipt' => (object)$record,
        'signature' => $signature, 'pf' => (object)$filter_status], JSON_THROW_ON_ERROR), PHP_EOL;
    exit;
}
if ($action === 'settings') {
    $policies = [];
    foreach (['ERP' => ['required', 'ignored'], 'Backup' => ['ignored', 'required']] as $name => [$p, $s]) {
        $policies[] = ['name' => $name, 'sla' => 'lab', 'strategy' => 'cost',
            'primary_check' => $p, 'secondary_check' => $s,
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
    $groups = ['G' => 'ERP', 'B' => 'Backup'];
    if (isset($argv[2])) {
        if (!isset($groups[$argv[2]])) {
            throw new InvalidArgumentException('Unknown acceptance gateway group');
        }
        $groups = [$argv[2] => $groups[$argv[2]]];
    }
    foreach ($groups as $group => $policy) {
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
