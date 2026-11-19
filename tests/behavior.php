<?php
/* Exercise the installed code with synthetic dpinger results and inventory. */
declare(strict_types=1);

require_once __DIR__ . '/../files/usr/local/pkg/sdwan.inc';
require_once __DIR__ . '/../files/usr/local/pkg/sdwan_engine.inc';

error_reporting(E_ALL);
set_error_handler(static function ($level, $message, $file, $line) {
    throw new ErrorException($message, 0, $level, $file, $line);
});

function check(string $label, bool $condition): void
{
    if (!$condition) {
        throw new RuntimeException("Failed: " . $label);
    }
    echo "ok - ", $label, PHP_EOL;
}

$config = [
    'version' => '1',
    'members' => [
        ['name' => 'a', 'gateway' => 'GW_A', 'cost' => '10'],
        ['name' => 'b', 'gateway' => 'GW_B', 'cost' => '20'],
    ],
    'slas' => [['name' => 'voice', 'latency_ms' => '100', 'loss_pct' => '2']],
    'policies' => [[
        'name' => 'calls', 'sla' => 'voice', 'members' => ['a', 'b'], 'strategy' => 'cost',
    ]],
];
$inventory = [
    'GW_A' => ['interface' => 'wan', 'address' => '192.0.2.1', 'monitor' => '192.0.2.1'],
    'GW_B' => ['interface' => 'opt1', 'address' => '198.51.100.1', 'monitor' => '198.51.100.1'],
];
check('valid configuration', sdwan_validate_config($config, $inventory) === []);
check('policy/member lists survive encode/decode', sdwan_decode_config(sdwan_encode_config($config)) === $config);
check('empty config survives encode/decode', sdwan_decode_config(sdwan_encode_config(sdwan_empty_config())) === sdwan_empty_config());
$invalid = $config;
$invalid['members'][0]['gateway'] = 'MISSING';
check('unknown gateway rejected', sdwan_validate_config($invalid, $inventory) !== []);
$invalid = $config;
$invalid['slas'][0]['loss_pct'] = 'NaN';
check('invalid SLA number rejected', sdwan_validate_config($invalid, $inventory) !== []);
$invalid = $config;
$invalid['members'][] = $invalid['members'][0];
check('duplicate member rejected', sdwan_validate_config($invalid, $inventory) !== []);
$invalid = $config;
$invalid['policies'][0]['sla'] = 'removed';
check('policy with missing SLA rejected', sdwan_validate_config($invalid, $inventory) !== []);
$invalid = $config;
$invalid['policies'][0]['members'] = ['removed'];
check('policy with missing member rejected', sdwan_validate_config($invalid, $inventory) !== []);
$invalid = $config;
$invalid['version'] = '99';
check('unsupported schema rejected', sdwan_validate_config($invalid, $inventory) !== []);
$changed = $config;
$changed['policies'][0]['strategy'] = 'latency';
check('revision depends on policy contents', sdwan_config_revision($changed) !== sdwan_config_revision($config));

check('socket measurements converted from microseconds', sdwan_parse_dpinger_line("WAN6 1234 200 1\n", 'WAN6') === [1.234, 0.2, 1.0]);
foreach (['WAN6 0 0 0', 'OTHER 1000 20 2', 'WAN6 123 2', 'WAN6 1234 200 101'] as $malformed) {
    check('reject socket reading ' . $malformed, sdwan_parse_dpinger_line($malformed, 'WAN6') === null);
}
$sample = ['status' => 'online', 'substatus' => 'none', 'delay' => '20.5ms', 'stddev' => '1ms', 'loss' => '0.0%'];
$gateways = ['GW_A' => $sample, 'GW_B' => array_replace($sample, ['delay' => '8.25ms'])];
function selected(array $config, array $gateways): ?string
{
    $snapshot = sdwan_evaluate($config, $gateways, 1700000000);
    return $snapshot['policies']['calls']['selected'];
}
check('lower cost wins within SLA', selected($config, $gateways) === 'a');
check('latency policy independently picks lowest RTT', selected($changed, $gateways) === 'b');
$strict = $config;
$strict['slas'][0]['loss_pct'] = '0';
check('zero loss is a valid measured value', selected($strict, $gateways) === 'a');
$degraded = $gateways;
$degraded['GW_A']['loss'] = '2.1%';
check('loss above SLA excludes cheaper path', selected($config, $degraded) === 'b');
$degraded['GW_B']['delay'] = '101ms';
check('no choice when all candidates violate SLA', selected($config, $degraded) === null);
$boundary = $gateways;
$boundary['GW_A']['delay'] = '100ms';
$boundary['GW_A']['loss'] = '2%';
check('SLA limits are inclusive', selected($config, $boundary) === 'a');
$invalid = $gateways;
unset($invalid['GW_A']['delay']);
check('missing RTT does not become zero', selected($config, $invalid) === 'b');
$invalid['GW_A'] = array_replace($sample, ['loss' => 'N/A']);
check('unparseable loss never wins', selected($config, $invalid) === 'b');
$invalid['GW_A'] = array_replace($sample, ['status' => 'down']);
check('down gateway with a prior valid sample never wins', selected($config, $invalid) === 'b');
$invalid['GW_A'] = array_replace($sample, ['loss' => '100%']);
$disabled = $gateways;
$disabled['GW_A']['monitor_disable'] = true;
check('disabled monitoring never wins', selected($config, $disabled) === 'b');
$permissive = $config;
$permissive['slas'][0]['loss_pct'] = '100';
check('total loss never eligible', selected($permissive, $invalid) === 'b');
$tied = $config;
$tied['members'][1]['cost'] = '10';
$tied['policies'][0]['members'] = ['b', 'a'];
check('policy order breaks ties', selected($tied, $gateways) === 'b');
check('missing monitoring data has no eligible member', selected($config, []) === null);

$result = sdwan_evaluate($config, $gateways, 1700000000);
check('time of evaluation is observable', $result['generated_at'] === 1700000000);
check('selection includes explanation', strlen($result['policies']['calls']['reason']) > 0);

/* Execute the privilege specification as pfSense does, on a clean registry. */
$priv_list = [];
require __DIR__ . '/../files/etc/inc/priv/sdwan.priv.inc';
$view = $priv_list['page-services-sdwan-view']['match'];
$manage = $priv_list['page-services-sdwan-manage']['match'];
foreach (['status', 'diagnostics', 'members', 'slas', 'policies'] as $page) {
    $route = "sdwan/$page.php";
    $granted = static function ($rules) use ($route) {
        foreach ($rules as $pattern) {
            if (fnmatch($pattern, $route)) {
                return true;
            }
        }
        return false;
    };
    check("viewer privilege for $page", $granted($view) === in_array($page, ['status', 'diagnostics'], true));
    check("management privilege for $page", $granted($manage));
}

// A restore may change the family of an existing gateway without editing a policy.
$restored = $inventory;
$restored['GW_A']['family'] = 'inet';
$restored['GW_B']['family'] = 'inet6';
$with_other = $config;
$with_other['policies'][] = ['name' => 'single', 'sla' => 'voice', 'strategy' => 'cost', 'members' => ['a']];
$decisions = sdwan_evaluate($with_other, $gateways, 1700000000, $restored)['policies'];
check('a restored policy mixing IPv4 and IPv6 cannot select a gateway', $decisions['calls']['selected'] === null);
check('mixed family exclusion is explained', str_contains($decisions['calls']['candidates']['b'], 'families'));
check('another restored policy stays eligible', $decisions['single']['selected'] === 'a');
