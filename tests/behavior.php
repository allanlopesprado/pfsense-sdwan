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
$variation = $config;
$variation['slas'][0]['rttsd_ms'] = '0.5';
check('an optional variation limit preserves the stored schema', sdwan_decode_config(sdwan_encode_config($variation)) === $variation);
$unstable = $gateways;
$unstable['GW_B']['stddev'] = '0.5ms';
check('RTT variation excludes an unstable path and accepts its exact limit', selected($variation, $unstable) === 'b');
$variation['slas'][0]['rttsd_ms'] = '-1';
check('negative RTT variation thresholds are rejected', sdwan_validate_config($variation, $inventory) !== []);

$twoWanProfile = $config;
$twoWanProfile['members'][0]['cost'] = '2';
$twoWanProfile['members'][1]['cost'] = '1';
$twoWanProfile['slas'][0] = ['name' => 'voice', 'latency_ms' => '40', 'rttsd_ms' => '30', 'loss_pct' => '5'];
$wan1 = array_replace($sample, ['delay' => '12ms']);
$wan2 = array_replace($sample, ['delay' => '24ms']);
$twoWanCases = [
    'both healthy' => [[], [], 'b', 2],
    'WAN2 at 40 ms RTT, 30 ms deviation and 5% loss' => [[], ['delay' => '40ms', 'stddev' => '30ms', 'loss' => '5%'], 'b', 2],
    'WAN2 at 40.001 ms RTT' => [[], ['delay' => '40.001ms'], 'a', 1],
    'WAN2 at 30.001 ms deviation' => [[], ['stddev' => '30.001ms'], 'a', 1],
    'WAN2 at 5.01% loss' => [[], ['loss' => '5.01%'], 'a', 1],
    'WAN2 offline' => [[], ['status' => 'down'], 'a', 1],
    'WAN2 without a valid measurement' => [[], ['stddev' => 'N/A'], 'a', 1],
    'WAN1 offline' => [['status' => 'down'], [], 'b', 1],
    'both offline' => [['status' => 'down'], ['status' => 'down'], null, 0],
    'WAN1 above the deviation limit and WAN2 above the loss limit' => [['stddev' => '30.001ms'], ['loss' => '5.01%'], null, 0],
];
foreach ($twoWanCases as $scenario => [$first, $second, $expected, $eligible]) {
    $policy = sdwan_evaluate($twoWanProfile, [
        'GW_A' => array_replace($wan1, $first), 'GW_B' => array_replace($wan2, $second),
    ], 1700000000)['policies']['calls'];
    check("40/30/5 cost profile: $scenario", $policy['selected'] === $expected && $policy['eligible_count'] === $eligible);
}

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

$checks = $config;
$checks['members'][0]['probe_primary'] = 'https://monitor.example.com/health 192.0.2.55';
$checks['members'][0]['probe_secondary'] = 'dns://example.com 192.0.2.53';
$inventory['GW_A']['family'] = 'inet';
$inventory['GW_B']['family'] = 'inet';
check('service check configuration survives saved XML structure',
    sdwan_validate_config($checks, $inventory) === [] && sdwan_decode_config(sdwan_encode_config($checks)) === $checks);
check('unknown service checks cannot make a configured link eligible', selected($checks, $gateways) === 'b');
$result = sdwan_evaluate($checks, $gateways, 1700000000, $inventory, [
    'a' => ['probe_primary' => 'Timed out', 'probe_secondary' => 'Passed'],
]);
check('a healthy secondary service check keeps a link eligible', $result['policies']['calls']['selected'] === 'a');
$checks['members'][1]['probe_primary'] = 'dns://example.com 192.0.2.53';
check('a service IP cannot take host routes on different members', sdwan_validate_config($checks, $inventory) !== []);
check('service targets require a supported protocol and a concrete destination IP',
    sdwan_probe_target('http://example.com 192.0.2.53') === null &&
    sdwan_probe_target('https://admin@example.com 192.0.2.53') === null &&
    sdwan_probe_target('dns://example.com 127.0.0.1') === null &&
    sdwan_probe_target('dns://example.com ::ffff:127.0.0.1') === null);
check('TCP probes accept only a literal routed IP and a valid port',
    sdwan_probe_target('tcp://192.0.2.2:587') === ['protocol' => 'tcp', 'port' => 587, 'address' => '192.0.2.2', 'family' => 'inet'] &&
    sdwan_probe_target('tcp://[2001:db8::20]:8443')['family'] === 'inet6' &&
    sdwan_probe_target('tcp://[192.0.2.2]:443') === null &&
    sdwan_probe_target('tcp://2001:db8::20:8443') === null &&
    sdwan_probe_target('tcp://example.com:443') === null &&
    sdwan_probe_target('tcp://192.0.2.2:0') === null &&
    sdwan_probe_target('tcp://192.0.2.2:65536') === null &&
    sdwan_probe_target('tcp://127.0.0.1:443') === null);
$listener = stream_socket_server('tcp://127.0.0.1:0');
check('a local TCP listener is available for the socket test', is_resource($listener));
$endpoint = 'tcp://' . stream_socket_get_name($listener, false);
$tcp_flags = STREAM_CLIENT_CONNECT | STREAM_CLIENT_ASYNC_CONNECT;
$socket = stream_socket_client($endpoint, $errno, $error, 0, $tcp_flags);
$accepted = stream_socket_accept($listener, 1);
check('a completed TCP handshake passes the check', is_resource($accepted) && sdwan_probe_tcp_status($socket) === true);
fclose($accepted);
fclose($socket);
fclose($listener);
$socket = @stream_socket_client($endpoint, $errno, $error, 0, $tcp_flags);
$status = false;
if (is_resource($socket)) {
    $status = null;
    $deadline = hrtime(true) + 3_000_000_000;
    while ($status === null && hrtime(true) < $deadline) {
        $status = sdwan_probe_tcp_status($socket);
        if ($status === null) {
            usleep(10_000);
        }
    }
    fclose($socket);
}
check('a refused TCP connection is distinguished from a successful handshake', $status === false);
$question = sdwan_probe_dns_question('example.com');
$answer = pack('nnnnnn', 17, 0x8180, 1, 1, 0, 0) . $question .
    pack('nnnNnC4', 0xc00c, 1, 1, 60, 4, 192, 0, 2, 43);
check('DNS probe requires a response matching its transaction and question',
    sdwan_probe_dns_answer($answer, 17, $question) && !sdwan_probe_dns_answer($answer, 18, $question) &&
    !sdwan_probe_dns_answer($answer, 17, sdwan_probe_dns_question('another.example')));
$base = pack('nnnnnn', 17, 0x8180, 1, 1, 0, 0) . $question;
$alias = substr(sdwan_probe_dns_question('target.example.net'), 0, -4);
$cname = pack('nnnNn', 0xc00c, 5, 1, 60, strlen($alias)) . $alias;
$rr = pack('nnNnC4', 1, 1, 60, 4, 192, 0, 2, 43);
$alias_offset = strlen($base) + 12;
$chain = pack('nnnnnn', 17, 0x8180, 1, 2, 0, 0) . $question .
    $cname . pack('n', 0xc000 | $alias_offset) . $rr;
check('DNS probes require a complete A answer for the requested name or its CNAME',
    sdwan_probe_dns_answer($chain, 17, $question) &&
    !sdwan_probe_dns_answer($base . $cname, 17, $question) &&
    !sdwan_probe_dns_answer($base . $alias . $rr, 17, $question) &&
    !sdwan_probe_dns_answer(substr($answer, 0, -1), 17, $question) &&
    !sdwan_probe_dns_answer(substr_replace($answer, pack('n', 0x8380), 2, 2), 17, $question));

$route = "gateway: 192.0.2.1\ninterface: wan0\nflags: <UP,GATEWAY,HOST,DONE,STATIC>";
check('service probes require an exact host route over the intended next hop',
    sdwan_probe_route_matches($route, 'wan0', '192.0.2.1') &&
    !sdwan_probe_route_matches($route, 'wan1', '192.0.2.1') &&
    !sdwan_probe_route_matches($route, 'wan0', '192.0.2.2') &&
    !sdwan_probe_route_matches(str_replace('HOST,', '', $route), 'wan0', '192.0.2.1'));

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
