<?php
declare(strict_types=1);
require_once(__DIR__ . '/../core/filter-sdwan.inc');

$gateway = ['interface' => 'igb0.431', 'ipprotocol' => 'inet'];
$v6 = array_replace($gateway, ['ipprotocol' => 'inet6']);
foreach ([
	[$gateway, '198.51.100.2', ' route-to (igb0.431 198.51.100.2) '],
	[$gateway, '100.64.0.1', ' route-to (igb0.431 100.64.0.1) '],
	[$gateway, '172.22.10.1', ' route-to (igb0.431 172.22.10.1) '],
	[$v6, 'fe80::1', ' route-to (igb0.431 fe80::1%igb0.431) '],
	[$v6, 'fe80::1%igb0.431', ' route-to (igb0.431 fe80::1%igb0.431) '],
	[$v6, '2001:db8::2', ' route-to (igb0.431 2001:db8::2) '],
	[$v6, 'fe80::1%other0', null], [$v6, '2001:db8::2%igb0.431', null],
	[$v6, '::', null], [$v6, '::1', null], [$v6, 'ff02::1', null],
	[$gateway, '0.0.0.0', null], [$gateway, '127.0.0.1', null],
	[$gateway, '255.255.255.255', null], [$gateway, '224.0.0.1', null],
	[$gateway, 'dynamic', null], [$gateway, '::1', null], [$v6, '192.0.2.1', null],
	[$gateway + ['force_down' => ''], '192.0.2.1', null],
	[$gateway + ['action_disable' => ''], '192.0.2.1', null],
	[$gateway + ['monitor_disable' => ''], '192.0.2.1', null],
	[array_replace($gateway, ['interface' => 'bad nic']), '192.0.2.1', null],
] as [$gw, $next, $expected]) {
	$route = filter_sdwan_gateway_route($gw, $next);
	if (($route['route'] ?? null) !== $expected || ($route !== null && $route['family'] !== $gw['ipprotocol'])) {
		throw new RuntimeException('Unexpected route normalization for ' . json_encode([$gw, $next]));
	}
}
echo "ok - concrete next hops, IP family, gateway action, interface and IPv6 scope validated\n";
$a = filter_sdwan_gateway_route($gateway, '192.0.2.1');
$b = filter_sdwan_gateway_route(array_replace($gateway, ['interface' => 'igb1', 'weight' => 2]), '192.0.2.2');
$pool = ' route-to { ' . str_repeat('(igb0.431 192.0.2.1) ', 2) .
    str_repeat('(igb1 192.0.2.2) ', 4) . '} round-robin ';
if (filter_sdwan_pool_route([$a, $b]) !== $pool ||
    filter_sdwan_pool_route([$a, $b], true) !== $pool . 'sticky-address ' ||
    filter_sdwan_pool_route([$b]) !== ' route-to (igb1 192.0.2.2) ' ||
    filter_sdwan_pool_route([$b], true) !== ' route-to (igb1 192.0.2.2) ' ||
    filter_sdwan_pool_route([]) !== null) {
	throw new RuntimeException('Unexpected weighted, sticky, single-gateway or empty route pool');
}
echo "ok - weighted pool preserves the configured ratio and sticky option; one hop or no hop is unchanged\n";
foreach ([null, 0, -1, 31] as $invalid_weight) {
	$invalid = array_replace($b, ['weight' => $invalid_weight]);
	if (filter_sdwan_pool_route([$invalid]) !== null || filter_sdwan_pool_route([$a, $invalid]) !== null) {
		throw new RuntimeException('Malformed pool weight created a route');
	}
}
echo "ok - null and out-of-range weights fail closed before pool arithmetic\n";

function config_get_path(string $path, mixed $default = null): mixed {
	return $path === 'gateways/sdwan_bindings/item' ? $GLOBALS['memory_rows'] : $default;
}

function g_get(string $key, mixed $default = null): mixed {
	return ['conf_path' => '/other', 'cf_conf_path' => '/fixture', 'xml_rootobj' => 'pfsense',
	    'booting' => $GLOBALS['native_booting'] ?? false][$key] ?? $default;
}

if (filter_sdwan_boot_load([true, ''], true)) {
	throw new RuntimeException('A normal native reload minted a boot marker');
}
$GLOBALS['native_booting'] = true;
if (filter_sdwan_boot_load(null, true) || filter_sdwan_boot_load([false, 'failed'], true) ||
    filter_sdwan_boot_load([true, ''], false) || !filter_sdwan_boot_load([true, ''], true)) {
	throw new RuntimeException('Boot marker eligibility did not require the current native boot hook and a successful transaction');
}
unset($GLOBALS['native_booting']);
$boot_stat = ['uid' => 0, 'mode' => 0100644, 'size' => 157];
foreach ([false, array_replace($boot_stat, ['uid' => 80]), array_replace($boot_stat, ['mode' => 0120777]),
    array_replace($boot_stat, ['mode' => 0100664]),
    array_replace($boot_stat, ['size' => SDWAN_FILTER_BOOT_MARKER_LIMIT + 1])] as $unsafe_marker) {
	if (filter_sdwan_boot_marker_trusted($unsafe_marker)) {
		throw new RuntimeException('An unsafe native boot marker was trusted');
	}
}
if (!filter_sdwan_boot_marker_trusted($boot_stat)) {
	throw new RuntimeException('A trusted native boot marker was rejected');
}
echo "ok - forwarding approvals require a boot-time PF transaction and a root-owned marker\n";

$overlay = tempnam(sys_get_temp_dir(), 'sdwan-');
$replacement = tempnam(sys_get_temp_dir(), 'sdwan-');
try {
	file_put_contents($overlay, 'overlay');
	file_put_contents($replacement, 'overlay');
	$original = filter_sdwan_boot_file_identity($overlay);
	if ($original === null || $original !== filter_sdwan_boot_file_identity($overlay)) {
		throw new RuntimeException('The installed overlay identity was unstable');
	}
	$identity = ['generator' => $original, 'adapter' => $original];
	$marker = json_encode($identity, JSON_THROW_ON_ERROR);
	if (strlen($marker) > SDWAN_FILTER_BOOT_MARKER_LIMIT || json_decode($marker, true, 3) !== $identity) {
		throw new RuntimeException('The boot marker did not retain the exact overlay file identities');
	}
	if (!unlink($overlay) || !rename($replacement, $overlay)) {
		throw new RuntimeException('Could not replace the overlay fixture');
	}
	$installed = filter_sdwan_boot_file_identity($overlay);
	// Windows PHP does not expose the filesystem's stable inode identity.
	if ($installed === null || $original['sha256'] !== $installed['sha256'] ||
	    (PHP_OS_FAMILY !== 'Windows' && $original === $installed)) {
		throw new RuntimeException('An identical reinstall reused the booted overlay identity');
	}
} finally {
	foreach ([$overlay, $replacement] as $file) {
		if (is_file($file)) {
			unlink($file);
		}
	}
}
echo "ok - a same-content overlay replacement invalidates the recorded filesystem identity\n";

function parse_xml_config(string $path, array $root): mixed {
	if ($path !== '/fixture/config.xml' || $root !== ['pfsense']) {
		throw new LogicException('Invalid native parser arguments');
	}
	$GLOBALS['parsedcfg'] = 'parser scratch';
	$GLOBALS['havedata'] = 1;
	return $GLOBALS['disk_config'];
}

$row = static fn(string $tracker, string|array $group = 'G'): array => [
	'group' => $group, 'policy' => 'ERP', 'rules_revision' => str_repeat('a', 64),
	'trackers' => ['item' => [$tracker]], 'gateways' => ['item' => ['A', 'B']],
];
$GLOBALS['memory_rows'] = [$row('41001'), $row('41002'), $row('41003')];
$saved = [$row('41001', ['G']), array_replace($row('41002'), ['rules_revision' => str_repeat('b', 64)]), $row('41004')];
$GLOBALS['disk_config'] = ['gateways' => ['sdwan_bindings' => ['item' => $saved]]];
$GLOBALS['parsedcfg'] = 'before';
$persisted = filter_sdwan_read_persisted_bindings();
if ($persisted !== $saved || $GLOBALS['parsedcfg'] !== 'before' || isset($GLOBALS['havedata'])) {
	throw new RuntimeException('Persisted config read did not preserve the native parser state');
}
filter_sdwan_begin_reload($persisted);
if ($GLOBALS['sdwan_filter_cycle']['trackers'] !== ['41001', '41002', '41003', '41004'] ||
    $GLOBALS['sdwan_filter_cycle']['bindings']['41001'] !== $row('41001') ||
    filter_sdwan_rule_route(['tracker' => '41002'], []) !== false ||
    filter_sdwan_rule_route(['tracker' => '41003'], []) !== false ||
    filter_sdwan_rule_route(['tracker' => '41004'], []) !== false ||
    filter_sdwan_rule_route(['tracker' => '41005'], []) !== null) {
	throw new RuntimeException('A reload did not preserve the union of approved tracker IDs');
}

$GLOBALS['disk_config'] = ['system' => []];
if (filter_sdwan_read_persisted_bindings() !== []) {
	throw new RuntimeException('A valid config without bound rules did not return an empty authority index');
}
foreach ([-1, ['gateways' => ['sdwan_bindings' => ['item' => [[$row('41001')]]]]]] as $malformed) {
	$GLOBALS['disk_config'] = $malformed;
	if (filter_sdwan_read_persisted_bindings() !== null) {
		throw new RuntimeException('An unreadable approval list was accepted for native generation');
	}
}
echo "ok - native rule generation uses saved approval authority while preserving unrelated rules\n";

$GLOBALS['disk_config'] = ['system' => []];
if (filter_sdwan_native_fallback_allowed()) {
	throw new RuntimeException('Native fallback discarded the filter generation authority');
}
unset($GLOBALS['sdwan_filter_cycle']);
if (filter_sdwan_native_fallback_allowed()) {
	throw new RuntimeException('Native fallback ignored the in-memory approvals');
}
$GLOBALS['memory_rows'] = [];
$GLOBALS['disk_config'] = ['gateways' => ['sdwan_bindings' => ['item' => $saved]]];
if (filter_sdwan_native_fallback_allowed()) {
	throw new RuntimeException('Native fallback ignored persisted approvals acquired during generation');
}
$GLOBALS['disk_config'] = -1;
if (filter_sdwan_native_fallback_allowed()) {
	throw new RuntimeException('Native fallback could not verify approval status');
}
$GLOBALS['disk_config'] = ['system' => []];
if (!filter_sdwan_native_fallback_allowed()) {
	throw new RuntimeException('Native fallback was changed for an unbound configuration');
}
echo "ok - native fallback remains available only when no forwarding approvals apply\n";

const LOG_PREFIX_FILTER = 'filter';

function update_filter_reload_status(string $message): void {
	$GLOBALS['filter_status'][] = $message;
}

function logger(int $level, string $message, string $prefix): void {
	$GLOBALS['filter_log'][] = [$level, $message, $prefix];
}

$GLOBALS['filter_status'] = $GLOBALS['filter_log'] = [];
filter_sdwan_begin_reload([]);
if (!filter_sdwan_precommit('0123456789abcdef') || $GLOBALS['filter_log']) {
	throw new RuntimeException('An unbound native generation was not accepted without a System Logs event');
}
$GLOBALS['disk_config'] = ['gateways' => ['sdwan_bindings' => ['item' => $saved]]];
if (filter_sdwan_precommit('0123456789abcdef')) {
	throw new RuntimeException('A stale generation was accepted after approvals changed');
}
filter_sdwan_begin_reload(filter_sdwan_read_persisted_bindings());
if (!filter_sdwan_precommit('0123456789abcdef') || !filter_sdwan_precommit('0123456789abcdef')) {
	throw new RuntimeException('The initial and retried transactions must accept identical saved approvals');
}
$GLOBALS['disk_config']['gateways']['sdwan_bindings']['item'][0]['policy'] = 'changed';
if (filter_sdwan_precommit('0123456789abcdef')) {
	throw new RuntimeException('A policy edit with the same tracker identities went undetected');
}
$GLOBALS['disk_config'] = -1;
if (filter_sdwan_precommit(null)) {
	throw new RuntimeException('A transaction without readable saved approvals was accepted');
}
$status = implode("\n", $GLOBALS['filter_status']);
if (!str_contains($status, 'approved pid=') || !str_contains($status, 'rejected pid=') ||
    !str_contains($status, 'ruleset=0123456789abcdef') || !str_contains($status, 'saved=-1') ||
    str_contains($status, 'ERP') || str_contains($status, $saved[0]['rules_revision'])) {
	throw new RuntimeException('Native filter metadata must identify the generation and omit approval contents');
}
echo "ok - native PF commit rechecks saved approvals and records process metadata\n";
