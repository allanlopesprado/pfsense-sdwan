<?php
// Read-only PHP integration using the addresses actually negotiated by the lab.
require_once __DIR__ . '/../fixtures/write/config.inc';
require_once __DIR__ . '/../fixtures/gwlb.inc';
require_once __DIR__ . '/../../files/usr/local/pkg/sdwan_engine.inc';

[$script, $device, $old_source, $old_target, $source, $target] = $argv;
$gateway = ['interface' => 'wan', 'family' => 'inet', 'monitor' => 'dynamic'];
$old = ['srcip' => $old_source, 'targetip' => $old_target];
$new = ['srcip' => $source, 'targetip' => $target];
$current = ['fixture_devices' => ['wan' => $device],
    'fixture_dynamic_targets' => ['wan' => $old_target], 'fixture_sources' => [$device => $old_source]];
if (!sdwan_monitor_matches($gateway, $old) || $source === $old_source || $target === $old_target) {
    throw new RuntimeException('The initial monitor or negotiated address change was invalid.');
}
$current['fixture_dynamic_targets']['wan'] = null;
if (sdwan_monitor_matches($gateway, $old)) {
    throw new RuntimeException('The old process was accepted with no current gateway.');
}
$current['fixture_sources'][$device] = $source;
$current['fixture_dynamic_targets']['wan'] = $target;
foreach ([$old, ['srcip' => $old_source, 'targetip' => $target],
    ['srcip' => $source, 'targetip' => $old_target]] as $stale) {
    if (sdwan_monitor_matches($gateway, $stale)) {
        throw new RuntimeException('A stale source or next hop was accepted.');
    }
}
if (!sdwan_monitor_matches($gateway, $new)) {
    throw new RuntimeException('The current address pair did not match the monitor.');
}
echo "ok - SD-WAN accepted both current endpoints and rejected stale monitor metadata after readdressing.\n";
