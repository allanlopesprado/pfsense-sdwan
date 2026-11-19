<?php
set_include_path(__DIR__ . '/fixtures/write');
require 'config.inc';
require __DIR__ . '/../files/usr/local/pkg/sdwan.inc';

function verify(bool $condition, string $description): void {
	if (!$condition) {
		throw new RuntimeException($description);
	}
	echo "ok - {$description}\n";
}
$disk = $current = [
	'interfaces' => ['wan' => ['enable' => '']],
	'gateways/gateway_item' => [['name' => 'GW', 'interface' => 'wan', 'gateway' => '192.0.2.1']],
	'filter' => ['rule' => [['descr' => 'Existing native rule']]],
];
$native = $disk;
$writes = 0;
$fail = $busy = false;
$initial = sdwan_get_config();
$revision = sdwan_config_revision($initial);
$edited = $initial;
$edited['members'][] = ['name' => 'link', 'gateway' => 'GW', 'cost' => '10'];
$busy = true;
verify(sdwan_save_config($edited, $revision) !== [] && $disk === $native, 'busy configuration lock preserves the durable configuration');
$busy = false;
$fail = true;
verify(sdwan_save_config($edited, $revision) !== [] && $disk === $native && $current === $disk, 'failed write rolls back the in-memory edit');
$fail = false;
verify(sdwan_save_config($edited, $revision) === [] && $writes === 1, 'retry commits the edit once');
verify(sdwan_save_config($initial, $revision) !== [] && $writes === 1, 'a stale editor cannot overwrite a newer revision');
verify(sdwan_save_config($edited, sdwan_config_revision($edited)) === [] && $writes === 1, 'an unchanged edit does not rewrite config');
$other = $disk;
unset($other[SDWAN_CONFIG_PATH]);
verify($other === $native, 'native routing and firewall settings survive package edits');
$disk['gateways/gateway_item'] = [];
$repaired = $edited;
$repaired['members'] = [];
verify(sdwan_save_config($repaired, sdwan_config_revision($edited)) === [] && sdwan_get_config() === $initial,
    'a restored reference to a missing gateway can be removed');
