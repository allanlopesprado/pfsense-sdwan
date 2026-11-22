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
$fail = false;
$initial = sdwan_get_config();
$revision = sdwan_config_revision($initial);
$edited = $initial;
$edited['members'][] = ['name' => 'link', 'gateway' => 'GW', 'cost' => '10'];
$held = sdwan_lock('sdwan-settings', 0);
verify(is_resource($held) && sdwan_lock('sdwan-settings', 0) === null, 'a held runtime lock excludes other writers');
verify(sdwan_save_config($edited, $revision) !== [] && $disk === $native, 'busy configuration lock preserves the durable configuration');
sdwan_unlock($held);
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

$disk['gateways/gateway_item'] = $native['gateways/gateway_item'];
$current = $disk;
$prior_writes = $writes;
$reads = 0;
$before_config_read = static function () use (&$reads, &$disk): void {
	if (++$reads === 2) {
		$disk['filter']['rule'][] = ['descr' => 'Concurrent native rule'];
	}
};
$errors = sdwan_save_config($edited, $revision);
unset($before_config_read);
verify($errors !== [] && $writes === $prior_writes && $current === $disk &&
    count($disk['filter']['rule']) === 2 && sdwan_get_config() === $initial,
    'a native edit during package validation survives and the user can retry');
verify(sdwan_save_config($edited, $revision) === [] && $writes === $prior_writes + 1 &&
    count($disk['filter']['rule']) === 2 && sdwan_get_config() === $edited,
    'retrying after the native edit only changes SD-WAN settings');

$disk[SDWAN_CONFIG_PATH] = ['version' => 'future'];
$errors = sdwan_save_config($initial, sdwan_config_revision($edited));
verify($errors !== [] && $writes === $prior_writes + 1 && $disk[SDWAN_CONFIG_PATH] === ['version' => 'future'],
    'an incompatible restore after the form opened returns a save error and is kept intact');
