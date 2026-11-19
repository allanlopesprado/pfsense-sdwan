<?php
/* Runs inside the disposable FreeBSD jail, with its own system log sockets. */
const SDWAN_SNAPSHOT_PATH = '/var/run/sdwan-observer.json';
// Use the same process-local transport contract as the shipped sdwand entry point.
const SDWAN_LOG_DEDICATED_CLI = true;
require '/fixture/sdwan_log.inc';
sdwan_log_event('start');
$secret = 'CREDENTIAL_CANARY';
foreach (['A', 'A', 'B', 'B', null, null] as $member) {
	$observation = ['policies' => ['voice' => ['selected' => $member,
	    'path_status' => $member === null ? 'no_eligible' : 'alternatives']],
	    'unrelated_config' => ['password' => $secret]];
	sdwan_log_event('observation', $observation);
}
for ($i = 0; $i < 25; $i++) {
	sdwan_log_event('error', [], $secret);
}
// A later native routine must not inherit the package's tag or facility.
syslog(LOG_NOTICE, 'native-ident-control');
