<?php
/* Runs inside the disposable FreeBSD jail, with its own system log sockets. */
const SDWAN_SNAPSHOT_PATH = '/var/run/sdwan-observer.json';
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
// Independent controls for the native syslog.conf default and program selector.
openlog('sdwan', LOG_PID, LOG_DAEMON);
syslog(LOG_DAEMON | LOG_INFO, 'below-default');
closelog();
openlog('dpinger', LOG_PID, LOG_DAEMON);
syslog(LOG_DAEMON | LOG_WARNING, 'separate-program');
closelog();
