<?php
// CLI lifecycle hook. Keep the native markers until an administrator rolls back the binding.
if (PHP_SAPI !== 'cli') {
	exit(1);
}
require_once('config.inc');
require_once(__DIR__ . '/sdwan_steering.inc');

$ok = sdwan_steering_retire_observation();
sdwan_log_event('stop');
if (!$ok) {
	sdwan_log_event('filter_retirement_unconfirmed');
	fwrite(STDERR, "Cannot confirm withdrawal of the previous SD-WAN forwarding rules. Check Status > Filter Reload.\n");
}
exit($ok ? 0 : 1);
