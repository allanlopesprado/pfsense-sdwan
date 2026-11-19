#!/bin/sh
# PROVIDE: sdwand
# REQUIRE: NETWORKING
# KEYWORD: shutdown

. /etc/rc.subr

name="sdwand"
command="/usr/sbin/daemon"
pidfile="/var/run/sdwand.pid"
command_args="-f -R 5 -P ${pidfile} /usr/local/bin/php /usr/local/sbin/sdwand.php"

# Removal runs the same cleanup after stop even when the service was already down.
if [ "${SDWAN_PACKAGE_REMOVING:-0}" != 1 ]; then
	stop_postcmd=sdwan_invalidate
fi
sdwan_invalidate()
{
	/usr/local/bin/php -f /usr/local/pkg/sdwan_invalidate.inc
}

load_rc_config "${name}"
run_rc_command "$1"
