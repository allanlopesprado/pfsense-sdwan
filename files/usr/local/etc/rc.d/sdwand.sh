#!/bin/sh
# PROVIDE: sdwand
# REQUIRE: NETWORKING
# KEYWORD: shutdown

# shellcheck source=/dev/null
. /etc/rc.subr

# rc.subr reads these variables indirectly.
# shellcheck disable=SC2034
name="sdwand"
# shellcheck disable=SC2034
command="/usr/sbin/daemon"
pidfile="/var/run/sdwand.pid"
# shellcheck disable=SC2034
command_args="-f -R 5 -P ${pidfile} /usr/local/bin/php /usr/local/sbin/sdwand.php"

# Removal runs the same cleanup after stop even when the service was already down.
if [ "${SDWAN_PACKAGE_REMOVING:-0}" != 1 ]; then
	# shellcheck disable=SC2034
	stop_postcmd=sdwan_invalidate
fi
sdwan_invalidate()
{
	/usr/local/bin/php -f /usr/local/pkg/sdwan_invalidate.inc
}

load_rc_config "${name}"
run_rc_command "$1"
