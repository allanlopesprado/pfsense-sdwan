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

# Supervise the expiry guard separately, while keeping one native package
# service for start, stop, status and restart.
# shellcheck disable=SC2034
start_postcmd=sdwan_watchdog_start
# shellcheck disable=SC2034
restart_precmd=sdwan_watchdog_stop

sdwan_watchdog_rc()
(
	unset start_postcmd restart_precmd stop_postcmd
	# shellcheck disable=SC2030
	name="sdwan_expiry"
	pidfile="/var/run/sdwan-expiry.pid"
	# shellcheck disable=SC2034
	command_args="-f -R 5 -P ${pidfile} /usr/local/bin/php /usr/local/sbin/sdwand.php --expiry-watchdog"
	load_rc_config "${name}"
	run_rc_command "$1"
)

# Called by rc.subr.
# shellcheck disable=SC2329
sdwan_watchdog_start()
{
	sdwan_watchdog_rc status >/dev/null 2>&1 || sdwan_watchdog_rc start
}

sdwan_watchdog_stop()
{
	if sdwan_watchdog_rc status >/dev/null 2>&1; then
		sdwan_watchdog_rc stop
	fi
}

# Removal runs the same cleanup after stop even when the service was already down.
if [ "${SDWAN_PACKAGE_REMOVING:-0}" != 1 ]; then
	# shellcheck disable=SC2034
	stop_postcmd=sdwan_invalidate
fi
# Called by rc.subr.
# shellcheck disable=SC2329
sdwan_invalidate()
{
	/usr/local/bin/php -f /usr/local/pkg/sdwan_invalidate.inc
}

# The watchdog's service name is scoped to its subshell.
# shellcheck disable=SC2031
load_rc_config "${name}"
if [ "$1" = "watchdog_status" ]; then
	sdwan_watchdog_rc status
	exit $?
fi
run_rc_command "$1"
result=$?
case "$1" in
	stop|faststop|forcestop|onestop)
		sdwan_watchdog_stop || result=1
		;;
esac
exit "$result"
