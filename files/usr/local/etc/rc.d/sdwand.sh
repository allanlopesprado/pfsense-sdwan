#!/bin/sh
# PROVIDE: sdwand
# REQUIRE: NETWORKING
# KEYWORD: shutdown

. /etc/rc.subr

name="sdwand"
command="/usr/sbin/daemon"
pidfile="/var/run/sdwand.pid"
command_args="-f -P ${pidfile} /usr/local/bin/php /usr/local/sbin/sdwand.php"

load_rc_config "${name}"
run_rc_command "$1"
