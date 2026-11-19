#!/bin/sh
# Exercise the released PHP emitter, real syslogd and the native GUI reader.
# Library directories are shared read-only. Kernel log device, host syslog
# sockets, configurations, log directories and network are not shared.
set -eu
test "$(uname -s)" = FreeBSD
test "$(id -u)" = 0
src=${1:?Pass the pinned pfSense syslog.inc}
test -f "$src"
repo=$(CDPATH='' cd "$(dirname "$0")/../.." && pwd)
php=$(command -v php)
work=$(mktemp -d /tmp/sdwan-log.XXXXXXXX)
node=sdlog$$
mounts=''
cleanup() {
    result=$?
    set +e
    jail -r "$node" >/dev/null 2>&1
    for mountpoint in $mounts; do
        umount "$mountpoint" || { echo "Could not unmount $mountpoint" >&2; return 1; }
    done
    rm -rf "$work"
    return "$result"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
mkdir -p "$work/shim" "$work/etc" "$work/fixture" "$work/var/log" "$work/var/run" "$work/tmp"
touch "$work/shim/util.inc" "$work/shim/config.inc"
version=$(awk '$1=="PORTVERSION=" {print $2}' "$repo/Makefile")
test -n "$version"
pkg="$repo/dist/pfSense-pkg-SDWAN-$version.pkg"
tar -xOf "$pkg" /usr/local/pkg/sdwan_log.inc >"$work/fixture/sdwan_log.inc"
cmp "$work/fixture/sdwan_log.inc" "$repo/files/usr/local/pkg/sdwan_log.inc"
cp "$repo/tests/lab/system-log-events.php" "$work/fixture/events.php"

for tree in /bin /lib /libexec /sbin /usr; do
    mkdir "$work$tree"
    mount -t nullfs -o ro "$tree" "$work$tree"
    mounts="$work$tree $mounts"
done
mkdir "$work/dev"
mount -t devfs devfs "$work/dev"
mounts="$work/dev $mounts"
devfs -m "$work/dev" rule apply hide
for device in null random urandom zero; do devfs -m "$work/dev" rule apply path "$device" unhide; done
test ! -e "$work/dev/klog"
for entry in /etc/netconfig /etc/hosts /etc/services /etc/protocols /etc/localtime /var/run/ld-elf.so.hints; do
    if [ -f "$entry" ]; then cp -L "$entry" "$work$entry"; fi
done
jail -c name="$node" host.hostname=sdwan-log-lab path="$work" persist vnet
for scenario in rfc3164-default rfc5424-default rfc5424-warning; do
    format=${scenario%-*}
    level=${scenario#*-}
    "$php" -n "$repo/tests/lab/native-system-log.php" prepare "$src" "$work" "$format" "$level"
    : >"$work/var/log/system.log"
    : >"$work/var/log/gateways.log"
    : >"$work/var/log/fixture-input.log"
    rm -f "$work/var/run/sdwan-observer.json.events"
    jexec "$node" /usr/sbin/syslogd -ss -c -c -m 0 -O "$format" -f /etc/lab-syslog.conf -P /var/run/lab.pid
    jexec "$node" "$php" -n /fixture/events.php
    # External FreeBSD logger controls are independent of PHP's emitter.
    jexec "$node" /usr/bin/logger -t sdwan -p daemon.info 'below-default'
    jexec "$node" /usr/bin/logger -t dpinger -p daemon.warning 'separate-program'
    # Queue drain marker goes through the next independent program selector.
    for attempt in 1 2 3 4 5; do
        grep -q separate-program "$work/var/log/gateways.log" && break
        sleep 1
    done
    jexec "$node" pkill -TERM -F /var/run/lab.pid syslogd
    for attempt in 1 2 3 4 5; do
        [ ! -f "$work/var/run/lab.pid" ] && break
        sleep 1
    done
    test ! -f "$work/var/run/lab.pid"
    if ! "$php" -n "$repo/tests/lab/native-system-log.php" verify "$src" "$work" "$format" "$level"; then
        echo "Isolated fixture diagnostics for $scenario" >&2
        cat "$work/etc/lab-syslog.conf" >&2
        for logfile in "$work"/var/log/*.log; do
            echo "$logfile" >&2
            # Only synthetic fixture data, never a host log.
            tail -20 "$logfile" >&2
        done
        exit 1
    fi
done
