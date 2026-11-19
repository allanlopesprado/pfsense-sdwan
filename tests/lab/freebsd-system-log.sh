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
# An event from a different UNIX socket is not a barrier for earlier clients.
# Never stop syslogd merely because an unrelated marker arrived. Do not replay
# or slow the package emitter, so lost messages still fail this test.
wait_for_count() {
    path=$1 pattern=$2 expected=$3
    attempt=0
    while [ "$attempt" -lt 80 ]; do
        count=$(grep -Fc "$pattern" "$path") || count=0
        [ "$count" -lt "$expected" ] || return 0
        sleep 0.1
        attempt=$((attempt + 1))
    done
    echo "Timed out waiting for $expected '$pattern' entries in ${path##*/}; observed $count" >&2
    return 1
}
diagnostics() {
    # Test jail contains only synthetic data, including the emitter's ledger.
    echo "Isolated fixture diagnostics for $scenario" >&2
    cat "$work/etc/lab-syslog.conf" >&2
    for file in "$work"/var/log/*.log "$work/var/run/sdwan-observer.json.events"; do
        echo "$file" >&2
        if [ -f "$file" ]; then tail -25 "$file" >&2; echo >&2; fi
    done
}
jail -c name="$node" host.hostname=sdwan-log-lab path="$work" persist vnet
# Repeat with freshly created sockets and an empty ledger on every run.
for round in 1 2 3; do
for scenario in rfc3164-default rfc5424-default rfc5424-warning; do
    format=${scenario%-*}
    level=${scenario#*-}
    if [ "$level" = warning ]; then general_count=2; else general_count=5; fi
    "$php" -n "$repo/tests/lab/native-system-log.php" prepare "$src" "$work" "$format" "$level"
    : >"$work/var/log/system.log"
    : >"$work/var/log/gateways.log"
    : >"$work/var/log/fixture-input.log"
    rm -f "$work/var/run/sdwan-observer.json.events"
    jexec "$node" /usr/sbin/syslogd -ss -c -c -m 0 -O "$format" -f /etc/lab-syslog.conf -P /var/run/lab.pid
    jexec "$node" /usr/bin/logger -t fixture-ready -p daemon.info "ready-$scenario-$round"
    wait_for_count "$work/var/log/fixture-input.log" "ready-$scenario-$round" 1 || { diagnostics; exit 1; }
    # On the final round, freeze only the test receiver across the complete
    # PHP batch. FreeBSD drops pending peer queues when several connected
    # datagram sockets disconnect before syslogd reads them (unix(4)).
    if [ "$round" -eq 3 ]; then
        jexec "$node" pkill -STOP -F /var/run/lab.pid syslogd
        pid=$(cat "$work/var/run/lab.pid")
        attempt=0
        until ps -p "$pid" -o state= | grep -q 'T'; do
            attempt=$((attempt + 1))
            [ "$attempt" -lt 50 ] || { diagnostics; exit 1; }
            sleep 0.1
        done
    fi
    # Emit the burst exactly once with no acknowledgments between calls.
    jexec "$node" "$php" -n /fixture/events.php
    if [ "$round" -eq 3 ]; then
        jexec "$node" pkill -CONT -F /var/run/lab.pid syslogd
    fi
    wait_for_count "$work/var/log/fixture-input.log" 'SD-WAN ' 5 &&
        wait_for_count "$work/var/log/fixture-input.log" native-ident-control 1 &&
        wait_for_count "$work/var/log/system.log" 'SD-WAN ' "$general_count" || { diagnostics; exit 1; }
    # Each control uses a separate external logger(1) connection and must
    # independently succeed after the complete package burst was received.
    jexec "$node" /usr/bin/logger -t sdwan -p daemon.info 'below-default'
    wait_for_count "$work/var/log/fixture-input.log" below-default 1 || { diagnostics; exit 1; }
    jexec "$node" /usr/bin/logger -t dpinger -p daemon.warning 'separate-program'
    wait_for_count "$work/var/log/gateways.log" separate-program 1 || { diagnostics; exit 1; }
    jexec "$node" pkill -TERM -F /var/run/lab.pid syslogd
    for attempt in 1 2 3 4 5; do
        [ ! -f "$work/var/run/lab.pid" ] && break
        sleep 1
    done
    test ! -f "$work/var/run/lab.pid"
    if [ "$round" -eq 3 ]; then echo "Checking $scenario after the complete PHP batch waited for syslogd"; fi
    if ! "$php" -n "$repo/tests/lab/native-system-log.php" verify "$src" "$work" "$format" "$level"; then
        diagnostics
        exit 1
    fi
done
done
