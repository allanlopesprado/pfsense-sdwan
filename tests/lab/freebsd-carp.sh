#!/bin/sh
# Isolated IPv4 CARP failover with two VIPs, NAT and pfsync.
set -eu

if [ "$(uname -s)" != FreeBSD ] || [ "$(id -u)" != 0 ]; then
    echo 'Run this CARP lab as root in a disposable FreeBSD VM with VNET.' >&2
    exit 1
fi

client=sdcarpc$$
first=sdcarpa$$
second=sdcarpb$$
fresh=sdcarpn$$
remote=sdcarpr$$
vip=192.0.2.1
vhid=41
wan_vip=198.51.100.1
wan_vhid=42
remote_ip=198.51.100.4
jails=''
links=''
bridges=''
session_pid=''
repo=$(CDPATH='' cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d /tmp/sdwan-carp.XXXXXXXX)

cleanup() {
    result=$?
    trap - EXIT
    set +e
    if [ -n "$session_pid" ]; then
        kill "$session_pid" 2>/dev/null
        wait "$session_pid" 2>/dev/null
    fi
    if [ "$result" -ne 0 ]; then
        for jailname in $jails; do
            echo "CARP lab diagnostics for $jailname" >&2
            jexec "$jailname" ifconfig -a
            jexec "$jailname" arp -an
            jexec "$jailname" netstat -rn -f inet
            jexec "$jailname" pfctl -vv -ss
            jexec "$jailname" netstat -s -p pfsync
        done
    fi
    for jailname in $jails; do jail -r "$jailname" >/dev/null 2>&1; done
    for nic in $links; do ifconfig "$nic" destroy >/dev/null 2>&1; done
    for nic in $bridges; do ifconfig "$nic" destroy >/dev/null 2>&1; done
    rm -rf "$work"
    exit "$result"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
for module in carp if_bridge if_epair pf pfsync; do kldload -n "$module"; done

make_jail() {
    jail -c name="$1" persist vnet allow.raw_sockets
    jails="$1 $jails"
    jexec "$1" ifconfig lo0 inet 127.0.0.1/8 up
}

make_segment() {
    bridge=$(ifconfig bridge create)
    bridges="$bridge $bridges"
    ifconfig "$bridge" vnet "$1"
    jexec "$1" ifconfig "$bridge" inet "$2/29" up
}

# Each endpoint's bridge acts as the L2 switch for its segment.
make_jail "$client"
make_segment "$client" 192.0.2.4
lan_bridge=$bridge
make_jail "$remote"
make_segment "$remote" "$remote_ip"
wan_bridge=$bridge
attach() {
    link=$(ifconfig epair create)
    peer="${link%a}b"
    links="$link $peer $links"
    ifconfig "$link" vnet "$3"
    ifconfig "$peer" vnet "$1"
    jexec "$3" ifconfig "$link" up
    jexec "$3" ifconfig "$4" addm "$link"
    jexec "$1" ifconfig "$peer" inet "$2/29" up
}

make_jail "$first"
make_jail "$second"
attach "$first" 192.0.2.2 "$client" "$lan_bridge"
first_if=$peer
attach "$second" 192.0.2.3 "$client" "$lan_bridge"
second_if=$peer
attach "$first" 198.51.100.2 "$remote" "$wan_bridge"
first_wan=$peer
attach "$second" 198.51.100.3 "$remote" "$wan_bridge"
second_wan=$peer
first_sync=$(ifconfig epair create)
second_sync=${first_sync%a}b
links="$first_sync $second_sync $links"
ifconfig "$first_sync" vnet "$first"
ifconfig "$second_sync" vnet "$second"
sync_a=203.0.113.1
sync_b=203.0.113.2
jexec "$first" ifconfig "$first_sync" inet "$sync_a/30" up
jexec "$second" ifconfig "$second_sync" inet "$sync_b/30" up
for node in "$first" "$second"; do
    jexec "$node" sysctl net.inet.carp.preempt=1 net.inet.ip.forwarding=1
done
jexec "$first" ifconfig "$first_if" inet add vhid "$vhid" advbase 1 advskew 20 "$vip/29"
jexec "$second" ifconfig "$second_if" inet add vhid "$vhid" advbase 1 advskew 150 "$vip/29"
jexec "$first" ifconfig "$first_wan" inet add vhid "$wan_vhid" advbase 1 advskew 20 "$wan_vip/29"
jexec "$second" ifconfig "$second_wan" inet add vhid "$wan_vhid" advbase 1 advskew 150 "$wan_vip/29"
jexec "$client" route -n add default "$vip"
for node_wan in "$first:$first_wan" "$second:$second_wan"; do
    node=${node_wan%:*}
    if [ "$node" = "$first" ]; then
        lan_if=$first_if sync_if=$first_sync local_sync=$sync_a peer_sync=$sync_b hostid=0x51d0a001
    else
        lan_if=$second_if sync_if=$second_sync local_sync=$sync_b peer_sync=$sync_a hostid=0x51d0a002
    fi
    cat >"$work/$node.pf" <<EOF
set state-policy floating
set hostid $hostid
nat on ${node_wan#*:} inet from 192.0.2.0/29 to $remote_ip -> $wan_vip
block all
pass quick on { $lan_if ${node_wan#*:} } inet proto carp no state
pass quick on $sync_if inet proto pfsync from $peer_sync to $local_sync no state
pass quick on $sync_if inet proto pfsync from $local_sync to $peer_sync no state
pass inet proto icmp no state
pass inet proto tcp to $remote_ip port 7 flags S/SA keep state
EOF
    jexec "$node" pfctl -nf "$work/$node.pf"
    jexec "${node_wan%:*}" pfctl -f "$work/${node_wan%:*}.pf"
    jexec "${node_wan%:*}" pfctl -e
done
cc -std=c99 -Wall -Wextra -Werror "$repo/tests/lab/tcp-peer.c" -o "$work/tcp-peer"
printf 'echo stream tcp4 nowait root %s tcp-peer\n' "$work/tcp-peer" >"$work/inetd.conf"
jexec "$remote" inetd -p "$work/inetd.pid" "$work/inetd.conf"

role() {
    jexec "$1" ifconfig "$2" | awk -v vhid="$3" '
        $1 == "carp:" && $3 == "vhid" && $4 == vhid { state=$2; matches++ }
        END { if (matches != 1) exit 1; print state }
    '
}

# Require the same single owner on two successive polls. A missing interface
# or CARP record is an error, never evidence that a peer is in BACKUP.
wait_roles() {
    attempt=0
    stable=0
    while [ "$attempt" -lt 25 ]; do
        a=$(role "$first" "$first_if" "$vhid")
        b=$(role "$second" "$second_if" "$vhid")
        wa=$(role "$first" "$first_wan" "$wan_vhid")
        wb=$(role "$second" "$second_wan" "$wan_vhid")
        if [ "$a:$b:$wa:$wb" = "$1:$2:$1:$2" ]; then
            stable=$((stable + 1))
            if [ "$stable" -eq 2 ]; then
                echo "CARP LAN: first=$a second=$b; WAN: first=$wa second=$wb"
                return 0
            fi
        else
            stable=0
        fi
        sleep 1
        attempt=$((attempt + 1))
    done
    echo "Timed out waiting for first=$1 second=$2; last roles LAN=$a/$b WAN=$wa/$wb" >&2
    return 1
}

probe() {
    jexec "$1" ping -n -c 1 -t 3 "$2" >/dev/null
}
transaction() {
    response=$(printf '%s\n' "$2" | jexec "$1" nc -n -N -w 5 "$remote_ip" 7)
    test "$response" = "$wan_vip $2"
    echo "ok - $2 TCP request and reply used the shared WAN VIP after NAT"
}

wait_reply() {
    for attempt in 1 2 3 4 5; do
        if grep -Fqx "$wan_vip $2" "$work/$1.out"; then return 0; fi
        sleep 1
    done
    echo "TCP reply missing for $2 on the open $1 connection" >&2
    return 1
}

open_session() {
    mkfifo "$work/$1.in"
    # This nc process opens the socket once. Keep its stdin open across the outage.
    jexec "$client" nc -n -N -w 45 -p "$2" "$remote_ip" 7 <"$work/$1.in" >"$work/$1.out" &
    session_pid=$!
    exec 3>"$work/$1.in"
    printf '%s\n' "$1-before" >&3
    wait_reply "$1" "$1-before"
}

close_session() {
    exec 3>&-
    kill "$session_pid" 2>/dev/null || :
    wait "$session_pid" 2>/dev/null || :
    session_pid=''
}

session_state() {
    jexec "$1" pfctl -vv -ss | awk -v source="192.0.2.4:$2" -v target="$remote_ip:7" -v translation="$wan_vip:" '
        /^[^[:space:]]/ { match_flow = index($0, source) && index($0, target) && index($0, translation) &&
                                        /ESTABLISHED:ESTABLISHED/ }
        match_flow && $1 == "id:" && $3 == "creatorid:" { print $2 "/" $4; match_flow = 0 }
    '
}

disable_preferred_data() {
    jexec "$first" ifconfig "$first_if" down
    jexec "$first" ifconfig "$first_wan" down
    wait_roles INIT MASTER
}

wait_roles MASTER BACKUP
probe "$client" 192.0.2.2
probe "$client" 192.0.2.3
probe "$client" "$vip"
transaction "$client" initial
echo 'ok - both node addresses and the initial VIP reply to the LAN client'

# The same topology permits a fresh connection without pfsync, while an
# already-established socket requires the original NAT state on the new owner.
open_session unsynced 34240
test -n "$(session_state "$first" 34240)"
test -z "$(session_state "$second" 34240)"
disable_preferred_data
printf 'unsynced-after\n' >&3
transaction "$client" unsynced-new
sleep 3
test -z "$(session_state "$second" 34240)"
if grep -Fqx "$wan_vip unsynced-after" "$work/unsynced.out"; then
    echo 'The negative-control connection survived without state synchronization' >&2
    exit 1
fi
close_session
echo 'ok - without pfsync only the fresh application connection survived takeover'
jexec "$first" ifconfig "$first_if" up
jexec "$first" ifconfig "$first_wan" up
wait_roles MASTER BACKUP

jexec "$first" ifconfig pfsync0 syncdev "$first_sync" syncpeer "$sync_b" maxupd 1 up
jexec "$second" ifconfig pfsync0 syncdev "$second_sync" syncpeer "$sync_a" maxupd 1 up
wait_roles MASTER BACKUP
open_session synced 34241
state=$(session_state "$first" 34241)
test -n "$state"
for attempt in 1 2 3 4 5; do
    if [ "$(session_state "$second" 34241)" = "$state" ]; then break; fi
    sleep 1
done
test "$(session_state "$second" 34241)" = "$state"
echo "ok - the standby received the established TCP NAT state with the same PF id and creator $state"

start=$(date +%s)
jexec "$first" ifconfig "$first_sync" down
disable_preferred_data
printf 'synced-after\n' >&3
wait_reply synced synced-after
test "$(session_state "$second" 34241)" = "$state"
close_session
echo 'ok - the same TCP socket completed a new request after both VIPs moved with the original NAT state'
probe "$client" "$vip"
transaction "$client" takeover
elapsed=$(($(date +%s) - start))
echo "ok - existing LAN client reached the VIP after master interface loss (verified in ${elapsed}s including role polling)"
if probe "$client" 192.0.2.2; then
    echo 'The disabled node unexpectedly responded on its individual address' >&2
    exit 1
fi
probe "$client" 192.0.2.3

# A new VNET and interface join only after takeover. Its first request uses
# its own neighbor table, independent of prior reachability on the old client.
make_jail "$fresh"
attach "$fresh" 192.0.2.5 "$client" "$lan_bridge"
jexec "$fresh" route -n add default "$vip"
probe "$fresh" "$vip"
transaction "$fresh" new-client
echo 'ok - a newly attached LAN client reached the VIP on the surviving peer'

jexec "$first" ifconfig "$first_sync" up
jexec "$first" ifconfig "$first_if" up
jexec "$first" ifconfig "$first_wan" up
wait_roles MASTER BACKUP
probe "$client" 192.0.2.2
probe "$client" 192.0.2.3
probe "$client" "$vip"
probe "$fresh" "$vip"
transaction "$client" recovered
echo 'ok - preferred peer recovered and both independent LAN clients reached the VIP'
