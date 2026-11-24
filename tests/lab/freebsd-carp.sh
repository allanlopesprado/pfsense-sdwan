#!/bin/sh
# Isolated IPv4 CARP with two WANs, NAT, pfsync and manual ESP SAs.
set +x
set -eu
export LC_ALL=C

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
wan_b_vip=192.0.2.129
wan_b_vhid=43
remote_b_ip=192.0.2.132
jails=''
links=''
bridges=''
session_pid=''
captures=''
repo=$(CDPATH='' cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d /tmp/sdwan-carp.XXXXXXXX)
evidence=${SDWAN_CARP_EVIDENCE:-}
if [ -n "$evidence" ]; then mkdir -p "$evidence"; fi

cleanup() {
    result=$?
    trap - EXIT
    set +e
    if [ -n "$session_pid" ]; then
        kill "$session_pid" 2>/dev/null
        wait "$session_pid" 2>/dev/null
    fi
    for capture in $captures; do
        kill -INT "$capture" 2>/dev/null
        wait "$capture" 2>/dev/null
    done
    if [ -n "$evidence" ]; then
        for file in "$work"/*.pcap "$work"/*.capture.log; do
            if [ -f "$file" ]; then cp "$file" "$evidence/"; fi
        done
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
make_segment "$remote" "$remote_b_ip"
wan_b_bridge=$bridge
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
first_wire=$link
attach "$second" 198.51.100.3 "$remote" "$wan_bridge"
second_wan=$peer
second_wire=$link
attach "$first" 192.0.2.130 "$remote" "$wan_b_bridge"
first_wan_b=$peer
first_wire_b=$link
attach "$second" 192.0.2.131 "$remote" "$wan_b_bridge"
second_wan_b=$peer
second_wire_b=$link
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
jexec "$first" ifconfig "$first_wan_b" inet add vhid "$wan_b_vhid" advbase 1 advskew 20 "$wan_b_vip/29"
jexec "$second" ifconfig "$second_wan_b" inet add vhid "$wan_b_vhid" advbase 1 advskew 150 "$wan_b_vip/29"
jexec "$client" route -n add default "$vip"
for node_wan in "$first:$first_wan" "$second:$second_wan"; do
    node=${node_wan%:*}
    if [ "$node" = "$first" ]; then
        lan_if=$first_if wan_b_if=$first_wan_b sync_if=$first_sync local_sync=$sync_a peer_sync=$sync_b hostid=0x51d0a001
    else
        lan_if=$second_if wan_b_if=$second_wan_b sync_if=$second_sync local_sync=$sync_b peer_sync=$sync_a hostid=0x51d0a002
    fi
    cat >"$work/$node.pf" <<EOF
set state-policy floating
set hostid $hostid
nat on ${node_wan#*:} inet from 192.0.2.0/29 to $remote_ip -> $wan_vip
block all
pass quick on { $lan_if ${node_wan#*:} $wan_b_if } inet proto carp no state
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
        ba=$(role "$first" "$first_wan_b" "$wan_b_vhid")
        bb=$(role "$second" "$second_wan_b" "$wan_b_vhid")
        if [ "$a:$b:$wa:$wb:$ba:$bb" = "$1:$2:$1:$2:$1:$2" ]; then
            stable=$((stable + 1))
            if [ "$stable" -eq 2 ]; then
                echo "CARP LAN: $a/$b; WAN A: $wa/$wb; WAN B: $ba/$bb"
                return 0
            fi
        else
            stable=0
        fi
        sleep 1
        attempt=$((attempt + 1))
    done
    echo "Timed out waiting for $1/$2; last roles LAN=$a/$b WAN A=$wa/$wb WAN B=$ba/$bb" >&2
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
        if grep -Fqx "${3:-$wan_vip} $2" "$work/$1.out"; then return 0; fi
        sleep 1
    done
    echo "TCP reply missing for $2 on the open $1 connection" >&2
    return 1
}

open_session() {
    mkfifo "$work/$1.in"
    # This nc process opens the socket once. Keep its stdin open across the outage.
    jexec "$client" nc -n -N -w 60 -p "$2" "${3:-$remote_ip}" 7 <"$work/$1.in" >"$work/$1.out" &
    session_pid=$!
    exec 3>"$work/$1.in"
    printf '%s\n' "$1-before" >&3
    wait_reply "$1" "$1-before" "${4:-$wan_vip}"
}

close_session() {
    exec 3>&-
    kill "$session_pid" 2>/dev/null || :
    wait "$session_pid" 2>/dev/null || :
    session_pid=''
}

session_state() {
    jexec "$1" pfctl -vv -ss | awk -v source="192.0.2.4:$2" -v target="${3:-$remote_ip}:7" -v translation="${4-$wan_vip:}" '
        /^[^[:space:]]/ { match_flow = index($0, source) && index($0, target) && (translation=="" || index($0, translation)) &&
                                        /ESTABLISHED:ESTABLISHED/ }
        match_flow && $1 == "id:" && $3 == "creatorid:" { print $2 "/" $4; match_flow = 0 }
    '
}

disable_preferred_data() {
    jexec "$first" ifconfig "$first_if" down
    jexec "$first" ifconfig "$first_wan" down
    jexec "$first" ifconfig "$first_wan_b" down
    wait_roles INIT MASTER
}

restore_preferred_data() {
    jexec "$first" ifconfig "$first_if" up
    jexec "$first" ifconfig "$first_wan" up
    jexec "$first" ifconfig "$first_wan_b" up
    wait_roles MASTER BACKUP
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
restore_preferred_data

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
echo 'ok - the same TCP socket completed a new request after all VIPs moved with the original NAT state'
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
restore_preferred_data
printf 'synced-failback\n' >&3
wait_reply synced synced-failback
test "$(session_state "$first" 34241)" = "$state"
close_session
echo 'ok - the same TCP socket and NAT state survived failback to the preferred node'
probe "$client" 192.0.2.2
probe "$client" 192.0.2.3
probe "$client" "$vip"
probe "$fresh" "$vip"
transaction "$client" recovered
echo 'ok - preferred peer recovered and both independent LAN clients reached the VIP'

# Reuse the CARP topology for a protected flow. Install separate lab SAs for
# each owner to model tunnel restoration without sharing keys or ESP sequence numbers.
protected=198.18.2.10
backup=198.18.2.11
inner_cluster=198.18.1.1
inner_peer=198.18.1.2
inner_cluster_b=198.18.1.5
inner_peer_b=198.18.1.6
reqid=411
reqid_b=412
if ! jexec "$first" ifconfig -C | tr ' ' '\n' | grep -qx ipsec; then kldload -n ipsec; fi
create_vti() {
    vti=$(jexec "$1" ifconfig ipsec create)
    jexec "$1" ifconfig "$vti" reqid "${6:-$reqid}"
    jexec "$1" ifconfig "$vti" inet tunnel "$2" "$3"
    jexec "$1" ifconfig "$vti" inet "$4/30" "$5" up
    printf '%s\n' "$vti"
}
first_vti=$(create_vti "$first" "$wan_vip" "$remote_ip" "$inner_cluster" "$inner_peer")
second_vti=$(create_vti "$second" "$wan_vip" "$remote_ip" "$inner_cluster" "$inner_peer")
remote_vti=$(create_vti "$remote" "$remote_ip" "$wan_vip" "$inner_peer" "$inner_cluster")
first_vti_b=$(create_vti "$first" "$wan_b_vip" "$remote_b_ip" "$inner_cluster_b" "$inner_peer_b" "$reqid_b")
second_vti_b=$(create_vti "$second" "$wan_b_vip" "$remote_b_ip" "$inner_cluster_b" "$inner_peer_b" "$reqid_b")
create_vti "$remote" "$remote_b_ip" "$wan_b_vip" "$inner_peer_b" "$inner_cluster_b" "$reqid_b" >/dev/null
jexec "$remote" ifconfig lo0 inet "$protected/32" alias
jexec "$remote" ifconfig lo0 inet "$backup/32" alias
jexec "$remote" route -n add -net 192.0.2.0/29 "$inner_cluster"
jexec "$remote" route -n add -host 192.0.2.4 "$inner_cluster"
jexec "$remote" route -n add -host 192.0.2.5 "$inner_cluster"

for node in "$first" "$second"; do
    if [ "$node" = "$first" ]; then
        vti=$first_vti vti_b=$first_vti_b lan_if=$first_if underlay=$first_wan underlay_b=$first_wan_b
    else
        vti=$second_vti vti_b=$second_vti_b lan_if=$second_if underlay=$second_wan underlay_b=$second_wan_b
    fi
    # A live native fallback route makes a no-leak assertion meaningful.
    jexec "$node" route -n add default "$remote_ip"
    jexec "$node" route -n add -host "$protected" "$inner_peer"
    jexec "$node" route -n add -host "$backup" "$inner_peer"
    jexec "$node" route -n get "$protected" | awk -v device="$vti" '$1=="interface:" && $2==device {ok=1} END {exit !ok}'
    cp "$work/$node.pf" "$work/$node-ipsec.pf"
    cat >>"$work/$node-ipsec.pf" <<EOF
block drop out quick on { $underlay $underlay_b } inet to { $protected $backup } label "protected-clear"
pass quick on { $underlay $underlay_b } inet proto esp no state
pass in quick on $lan_if inet proto tcp to { $protected $backup } port 7 flags S/SA keep state
pass quick on { $vti $vti_b } inet proto tcp from any to any no state
EOF
    jexec "$node" pfctl -nf "$work/$node-ipsec.pf"
    jexec "$node" pfctl -f "$work/$node-ipsec.pf"
done

peer_rules="$work/ipsec-peer.pf"
cat >"$peer_rules" <<EOF
block drop in quick on { $wan_bridge $first_wire $second_wire $wan_b_bridge $first_wire_b $second_wire_b } inet to { $protected $backup } label "protected-clear"
pass in quick on { $wan_bridge $first_wire $second_wire } inet proto esp from $wan_vip to $remote_ip no state label "esp-a-in"
pass out quick on { $wan_bridge $first_wire $second_wire } inet proto esp from $remote_ip to $wan_vip no state label "esp-a-out"
pass in quick on { $wan_b_bridge $first_wire_b $second_wire_b } inet proto esp from $wan_b_vip to $remote_b_ip no state label "esp-b-in"
pass out quick on { $wan_b_bridge $first_wire_b $second_wire_b } inet proto esp from $remote_b_ip to $wan_b_vip no state label "esp-b-out"
pass all no state
EOF
load_peer_rules() {
    jexec "$remote" pfctl -nf "$1"
    jexec "$remote" pfctl -f "$1"
}
load_peer_rules "$peer_rules"
jexec "$remote" pfctl -e
# FreeBSD otherwise skips PF on packets tagged as already decrypted.
jexec "$remote" sysctl net.inet.ipsec.filtertunnel=1

count_label() {
    jexec "$1" pfctl -s labels | awk -v label="$2" '
        $1==label {count+=$3; ok=1} END {if (!ok) exit 1; print count+0}'
}
install_pair() (
    local_endpoint=${4:-$wan_vip}
    peer_endpoint=${5:-$remote_ip}
    identifier=${6:-$reqid}
    key_to_peer=$(openssl rand -hex 20)
    key_from_peer=$(openssl rand -hex 20)
    for instance in "$1" "$remote"; do
        {
            printf 'add %s %s esp %s -m tunnel -u %s -E aes-gcm-16 0x%s;\n' "$local_endpoint" "$peer_endpoint" "$2" "$identifier" "$key_to_peer"
            printf 'add %s %s esp %s -m tunnel -u %s -E aes-gcm-16 0x%s;\n' "$peer_endpoint" "$local_endpoint" "$3" "$identifier" "$key_from_peer"
        } | jexec "$instance" setkey -c >/dev/null
    done
)
retire_pair() (
    local_endpoint=${4:-$wan_vip}
    peer_endpoint=${5:-$remote_ip}
    for instance in "$1" "$remote"; do
        {
            printf 'delete %s %s esp %s;\n' "$local_endpoint" "$peer_endpoint" "$2"
            printf 'delete %s %s esp %s;\n' "$peer_endpoint" "$local_endpoint" "$3"
        } | jexec "$instance" setkey -c >/dev/null
    done
)
protected_transaction() (
    reply=$(printf '%s\n' "$1" | jexec "${2:-$client}" nc -n -N -w 3 "${3:-$protected}" 7) ||
        test -n "$reply"
    test "$reply" = "${4:-192.0.2.4} $1"
)

replace_host_route() (
    jexec "$1" route -n delete -host "$2"
    jexec "$1" route -n add -host "$2" "$3"
    jexec "$1" route -n get "$2" | awk -v next_hop="$3" '
        $1=="gateway:" && $2==next_hop {ok=1} END {exit !ok}'
)

select_path() (
    replace_host_route "$first" "$protected" "$1"
    replace_host_route "$second" "$protected" "$1"
    replace_host_route "$remote" 192.0.2.4 "$2"
)

wire_packets() (
    file="$work/wan-$1.pcap"
    if [ ! -s "$file" ]; then
        echo 0
        exit 0
    fi
    case "$1" in
        a) cluster=$wan_vip peer=$remote_ip ;;
        b) cluster=$wan_b_vip peer=$remote_b_ip ;;
        *) exit 1 ;;
    esac
    case "$2" in
        in) source=$cluster destination=$peer ;;
        out) source=$peer destination=$cluster ;;
        *) exit 1 ;;
    esac
    packets=$(tcpdump -nr "$file" "ip proto 50 and src $source and dst $destination" 2>/dev/null)
    printf '%s\n' "$packets" | awk 'NF {count++} END {print count+0}'
)

transaction_on() (
    wire_in=$(wire_packets "$1" in)
    wire_out=$(wire_packets "$1" out)
    inbound=$(count_label "$remote" "esp-$1-in")
    outbound=$(count_label "$remote" "esp-$1-out")
    if ! protected_transaction "$2" "${3:-$client}" "${4:-$protected}" "${5:-192.0.2.4}"; then
        printf 'Missing application reply for %s on tunnel %s\n' "$2" "$1" >&2
        exit 1
    fi
    current_inbound=$(count_label "$remote" "esp-$1-in")
    current_outbound=$(count_label "$remote" "esp-$1-out")
    for attempt in 1 2 3; do
        current_wire_in=$(wire_packets "$1" in)
        current_wire_out=$(wire_packets "$1" out)
        if [ "$current_wire_in" -gt "$wire_in" ] && [ "$current_wire_out" -gt "$wire_out" ]; then break; fi
        sleep 1
    done
    printf '%s transaction=%s tunnel=%s esp-in-delta=%s esp-out-delta=%s pf-in-delta=%s pf-out-delta=%s\n' \
        "$(date -u +%FT%TZ)" "$2" "$1" "$((current_wire_in-wire_in))" "$((current_wire_out-wire_out))" \
        "$((current_inbound-inbound))" "$((current_outbound-outbound))"
    test "$current_wire_in" -gt "$wire_in"
    test "$current_wire_out" -gt "$wire_out"
)

observe_held() {
    printf '%s-switch\n' "$1" >&3
    if wait_reply "$1" "$1-switch" 192.0.2.4; then
        outcome=same-socket-replied
    else
        outcome=same-socket-no-reply
    fi
    printf '%s scenario=%s held=%s\n' "$(date -u +%FT%TZ)" "$1" "$outcome"
    close_session
}

start_capture() {
    jexec "$remote" tcpdump --immediate-mode -pUn -s 128 -i "$1" -w "$work/$2.pcap" \
        "ip proto 50 or host $protected or host $backup" >"$work/$2.capture.log" 2>&1 &
    call=$!
    captures="$captures $call"
    for attempt in 1 2 3 4 5; do
        if grep -q 'listening on' "$work/$2.capture.log"; then return 0; fi
        kill -0 "$call" || break
        sleep 1
    done
    cat "$work/$2.capture.log" >&2
    return 1
}

verify_capture() (
    tcpdump -nr "$work/$1.pcap" "ip proto 50 and src $2 and dst $3" >"$work/$1.esp-in" 2>/dev/null
    tcpdump -nr "$work/$1.pcap" "ip proto 50 and src $3 and dst $2" >"$work/$1.esp-out" 2>/dev/null
    tcpdump -nr "$work/$1.pcap" "host $protected or host $backup" >"$work/$1.clear" 2>/dev/null
    test -s "$work/$1.esp-in"
    test -s "$work/$1.esp-out"
    test ! -s "$work/$1.clear"
    grep -Eq '^0 packets dropped by kernel$' "$work/$1.capture.log"
    printf 'capture=%s esp-in=%s esp-out=%s protected-plaintext=0 kernel-drops=0\n' \
        "$1" "$(wc -l <"$work/$1.esp-in")" "$(wc -l <"$work/$1.esp-out")"
)

start_capture "$wan_bridge" wan-a
start_capture "$wan_b_bridge" wan-b
install_pair "$first" 0x14101 0x14102
install_pair "$first" 0x15101 0x15102 "$wan_b_vip" "$remote_b_ip" "$reqid_b"
echo "$(date -u +%FT%TZ) owner=first assigned-esp-spis=A:0x14101/0x14102,B:0x15101/0x15102"
transaction_on a baseline
open_session wan-held 34243 "$protected" 192.0.2.4

# Reproduce upstream reachability loss on A without demoting the CARP node.
{
    printf 'block drop quick on { %s %s %s } inet to %s\n' "$wan_bridge" "$first_wire" "$second_wire" "$remote_ip"
    cat "$peer_rules"
} >"$work/wan-a-down.pf"
echo "$(date -u +%FT%TZ) fault=wan-a-reachability"
load_peer_rules "$work/wan-a-down.pf"
if probe "$first" "$remote_ip"; then echo 'WAN A remained reachable' >&2; exit 1; fi
if protected_transaction wan-a-prefers-failed; then echo 'WAN A outage did not interrupt ERP' >&2; exit 1; fi
probe "$first" "$remote_b_ip"
select_path "$inner_peer_b" "$inner_cluster_b"
transaction_on b wan-a-failed
observe_held wan-held
wait_roles MASTER BACKUP
load_peer_rules "$peer_rules"
select_path "$inner_peer" "$inner_cluster"
probe "$first" "$remote_ip"
probe "$first" "$inner_peer"
transaction_on a wan-a-restored

open_session tunnel-held 34244 "$protected" 192.0.2.4
echo "$(date -u +%FT%TZ) fault=tunnel-a-no-sa"
retire_pair "$first" 0x14101 0x14102
probe "$first" "$remote_ip"
if protected_transaction tunnel-a-prefers-failed; then echo 'ERP replied with A SA removed' >&2; exit 1; fi
select_path "$inner_peer_b" "$inner_cluster_b"
transaction_on b tunnel-a-failed
observe_held tunnel-held
install_pair "$first" 0x14103 0x14104
select_path "$inner_peer" "$inner_cluster"
transaction_on a tunnel-a-restored

open_session erp-held 34245 "$protected" 192.0.2.4
{
    printf 'block drop in quick on %s inet proto tcp to %s port 7 label "erp-fault"\n' "$remote_vti" "$protected"
    cat "$peer_rules"
} >"$work/erp-on-a-down.pf"
echo "$(date -u +%FT%TZ) fault=erp-on-tunnel-a"
load_peer_rules "$work/erp-on-a-down.pf"
probe "$first" "$remote_ip"
jexec "$first" ping -n -c 1 -t 3 -S "$inner_cluster" "$inner_peer" >/dev/null
if protected_transaction erp-prefers-failed; then echo 'ERP fault left ERP reachable on A' >&2; exit 1; fi
test "$(count_label "$remote" erp-fault)" -gt 0
select_path "$inner_peer_b" "$inner_cluster_b"
transaction_on b erp-failed
transaction_on a backup-control "$fresh" "$backup" 192.0.2.5
observe_held erp-held
wait_roles MASTER BACKUP
load_peer_rules "$peer_rules"
select_path "$inner_peer" "$inner_cluster"
transaction_on a erp-restored

open_session protected 34242 "$protected" 192.0.2.4
state=$(session_state "$first" 34242 "$protected" '')
test -n "$state"
for attempt in 1 2 3 4 5; do
    if [ "$(session_state "$second" 34242 "$protected" '')" = "$state" ]; then break; fi
    sleep 1
done
test "$(session_state "$second" 34242 "$protected" '')" = "$state"

echo "$(date -u +%FT%TZ) fault=both-tunnels-no-sa"
retire_pair "$first" 0x14103 0x14104
retire_pair "$first" 0x15101 0x15102 "$wan_b_vip" "$remote_b_ip"
probe "$first" "$remote_ip"
probe "$first" "$remote_b_ip"
if protected_transaction blackout-a; then echo 'ERP replied without either SA' >&2; exit 1; fi
select_path "$inner_peer_b" "$inner_cluster_b"
if protected_transaction blackout-b; then echo 'ERP replied without either SA' >&2; exit 1; fi
select_path "$inner_peer" "$inner_cluster"
printf 'protected-during-blackout\n' >&3

echo "$(date -u +%FT%TZ) fault=carp-first-to-second synced-state=$state"
jexec "$first" ifconfig "$first_sync" down
disable_preferred_data
if protected_transaction ipsec-no-sa; then
    echo 'A protected request succeeded before the new tunnel was ready.' >&2
    exit 1
fi
if grep -Fqx '192.0.2.4 protected-during-blackout' "$work/protected.out"; then
    echo 'The already open connection replied with both ESP paths withdrawn' >&2
    exit 1
fi
echo 'ok - the standby held the PF state and new protected requests failed before tunnel restoration'
install_pair "$second" 0x14201 0x14202
install_pair "$second" 0x15201 0x15202 "$wan_b_vip" "$remote_b_ip" "$reqid_b"
echo "$(date -u +%FT%TZ) owner=second assigned-esp-spis=A:0x14201/0x14202,B:0x15201/0x15202"
printf 'protected-takeover\n' >&3
wait_reply protected protected-takeover 192.0.2.4
transaction_on a carp-takeover
test "$(session_state "$second" 34242 "$protected" '')" = "$state"
test "$(count_label "$remote" protected-clear)" -eq 0
echo 'ok - the same protected TCP socket and a new connection succeeded after CARP takeover and installation of fresh ESP SAs'

echo "$(date -u +%FT%TZ) fault=carp-second-to-first"
retire_pair "$second" 0x14201 0x14202
retire_pair "$second" 0x15201 0x15202 "$wan_b_vip" "$remote_b_ip"
jexec "$first" ifconfig "$first_sync" up
restore_preferred_data
install_pair "$first" 0x14301 0x14302
install_pair "$first" 0x15301 0x15302 "$wan_b_vip" "$remote_b_ip" "$reqid_b"
echo "$(date -u +%FT%TZ) owner=first assigned-esp-spis=A:0x14301/0x14302,B:0x15301/0x15302"
printf 'protected-failback\n' >&3
wait_reply protected protected-failback 192.0.2.4
transaction_on a carp-failback
test "$(session_state "$first" 34242 "$protected" '')" = "$state"
test "$(count_label "$remote" protected-clear)" -eq 0
test "$(count_label "$first" protected-clear)" -eq 0
test "$(count_label "$second" protected-clear)" -eq 0
close_session
for capture in $captures; do
    kill -INT "$capture"
    wait "$capture" || :
done
captures=''
verify_capture wan-a "$wan_vip" "$remote_ip"
verify_capture wan-b "$wan_b_vip" "$remote_b_ip"
echo 'ok - both CARP transfers restored the encrypted flow over fresh manual SAs with zero protected cleartext on either WAN'
