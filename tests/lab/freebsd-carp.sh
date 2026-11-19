#!/bin/sh
# Isolated IPv4 CARP failover on FreeBSD. Each node has its own network stack.
set -eu

if [ "$(uname -s)" != FreeBSD ] || [ "$(id -u)" != 0 ]; then
    echo 'Run this CARP lab as root in a disposable FreeBSD VM with VNET.' >&2
    exit 1
fi

client=sdcarpc$$
first=sdcarpa$$
second=sdcarpb$$
fresh=sdcarpn$$
vip=192.0.2.1
vhid=41
jails=''
links=''
bridge=''

cleanup() {
    result=$?
    trap - EXIT
    set +e
    if [ "$result" -ne 0 ]; then
        for jailname in $jails; do
            echo "CARP lab diagnostics for $jailname" >&2
            jexec "$jailname" ifconfig -a
            jexec "$jailname" arp -an
        done
    fi
    for jailname in $jails; do jail -r "$jailname" >/dev/null 2>&1; done
    for nic in $links; do ifconfig "$nic" destroy >/dev/null 2>&1; done
    if [ -n "$bridge" ]; then ifconfig "$bridge" destroy >/dev/null 2>&1; fi
    exit "$result"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
for module in carp if_bridge if_epair; do kldload -n "$module"; done

make_jail() {
    jail -c name="$1" persist vnet allow.raw_sockets
    jails="$1 $jails"
    jexec "$1" ifconfig lo0 inet 127.0.0.1/8 up
}

# Leave the host with no address on the test segment. The first client's
# bridge also acts as the L2 switch between the other VNETs.
make_jail "$client"
bridge=$(ifconfig bridge create)
ifconfig "$bridge" vnet "$client"
jexec "$client" ifconfig "$bridge" inet 192.0.2.4/29 up

attach() {
    link=$(ifconfig epair create)
    peer="${link%a}b"
    links="$link $peer $links"
    ifconfig "$link" vnet "$client"
    ifconfig "$peer" vnet "$1"
    jexec "$client" ifconfig "$link" up
    jexec "$client" ifconfig "$bridge" addm "$link"
    jexec "$1" ifconfig "$peer" inet "$2/29" up
}

make_jail "$first"
make_jail "$second"
attach "$first" 192.0.2.2
first_if=$peer
attach "$second" 192.0.2.3
second_if=$peer
for node in "$first" "$second"; do jexec "$node" sysctl net.inet.carp.preempt=1; done
jexec "$first" ifconfig "$first_if" inet add vhid "$vhid" advbase 1 advskew 20 "$vip/29"
jexec "$second" ifconfig "$second_if" inet add vhid "$vhid" advbase 1 advskew 150 "$vip/29"

role() {
    jexec "$1" ifconfig "$2" | awk -v vhid="$vhid" '
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
        a=$(role "$first" "$first_if")
        b=$(role "$second" "$second_if")
        if [ "$a" = "$1" ] && [ "$b" = "$2" ]; then
            stable=$((stable + 1))
            if [ "$stable" -eq 2 ]; then
                echo "CARP vhid $vhid: first=$a second=$b"
                return 0
            fi
        else
            stable=0
        fi
        sleep 1
        attempt=$((attempt + 1))
    done
    echo "Timed out waiting for first=$1 second=$2; last roles first=$a second=$b" >&2
    return 1
}

probe() {
    jexec "$1" ping -n -c 1 -t 3 "$2" >/dev/null
}

wait_roles MASTER BACKUP
probe "$client" 192.0.2.2
probe "$client" 192.0.2.3
probe "$client" "$vip"
echo 'ok - both node addresses and the initial VIP reply to the LAN client'

start=$(date +%s)
jexec "$first" ifconfig "$first_if" down
wait_roles INIT MASTER
probe "$client" "$vip"
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
attach "$fresh" 192.0.2.5
probe "$fresh" "$vip"
echo 'ok - a newly attached LAN client reached the VIP on the surviving peer'

jexec "$first" ifconfig "$first_if" up
wait_roles MASTER BACKUP
probe "$client" 192.0.2.2
probe "$client" 192.0.2.3
probe "$client" "$vip"
probe "$fresh" "$vip"
echo 'ok - preferred peer recovered and both independent LAN clients reached the VIP'
