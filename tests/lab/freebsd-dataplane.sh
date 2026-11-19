#!/bin/sh
# FreeBSD reference topology. Run only on a disposable FreeBSD VM as root.
# Every route, PF rule, NAT rule and simulated outage is confined to a VNET.
set -eu

if [ "$(uname -s)" != FreeBSD ] || [ "$(id -u)" != 0 ]; then
    echo 'This lab requires a disposable FreeBSD VM with root and VNET.' >&2
    exit 1
fi
repo=$(CDPATH='' cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d /tmp/sdwan-lab.XXXXXXXX)
client=sdclient$$
firewall=sdfw$$
remote=sdremote$$
interfaces=''
jails=''
clean() {
    result=$?
    set +e
    if [ "$result" -ne 0 ]; then
        for node in $jails; do
            echo "Failure diagnostics for $node"
            jexec "$node" ifconfig -a inet
            jexec "$node" netstat -rn -f inet
            jexec "$node" arp -an
            jexec "$node" sockstat -4
            jexec "$node" pfctl -vvsr
            jexec "$node" pfctl -a lab-steer -vvsr
            jexec "$node" pfctl -ss -vv
        done
    fi
    for node in $jails; do jail -r "$node" >/dev/null 2>&1; done
    # FreeBSD returns surviving interfaces to the parent VNET on jail removal.
    for nic in $interfaces; do ifconfig "$nic" destroy >/dev/null 2>&1; done
    rm -rf "$work"
    return "$result"
}
trap clean EXIT
trap 'exit 1' HUP INT TERM

kldload -n if_epair
kldload -n pf
cc -std=c99 -Wall -Wextra -Werror "$repo/tests/lab/tcp-peer.c" -o "$work/tcp-peer"

for node in "$client" "$firewall" "$remote"; do
    jail -c name="$node" persist vnet
    jails="$node $jails"
    jexec "$node" ifconfig lo0 inet 127.0.0.1/8 up
done

pair() {
    endpoint=$(ifconfig epair create)
    base=${endpoint%a}
    interfaces="$interfaces ${base}a ${base}b"
    ifconfig "${base}a" vnet "$1"
    ifconfig "${base}b" vnet "$3"
    jexec "$1" ifconfig "${base}a" inet "$2" up
    jexec "$3" ifconfig "${base}b" inet "$4" up
}
pair "$client" 192.0.2.11/25 "$firewall" 192.0.2.1/25
lan=${base}b
pair "$firewall" 198.51.100.1/30 "$remote" 198.51.100.2/30
wan_a=${base}a
remote_a=${base}b
pair "$firewall" 203.0.113.1/30 "$remote" 203.0.113.2/30
wan_b=${base}a
jexec "$remote" ifconfig lo0 inet 192.0.2.162/32 alias
jexec "$remote" ifconfig lo0 inet 192.0.2.163/32 alias
jexec "$client" route -n add default 192.0.2.1
jexec "$firewall" route -n add default 198.51.100.2
jexec "$firewall" sysctl net.inet.ip.forwarding=1

# Upstream PF tests use inetd and the standard echo port. Our handler also
# returns the observed source IP so each direction and NAT are asserted.
printf 'echo stream tcp4 nowait root %s tcp-peer\n' "$work/tcp-peer" >"$work/inetd.conf"
jexec "$remote" inetd -p "$work/inetd.pid" "$work/inetd.conf"
if ! printf 'listener-test\n' | jexec "$remote" nc -n -N -w 3 192.0.2.162 7 | grep -Eq '^[0-9.]+ listener-test$'; then
    echo 'The test TCP listener failed a local round trip' >&2
    exit 1
fi
printf 'pass all no state\n' >"$work/remote.pf"
jexec "$remote" pfctl -f "$work/remote.pf"
jexec "$remote" pfctl -e
jexec "$firewall" pfctl -e

# Load this parent ruleset exactly once. All subsequent steering changes use
# only the named anchor. Native NAT and the independent fallback remain intact.
cat >"$work/main.pf" <<EOF
set state-policy if-bound
nat on $wan_a inet from 192.0.2.0/25 to any -> ($wan_a)
nat on $wan_b inet from 192.0.2.0/25 to any -> ($wan_b)
block all
anchor "lab-steer" quick
# A later permissive native rule would allow either test destination via the
# kernel default route. The package's no-path guard must precede it.
pass in quick on $lan inet proto tcp from 192.0.2.11 to 192.0.2.128/25 port 7 label "baseline"
pass out inet all
EOF
jexec "$firewall" pfctl -nf "$work/main.pf"
jexec "$firewall" pfctl -f "$work/main.pf"
baseline() {
    jexec "$firewall" pfctl -sn
    jexec "$firewall" pfctl -sr
    jexec "$firewall" route -n get default | awk '/gateway:|interface:/ {print}'
}
baseline >"$work/baseline"

steer() {
    case "$1" in
        a) outbound=$wan_a; next_hop=198.51.100.2 ;;
        b) outbound=$wan_b; next_hop=203.0.113.2 ;;
        none) outbound='' ;;
        *) return 1 ;;
    esac
    if [ -n "$outbound" ]; then
        printf 'pass in quick on %s route-to (%s %s) inet proto tcp from 192.0.2.11 to 192.0.2.162 port 7 keep state label "path-%s"\n' \
            "$lan" "$outbound" "$next_hop" "$1" >"$work/selected.pf"
    else
        printf 'block drop in quick on %s inet proto tcp from 192.0.2.11 to 192.0.2.162 port 7 label "no-member"\n' \
            "$lan" >"$work/selected.pf"
    fi
    jexec "$firewall" pfctl -a lab-steer -nf "$work/selected.pf"
    jexec "$firewall" pfctl -a lab-steer -f "$work/selected.pf"
}
request() {
    printf '%s\n' "$2" | jexec "$client" nc -n -N -w 3 "$1" 7
}
expect_roundtrip() {
    response=$(request "$1" "$3") || {
        echo "TCP transaction $3 could not connect to $1" >&2
        return 1
    }
    if [ "$response" != "$2 $3" ]; then
        echo "TCP transaction $3 expected peer $2, received: $response" >&2
        return 1
    fi
    echo "ok - $3 TCP request and response observed after NAT to $2"
}
counter() {
    # labels columns: label, evaluations, packets, bytes, in/out totals, states
    awk -v label="$1" '$1 == label && $3 > 0 {print; seen=1} END {exit !seen}'
}

expect_roundtrip 192.0.2.163 198.51.100.1 default-route-control
steer a
expect_roundtrip 192.0.2.162 198.51.100.1 initial-A
jexec "$firewall" pfctl -a lab-steer -s labels | counter path-a
expect_roundtrip 192.0.2.163 198.51.100.1 baseline-A

# Hold one TCP session open on A. After switching the rule to B, a second
# transaction on this same socket must retain its A translation and state.
(
    printf 'held-before\n'
    for index in 1 2 3 4 5 6 7 8 9 10; do
        [ ! -e "$work/send-next" ] || break
        sleep 1
    done
    printf 'held-after\n'
) | jexec "$client" nc -n -N -w 15 192.0.2.162 7 >"$work/held" &
held_pid=$!
for index in 1 2 3 4 5; do
    grep -Fqx '198.51.100.1 held-before' "$work/held" && break
    sleep 1
done
grep -Fqx '198.51.100.1 held-before' "$work/held"
steer b
expect_roundtrip 192.0.2.162 203.0.113.1 new-session-B
touch "$work/send-next"
wait "$held_pid"
grep -Fqx '198.51.100.1 held-after' "$work/held"
echo 'ok - an established session retains A while a new session uses B'
steer a

# Drop remotely on only A. The independent destination remains usable on A.
printf 'block drop in quick on %s inet proto tcp from 198.51.100.1 to 192.0.2.162 port 7 label "outage"\npass all no state\n' \
    "$remote_a" >"$work/remote.pf"
jexec "$remote" pfctl -f "$work/remote.pf"
if request 192.0.2.162 loss-A >"$work/failed"; then
    echo 'The expected loss on A did not occur' >&2
    exit 1
fi
test ! -s "$work/failed"
jexec "$remote" pfctl -s labels | counter outage
steer b
expect_roundtrip 192.0.2.162 203.0.113.1 alternate-B
jexec "$firewall" pfctl -a lab-steer -s labels | counter path-b
expect_roundtrip 192.0.2.163 198.51.100.1 unaffected-A

printf 'pass all no state\n' >"$work/remote.pf"
jexec "$remote" pfctl -f "$work/remote.pf"
# Make both physical paths usable, then give the steering rule no eligible
# member. New traffic must stay blocked even though the default route and
# broader allow rule would otherwise carry it successfully.
steer none
if request 192.0.2.162 no-member >"$work/blocked"; then
    echo 'The no-member guard leaked a new TCP flow to the default path' >&2
    exit 1
fi
test ! -s "$work/blocked"
jexec "$firewall" pfctl -a lab-steer -s labels | counter no-member
expect_roundtrip 192.0.2.163 198.51.100.1 guard-is-scoped
steer a
expect_roundtrip 192.0.2.162 198.51.100.1 recovered-A
jexec "$firewall" pfctl -a lab-steer -s labels | counter path-a
jexec "$firewall" pfctl -s labels | counter baseline
baseline >"$work/final"
cmp "$work/baseline" "$work/final"
echo 'ok - baseline PF rules, NAT rules and kernel default route survived the path changes'
