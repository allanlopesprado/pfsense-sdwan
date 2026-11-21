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
pair "$firewall" 192.0.2.129/30 "$remote" 192.0.2.130/30
wan_c=${base}a
remote_c=${base}b
jexec "$remote" ifconfig lo0 inet 192.0.2.162/32 alias
jexec "$remote" ifconfig lo0 inet 192.0.2.163/32 alias
jexec "$client" route -n add default 192.0.2.1
jexec "$firewall" route -n add default 198.51.100.2
jexec "$firewall" sysctl net.inet.ip.forwarding=1

# Upstream PF tests use inetd and the standard echo port. Our handler also
# returns the observed source IP so each direction and NAT are asserted.
printf 'echo stream tcp4 nowait root %s tcp-peer\necho stream tcp6 nowait root %s tcp-peer\n' \
    "$work/tcp-peer" "$work/tcp-peer" >"$work/inetd.conf"
jexec "$remote" inetd -p "$work/inetd.pid" "$work/inetd.conf"
if ! printf 'listener-test\n' | jexec "$remote" nc -n -N -w 3 192.0.2.162 7 | grep -Eq '^[0-9.]+ listener-test$'; then
    echo 'The test TCP listener failed a local round trip' >&2
    exit 1
fi
printf 'pass all no state\n' >"$work/remote.pf"
jexec "$remote" pfctl -f "$work/remote.pf"
jexec "$remote" pfctl -e
jexec "$firewall" pfctl -e

# Like filter_configure(), load the complete ruleset at each change. Preserve
# the native rule's position ahead of the broader independent route.
cat >"$work/before.pf" <<EOF
set state-policy if-bound
table <snort2c>
nat on $wan_a inet from 192.0.2.0/25 to any -> ($wan_a)
nat on $wan_b inet from 192.0.2.0/25 to any -> ($wan_b)
nat on $wan_c inet from 192.0.2.0/25 to any -> ($wan_c)
rdr on $wan_b inet proto tcp from any to 203.0.113.1 port 7 -> 192.0.2.11
rdr on $wan_c inet proto tcp from any to 192.0.2.129 port 7 -> 192.0.2.11
block all
# Native pfSense places its offender-table quick blocks before user rules.
block drop quick from <snort2c> to any label "ids-block-from"
block drop quick from any to <snort2c> label "ids-block-to"
pass in quick on $wan_b reply-to ($wan_b 203.0.113.2) inet proto tcp to 192.0.2.11 port 7 keep state label "port-forward-b"
pass in quick on $wan_c reply-to ($wan_c 192.0.2.130) inet proto tcp to 192.0.2.11 port 7 keep state label "port-forward-c"
pass out on $lan inet proto tcp to 192.0.2.11 port 7
EOF
cat >"$work/after.pf" <<EOF
# A later permissive native rule would allow either test destination via the
# kernel default route. The package's no-path guard must precede it.
pass in quick on $lan inet proto tcp from 192.0.2.11 to 192.0.2.128/25 port 7 label "baseline"
pass out inet all
EOF
load_rules() {
    cat "$work/before.pf" "$work/selected.pf" "$work/after.pf" >"$work/main.pf"
    jexec "$firewall" pfctl -nf "$work/main.pf"
    jexec "$firewall" pfctl -f "$work/main.pf"
}
: >"$work/selected.pf"
load_rules
baseline() {
    jexec "$firewall" pfctl -sn
    jexec "$firewall" pfctl -sr | awk '!/label "(descr=)?(path-a|path-b|path-c|no-member)"/'
    jexec "$firewall" route -n get default | awk '/gateway:|interface:/ {print}'
}
baseline >"$work/baseline"

steer() {
    case "$1" in
        a) outbound=$wan_a; next_hop=198.51.100.2; rule=path-a ;;
        b) outbound=$wan_b; next_hop=203.0.113.2; rule=path-b ;;
        c) outbound=$wan_c; next_hop=192.0.2.130; rule=path-c ;;
        none) outbound=''; rule=no-member ;;
        *) return 1 ;;
    esac
    : >"$work/selected.pf"
    if [ -n "${SDWAN_RENDERED_RULES:-}" ]; then
        # The integration job provides the real pfSense filter compiler output.
        # FreeBSD 15 supports ridentifier, so preserve the entire rule including
        # its tracker, labels, flags and order. Substitute only device names.
        ruleset="$SDWAN_RENDERED_RULES/${2:-}$rule.pf"
        test -s "$ruleset"
        sed -e 's/\$LABLAN/'"$lan"'/g' -e "s/labwana/$wan_a/g" -e "s/labwanb/$wan_b/g" -e "s/labwanc/$wan_c/g" \
            "$ruleset" >>"$work/selected.pf"
    elif [ -n "$outbound" ]; then
        printf 'pass in quick on %s route-to (%s %s) inet proto tcp from 192.0.2.11 to 192.0.2.162 port 7 keep state label "path-%s"\n' \
            "$lan" "$outbound" "$next_hop" "$1" >>"$work/selected.pf"
    else
        printf 'block drop in quick on %s inet proto tcp from 192.0.2.11 to 192.0.2.162 port 7 label "no-member"\n' \
            "$lan" >>"$work/selected.pf"
    fi
    load_rules
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
    # pfctl prints every label (the native compiler emits id, tags and
    # descr), followed by eight numeric fields. Total packets is field 2.
    awk -v label="$1" 'NF >= 9 && $(NF-6) > 0 {
        for (i = 1; i <= NF-8; i++) {
            if ($i == label || $i == "descr=" label) { print; seen = 1; break }
        }
    } END {exit !seen}'
}

if [ -n "${SDWAN_RENDERED_RULES:-}" ]; then
    echo 'Testing upstream pfSense filter compiler output in the FreeBSD VNET lab'
else
    echo 'Testing the reference PF rules in the FreeBSD VNET lab'
fi
expect_roundtrip 192.0.2.163 198.51.100.1 default-route-control
steer a
expect_roundtrip 192.0.2.162 198.51.100.1 initial-A
jexec "$firewall" pfctl -s labels | counter path-a
expect_roundtrip 192.0.2.163 198.51.100.1 baseline-A

if [ -n "${SDWAN_RENDERED_RULES:-}" ]; then
    verify_pf() {
        node=$1
        shift
        jexec "$node" /usr/local/bin/php -n -r '
            function get_real_interface($interface, $family, $realv6iface, $flush) { return $interface; }
            require $argv[1] . "/files/usr/local/pkg/sdwan_steering.inc";
            $binding = ["gateways" => ["A", "B"], "trackers" => ["41001"]];
            $state = ["gateway" => $argv[4], "revision" => sdwan_config_revision($binding)];
            $inventory = [
                "A" => ["interface" => $argv[2], "family" => "inet", "address" => "198.51.100.2"],
                "B" => ["interface" => $argv[3], "family" => "inet", "address" => "203.0.113.2"],
            ];
            $status = sdwan_steering_pf_status($binding, $state, $inventory, sdwan_steering_pf_rules());
            if ($status !== $argv[5]) {
                fwrite(STDERR, "Expected {$argv[5]}, found {$status}\n");
                exit(1);
            }
        ' -- "$repo" "$wan_a" "$wan_b" "$1" "$2"
    }
    verify_pf "$firewall" A applied
    verify_pf "$firewall" B pending
    echo 'ok - the package distinguishes matching and mismatched native PF rules'
fi

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

if [ -n "${SDWAN_RENDERED_RULES:-}" ]; then
    # Keep an SD-WAN session and an unrelated native session on A. After the
    # filter changes to B, recover only the sessions whose state carries the
    # SD-WAN rule identifier and the retired route-to hop.
    hold_request() {
        scope=$1
        (
            printf '%s-before\n' "$scope"
            for tick in $(jot 24); do
                [ ! -f "$work/reconnect-release" ] || break
                sleep 1
            done
            printf '%s-after\n' "$scope"
        ) | jexec "$client" nc -n -N -w 28 "$2" 7
    }
    hold_request scoped 192.0.2.162 >"$work/scoped" &
    scoped_pid=$!
    hold_request control 192.0.2.163 >"$work/control-reconnect" &
    control_pid=$!
    for tick in $(jot 5); do
        if grep -Fqx '198.51.100.1 scoped-before' "$work/scoped" &&
           grep -Fqx '198.51.100.1 control-before' "$work/control-reconnect"; then break; fi
        sleep 1
    done
    grep -Fqx '198.51.100.1 scoped-before' "$work/scoped"
    grep -Fqx '198.51.100.1 control-before' "$work/control-reconnect"
    jexec "$firewall" pfctl -vvss >"$work/states-reconnect"
    if ! grep -Eq 'ridentifier[[:space:]]+41001([[:space:]]|$)' "$work/states-reconnect"; then
        # FreeBSD 15's pfctl exposes state rule ordinals only. For the
        # disposable test, resolve the ordinal in this same generation
        # before changing the rules. The deployed parser uses ridentifier
        # directly on pfSense and never guesses from rule order.
        ordinal=$(jexec "$firewall" pfctl -vvsr | awk '/ridentifier 41001$/{sub(/^@/,"",$1); print $1}')
        test -n "$ordinal"
        awk -v ordinal="$ordinal" '{
            print
            if ($0 ~ ("(^|[[:space:]])rule " ordinal "([[:space:],]|$)")) print "    ridentifier 41001"
        }' "$work/states-reconnect" >"$work/states-identifiers"
        mv "$work/states-identifiers" "$work/states-reconnect"
    fi
    steer b
    php -r '
        require $argv[1];
        foreach (sdwan_steering_state_ids(file($argv[2]), ["41001"], $argv[3], "198.51.100.2") as $id) {
            echo $id, PHP_EOL;
        }
    ' "$(dirname "$0")/../../files/usr/local/pkg/sdwan_steering.inc" "$work/states-reconnect" "$wan_a" >"$work/state-ids"
    test -s "$work/state-ids"
    while IFS= read -r id; do
        jexec "$firewall" pfctl -k id -k "$id" 2>&1 | grep -Ei 'killed [01] states?'
    done <"$work/state-ids"
    touch "$work/reconnect-release"
    wait "$scoped_pid" || true
    wait "$control_pid"
    if grep -Fq 'scoped-after' "$work/scoped"; then
        echo 'The retired SD-WAN state carried another transaction' >&2
        exit 1
    fi
    grep -Fqx '198.51.100.1 control-after' "$work/control-reconnect"
    expect_roundtrip 192.0.2.162 203.0.113.1 scoped-session-reconnected
    steer a
    echo 'ok - state recovery reconnected only the retired SD-WAN path and preserved an unrelated established session'
fi

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
jexec "$firewall" pfctl -s labels | counter path-b
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
jexec "$firewall" pfctl -s labels | counter no-member
expect_roundtrip 192.0.2.163 198.51.100.1 guard-is-scoped
steer a
expect_roundtrip 192.0.2.162 198.51.100.1 recovered-A
jexec "$firewall" pfctl -s labels | counter path-a
expect_roundtrip 192.0.2.163 198.51.100.1 final-baseline-A
jexec "$firewall" pfctl -s labels | counter baseline
baseline >"$work/final"
cmp "$work/baseline" "$work/final"
echo 'ok - baseline PF rules, NAT rules and kernel default route survived the path changes'

jexec "$firewall" pfctl -t snort2c -T add 192.0.2.162 >/dev/null
for path in a b; do
    steer "$path"
    if request 192.0.2.162 "ids-block-$path" >"$work/ids-blocked"; then
        echo "A new connection bypassed the offender block on path $path" >&2
        exit 1
    fi
    test ! -s "$work/ids-blocked"
    jexec "$firewall" pfctl -s labels | counter ids-block-to
    expect_roundtrip 192.0.2.163 198.51.100.1 "ids-control-$path"
done
jexec "$firewall" pfctl -t snort2c -T delete 192.0.2.162 >/dev/null
expect_roundtrip 192.0.2.162 203.0.113.1 ids-removal-B
steer a
echo 'ok - the legacy PF offender block survived SD-WAN re-selection and stopped new sessions on both paths'

if [ -n "${SDWAN_RENDERED_RULES:-}" ]; then
    for path in a b c; do
        steer "$path" triple-
        case "$path" in
            a) translated=198.51.100.1 ;;
            b) translated=203.0.113.1 ;;
            c) translated=192.0.2.129 ;;
        esac
        expect_roundtrip 192.0.2.162 "$translated" "three-wan-$path"
        jexec "$firewall" pfctl -s labels | counter "path-$path"
    done
    steer none triple-
    if request 192.0.2.162 three-wan-down >"$work/blocked-triple"; then
        echo 'The three-WAN rule allowed a new flow without a path' >&2
        exit 1
    fi
    test ! -s "$work/blocked-triple"
    jexec "$firewall" pfctl -s labels | counter no-member
    expect_roundtrip 192.0.2.163 198.51.100.1 three-wan-control
    steer a triple-
    expect_roundtrip 192.0.2.162 198.51.100.1 three-wan-recovered
    weighted_rule() {
        sed -e 's/\$LABLAN/'"$lan"'/g' -e "s/labwana/$wan_a/g" -e "s/labwanb/$wan_b/g" \
            "$SDWAN_RENDERED_RULES/weighted-$1.pf" >"$work/selected.pf"
        load_rules
    }
    weighted_rule pool
    : >"$work/weighted-replies"
    for seq in $(jot 18); do request 192.0.2.162 "weighted-$seq" >>"$work/weighted-replies"; done
    awk '$1=="198.51.100.1"{a++} $1=="203.0.113.1"{b++} END{exit !(NR==18 && a==6 && b==12)}' "$work/weighted-replies"
    weighted_rule sticky-pool
    : >"$work/sticky-replies"
    for seq in $(jot 6); do request 192.0.2.162 "sticky-$seq" >>"$work/sticky-replies"; done
    awk 'NR==1{chosen=$1} $1!=chosen{bad=1} END{exit !(NR==6 && !bad && (chosen=="198.51.100.1" || chosen=="203.0.113.1"))}' "$work/sticky-replies"
    weighted_rule sticky-backup
    expect_roundtrip 192.0.2.162 203.0.113.1 only-eligible-weighted
    echo 'ok - native sticky option kept new sessions from the same source on one eligible WAN'
    weighted_rule blocked
    if request 192.0.2.162 weighted-no-member >"$work/weighted-blocked"; then
        echo 'An empty weighted pool allowed a new connection' >&2
        exit 1
    fi
    expect_roundtrip 192.0.2.163 198.51.100.1 weighted-control
    steer a triple-
    echo 'ok - weighted TCP sessions used both paths in a 1:2 ratio and followed SLA loss'
    # The independent incoming services must answer on the arriving WAN,
    # despite the kernel default on A and a different steering decision.
    jexec "$client" inetd -p "$work/client-inetd.pid" "$work/inetd.conf"
    cat >"$work/port-forward.pf" <<EOF
pass in quick on ${wan_b%?}b inet proto tcp from 203.0.113.1 port 7 to 192.0.2.163 no state label "reply-b"
pass in quick on $remote_c inet proto tcp from 192.0.2.129 port 7 to 192.0.2.163 no state label "reply-c"
pass all no state
EOF
    jexec "$remote" pfctl -f "$work/port-forward.pf"
    for decision in a none c; do
        steer "$decision" triple-
        for entry in 'b:203.0.113.1' 'c:192.0.2.129'; do
            marker="port-forward-${entry%:*}-$decision"
            result=$(printf '%s\n' "$marker" | jexec "$remote" nc -n -N -w 4 -s 192.0.2.163 "${entry#*:}" 7)
            test "$result" = "192.0.2.163 $marker"
            jexec "$firewall" pfctl -s labels | counter "port-forward-${entry%:*}"
            jexec "$remote" pfctl -s labels | counter "reply-${entry%:*}"
        done
        # Next iteration must generate new counters on both underlay paths.
        jexec "$remote" pfctl -f "$work/port-forward.pf"
    done
    echo 'ok - independent WAN B and C port forwards retained their reply-to with an active or denied steering policy'
    jexec "$remote" pfctl -f "$work/remote.pf"
    steer a triple-
    baseline >"$work/triple-final"
    cmp "$work/baseline" "$work/triple-final"

    for node in "$client" "$firewall" "$remote"; do
        jexec "$node" sysctl net.inet6.ip6.dad_count=0
    done
    lan_client=${lan%?}a
    remote_b=${wan_b%?}b
    add6() {
        jexec "$1" ifconfig "$2" inet6 -ifdisabled
        jexec "$1" ifconfig "$2" inet6 "$3" alias
    }
    add6 "$client" "$lan_client" 2001:db8:10::11/64
    add6 "$firewall" "$lan" 2001:db8:10::1/64
    add6 "$firewall" "$wan_a" 2001:db8:20::1/64
    add6 "$remote" "$remote_a" 2001:db8:20::2/64
    add6 "$firewall" "$wan_b" 2001:db8:30::1/64
    add6 "$remote" "$remote_b" 2001:db8:30::2/64
    add6 "$remote" "$remote_b" fe80::2/64
    add6 "$firewall" "$wan_c" 2001:db8:50::1/64
    add6 "$remote" "$remote_c" 2001:db8:50::2/64
    add6 "$remote" lo0 2001:db8:40::162/128
    add6 "$remote" lo0 2001:db8:40::163/128
    jexec "$firewall" sysctl net.inet6.ip6.forwarding=1
    jexec "$client" route -n add -inet6 default 2001:db8:10::1
    jexec "$firewall" route -n add -inet6 default 2001:db8:20::2
    jexec "$remote" route -n add -inet6 2001:db8:10::/64 2001:db8:20::1
    jexec "$firewall" route -n get -inet6 default | awk '/gateway:|interface:/ {print}' >"$work/default6.before"
    test -s "$work/default6.before"

    cat >"$work/remote6.pf" <<EOF
pass in quick on $remote_a inet6 proto tcp from 2001:db8:10::11 to 2001:db8:40::162 port 7 no state label "ingress-a"
pass in quick on $remote_b inet6 proto tcp from 2001:db8:10::11 to 2001:db8:40::162 port 7 no state label "ingress-b"
pass in quick on $remote_c inet6 proto tcp from 2001:db8:10::11 to 2001:db8:40::162 port 7 no state label "ingress-c"
pass all no state
EOF
    jexec "$remote" pfctl -f "$work/remote6.pf"
    steer6() {
        ruleset="$SDWAN_RENDERED_RULES/${2:-}ipv6-$1.pf"
        test -s "$ruleset"
        {
            printf 'set state-policy if-bound\nblock all\npass quick inet6 proto icmp6 no state\n'
            sed -e 's/\$LABLAN/'"$lan"'/g' -e "s/labwana/$wan_a/g" -e "s/labwanb/$wan_b/g" -e "s/labwanc/$wan_c/g" \
                "$ruleset"
            printf 'pass in quick on %s inet6 proto tcp from 2001:db8:10::11 to 2001:db8:40::/64 port 7\n' "$lan"
            printf 'pass out inet6 all\n'
        } >"$work/ipv6.pf"
        jexec "$firewall" pfctl -nf "$work/ipv6.pf"
        jexec "$firewall" pfctl -f "$work/ipv6.pf"
    }
    request6() {
        printf '%s\n' "$2" | jexec "$client" nc -6 -n -N -w 4 "$1" 7
    }
    return_via6() {
        # Reinstall the prefix when changing interfaces so the next hop
        # cannot retain the previous adjacency in the laboratory routing table.
        jexec "$remote" route -n delete -inet6 2001:db8:10::/64
        jexec "$remote" route -n add -inet6 2001:db8:10::/64 "$1"
        returned=$(jexec "$remote" route -n get -inet6 2001:db8:10::11 | awk '/interface:/ {print $2}')
        test "$returned" = "$2"
    }
    steer6 path-a
    test "$(request6 2001:db8:40::162 v6-wan-a)" = '2001:db8:10::11 v6-wan-a'
    jexec "$remote" pfctl -s labels | counter ingress-a
    steer6 path-b
    return_via6 2001:db8:30::1 "$remote_b"
    test "$(request6 2001:db8:40::162 v6-wan-b)" = '2001:db8:10::11 v6-wan-b'
    jexec "$remote" pfctl -s labels | counter ingress-b
    steer6 no-member
    return_via6 2001:db8:20::1 "$remote_a"
    if request6 2001:db8:40::162 v6-block >"$work/blocked6"; then
        echo 'The IPv6 no-member rule allowed a new flow' >&2
        exit 1
    fi
    test ! -s "$work/blocked6"
    jexec "$firewall" pfctl -s labels | counter no-member
    test "$(request6 2001:db8:40::163 v6-control)" = '2001:db8:10::11 v6-control'
    steer6 path-a
    test "$(request6 2001:db8:40::162 v6-recovered)" = '2001:db8:10::11 v6-recovered'
    jexec "$firewall" route -n get -inet6 default | awk '/gateway:|interface:/ {print}' >"$work/default6.after"
    cmp "$work/default6.before" "$work/default6.after"
    echo 'ok - IPv6 TCP crossed both WANs (including a link-local next hop), blocked without a path and recovered'
    steer6 path-c triple-
    return_via6 2001:db8:50::1 "$remote_c"
    test "$(request6 2001:db8:40::162 v6-wan-c)" = '2001:db8:10::11 v6-wan-c'
    jexec "$remote" pfctl -s labels | counter ingress-c
    steer6 no-member triple-
    return_via6 2001:db8:20::1 "$remote_a"
    if request6 2001:db8:40::162 v6-block-triple >"$work/blocked6-triple"; then
        echo 'The three-WAN IPv6 rule allowed a new flow without a path' >&2
        exit 1
    fi
    test ! -s "$work/blocked6-triple"
    jexec "$firewall" pfctl -s labels | counter no-member
    test "$(request6 2001:db8:40::163 v6-control-triple)" = '2001:db8:10::11 v6-control-triple'
    steer6 path-a triple-
    test "$(request6 2001:db8:40::162 v6-recovered-triple)" = '2001:db8:10::11 v6-recovered-triple'
    echo 'ok - three-WAN IPv6 reached WAN C, blocked without a path and retained independent reachability'
    jexec "$remote" pfctl -f "$work/remote.pf"
    load_rules
fi

if [ -n "${SDWAN_RENDERED_RULES:-}" ]; then
    python3 -B "$repo/tests/lab/freebsd_supervised_recovery.py" "$work" "$SDWAN_RENDERED_RULES" \
        "$client" "$firewall" "$lan" "$wan_a" "$wan_b"
    steer a
fi

if [ "${SDWAN_REAL_DPINGER:-0}" = 1 ]; then
    set -- "$firewall" "$remote" "$remote_a" "${wan_b%?}b" "$remote_c" "$work/remote.pf"
    if [ -n "${SDWAN_NATIVE_CORE:-}" ]; then
        set -- "$@" --erp "$SDWAN_NATIVE_CORE" "$work" "$client" "$lan"
    fi
    python3 -B "$repo/tests/lab/freebsd_dpinger.py" "$@"
fi

sh "$repo/tests/lab/freebsd-vti-no-sa.sh" "$firewall" "$remote" "$wan_a" "$remote_a" "$work"
sh "$repo/tests/lab/freebsd-vti-esp.sh" "$firewall" "$remote" "$wan_a" "$remote_a" "$work" 198.51.100.1 198.51.100.2
sh "$repo/tests/lab/freebsd-vti-esp.sh" "$firewall" "$remote" "$wan_b" "${wan_b%?}b" "$work" 203.0.113.1 203.0.113.2
sh "$repo/tests/lab/freebsd-vti-esp.sh" "$firewall" "$remote" "$wan_c" "$remote_c" "$work" 192.0.2.129 192.0.2.130

if [ -n "${SDWAN_RENDERED_RULES:-}" ]; then
    disabled=sdpfdisabled$$
    jail -c name="$disabled" persist vnet
    jails="$jails $disabled"
    printf 'block drop all ridentifier 41001\n' >"$work/disabled.pf"
    jexec "$disabled" pfctl -f "$work/disabled.pf"
    verify_pf "$disabled" A unavailable
    echo 'ok - an installed ruleset is reported unavailable while PF is disabled'
fi
