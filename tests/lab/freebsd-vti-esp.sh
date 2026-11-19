#!/bin/sh
# End-of-suite test in the disposable VNETs from freebsd-dataplane.sh.
# Manual ESP SAs isolate kernel behavior from IKE negotiation and CARP.
# Reproduce on a disposable FreeBSD VM as root: sh tests/lab/freebsd-dataplane.sh
# See FreeBSD if_ipsec(4), setkey(8), and tests/sys/netipsec/tunnel/aes_gcm_128.sh.
set +x
set -eu
export LC_ALL=C
umask 077
fw=$1 peer=$2 wan=$3 peer_wan=$4 work=$5
test "$(uname -s)" = FreeBSD
test -d "$work"
outer_a=$6 outer_b=$7
inner_a=198.18.1.1 inner_b=198.18.1.2 target=192.0.2.164
req_a=410 req_b=420 spi_ab=0x14001 spi_ba=0x14002
jexec "$fw" ifconfig "$wan" | grep -Fq "inet $outer_a "
jexec "$peer" ifconfig "$peer_wan" | grep -Fq "inet $outer_b "
interface_to() {
    jexec "$1" route -n get "$2" | awk '$1=="interface:" {print $2; ok=1} END {exit !ok}'
}
fw_wans=''
peer_wans=''
for pair in '198.51.100.1 198.51.100.2' '203.0.113.1 203.0.113.2' '192.0.2.129 192.0.2.130'; do
    read -r local_ip remote_ip <<EOF
$pair
EOF
    fw_wans="$fw_wans $(interface_to "$fw" "$remote_ip")"
    peer_wans="$peer_wans $(interface_to "$peer" "$local_ip")"
done

key_ab=$(openssl rand -hex 20)
key_ba=$(openssl rand -hex 20)
fw_vti='' peer_vti='' alias_added=no route_added=no
delete_sa() {
    printf 'delete %s %s esp %s;\n' "$2" "$3" "$4" | jexec "$1" setkey -c >/dev/null 2>&1
}
cleanup() {
    set +e
    [ "$route_added" = no ] || jexec "$fw" route -n delete -host "$target" >/dev/null 2>&1
    for node in "$fw" "$peer"; do
        delete_sa "$node" "$outer_a" "$outer_b" "$spi_ab"
        delete_sa "$node" "$outer_b" "$outer_a" "$spi_ba"
    done
    [ -z "$fw_vti" ] || jexec "$fw" ifconfig "$fw_vti" destroy >/dev/null 2>&1
    [ -z "$peer_vti" ] || jexec "$peer" ifconfig "$peer_vti" destroy >/dev/null 2>&1
    [ "$alias_added" = no ] || jexec "$peer" ifconfig lo0 inet "$target" -alias >/dev/null 2>&1
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
jail -m name="$fw" allow.raw_sockets
jail -m name="$peer" allow.raw_sockets
if ! jexec "$fw" ifconfig -C | tr ' ' '\n' | grep -qx ipsec; then kldload -n ipsec; fi

# Count ESP only after arrival at the opposite physical interface. The
# cleartext counters cover both physical links and any translated client IP.
cat > "$work/esp-fw.pf" <<EOF
pass in quick on $wan inet proto esp from $outer_b to $outer_a no state label "esp-in"
pass in quick on { $fw_wans } inet proto icmp from $target to any icmp-type echorep no state label "clear-in"
pass all no state
EOF
cat > "$work/esp-peer.pf" <<EOF
pass in quick on $peer_wan inet proto esp from $outer_a to $outer_b no state label "esp-in"
pass in quick on { $peer_wans } inet proto icmp from any to $target icmp-type echoreq no state label "clear-in"
pass all no state
EOF
for spec in "$fw:fw" "$peer:peer"; do
    rules="$work/esp-${spec#*:}.pf"
    jexec "${spec%:*}" pfctl -nf "$rules"
    jexec "${spec%:*}" pfctl -f "$rules"
done
count() {
    # Several physical interfaces expand to multiple rules with the same label.
    jexec "$1" pfctl -s labels | awk -v label="$2" '
        $1==label && $3 ~ /^[0-9]+$/ {sum+=$3; ok=1} END {if (!ok) exit 1; print sum+0}'
}
probe() {
    jexec "$fw" ping -n -c 3 -t 5 -S "$1" "$target" > "$work/esp-probe.out" 2>&1
}
all_replied() {
    grep -Eq '3 packets transmitted, 3 (packets )?received,' "$work/esp-probe.out"
}
jexec "$peer" ifconfig lo0 inet "$target/32" alias
alias_added=yes
jexec "$fw" route -n add -host "$target" "$outer_b"
route_added=yes
probe "$outer_a"
all_replied
clear_fw=$(count "$fw" clear-in)
clear_peer=$(count "$peer" clear-in)
test "$clear_fw" -ge 3
test "$clear_peer" -ge 3
echo "ok - pre-tunnel cleartext detected on underlay $outer_a to $outer_b"

# if_ipsec(4) uses a local reqid per VTI. Each peer stores both directional
# SAs with its own reqid. AES-GCM-128 needs 16 key bytes plus 4 salt bytes.
add_sas() {
    {
        printf 'add %s %s esp %s -m tunnel -u %s -E aes-gcm-16 0x%s;\n' "$outer_a" "$outer_b" "$spi_ab" "$2" "$key_ab"
        printf 'add %s %s esp %s -m tunnel -u %s -E aes-gcm-16 0x%s;\n' "$outer_b" "$outer_a" "$spi_ba" "$2" "$key_ba"
    } | jexec "$1" setkey -c >/dev/null 2>&1 || { echo 'Could not install laboratory ESP SAs' >&2; return 1; }
}
fw_vti=$(jexec "$fw" ifconfig ipsec create)
peer_vti=$(jexec "$peer" ifconfig ipsec create)
jexec "$fw" ifconfig "$fw_vti" reqid "$req_a"
jexec "$peer" ifconfig "$peer_vti" reqid "$req_b"
jexec "$fw" ifconfig "$fw_vti" inet tunnel "$outer_a" "$outer_b"
jexec "$peer" ifconfig "$peer_vti" inet tunnel "$outer_b" "$outer_a"
jexec "$fw" ifconfig "$fw_vti" inet "$inner_a/30" "$inner_b" up
jexec "$peer" ifconfig "$peer_vti" inet "$inner_b/30" "$inner_a" up
add_sas "$fw" "$req_a"
add_sas "$peer" "$req_b"
unset key_ab key_ba
# Re-add the host route so the kernel resolves it against the VTI. Wait
# for one reply after the transition before measuring steady-state delivery.
jexec "$fw" route -n delete -host "$target"
route_added=no
jexec "$fw" route -n add -host "$target" "$inner_b"
route_added=yes
test "$(interface_to "$fw" "$target")" = "$fw_vti"
test "$(interface_to "$peer" "$inner_a")" = "$peer_vti"
ready=no
for attempt in 1 2 3; do
    if jexec "$fw" ping -n -c 1 -t 2 -S "$inner_a" "$target" >"$work/esp-probe.out" 2>&1; then
        ready=yes
        break
    fi
done
if [ "$ready" != yes ]; then
    cat "$work/esp-probe.out" >&2
    exit 1
fi
esp_fw=$(count "$fw" esp-in)
esp_peer=$(count "$peer" esp-in)
probe "$inner_a"
if ! all_replied; then
    cat "$work/esp-probe.out" >&2
    exit 1
fi
test "$(count "$fw" esp-in)" -ge "$((esp_fw+3))"
test "$(count "$peer" esp-in)" -ge "$((esp_peer+3))"
test "$(count "$fw" clear-in)" -eq "$clear_fw"
test "$(count "$peer" clear-in)" -eq "$clear_peer"
echo "ok - VTI on $outer_a: three replies, bidirectional ESP and no protected ICMP in clear"

no_sa() {
    jexec "$fw" netstat -s -p ipsec |
        awk '/outbound packets? with no SA available/ && $1 ~ /^[0-9]+$/ {print $1; ok=1} END {exit !ok}'
}
before=$(no_sa)
delete_sa "$fw" "$outer_a" "$outer_b" "$spi_ab"
if probe "$inner_a"; then echo 'The protected target replied after withdrawal of its outbound SA' >&2; exit 1; fi
test "$(no_sa)" -gt "$before"
test "$(count "$fw" clear-in)" -eq "$clear_fw"
test "$(count "$peer" clear-in)" -eq "$clear_peer"
echo 'ok - withdrawing only the outbound SA interrupts the flow, records a no-SA event and leaves cleartext counters unchanged'
