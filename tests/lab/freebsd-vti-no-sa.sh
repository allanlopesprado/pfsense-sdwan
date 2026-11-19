#!/bin/sh
# Invoked by freebsd-dataplane.sh in its disposable VNETs, after the PF/NAT tests.
set -eu
firewall=$1 remote=$2 wan=$3 remote_wan=$4 work=$5
test "$(uname -s)" = FreeBSD
test -d "$work"
export LC_ALL=C
target=192.0.2.162
outer_local=198.51.100.1
outer_peer=198.51.100.2
jexec "$firewall" ifconfig "$wan" | grep -Fq "inet $outer_local "
jexec "$remote" ifconfig "$remote_wan" | grep -Fq "inet $outer_peer "
jail -m name="$firewall" allow.raw_sockets
# GENERIC may provide IPSEC_SUPPORT with the actual cloner in the ipsec module.
if ! jexec "$firewall" ifconfig -C | tr ' ' '\n' | grep -qx ipsec; then
    kldload -n ipsec
fi
vti=$(jexec "$firewall" ifconfig ipsec create)
jexec "$firewall" ifconfig "$vti" inet tunnel "$outer_local" "$outer_peer"
jexec "$firewall" ifconfig "$vti" inet 198.18.0.1/30 198.18.0.2 up

# Count requests addressed to the test target in clear text on any peer interface.
# Match by destination and type so NAT cannot hide the packet from this check.
cat >"$work/vti-peer.pf" <<EOF
pass in quick inet proto icmp from any to $target icmp-type echoreq no state label "lab-clear"
pass all no state
EOF
jexec "$remote" pfctl -nf "$work/vti-peer.pf"
jexec "$remote" pfctl -f "$work/vti-peer.pf"
clear_count() {
    jexec "$remote" pfctl -s labels |
        awk '$1=="lab-clear" && $3 ~ /^[0-9]+$/ {print $3; ok=1} END {exit !ok}'
}
no_sa_count() {
    jexec "$firewall" netstat -s -p ipsec |
        awk '/outbound packets? with no SA available/ && $1 ~ /^[0-9]+$/ {print $1; ok=1} END {exit !ok}'
}
sample_ping() {
    jexec "$firewall" ping -n -c 2 -t 5 -S "$outer_local" "$target"
}
before=$(clear_count)
sample_ping >"$work/vti-control.out"
control=$(clear_count)
test "$control" -gt "$before"
echo 'ok - cleartext positive control reaches the peer and increments the peer ICMP counter'

# These fresh VNETs run no IKE daemon and this test never provisions an SA.
jexec "$firewall" route -n add -host "$target" 198.18.0.2
jexec "$firewall" route -n get "$target" | awk -v dev="$vti" '$1=="interface:" && $2==dev {ok=1} END {exit !ok}'
no_sa_before=$(no_sa_count)
if sample_ping >"$work/vti-no-sa.out" 2>&1; then
    echo 'Unexpected reply through a VTI without an SA' >&2
    exit 1
fi
no_sa_after=$(no_sa_count)
test "$no_sa_after" -gt "$no_sa_before"
test "$(clear_count)" -eq "$control"
echo 'ok - the VTI without an SA records an IPsec no-SA event and sends no cleartext echo to the peer'

jexec "$firewall" route -n delete -host "$target"
jexec "$firewall" ifconfig "$vti" destroy
sample_ping >"$work/vti-restored.out"
test "$(clear_count)" -gt "$control"
echo 'ok - removing the test VTI route restores the original successful path and peer observation'
