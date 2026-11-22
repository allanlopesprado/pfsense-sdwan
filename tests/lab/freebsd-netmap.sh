#!/bin/sh
# Exercise Suricata on FreeBSD host-stack netmap using a disposable epair.
set -eu
test "$(uname -s)" = FreeBSD
test "$(id -u)" -eq 0

work=$(mktemp -d /tmp/sdwan-netmap.XXXXXXXX)
client=sdnetmap$$
server_ip=198.18.3.1
port=18081
service_pid=''
suricata_pid=''
link=''
proc_cleanup() {
    if [ -n "$1" ]; then
        kill "$1" 2>/dev/null || :
        wait "$1" 2>/dev/null || :
    fi
}
cleanup() {
    status=$?
    set +e
    proc_cleanup "$suricata_pid"
    proc_cleanup "$service_pid"
    if [ "$status" -ne 0 ]; then
        for log in "$work/suricata-console.log" "$work/suricata.log" "$work/http.log"; do
            if [ -f "$log" ]; then tail -n 40 "$log" >&2; fi
        done
    fi
    jail -r "$client" >/dev/null 2>&1
    if [ -n "$link" ]; then ifconfig "$link" destroy >/dev/null 2>&1; fi
    rm -rf "$work"
    return "$status"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

kldload -n if_epair
test -c /dev/netmap || kldload -n netmap
test -c /dev/netmap
link=$(ifconfig epair create)
twin=$(printf '%s\n' "$link" | sed 's/a$/b/')
jail -c name="$client" persist vnet allow.raw_sockets
ifconfig "$twin" vnet "$client"
ifconfig "$link" inet "$server_ip/30" up
jexec "$client" ifconfig lo0 inet 127.0.0.1/8 up
jexec "$client" ifconfig "$twin" inet 198.18.3.2/30 up
printf 'sdwan-netmap\n' > "$work/allowed"
cp "$work/allowed" "$work/denied"
python3 -m http.server "$port" --bind "$server_ip" --directory "$work" > "$work/http.log" 2>&1 &
service_pid=$!

request() {
    result=$(jexec "$client" fetch -q -T 2 -o - "http://$server_ip:$port/$1") || return 1
    test "$result" = sdwan-netmap
}
ready() {
    for _ in 1 2 3 4 5 6; do
        if request allowed; then return 0; fi
        sleep 1
    done
    return 1
}
ready

cat > "$work/inspection.yaml" <<EOF
%YAML 1.1
---
netmap:
  - interface: $link
    threads: 1
    copy-mode: ips
    copy-iface: $link^
    checksum-checks: no
  - interface: $link^
    threads: 1
    copy-mode: ips
    copy-iface: $link
    checksum-checks: no
EOF
cat > "$work/inspection.rules" <<EOF
drop http any any -> $server_ip $port (msg:"SD-WAN netmap test"; flow:established,to_server; http.uri; content:"/denied"; endswith; sid:9900003; rev:1;)
EOF
suricata_config=/usr/local/etc/suricata/suricata.yaml
if [ ! -f "$suricata_config" ]; then suricata_config="$suricata_config.sample"; fi
suricata -c "$suricata_config" --include "$work/inspection.yaml" \
    --netmap -S "$work/inspection.rules" -l "$work" -k none --init-errors-fatal \
    --set stream.inline=yes --set unix-command.enabled=no > "$work/suricata-console.log" 2>&1 &
suricata_pid=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do
    if ! kill -0 "$suricata_pid" 2>/dev/null; then cat "$work/suricata-console.log" >&2; exit 1; fi
    if grep -q 'engine started' "$work/suricata-console.log"; then break; fi
    sleep 1
done
ready
if request denied; then
    echo 'The FreeBSD netmap inspector allowed the test signature.' >&2
    exit 1
fi
python3 - "$work/eve.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as events:
    alerts = [record.get("alert", {}) for record in map(json.loads, events)]
assert any(alert.get("signature_id") == 9900003 and alert.get("action") == "blocked" for alert in alerts)
PY
if grep -q 'GET /denied' "$work/http.log"; then exit 1; fi
ready
jexec "$client" ping -n -q -c 3 -t 5 "$server_ip"
echo 'ok - FreeBSD netmap passed the allowed HTTP request and ICMP but blocked the test signature before delivery'
proc_cleanup "$suricata_pid"
suricata_pid=''
ready
echo 'ok - the test endpoint remained reachable after stopping netmap inspection'
