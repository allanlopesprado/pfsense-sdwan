#!/bin/sh
# Run on a pfSense clone. The client generates an isolated IPv4 ping flow.
set -eu
export LC_ALL=C
if [ "$#" -lt 5 ] || [ "$#" -gt 6 ]; then
    echo 'Usage: sh observe-path.sh LAN_IF PATH_IF CLIENT_V4 CLIENT_ON_PATH_V4 TARGET_V4 [5-120 seconds]' >&2
    exit 2
fi
lan=$1 path_if=$2 client=$3 translated=$4 target=$5 seconds=${6:-15}
for iface in "$lan" "$path_if"; do
    case "$iface" in ''|-*|*[!A-Za-z0-9_.-]*) echo 'Invalid interface' >&2; exit 2;; esac
done
if [ "$lan" = "$path_if" ]; then echo 'Choose two distinct interfaces' >&2; exit 2; fi
if ! awk -v t="$seconds" 'BEGIN {exit !(t ~ /^[1-9][0-9]*$/ && t+0 >= 5 && t+0 <= 120)}'; then
    echo 'Invalid sample duration' >&2; exit 2
fi
for addr in "$client" "$translated" "$target"; do
    if ! awk -v addr="$addr" 'BEGIN {
        if (split(addr, n, /\./) != 4) exit 1
        for (i=1; i<=4; i++) if (n[i] !~ /^(0|[1-9][0-9]?[0-9]?)$/ || n[i]+0>255) exit 1
        if (n[1]+0 == 0 || n[1]+0 == 127 || n[1]+0 >= 224) exit 1
    }'; then echo 'Expected canonical unicast IPv4 addresses' >&2; exit 2; fi
done
if [ "$target" = "$client" ] || [ "$target" = "$translated" ]; then
    echo 'Choose distinct client and target addresses' >&2; exit 2
fi
command -v tcpdump >/dev/null || { echo 'tcpdump is required' >&2; exit 2; }

umask 077
work=$(mktemp -d)
captures=''
readers=''
cleanup() {
    for pid in $captures $readers; do kill -TERM "$pid" 2>/dev/null || :; done
    for pid in $captures $readers; do wait "$pid" 2>/dev/null || :; done
    rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 2' HUP INT TERM

capture() {
    label=$1 interface=$2 source=$3
    pipe="$work/$label.pipe"
    mkfifo "$pipe"
    : > "$work/$label.err"
    # tcpdump text stays in the pipe. Retain only the ICMP fields needed to match requests.
    awk -v role="$label" '/ICMP echo (request|reply),/ {
        kind=""; id=""; seq=""
        for (i=1; i<NF; i++) {
            if ($i=="request," || $i=="reply,") kind=$i
            if ($i=="id") id=$(i+1)
            if ($i=="seq") seq=$(i+1)
        }
        gsub(/,/, "", kind); gsub(/,/, "", seq); gsub(/,/, "", id)
        if (kind!="" && seq ~ /^[0-9]+$/ && id ~ /^[0-9]+$/) print role,kind,id,seq
        else print "unparsed"
    }' < "$pipe" > "$work/$label.events" &
    readers="$readers $!"
    bpf="icmp and ((src host $source and dst host $target and icmp[icmptype] = icmp-echo) or (src host $target and dst host $source and icmp[icmptype] = icmp-echoreply))"
    tcpdump -p -l -nn -t -s 96 -i "$interface" "$bpf" > "$pipe" 2> "$work/$label.err" &
    captures="$captures $!"
}
capture lan "$lan" "$client"
capture path "$path_if" "$translated"
retry=0
until grep -q 'listening on ' "$work/lan.err" && grep -q 'listening on ' "$work/path.err"; do
    if [ "$retry" -ge 5 ]; then echo 'Capture unavailable on one or both interfaces' >&2; exit 2; fi
    retry=$((retry+1))
    sleep 1
done
echo 'Captures ready. Start one new ping from the dedicated client now.' >&2
sleep "$seconds"
for pid in $captures; do
    kill -TERM "$pid" 2>/dev/null || { echo 'Capture ended early' >&2; exit 2; }
done
for pid in $captures; do wait "$pid" || { echo 'Capture failed' >&2; exit 2; }; done
captures=''
for pid in $readers; do wait "$pid" || { echo 'Capture parser failed' >&2; exit 2; }; done
readers=''
for label in lan path; do
    if ! grep -Eq '^0 packets? dropped by kernel' "$work/$label.err"; then
        echo 'Missing drop counters or kernel capture loss; repeat the measurement' >&2; exit 2
    fi
    # Enforce complete decoding; tcpdump reports the delivered packet count at exit.
    recorded=$(awk '/^[0-9]+ packets? captured/ {print $1}' "$work/$label.err")
    decoded=$(awk 'END {print NR+0}' "$work/$label.events")
    if [ "$recorded" != "$decoded" ]; then echo 'Incomplete capture decoding' >&2; exit 2; fi
done

awk -v sec="$seconds" '
    NF != 4 {bad=1; next}
    {
        # A NAT may translate the ICMP ID; keep each side independent.
        if ($1 in id && id[$1]!=$3) ambiguous=1
        id[$1]=$3
        key=$1 SUBSEP $2 SUBSEP $4
        if (!seen[key]++) count[$1,$2]++
        sequences[$4]=1
    }
    END {
        if (bad) {print "Unrecognized capture record" > "/dev/stderr"; exit 2}
        for (s in sequences) {
            total++
            if (seen["lan","request",s] && seen["path","request",s] &&
                seen["path","reply",s] && seen["lan","reply",s]) full++
        }
        result=ambiguous ? "multiple_flows" : !total ? "no_samples" : full!=total ? "incomplete" : "round_trip_observed"
        printf "{\"result\":\"%s\",\"window_s\":%d,\"lan_requests\":%d,\"path_requests\":%d,",result,sec,count["lan","request"],count["path","request"]
        printf "\"path_replies\":%d,\"lan_replies\":%d,\"complete_sequences\":%d}\n",count["path","reply"],count["lan","reply"],ambiguous?0:full
        exit (result=="round_trip_observed" ? 0 : 1)
    }' "$work/lan.events" "$work/path.events"
