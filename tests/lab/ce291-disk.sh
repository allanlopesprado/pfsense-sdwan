#!/bin/sh
# Build a BIOS/UFS disk using only the signed reference CE packages.
set -eu
test "$(uname -s)" = FreeBSD
test "$(id -u)" = 0
out=$(realpath "$1")
version=${2:-2.9.1}
scenario=${3:-acceptance}
case "$version" in
    2.9.1) lab=ce291; series=2_9_1 ;;
    2.9.2) lab=ce292; series=2_9_2 ;;
    *) echo "Unsupported pfSense CE release: $version" >&2; exit 2 ;;
esac
if [ "$scenario" = recovery ]; then test "$version" = 2.9.1; fi
set -- "$out"/ce-candidate-package/*.pkg
test "$#" -eq 1
test -f "$1"
candidate=$1
rollback="$out/dist/pfSense-pkg-SDWAN-0.4.27.pkg"
for package in "$candidate" "$rollback"; do
    test "$(sha256 -q "$package")" = "$(awk 'NR == 1 {print $1}' "$package.sha256")"
done
work=$(mktemp -d "/tmp/$lab.XXXXXX")
root="$work/root"
image="$work/$lab.raw"
device=
mounted=
cleanup() {
    result=$?
    trap - EXIT
    if [ -n "$mounted" ]; then umount "$root" || result=1; fi
    if [ -n "$device" ]; then mdconfig -d -u "${device#md}" || result=1; fi
    rm -rf "$work"
    exit "$result"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
mkdir "$root" "$work/repos" "$work/keys"
mkdir "$work/keys/trusted" "$work/keys/revoked"
cat > "$work/keys/trusted/netgate" <<'KEY'
function: sha256
fingerprint: 30be9cc2e7b2b3ba1ff3b2be1795f3f0719ab9a65322695703dc7b8f004035a8
KEY
mirror="https://pkg01-atx.netgate.com/pfSense_v${series}_amd64"
cat > "$work/repos/pfsense.conf" <<REPO
ce-core: { url: "$mirror-core", enabled: yes, signature_type: "fingerprints", fingerprints: "/root/netgate-keys" }
ce-system: { url: "$mirror-pfSense_v$series", enabled: yes, signature_type: "fingerprints", fingerprints: "/root/netgate-keys" }
REPO
if [ "$scenario" != security ]; then
    truncate -s 4G "$image"
    device=$(mdconfig -a -t vnode -f "$image")
    gpart create -s GPT "$device"
    gpart add -a 4k -s 512k -t freebsd-boot "$device"
    gpart add -a 1m -l "$lab" -t freebsd-ufs "$device"
    newfs -U "/dev/${device}p2"
    mount "/dev/${device}p2" "$root"
    mounted=yes
fi
mkdir -p "$root/var/cache/pkg" "$root/root"
cp -R "$work/keys" "$root/root/netgate-keys"
ce_pkg() {
    env ABI=FreeBSD:16:amd64 OSVERSION=1600018 REPOS_DIR="$work/repos" PKG_CACHEDIR="$root/var/cache/pkg" \
        /usr/local/sbin/pkg-static --rootdir "$root" "$@"
}
ce_pkg update
ce_pkg install -Iy -U pfSense-base pfSense-kernel-pfSense pkg
if [ "$scenario" = security ]; then
    reports="$out/$lab-security"
    mkdir "$reports"
    ce_pkg install -Iy -U pfSense pfSense-default-config-serial
    ce_pkg add -I "$candidate"
    test "$(ce_pkg query '%n' pfSense-pkg-SDWAN)" = pfSense-pkg-SDWAN
    ce_pkg query -a '%n|%v|%o' > "$work/inventory"
    LC_ALL=C sort "$work/inventory" > "$reports/packages.txt"
    vuln_site=https://vuxml.freebsd.org/freebsd/vuln.xml.xz
    fetch -T 45 -o "$work/vuln.xml.xz" "$vuln_site"
    xz -dc "$work/vuln.xml.xz" > "$work/vuln.xml"
    test -s "$work/vuln.xml"
    printf 'TARGET_CE=%s\nCANDIDATE_SHA256=%s\nVUXML_URL=%s\nVUXML_SHA256=%s\n' \
        "$version" "$(sha256 -q "$candidate")" "$vuln_site" "$(sha256 -q "$work/vuln.xml")" > "$reports/metadata.txt"
    audit_status=0
    ce_pkg audit -f "$work/vuln.xml" -Rjson > "$reports/vuxml.json" || audit_status=$?
    printf 'PKG_AUDIT_EXIT=%s\n' "$audit_status" >> "$reports/metadata.txt"
    # A match and a scan failure both return nonzero. The workflow requires a valid result.
    test -s "$reports/vuxml.json"
    exit 0
fi
# The official base package ships the native FreeBSD userland as a release set.
tar -xpf "$root/usr/local/share/pfSense/base.txz" -C "$root"
ce_pkg fetch -dy -U pfSense pfSense-default-config-serial
if [ "$scenario" = inspection ]; then
    ce_pkg fetch -dy -U suricata
fi
mkdir -p "$root/root/sdwan-lab"
cp "$work/repos/pfsense.conf" "$root/root/sdwan-lab/pfsense.conf"
if [ "$scenario" = recovery ]; then
    next="$root/root/sdwan-lab/ce292-repos"
    mkdir "$next"
    next_mirror="https://pkg01-atx.netgate.com/pfSense_v2_9_2_amd64"
    cat > "$next/pfsense.conf" <<REPO
next-core: { url: "$next_mirror-core", enabled: yes, signature_type: "fingerprints", fingerprints: "/root/netgate-keys" }
next-system: { url: "$next_mirror-pfSense_v2_9_2", enabled: yes, signature_type: "fingerprints", fingerprints: "/root/netgate-keys" }
REPO
    ce_pkg_next() {
        env ABI=FreeBSD:16:amd64 OSVERSION=1600018 REPOS_DIR="$next" PKG_CACHEDIR="$root/var/cache/pkg" \
            /usr/local/sbin/pkg-static --rootdir "$root" "$@"
    }
    ce_pkg_next update
    ce_pkg_next fetch -dy -U pfSense pfSense-base pfSense-kernel-pfSense pfSense-system pfSense-default-config-serial
fi
cp "$out/tests/lab/ce291-guest.php" "$root/root/sdwan-lab/"
cp "$out/tools/verify-appliance.sh" "$root/root/sdwan-lab/"
cp "$out"/lab-overlay/src/etc/inc/filter*.inc "$root/root/sdwan-lab/"
cp "$candidate" "$root/root/sdwan-lab/candidate.pkg"
sha256 -q "$candidate" > "$root/root/sdwan-lab/candidate.sha256"
cp "$rollback" "$root/root/sdwan-lab/"
test -s "$root/boot/gptboot"
test -s "$root/boot/kernel/kernel"
gpart bootcode -b "$root/boot/pmbr" -p "$root/boot/gptboot" -i 1 "$device"
printf '/dev/gpt/%s / ufs rw 1 1\n' "$lab" > "$root/etc/fstab"
cat > "$root/boot/loader.conf.local" <<'LOADER'
boot_single="YES"
console="comconsole"
comconsole_speed="115200"
autoboot_delay="1"
net.fibs="3"
LOADER
sync
umount "$root"
mounted=
mdconfig -d -u "${device#md}"
device=
gzip -1c "$image" > "$out/$lab.raw.gz"
