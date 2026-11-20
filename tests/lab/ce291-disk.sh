#!/bin/sh
# Build a BIOS/UFS disk using only the signed reference CE packages.
set -eu
test "$(uname -s)" = FreeBSD
test "$(id -u)" = 0
out=$(realpath "$1")
work=$(mktemp -d /tmp/ce291.XXXXXX)
root="$work/root"
image="$work/ce291.raw"
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
mirror=https://pkg01-atx.netgate.com/pfSense_v2_9_1_amd64
cat > "$work/repos/pfsense.conf" <<REPO
ce-core: { url: "$mirror-core", enabled: yes, signature_type: "fingerprints", fingerprints: "/root/netgate-keys" }
ce-system: { url: "$mirror-pfSense_v2_9_1", enabled: yes, signature_type: "fingerprints", fingerprints: "/root/netgate-keys" }
REPO
truncate -s 4G "$image"
device=$(mdconfig -a -t vnode -f "$image")
gpart create -s GPT "$device"
gpart add -a 4k -s 512k -t freebsd-boot "$device"
gpart add -a 1m -l sdwan291 -t freebsd-ufs "$device"
newfs -U "/dev/${device}p2"
mount "/dev/${device}p2" "$root"
mounted=yes
mkdir -p "$root/var/cache/pkg" "$root/root"
cp -R "$work/keys" "$root/root/netgate-keys"
ce_pkg() {
    env ABI=FreeBSD:16:amd64 OSVERSION=1600018 REPOS_DIR="$work/repos" PKG_CACHEDIR="$root/var/cache/pkg" \
        /usr/local/sbin/pkg-static --rootdir "$root" "$@"
}
ce_pkg update
ce_pkg install -Iy -U pfSense-base pfSense-kernel-pfSense pkg
# The official base package ships the native FreeBSD userland as a release set.
tar -xpf "$root/usr/local/share/pfSense/base.txz" -C "$root"
ce_pkg fetch -dy -U pfSense pfSense-default-config-serial
mkdir -p "$root/root/sdwan-lab"
cp "$work/repos/pfsense.conf" "$root/root/sdwan-lab/pfsense.conf"
cp "$out/tests/lab/ce291-guest.php" "$root/root/sdwan-lab/"
cp "$out"/lab-overlay/src/etc/inc/filter*.inc "$root/root/sdwan-lab/"
for package in "$out"/dist/pfSense-pkg-SDWAN-0.4.2[78].pkg; do
    test "$(sha256 -q "$package")" = "$(awk 'NR == 1 {print $1}' "$package.sha256")"
done
cp "$out"/dist/pfSense-pkg-SDWAN-0.4.2[78].pkg "$root/root/sdwan-lab/"
test -s "$root/boot/gptboot"
test -s "$root/boot/kernel/kernel"
gpart bootcode -b "$root/boot/pmbr" -p "$root/boot/gptboot" -i 1 "$device"
printf '/dev/gpt/sdwan291 / ufs rw 1 1\n' > "$root/etc/fstab"
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
gzip -1c "$image" > "$out/ce291.raw.gz"
