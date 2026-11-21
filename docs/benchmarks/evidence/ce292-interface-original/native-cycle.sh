#!/bin/sh
# Run only inside the disposable QEMU pfSense CE disk prepared for this lab.
set -eu
umask 077

die() { printf '%s\n' "$*" >&2; exit 1; }
[ "$#" -eq 1 ] || die 'Usage: sh native-cycle.sh stock|install|reload|check|save|restore|rollback'
[ "$(id -u)" -eq 0 ] && [ "$(kenv -q smbios.system.maker)" = QEMU ] && [ -c /dev/gpt/pfsensece292lab ] ||
    die 'This command requires the named disposable QEMU disk.'
[ "$(cat /etc/version)" = 2.9.2-RELEASE ] || die 'Unexpected pfSense version.'
case "$(uname -r)" in 16.0-CURRENT*) ;; *) die 'Unexpected FreeBSD kernel.' ;; esac

state=/root/sdwan-lab-proof
media=/root/sdwan-lab-media
overlay=$media/overlay311ce94/src/etc/inc
package=$media/pfSense-pkg-SDWAN-0.4.28.pkg
native=/etc/inc/filter.inc
adapter=/etc/inc/filter-sdwan.inc
archive=/conf/config.xml
php=/usr/local/bin/php
pkg=/usr/local/sbin/pkg-static
service=/usr/local/etc/rc.d/sdwand.sh
status=/var/run/filter_reload_status
stock_hash=70758089d12a271ff08ccf3e20a180d3f441f8d468e984be6b1476c366c66c30
native_hash=3016dc9a9ddbebff787f1664464e8d40040fd35bbfc77d1420739c5029f4467a
adapter_hash=a0e6c146a0ecf3b75817cc24ce2ee3d5b000881c2671cb4aeff1d1be93e80d4f
package_hash=c23dfbc1f1484469e9831a5099402c93a5a22d4bd9c0f339ab42d6a074398fe5
mkdir -p "$state"

verify_hash() {
    [ "$(sha256 -q "$1")" = "$2" ] || die "Unexpected digest: $1"
}

replace_file() {
    tmp=$(mktemp "$2.lab.XXXXXXXX")
    install -m 0644 "$1" "$tmp"
    mv -f "$tmp" "$2"
}

reload() {
    test -S /var/run/check_reload_status
    touch "$state/reload-request"
    sleep 1
    "$php" -r 'require_once("filter.inc"); filter_configure();'
    count=0
    while [ "$count" -lt 30 ]; do
        if [ -f "$status" ] && [ "$status" -nt "$state/reload-request" ] &&
            grep -Eq '^Done\.?$' "$status"; then
            cp "$status" "$state/native-reload.log"
            pfctl -si | sed -n '1p'
            pfctl -sr | sha256
            printf 'Native reload finished. Inspect loaded trackers separately.\n'
            return 0
        fi
        sleep 1
        count=$((count + 1))
    done
    [ ! -f "$status" ] || tail -n 20 "$status"
    die 'A completed native reload was not observed within 30 seconds.'
}

case "$1" in
    stock)
        verify_hash "$native" "$stock_hash"
        [ ! -e "$adapter" ] || die 'Unexpected native adapter in stock image.'
        uname -a
        cat /etc/version
        for stock in pfSense pfSense-system pfSense-kernel-pfSense; do
            [ "$("$pkg" query '%v' "$stock")" = 2.9.2 ] || die "Unexpected version for $stock."
            "$pkg" query '%n %v' "$stock"
        done
        for nic in em0 em1 em2; do ifconfig "$nic"; done
        ps ax | grep -E '[c]heck_reload_status|[p]hp-fpm|[d]pinger'
        pfctl -si | sed -n '1p'
        ;;
    install)
        verify_hash "$native" "$stock_hash"
        verify_hash "$overlay/filter.inc" "$native_hash"
        verify_hash "$overlay/filter-sdwan.inc" "$adapter_hash"
        verify_hash "$package" "$package_hash"
        [ ! -e "$adapter" ] && [ ! -e "$state/filter.stock.inc" ] || die 'Existing adapter or rollback bundle. Inspect before replacing.'
        [ -s /var/run/php-fpm.pid ] && kill -0 "$(cat /var/run/php-fpm.pid)" || die 'Native PHP-FPM is unavailable.'
        [ -S /var/run/check_reload_status ] || die 'Native filter reload queue is unavailable.'
        "$php" -l "$overlay/filter.inc"
        "$php" -l "$overlay/filter-sdwan.inc"
        cp -p "$native" "$state/filter.stock.inc"
        cp -p "$archive" "$state/config.stock.xml"
        sha256 -q "$state/config.stock.xml" > "$state/config.stock.sha256"
        "$pkg" add "$package"
        [ "$("$pkg" query %v pfSense-pkg-SDWAN)" = 0.4.28 ] || die 'Unexpected installed SD-WAN version.'
        "$pkg" check -s pfSense-pkg-SDWAN
        replace_file "$overlay/filter-sdwan.inc" "$adapter"
        replace_file "$overlay/filter.inc" "$native"
        "$php" -r 'require_once("filter.inc"); exit(function_exists("filter_sdwan_binding_api") && filter_sdwan_binding_api() === 2 ? 0 : 1);'
        "$service" restart
        reload
        ;;
    reload) reload ;;
    check)
        verify_hash "$native" "$native_hash"
        verify_hash "$adapter" "$adapter_hash"
        sysctl kern.boottime
        "$service" status
        ps ax | grep -E '[s]dwand.php|[d]pinger'
        "$php" -r 'require_once("/usr/local/pkg/sdwan_engine.inc"); $s = sdwan_read_snapshot(); if ($s === null) { fwrite(STDERR, "No current snapshot\n"); exit(1); } echo json_encode(array_intersect_key($s, array_flip(["generated_at", "steering"])), JSON_PRETTY_PRINT), PHP_EOL;'
        pfctl -sr | awk '/ridentifier 77129210[12]([[:space:]]|$)/ { print; found=1 } END { exit !found }'
        netstat -rn -f inet | sed -n '1,10p'
        ;;
    save)
        [ ! -e "$state/config.test.xml" ] || die 'Existing scenario backup. Preserve it before repeating.'
        "$php" -r 'require_once("config.inc"); exit(config_get_path("system/hostname") === "sdwan-ce292-lab" ? 0 : 1);' || die 'Capture only the explicitly named synthetic configuration.'
        cp -p "$archive" "$state/config.test.xml"
        sha256 -q "$state/config.test.xml" > "$state/config.test.sha256"
        ;;
    restore)
        verify_hash "$state/config.test.xml" "$(cat "$state/config.test.sha256")"
        "$php" -r 'require_once("config.inc"); $file = $argv[1]; exit(config_validate($file) && config_restore($file, "SD-WAN isolated test configuration") ? 0 : 1);' -- "$state/config.test.xml"
        printf 'Native configuration restore succeeded. Run reboot to activate the full scenario.\n'
        ;;
    rollback)
        verify_hash "$state/filter.stock.inc" "$stock_hash"
        verify_hash "$state/config.stock.xml" "$(cat "$state/config.stock.sha256")"
        if [ -e "$adapter" ]; then verify_hash "$adapter" "$adapter_hash"; fi
        if [ -x "$service" ] && "$service" status >/dev/null 2>&1; then "$service" stop; fi
        "$php" -r 'require_once("config.inc"); exit(config_validate($argv[1]) && config_restore($argv[1], "SD-WAN isolated stock configuration") ? 0 : 1);' -- "$state/config.stock.xml"
        replace_file "$state/filter.stock.inc" "$native"
        if [ -e "$adapter" ]; then
            mv "$adapter" "$state/filter-sdwan.retired.inc"
        fi
        if "$pkg" query '%v' pfSense-pkg-SDWAN >/dev/null 2>&1; then "$pkg" delete -y pfSense-pkg-SDWAN; fi
        reload
        printf 'Stock setup restored. Run reboot to activate all restored settings.\n'
        ;;
    *) die 'Unknown command.' ;;
esac
