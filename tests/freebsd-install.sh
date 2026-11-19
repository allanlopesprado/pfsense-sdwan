#!/bin/sh
# These tests exercise FreeBSD tools in a disposable VM, without pfSense hooks.
set -eu
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
dbroot="$root/image"
mkdir -p "$dbroot/tmp" "$dbroot/var/db/pkg" "$dbroot/var/cache/pkg" "$root/bin"
export SDWAN_TEST_ROOT="$dbroot"
# The README's installation line runs unmodified. Replace only its final pkg
# command with a call to a real pkg-static using an isolated destination.
cat > "$root/bin/pkg" <<'WRAPPER'
#!/bin/sh
set -eu
[ "$1" = add ]
exec /usr/local/sbin/pkg-static -r "$SDWAN_TEST_ROOT" -o ABI=FreeBSD:16:amd64 -o OSVERSION=1600018 add -I "$2"
WRAPPER
chmod +x "$root/bin/pkg"
installer=$(awk '/<!-- install-command -->/{getline;getline;print;exit}' README.md)
test -n "$installer"
run_pkg() {
    /usr/local/sbin/pkg-static -r "$dbroot" -o ABI=FreeBSD:16:amd64 -o OSVERSION=1600018 "$@"
}
# Simulate corruption and a failed transfer using the same command as a reader.
cat > "$root/bin/fetch" <<'CORRUPT'
#!/bin/sh
printf 'partial archive' > "$2"
CORRUPT
chmod +x "$root/bin/fetch"
if PATH="$root/bin:$PATH" sh -c "$installer"; then exit 1; fi
if run_pkg info -e pfSense-pkg-SDWAN; then exit 1; fi
printf '#!/bin/sh\nexit 1\n' > "$root/bin/fetch"
if PATH="$root/bin:$PATH" sh -c "$installer"; then exit 1; fi
rm "$root/bin/fetch"
# The prior published release remains installed after a rejected upgrade.
package=pfSense-pkg-SDWAN
version=$(awk '$1=="PORTVERSION="{print $2}' Makefile)
test -n "$version"
head -c 80 "$PWD/dist/$package-$version.pkg" > "$root/interrupted.pkg"

# Direct upgrades from both the main observer and the earlier lab release.
for baseline in 0.2.0 0.3.0 0.4.0; do
    test "$(run_pkg version -t "$baseline" "$version")" = '<'
    run_pkg add -I "$PWD/dist/$package-$baseline.pkg"
    test "$(run_pkg query '%v' "$package")" = "$baseline"
    if run_pkg add -I "$root/interrupted.pkg"; then exit 1; fi
    test "$(run_pkg query '%v' "$package")" = "$baseline"
    run_pkg check -s "$package"

    PATH="$root/bin:$PATH" sh -c "$installer"
    test "$(run_pkg query '%v' "$package")" = "$version"
    run_pkg check -s "$package"
    test -f "$dbroot/usr/local/pkg/sdwan_steering.inc"
    test -f "$dbroot/usr/local/pkg/sdwan_log.inc"
    test -f "$dbroot/usr/local/www/sdwan/forwarding.php"
    test ! -e "$dbroot/etc/inc/filter.inc"
    test ! -e "$dbroot/etc/inc/filter-sdwan.inc"
    run_pkg delete -Dy "$package"
    test ! -e "$dbroot/usr/local/www/sdwan/status.php"
    test ! -e "$dbroot/usr/local/www/sdwan/updates.php"
    test ! -e "$dbroot/usr/local/www/sdwan/forwarding.php"
    test ! -e "$dbroot/usr/local/www/widgets/widgets/sdwan.widget.php"
    test ! -e "$dbroot/usr/local/sbin/sdwand.php"
    test ! -e "$dbroot/usr/local/pkg/sdwan_log.inc"
    if run_pkg info -e "$package"; then exit 1; fi

    # Roll back by removing the new package first. Do not force pkg past ABI checks.
    run_pkg add -I "$PWD/dist/$package-$baseline.pkg"
    test "$(run_pkg query '%v' "$package")" = "$baseline"
    test ! -e "$dbroot/usr/local/pkg/sdwan_log.inc"
    run_pkg check -s "$package"
    run_pkg delete -Dy "$package"
done
PATH="$root/bin:$PATH" sh -c "$installer"
test "$(run_pkg query '%v' "$package")" = "$version"
run_pkg check -s "$package"
# Exercise the shipped service wrapper with FreeBSD rc.subr and daemon(8).
# Substitute a temporary pidfile and a sleeping process for the pfSense worker.
sed -e "s|/var/run/sdwand.pid|$root/sdwand.pid|" \
    -e 's|/usr/local/bin/php /usr/local/sbin/sdwand.php|/bin/sleep 120|' \
    -e "s|/usr/local/bin/php -f /usr/local/pkg/sdwan_invalidate.inc|/usr/bin/touch $root/invalidated|" \
    "$dbroot/usr/local/etc/rc.d/sdwand.sh" > "$root/sdwand.sh"
sh "$root/sdwand.sh" start
sh "$root/sdwand.sh" status
sh "$root/sdwand.sh" restart
test -f "$root/invalidated"
rm "$root/invalidated"
sh "$root/sdwand.sh" status
sh "$root/sdwand.sh" stop
test -f "$root/invalidated"
if sh "$root/sdwand.sh" status; then exit 1; fi
echo "Verified FreeBSD service start, restart and stop with a fixture worker."
echo "Verified checksum rejection, download failure, direct upgrades from 0.2.0, 0.3.0 and 0.4.0 to $version, removal, rollback to each prior version and reinstall (hooks disabled)."
