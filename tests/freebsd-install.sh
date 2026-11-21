#!/bin/sh
# These tests exercise FreeBSD tools in a disposable VM, without pfSense hooks.
set -eu
root=$(mktemp -d)
trap 'if [ -f "$root/sdwand.sh" ]; then sh "$root/sdwand.sh" stop >/dev/null 2>&1 || true; fi; rm -rf "$root"' EXIT
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

# Cover both update channels and the previous patch level.
for baseline in 0.2.0 0.3.0 0.4.0 0.4.1 0.4.2 0.4.3 0.4.4 0.4.5 0.4.6 0.4.7 0.4.8 0.4.9 0.4.10 0.4.11 0.4.12 0.4.18; do
    test "$(run_pkg version -t "$baseline" "$version")" = '<'
    checksum=$(awk '{print $1}' "$PWD/dist/$package-$baseline.pkg.sha256")
    sha256 -c "$checksum" "$PWD/dist/$package-$baseline.pkg" || exit 1
    run_pkg add -I "$PWD/dist/$package-$baseline.pkg"
    test "$(run_pkg query '%v' "$package")" = "$baseline"
    if [ "${baseline%.*}" = 0.4 ]; then
        php -n -r '
            require $argv[1];
            $release = sdwan_release_parse(file_get_contents($argv[2]));
            exit(is_array($release) && $release["version"] === $argv[3] &&
                $release["sha256"] === hash_file("sha256", $argv[4]) &&
                $release["maturity"] === "experimental" ? 0 : 1);
        ' "$dbroot/usr/local/pkg/sdwan_release.inc" "$PWD/dist/release.json" "$version" "$PWD/dist/$package-$version.pkg"
    fi
    if run_pkg add -I "$root/interrupted.pkg"; then exit 1; fi
    test "$(run_pkg query '%v' "$package")" = "$baseline"
    run_pkg check -s "$package"

    PATH="$root/bin:$PATH" sh -c "$installer"
    test "$(run_pkg query '%v' "$package")" = "$version"
    run_pkg check -s "$package"
    test -f "$dbroot/usr/local/pkg/sdwan_steering.inc"
    test -f "$dbroot/usr/local/pkg/sdwan_log.inc"
    test -f "$dbroot/usr/local/www/sdwan/forwarding.php"
    test -f "$dbroot/usr/local/pkg/shortcuts/pkg_sdwan.inc"
    test ! -e "$dbroot/etc/inc/filter.inc"
    test ! -e "$dbroot/etc/inc/filter-sdwan.inc"
    run_pkg delete -Dy "$package"
    test ! -e "$dbroot/usr/local/www/sdwan/status.php"
    test ! -e "$dbroot/usr/local/www/sdwan/updates.php"
    test ! -e "$dbroot/usr/local/www/sdwan/forwarding.php"
    test ! -e "$dbroot/usr/local/pkg/shortcuts/pkg_sdwan.inc"
    test ! -e "$dbroot/usr/local/www/widgets/widgets/sdwan.widget.php"
    test ! -e "$dbroot/usr/local/sbin/sdwand.php"
    test ! -e "$dbroot/usr/local/pkg/sdwan_log.inc"
    if run_pkg info -e "$package"; then exit 1; fi

    # Roll back by removing the new package first. Do not force pkg past ABI checks.
    run_pkg add -I "$PWD/dist/$package-$baseline.pkg"
    test "$(run_pkg query '%v' "$package")" = "$baseline"
    if [ "${baseline%.*}" = 0.4 ]; then
        test -f "$dbroot/usr/local/pkg/sdwan_log.inc"
    else
        test ! -e "$dbroot/usr/local/pkg/sdwan_log.inc"
    fi
    run_pkg check -s "$package"
    run_pkg delete -Dy "$package"
done
baseline=0.4.18
sed "s|'/etc/version'|'$root/pfsense-version'|" files/usr/local/pkg/sdwan_release.inc > "$root/sdwan_release.inc"
for platform in 2.9.1-RELEASE 2.9.2-RELEASE; do
    if run_pkg info -e "$package"; then
        run_pkg delete -Dy "$package"
    fi
    run_pkg add -I "$PWD/dist/$package-$baseline.pkg"
    printf '%s\n' "$platform" > "$root/pfsense-version"
    php -n -d disable_functions=curl_init,curl_setopt_array,curl_exec,curl_getinfo \
        tests/release_transport.php "$root/sdwan_release.inc" "$dbroot" "$version" "$PWD/dist/$package-$version.pkg" "$baseline"
    test "$(run_pkg query '%v' "$package")" = "$version"
    run_pkg check -s "$package"
done
# Exercise the shipped service wrapper with FreeBSD rc.subr and daemon(8).
# Substitute a temporary pidfile and a sleeping process for the pfSense worker.
cat > "$root/observer" <<'WORKER'
#!/bin/sh
printf '%s\n' "$$" > "$1"
exec /bin/sleep 120
WORKER
chmod +x "$root/observer"
sed -e "s|/var/run/sdwand.pid|$root/sdwand.pid|" \
    -e "s|/usr/local/bin/php /usr/local/sbin/sdwand.php|$root/observer $root/child.pid|" \
    -e "s|/usr/local/bin/php -f /usr/local/pkg/sdwan_invalidate.inc|/usr/bin/touch $root/invalidated|" \
    "$dbroot/usr/local/etc/rc.d/sdwand.sh" > "$root/sdwand.sh"
wait_for_child() {
    for attempt in 1 2 3 4 5 6 7 8 9 10 11 12; do
        if [ -s "$root/child.pid" ]; then
            current=$(cat "$root/child.pid")
            if [ -n "$current" ] && [ "$current" != "$1" ] && kill -0 "$current" 2>/dev/null; then
                printf '%s\n' "$current"
                return 0
            fi
        fi
        sleep 1
    done
    echo 'FreeBSD daemon failed to run a distinct observer process.' >&2
    return 1
}
sh "$root/sdwand.sh" start
sh "$root/sdwand.sh" status
supervisor=$(cat "$root/sdwand.pid")
first=$(wait_for_child '')
kill -KILL "$first"
recovered=$(wait_for_child "$first")
test "$(cat "$root/sdwand.pid")" = "$supervisor"
sh "$root/sdwand.sh" restart
restarted=$(wait_for_child "$recovered")
test -f "$root/invalidated"
rm "$root/invalidated"
sh "$root/sdwand.sh" status
sh "$root/sdwand.sh" stop
test -f "$root/invalidated"
if sh "$root/sdwand.sh" status; then exit 1; fi
sleep 6
test "$(cat "$root/child.pid")" = "$restarted"
if kill -0 "$restarted" 2>/dev/null; then exit 1; fi
echo "Verified FreeBSD service crash recovery, start, restart and deliberate stop with a fixture worker."
echo "Verified checksum rejection, download failure, direct upgrades through 0.4.18 to $version, removal, rollback to each prior version and reinstall (hooks disabled)."
