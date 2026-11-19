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
PATH="$root/bin:$PATH" sh -c "$installer"
version=$(awk '$1=="PORTVERSION="{print $2}' Makefile)
test "$(run_pkg query '%v' pfSense-pkg-SDWAN)" = "$version"
run_pkg check -s pfSense-pkg-SDWAN
run_pkg delete -Iy pfSense-pkg-SDWAN
test ! -e "$dbroot/usr/local/www/sdwan/status.php"
if run_pkg info -e pfSense-pkg-SDWAN; then exit 1; fi
PATH="$root/bin:$PATH" sh -c "$installer"
run_pkg check -s pfSense-pkg-SDWAN
echo "Verified checksum rejection, download failure, installation, removal and reinstall (hooks disabled)."
