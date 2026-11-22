#!/bin/sh
# Refresh only the marked README command using a package already committed in Git.
set -eu

die() {
	printf '%s\n' "$*" >&2
	exit 1
}

expected_abi=FreeBSD:16:amd64
abi=$(pkg config ABI 2>/dev/null) || die "Cannot read pkg ABI. Expected $expected_abi."
[ "$abi" = "$expected_abi" ] || die "Expected pkg ABI $expected_abi, got $abi."

cd "$(dirname "$0")/.."
version=
for candidate in dist/pfSense-pkg-SDWAN-*.pkg; do
	[ -f "$candidate" ] || continue
	name=${candidate##*/}
	number=${name#pfSense-pkg-SDWAN-}
	number=${number%.pkg}
	printf '%s\n' "$number" | grep -Eq '^(0|[1-9][0-9]{0,8})(\.(0|[1-9][0-9]{0,8})){2}$' || continue
	if [ -n "$version" ]; then
		compare=$(pkg version -t "$number" "$version") || die "Cannot compare package versions."
		[ "$compare" = '>' ] || continue
	fi
	version=$number
done
[ -n "$version" ] || die 'No versioned SD-WAN package found in dist/.'

filename=pfSense-pkg-SDWAN-$version.pkg
artifact=dist/$filename
digest=$(sha256 -q "$artifact") || die "Cannot calculate SHA-256 for $artifact."
[ "${#digest}" -eq 64 ] || die "Invalid SHA-256 for $artifact."
case "$digest" in *[!a-f0-9]*) die "Invalid SHA-256 for $artifact." ;; esac

blob=$(git hash-object --no-filters "$artifact") || die "Cannot identify the Git blob for $artifact."
commits=$(git log --format=%H HEAD -- "$artifact") || die "Cannot read Git history for $artifact."
pin=
for commit in $commits; do
	committed_blob=$(git rev-parse --verify "$commit:$artifact" 2>/dev/null) || continue
	if [ "$blob" = "$committed_blob" ]; then
		pin=$commit
		break
	fi
done
[ -n "$pin" ] || die "No commit in this branch contains the exact bytes of $artifact."

url=https://raw.githubusercontent.com/allanlopesprado/pfsense-sdwan/$pin/$artifact
install_line=$(cat <<EOF
d=\$(mktemp -d /tmp/sdwan.XXXXXXXX) && (trap 'rm -rf "\$d"' EXIT; p="\$d/$filename"; fetch -o "\$p" '$url' && sha256 -c $digest "\$p" && pkg add "\$p")
EOF
)

readme=README.md
temp=$(mktemp "$readme.XXXXXXXX")
trap 'rm -f "$temp"' EXIT
trap 'exit 1' HUP INT TERM
cp -p "$readme" "$temp"
if ! INSTALL_LINE=$install_line awk '
	$0 == "<!-- install-command -->" { if (++count != 1) exit 1; print; state = 1; next }
	state == 1 { if ($0 != "```sh") exit 1; print; print ENVIRON["INSTALL_LINE"]; state = 2; next }
	state == 2 { if ($0 == "```") { print; state = 0 }; next }
	{ print }
	END { if (count != 1 || state != 0) exit 1 }
' "$readme" > "$temp"; then
	die 'Expected exactly one marked shell code block in README.md.'
fi
if ! cmp -s "$readme" "$temp"; then
	mv -f "$temp" "$readme"
fi
printf 'Verified README installer for %s at %s.\n' "$filename" "$pin"
