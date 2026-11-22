#!/bin/sh
# Return the most recent distributed package older than the candidate version.
set -eu
cd "$(dirname "$0")/.."
version=${1:?Expected the candidate version}
previous=
for file in dist/pfSense-pkg-SDWAN-*.pkg; do
    [ -f "$file" ] || continue
    number=${file#dist/pfSense-pkg-SDWAN-}
    number=${number%.pkg}
    printf '%s\n' "$number" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || continue
    compare=$(pkg version -t "$number" "$version")
    [ "$compare" = '<' ] || continue
    if [ -n "$previous" ]; then
        compare=$(pkg version -t "$number" "$previous")
        [ "$compare" = '>' ] || continue
    fi
    previous=$number
done
if [ -z "$previous" ]; then
    echo "No distributed SD-WAN package precedes $version." >&2
    exit 1
fi
printf 'dist/pfSense-pkg-SDWAN-%s.pkg\n' "$previous"
