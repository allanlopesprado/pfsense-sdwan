#!/bin/bash
set -euo pipefail

sources=$(mktemp)
trap 'rm -f "$sources"' EXIT
for suite in noble noble-updates noble-security; do
    printf 'deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://mirrors.mit.edu/ubuntu/ %s main universe\n' "$suite"
done > "$sources"
sudo install -m 0644 "$sources" /etc/apt/sdwan-ubuntu.list

# Use the same verified HTTPS archive for apt calls made by VM actions.
sudo tee /etc/apt/apt.conf.d/70-sdwan-archive >/dev/null <<'APT'
Dir::Etc::sourcelist "/etc/apt/sdwan-ubuntu.list";
Dir::Etc::sourceparts "-";
Acquire::Retries "2";
Acquire::https::Timeout "20";
APT

sudo apt-get -o APT::Update::Error-Mode=any update -qq
