#!/usr/bin/env bash
# Install the pinned static shellcheck into a user directory, no system package. Upstream publishes no checksum file,
# so the sha256 below is pinned here (first verified 2026-11-16 against the v0.10.0 release asset and the value widely
# pinned by other projects). Usage: scripts/release/install-shellcheck.sh [dir]   (default /root/fuigo-builds/shared/bin)
set -euo pipefail
VER=v0.10.0
SHA=6c881ab0698e4e6ea235245f22832860544f17ba386442fe7e9d629f8cbedf87
DIR=${1:-/root/fuigo-builds/shared/bin}
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
curl -fsSL -o "$W/sc.tar.xz" "https://github.com/koalaman/shellcheck/releases/download/$VER/shellcheck-$VER.linux.x86_64.tar.xz"
echo "$SHA  $W/sc.tar.xz" | sha256sum -c -
tar -xJf "$W/sc.tar.xz" -C "$W"
mkdir -p "$DIR"; install -m 0755 "$W/shellcheck-$VER/shellcheck" "$DIR/shellcheck"
"$DIR/shellcheck" --version | sed -n 2p
