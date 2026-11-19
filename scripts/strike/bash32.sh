#!/usr/bin/env bash
# bash32.sh <work-dir>
# Builds GNU bash 3.2.57 (the bash that ships on macOS) under <work-dir> and prints the path of the binary on stdout.
# Used by final-gate.sh so shell_state_fifo_tests runs against a real bash < 4 (the FIFO dump channel). Reuses a binary
# already built there. The tarball is checked against a pinned sha256 before it is unpacked; everything else goes to stderr.
set -euo pipefail
W="${1:?usage: bash32.sh <work-dir>}"
VER=3.2.57
SHA256=3fa9daf85ebf35068f090ce51283ddeeb3c75eb5bc70b1a4a7cb05868bfe06a4
URL="https://ftp.gnu.org/gnu/bash/bash-$VER.tar.gz"
BIN="$W/bash-$VER/bash"
mkdir -p "$W"
if [ -x "$BIN" ] && "$BIN" -c 'test "${BASH_VERSINFO[0]}" = 3' 2>/dev/null; then echo "$BIN"; exit 0; fi
TAR="$W/bash-$VER.tar.gz"
if [ ! -f "$TAR" ]; then
  if command -v curl >/dev/null; then curl -fsSL --retry 3 -o "$TAR.part" "$URL"; else wget -q -O "$TAR.part" "$URL"; fi
  mv "$TAR.part" "$TAR"
fi
[ "$(sha256sum "$TAR" | cut -d' ' -f1)" = "$SHA256" ] || { echo "bash32: tarball checksum mismatch" >&2; rm -f "$TAR"; exit 1; }
rm -rf "$W/bash-$VER"
tar -xzf "$TAR" -C "$W"
cd "$W/bash-$VER"
# bash 3.2 predates C99 defaults: ask a modern compiler for the dialect it was written in.
CFLAGS="-O1 -std=gnu89 -w" ./configure --without-bash-malloc --disable-nls >&2
# bash 3.2.57's Makefile races under -j (two mkversion runs: "mv: cannot stat newversion.h", Error 1, seen twice
# on the 1.0.46 box); a serial make finishes whatever the parallel pass left undone.
make -j"$(nproc)" >&2 || make >&2
"$BIN" -c 'test "${BASH_VERSINFO[0]}" = 3' || { echo "bash32: built binary is not bash 3" >&2; exit 1; }
echo "$BIN"
