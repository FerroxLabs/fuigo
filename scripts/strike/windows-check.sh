#!/usr/bin/env bash
# windows-check.sh [--src <dir>] [--target-dir <dir>] [--keep-target] [pkg...]
#
# Type-check the TEST targets for Windows (x86_64-pc-windows-gnu) on the build box, so a Unix-only test that
# forgot #[cfg(unix)] fails here instead of on a Windows CI runner. HARD RULE: runs on hetzner-dsm, never on a Mac.
#
#   default pkgs : fuigo-shell fuigo-pager
#   --src        : checkout to check (default: the repo this script lives in)
#   --target-dir : private CARGO_TARGET_DIR (default <src>/../target-win-gnu); ~6 GB, deleted afterwards unless --keep-target
#
# Why the gnu target and not msvc: msvc needs the MSVC/clang-cl C toolchain for the C build scripts (ring, zstd-sys,
# aws-lc-sys all fail at their build scripts, measured at 99b86438). gnu uses the mingw-w64 gcc already on the box
# (x86_64-w64-mingw32-gcc). `cargo check` never links, so no Windows linker or SDK is needed.
# The rustup target is added to the pinned toolchain's user dir (no system install).
set -uo pipefail
case "$(uname -s)" in Linux) ;; *) echo "windows-check.sh: run this on the Linux build box (ssh hetzner-dsm), not here" >&2; exit 2;; esac
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
SRC=$(cd "$HERE/../.." && pwd); TD=""; KEEP=0; PKGS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --src) SRC=$(cd "$2" && pwd); shift 2;;
    --target-dir) TD=$2; shift 2;;
    --keep-target) KEEP=1; shift;;
    *) PKGS+=("$1"); shift;;
  esac
done
[ ${#PKGS[@]} -gt 0 ] || PKGS=(fuigo-shell fuigo-pager)
TARGET=x86_64-pc-windows-gnu
[ -n "$TD" ] || TD=$(dirname "$SRC")/target-win-gnu
command -v x86_64-w64-mingw32-gcc >/dev/null || { echo "windows-check.sh: mingw-w64 gcc missing (x86_64-w64-mingw32-gcc)" >&2; exit 2; }
export PATH=/root/.cargo/bin:$PATH RUSTUP_HOME=${RUSTUP_HOME:-/root/.rustup} CARGO_HOME=${CARGO_HOME:-/root/.cargo}
export RUST_MIN_STACK=16777216 RG_BIN_PATH=/usr/bin/rg CARGO_TERM_COLOR=never CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-16}
export CARGO_TARGET_DIR=$TD
FREE_G=$(df -BG --output=avail /root | tail -1 | tr -dc 0-9)
[ "$FREE_G" -ge 60 ] || { echo "windows-check.sh: only ${FREE_G}G free on /root, need 60G" >&2; exit 2; }
cd "$SRC" || exit 2
echo "windows-check: src=$(git rev-parse --short HEAD) toolchain=$(rustc --version) target=$TARGET pkgs=${PKGS[*]} start=$(date -u +%FT%TZ)"
rustup target add "$TARGET" || exit 2
START=$(date +%s)
ARGS=(); for p in "${PKGS[@]}"; do ARGS+=(-p "$p"); done
nice -n 10 cargo check --locked --tests --target "$TARGET" "${ARGS[@]}"
RC=$?
echo "windows-check: exit=$RC secs=$(( $(date +%s) - START )) end=$(date -u +%FT%TZ)"
[ "$KEEP" = 1 ] || rm -rf "$TD"
exit $RC
