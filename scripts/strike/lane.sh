#!/usr/bin/env bash
# lane.sh <lane> <cpus> <cmd...>
#
# Build (or otherwise operate) inside one Fuigo build lane, with network.
#
#   lane      lane name under /root/fuigo-builds, or an absolute lane dir.
#             The lane holds <lane>/src (checkout) and <lane>/target (its OWN
#             CARGO_TARGET_DIR -- never shared with another lane).
#   cpus      job count; exported as CARGO_BUILD_JOBS and appended as -j<cpus>
#             only when the command is cargo and carries no -j of its own.
#   cmd...    the command to run, e.g. `cargo build --locked -p fuigo-shell`.
#
# Use this for anything that may need the network (fetch, build, --no-run).
# For TEST EXECUTION use testlane.sh, which runs with `--network none`.
set -uo pipefail

usage() { sed -n '2,20p' "$0" >&2; exit 2; }
[ $# -ge 3 ] || usage

LANE_ARG=$1; CPUS=$2; shift 2
case "$LANE_ARG" in
  /*) LANE=$LANE_ARG ;;
  *)  LANE=/root/fuigo-builds/$LANE_ARG ;;
esac

[ -d "$LANE/src" ] || { echo "lane.sh: no checkout at $LANE/src" >&2; exit 2; }
case "$CPUS" in ''|*[!0-9]*) echo "lane.sh: cpus must be an integer, got '$CPUS'" >&2; exit 2 ;; esac

mkdir -p "$LANE/target"
export CARGO_TARGET_DIR="$LANE/target"
export PATH="$HOME/.cargo/bin:$PATH"
export RUST_MIN_STACK=16777216
export CARGO_BUILD_JOBS="$CPUS"
export CARGO_TERM_COLOR=never
# ripgrep is required by fuigo-tools' grep/glob paths; bundle_rg is release-only,
# so a debug build falls back to $RG_BIN_PATH / $PATH (R007: its absence produced
# 34 ENOENT failures misread as EMFILE).
export RG_BIN_PATH="${RG_BIN_PATH:-/usr/bin/rg}"

cd "$LANE/src" || exit 2

set -- "$@"
if [ "${1##*/}" = "cargo" ] && ! printf '%s\n' "$@" | grep -qE '^-j|^--jobs'; then
  set -- "$@" -j "$CPUS"
fi

echo "lane.sh lane=$LANE cpus=$CPUS rev=$(git rev-parse --short HEAD 2>/dev/null || echo '?')" >&2
echo "lane.sh CARGO_TARGET_DIR=$CARGO_TARGET_DIR RG_BIN_PATH=$RG_BIN_PATH" >&2
echo "lane.sh cmd: $*" >&2
exec "$@"
