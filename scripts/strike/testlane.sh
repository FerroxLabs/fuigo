#!/usr/bin/env bash
# testlane.sh <lane> <src> <target> <cpus> [-- <cargo test args>...]
#
# Run a lane's tests with NO NETWORK (`--network none`) and with RG_BIN_PATH set.
#
#   lane      lane name under /root/fuigo-builds, or an absolute lane dir
#             (used for log naming and as the default for src/target).
#   src       checkout to test in;  `-` means <lane>/src.
#   target    CARGO_TARGET_DIR;     `-` means <lane>/target.
#   cpus      job count for the compile step and --test-threads for the run.
#   args...   cargo test arguments; default `--locked --no-fail-fast --workspace`.
#             Anything after a literal `--` is passed through verbatim.
#
# Why two phases: compiling may need the network (registry, git deps), running
# must not. So the test binaries are BUILT with network via `cargo test --no-run`
# and then EXECUTED inside a fresh, empty network namespace (`unshare --net`)
# with only loopback brought up -- loopback is required because the suite's mock
# servers bind 127.0.0.1. Inside the namespace cargo runs `--offline`, so a
# missed dependency is an immediate error instead of a hang.
#
# Env:
#   TESTLANE_LOCK   flock this path for the whole run (host-wide serialisation).
#                   fuigo-shell runs MUST pass /root/fuigo-builds/.shell-test.lock
#                   -- three concurrent fuigo-shell suites contaminated a run.
#   TESTLANE_LOG    log path (default /root/fuigo-builds/testlane-<lane>-<ts>.log)
#   TESTLANE_NET    `none` (default) or `host` to skip the namespace.
#   TESTLANE_TEST_THREADS
#                   --test-threads for the run (default <cpus>). Pass the box's
#                   nproc to reproduce a default `cargo test` thread count.
#   TESTLANE_TIMEOUT
#                   seconds before the RUN phase is killed (default 5400). A hung
#                   test must not hold a host-wide flock forever: the run is
#                   killed, `cargo_exit=124` is recorded, and the failing set is
#                   whatever the log had reached.
#   TESTLANE_FILTERS
#                   extra libtest arguments, appended after `-- --test-threads`
#                   (e.g. test-name filters, --exact).
set -uo pipefail

usage() { sed -n '2,26p' "$0" >&2; exit 2; }
[ $# -ge 4 ] || usage

LANE_ARG=$1; SRC_ARG=$2; TGT_ARG=$3; CPUS=$4; shift 4
[ "${1:-}" = "--" ] && shift

case "$LANE_ARG" in /*) LANE=$LANE_ARG ;; *) LANE=/root/fuigo-builds/$LANE_ARG ;; esac
LANE_TAG=$(basename "$LANE")
[ "$SRC_ARG" = "-" ] && SRC="$LANE/src" || SRC=$SRC_ARG
[ "$TGT_ARG" = "-" ] && TGT="$LANE/target" || TGT=$TGT_ARG
case "$CPUS" in ''|*[!0-9]*) echo "testlane.sh: cpus must be an integer, got '$CPUS'" >&2; exit 2 ;; esac

[ -d "$SRC" ] || { echo "testlane.sh: no checkout at $SRC" >&2; exit 2; }
mkdir -p "$TGT"

[ $# -gt 0 ] || set -- --locked --no-fail-fast --workspace

NET=${TESTLANE_NET:-none}
THREADS=${TESTLANE_TEST_THREADS:-$CPUS}
case "$THREADS" in ''|*[!0-9]*) echo "testlane.sh: TESTLANE_TEST_THREADS must be an integer, got '$THREADS'" >&2; exit 2 ;; esac
LOG=${TESTLANE_LOG:-/root/fuigo-builds/testlane-$LANE_TAG-$(date -u +%Y%m%dT%H%M%SZ).log}

export CARGO_TARGET_DIR="$TGT"
export PATH="$HOME/.cargo/bin:$PATH"
export RUST_MIN_STACK=16777216
export CARGO_TERM_COLOR=never
# See lane.sh: bundle_rg is release-only, so debug tests resolve ripgrep here.
export RG_BIN_PATH="${RG_BIN_PATH:-/usr/bin/rg}"
[ -x "$RG_BIN_PATH" ] || { echo "testlane.sh: RG_BIN_PATH=$RG_BIN_PATH is not executable" >&2; exit 2; }

cd "$SRC" || exit 2
REV=$(git rev-parse HEAD 2>/dev/null || echo unknown)

{
  echo "testlane.sh lane=$LANE_TAG src=$SRC target=$TGT cpus=$CPUS net=$NET"
  echo "rev=$REV"
  echo "rustc=$(rustc --version)  cargo=$(cargo --version)  rg=$($RG_BIN_PATH --version | head -1)"
  echo "RG_BIN_PATH=$RG_BIN_PATH  RUST_MIN_STACK=$RUST_MIN_STACK"
  echo "lock=${TESTLANE_LOCK:-<none>}"
  echo "started=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "compile: cargo test --no-run $* -j $CPUS   (network: yes)"
  echo "run:     cargo test --offline $* -j $CPUS -- --test-threads=$THREADS ${TESTLANE_FILTERS:-}   (network: $NET)"
  echo "---- 8< ---- compile ---- 8< ----"
} > "$LOG"

# Phase 1: build the test binaries. Network allowed; never counted as the gate.
cargo test --no-run "$@" -j "$CPUS" >> "$LOG" 2>&1
BUILD_RC=$?
if [ $BUILD_RC -ne 0 ]; then
  echo "testlane.sh: compile failed (exit $BUILD_RC); see $LOG" >&2
  echo "compile_exit=$BUILD_RC" >> "$LOG"
  echo "$LOG"
  exit $BUILD_RC
fi
echo "compile_exit=0" >> "$LOG"
echo "---- 8< ---- run (network=$NET) ---- 8< ----" >> "$LOG"

# Phase 2: execute with no network.
INNER=$(printf 'cd %q && CARGO_TARGET_DIR=%q PATH=%q RUST_MIN_STACK=%q RG_BIN_PATH=%q CARGO_TERM_COLOR=never cargo test --offline' \
  "$SRC" "$TGT" "$PATH" "$RUST_MIN_STACK" "$RG_BIN_PATH")
for a in "$@"; do INNER="$INNER $(printf '%q' "$a")"; done
INNER="$INNER -j $CPUS -- --test-threads=$THREADS"
for a in ${TESTLANE_FILTERS:-}; do INNER="$INNER $(printf '%q' "$a")"; done

RUN_TIMEOUT=${TESTLANE_TIMEOUT:-5400}
case "$RUN_TIMEOUT" in ''|*[!0-9]*) echo "testlane.sh: TESTLANE_TIMEOUT must be an integer, got '$RUN_TIMEOUT'" >&2; exit 2 ;; esac

if [ "$NET" = "none" ]; then
  # A fresh netns has only a DOWN loopback; the suite's mock servers bind
  # 127.0.0.1, so bring lo up and nothing else. No route off the host exists.
  CMD=(timeout -k 30 "$RUN_TIMEOUT" unshare --net -- /bin/sh -c "ip link set lo up; $INNER")
else
  CMD=(timeout -k 30 "$RUN_TIMEOUT" /bin/sh -c "$INNER")
fi

if [ -n "${TESTLANE_LOCK:-}" ]; then
  flock "$TESTLANE_LOCK" "${CMD[@]}" >> "$LOG" 2>&1
else
  "${CMD[@]}" >> "$LOG" 2>&1
fi
RC=$?

{
  echo "---- 8< ---- end ---- 8< ----"
  echo "cargo_exit=$RC"
  [ $RC -eq 124 ] && echo "TIMED OUT after ${RUN_TIMEOUT}s: the run was KILLED, this log is truncated and its failing set is NOT a failing set"
  echo "finished=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} >> "$LOG"

# Nothing may be appended to $LOG past this point: its sha256 is the receipt.
# Contract A.2's `grep -cE '^test .* FAILED$'` undercounts when a FAILED line
# interleaves with another test's stdout, and binaries_run vs result_lines
# false-positives on tests that drive child processes (running_headers 37 vs
# binaries_run 52). The failing set is taken from the `failures:` block instead.
FAILSET="${LOG%.log}.failset"
META="${LOG%.log}.meta"
awk '/^failures:$/{f=1;next} f&&/^ +[A-Za-z0-9_:]+$/{print $1} f&&/^$/{f=0}' "$LOG" | sort -u > "$FAILSET"

{
  echo "commit:     $REV"
  echo "command:    TESTLANE_NET=$NET TESTLANE_TEST_THREADS=$THREADS TESTLANE_FILTERS=${TESTLANE_FILTERS:-} testlane.sh $LANE_TAG $SRC_ARG $TGT_ARG $CPUS -- $*"
  echo "inner:      $INNER"
  echo "network:    $NET"
  echo "run_timeout: ${RUN_TIMEOUT}s"
  echo "exit_code:  $RC"
  echo "log:        $LOG"
  echo "log_digest: $(sha256sum "$LOG" | cut -d' ' -f1)"
  echo "failset:    $FAILSET"
  echo "failset_digest: $(sha256sum "$FAILSET" | cut -d' ' -f1)"
  echo "failset_count:  $(wc -l < "$FAILSET")"
  echo "result_lines:   $(grep -cE '^test result:' "$LOG")"
  echo "binaries_run:   $(grep -cE '^running [0-9]+ tests?$' "$LOG")"
  echo "running_headers: $(grep -cE '^ +Running |^ +Doc-tests ' "$LOG")"
  echo "timestamp:  $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "env_digest: $(rustc --version) | $(cargo --version) | $($RG_BIN_PATH --version | head -1)"
} > "$META"

cat "$META" >&2
echo "$LOG"
exit $RC
