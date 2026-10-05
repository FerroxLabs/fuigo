#!/usr/bin/env bash
# final-gate.sh [--network none|host] [--pkg <name>]... [--src <dir>] [--lane <name>] [--timeout <s>] <sha> <jobs>
#
# The Contract A.2.1 release gate. HARD RULE: runs on hetzner-dsm, never on a developer Mac.
#
#   default scope  : cargo test --locked --no-fail-fast --workspace
#   --pkg P        : restrict to package P (repeatable); used for small-crate proofs, never for the release gate
#   --network none : EXECUTE the tests inside an empty network namespace (`unshare -n`, loopback only).
#                    The test binaries are built first WITH network; the run phase is `cargo test --offline`.
#                    Default `host` (the release gate on 1.0.21 is judged under the default).
#   --src <dir>    : use an existing checkout (must be at <sha>) instead of cloning into <lane>/src
#   --lane <name>  : lane under /root/fuigo-builds (default final-gate-<sha12>); holds src/ target/ home/ logs
#   --timeout <s>  : wall clock for the RUN phase (default 7200); expiry => exit 124 => INADMISSIBLE
#
# Every test run goes through /root/fuigo-builds/slot-run.sh (private HOME + one of N host slots); the legacy
# .shell-test.lock is not used. Every phase that executes candidate code (the build, the --list, the run) is its own
# systemd cgroup scope AND session, tagged FUIGO_GATE_RUN=<run id>. ABORT: `pkill -s <gate sid>` (or kill <gate pid>;
# the sid is printed in the header and in runs/<id>/sid). INT/TERM/HUP run a trap that kills every scope of this run
# by cgroup, then sweeps the env marker; a SIGKILLed gate is caught by a detached watchdog that does the same. Never
# abort by process group: `timeout` and cargo put their children in NEW groups, so `kill -- -<pgid>` misses them.
# After the run, any survivor makes the run inadmissible.
#
# The log is judged by gate-verify.sh (A.2.1): headers == derived count (derive.py, from THE CANDIDATE), each
# header reaching its own `test result:`, exit not 124/signal, GATE_DONE last, failing set from `failures:`.
set -uo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# The gate must be its OWN session, or `pkill -s <gate sid>` (printed below) would hit the caller's whole session.
# abort_guard re-launches it under setsid (exit code and TERM/INT/HUP forwarded) when it is not already a leader. It runs
# FIRST: the re-launched instance then performs the hook refusal below on the caller's untouched environment.
. "$HERE/abort-lib.sh"
abort_guard "${BASH_SOURCE[0]}" "$@"
# Self-test hooks are NEVER honoured by the production gate (Fable audit, MEDIUM): GATE_CG_MOUNT / GATE_PROC_ROOT
# would point the survivor scans at a fake tree, GATE_ALLOW_NO_EXPECT would waive the mandatory expected-N file.
# gate-selftest.sh drives gate-lib.sh / gate-verify.sh directly and never runs this script with a hook set, so
# there is no "self-test mode" here at all: any hook in the environment (even set to empty) is refused, and the
# real values are then hard-set before gate-lib.sh is sourced.
for v in GATE_CG_MOUNT GATE_PROC_ROOT GATE_ALLOW_NO_EXPECT; do
  if [ -n "${!v+x}" ]; then echo "final-gate: $v is a self-test hook and is not accepted by the release gate; unset it. Refusing to run." >&2; exit 2; fi
done
export GATE_CG_MOUNT=/sys/fs/cgroup GATE_PROC_ROOT=/proc
unset GATE_ALLOW_NO_EXPECT
. "$HERE/gate-lib.sh"
B=/root/fuigo-builds
NET=host; PKGS=(); SRC=""; LANE_NAME=""; TMO=7200
while [ $# -gt 0 ]; do
  case "$1" in
    --network) NET=${2:?}; shift 2;;
    --pkg) PKGS+=("${2:?}"); shift 2;;
    --src) SRC=${2:?}; shift 2;;
    --lane) LANE_NAME=${2:?}; shift 2;;
    --timeout) TMO=${2:?}; shift 2;;
    --) shift; break;;
    -*) echo "final-gate: unknown option $1" >&2; exit 2;;
    *) break;;
  esac
done
SHA="${1:?usage: final-gate.sh [opts] <sha> <jobs>}"; JOBS="${2:?usage: final-gate.sh [opts] <sha> <jobs>}"
case "$NET" in none|host) ;; *) echo "final-gate: --network must be none|host" >&2; exit 2;; esac
[[ "$SHA" =~ ^[0-9a-f]{12,40}$ ]] || { echo "final-gate: sha must match ^[0-9a-f]{12,40}\$ (got '$SHA')" >&2; exit 2; }
LANE_NAME=${LANE_NAME:-final-gate-${SHA:0:12}}
LANE=$B/$LANE_NAME
[ -n "$SRC" ] || SRC=$LANE/src
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$LANE/target}"
export PATH="/root/.cargo/bin:$PATH"
# REQUIRED (release.yml:309, dispatch-policy.yml:18, f13-test-reliability.yml:23): large fuigo-pager fixtures
# overflow the default 2 MiB test-thread stack in debug builds.
export RUST_MIN_STACK="${RUST_MIN_STACK:-16777216}" RG_BIN_PATH="${RG_BIN_PATH:-/usr/bin/rg}" CARGO_TERM_COLOR=never
export CARGO_BUILD_JOBS="$JOBS"
mkdir -p "$LANE"
# One gate per lane at a time (lock held by fd 9 for the life of this shell, and inherited by the run).
gate_lane_lock "$LANE" || { echo "GATE: lane $LANE_NAME is locked by another gate run"; exit 2; }
# Every run gets its OWN directory; nothing is overwritten, and the inventory is append-only.
RUNDIR=$(gate_new_run_dir "$LANE") || { echo "GATE: cannot create a run directory"; exit 2; }
RUNID=$(basename "$RUNDIR")
LOG="$RUNDIR/suite.log"
SURVF="$RUNDIR/survivors.txt"   # every process found alive after a phase is recorded here (pid, ppid, cmdline, cwd, cgroup, start, marker) BEFORE it is killed
: > "$SURVF" || { echo "GATE: cannot create $SURVF"; exit 2; }
GSID=$(ps -o sid= -p $$ | tr -d ' ')
echo "$GSID" > "$RUNDIR/sid"
# surv_note: print the survivors summary (if any process outlived a phase) and append it to verdict.txt, so EVERY exit that is
# not the final verdict still says which processes were killed.
surv_note() {
  local n; n=$(grep -c '^== survivor' "$SURVF" 2>/dev/null || true)
  [ "${n:-0}" -gt 0 ] || return 0
  { echo "survivors:      $n process(es) outlived their phase and were killed; full details in $SURVF"; gate_survivor_summary "$SURVF"; } | tee -a "$RUNDIR/verdict.txt"
}
gate_inventory "$LANE" "run=$RUNID event=start sha=$SHA net=$NET pkgs=${PKGS[*]:-workspace} gate_pid=$$ gate_sid=$GSID"
command -v systemd-run >/dev/null && [ -w "$GATE_CG_MOUNT" ] || { echo "GATE: systemd-run / writable cgroup v2 required for survivor tracking (fail closed)"; gate_inventory "$LANE" "run=$RUNID event=no-cgroup"; exit 3; }
# Scopes of this run: <base>-build, <base>-list, <base>. Their cgroup paths are recorded under $RUNDIR by the wrapper
# inside each scope. Abort kills ALL of them (cgroup.kill is recursive and survives setsid / env clearing), then sweeps
# the env marker (prefix match on the unit base covers all three scopes).
UNITBASE="fuigo-gate-$(printf '%s' "$RUNID" | tr -c 'A-Za-z0-9' '-')"
SID=""
# cleanup = stop everything in the gate's own session (launchers and unscoped startup commands), then every scope, then the marker
cleanup_run() { gate_abort_run "$RUNDIR" "$RUNID" "$UNITBASE"; }
on_abort() {
  trap '' INT TERM HUP; cleanup_run; local rc=$?
  if [ $rc -eq 0 ]; then echo "GATE: aborted, run $RUNID killed"; gate_inventory "$LANE" "run=$RUNID event=aborted"
  else echo "GATE: aborted but cleanup INCOMPLETE (status $rc): processes of run $RUNID may survive"; gate_inventory "$LANE" "run=$RUNID event=aborted-incomplete status=$rc"; fi
  exit 143
}
trap on_abort INT TERM HUP
# Every auxiliary command (git clone/fetch/checkout, cargo metadata) runs through bg: its own systemd scope AND a background job
# (a TERM is not deferred until it returns). The unit names go to a file so the watchdog, a different process, can kill them too.
abort_init gate "$LANE_NAME"; ABORT_FLAG="$RUNDIR/abort.flag"; ABORT_UNITS_FILE="$RUNDIR/aux.units"; : > "$ABORT_UNITS_FILE" || { echo "GATE: cannot create $ABORT_UNITS_FILE"; exit 2; }
ABORT_LAUNCHER_FILE="$RUNDIR/launcher.id"; : > "$ABORT_LAUNCHER_FILE" || { echo "GATE: cannot create $ABORT_LAUNCHER_FILE"; exit 2; }
# aux_check <status> : a failed CONTAINMENT (97 = could not be recorded / contained, 98 = its scope still holds processes) of an
# auxiliary command invalidates the run: clean up everything and stop (INADMISSIBLE), never carry on to a passing verdict.
aux_check() {
  abort_contain_failed "$1" || return 0
  echo "GATE: containment failure of an auxiliary command (status $1); the run is INADMISSIBLE"; surv_note
  gate_inventory "$LANE" "run=$RUNID event=aux-containment-failed status=$1"; cleanup_run; exit 3
}
# EXIT (any path, incl. the early refusals and failures): a last marker sweep BEFORE the watchdog is disarmed, so nothing that still
# carries this run's marker can outlive the gate (recorded in survivors.txt like everything else)
# A sweep that finds something or fails is NOT silent: the gate then exits 3 (INADMISSIBLE, even if a verdict was already printed)
# and the watchdog stays armed (the gate pid is about to disappear, so the watchdog runs the full abort).
final_sweep() {
  local rc=$? n sr
  if [ -n "${RUNID:-}" ] && [ -n "${SURVF:-}" ]; then
    n=$(gate_reap_marker "$RUNID" "$UNITBASE" "$SURVF" exit 2>/dev/null); sr=$?
    if [ "${n:-0}" -gt 0 ] || [ $sr -ne 0 ]; then
      echo "GATE: INADMISSIBLE: at exit ${n:-0} process(es) still carried this run's marker (sweep status $sr); see $SURVF" | tee -a "$RUNDIR/verdict.txt" >&2
      gate_inventory "$LANE" "run=$RUNID event=exit-sweep-found n=${n:-0} status=$sr" 2>/dev/null
      exit 3
    fi
  fi
  # the watchdog is disarmed only when no scope of the run still holds a process (a failed cgroup.kill must keep it armed)
  if gate_scopes_populated "$RUNDIR" "$UNITBASE"; then
    echo "GATE: INADMISSIBLE: a scope of this run is still populated at exit; the watchdog stays armed" | tee -a "$RUNDIR/verdict.txt" >&2
    gate_inventory "$LANE" "run=$RUNID event=exit-scope-populated" 2>/dev/null
    exit 3
  fi
  gate_wd_stop "$RUNDIR"; exit $rc
}
trap final_sweep EXIT
gate_wd_start "$RUNDIR" "$$" "$RUNID" "$UNITBASE"

if [ ! -d "$SRC/.git" ] && [ ! -f "$SRC/.git" ]; then
  FUIGO_GATE_RUN=$RUNID bg git clone --quiet https://github.com/FerroxLabs/fuigo.git "$SRC"; AUXRC=$?; aux_check $AUXRC
  [ $AUXRC -eq 0 ] || { echo "GATE: clone failed"; exit 2; }
fi
cd "$SRC" || exit 2
if [ "$SRC" = "$LANE/src" ]; then
  FUIGO_GATE_RUN=$RUNID bg git fetch --quiet --all; aux_check $?
  FUIGO_GATE_RUN=$RUNID bg git checkout --quiet --detach "$SHA"; AUXRC=$?; aux_check $AUXRC
  [ $AUXRC -eq 0 ] || { echo "GATE: sha $SHA not found"; exit 2; }
fi
ACTUAL=$(git rev-parse HEAD)
case "$ACTUAL" in "$SHA"*) ;; *) echo "GATE: checkout is at $ACTUAL, not $SHA"; exit 2;; esac
# The SHA must identify what is tested: refuse a tree with ANY modified, staged or untracked file.
TREEOUT=$(gate_tree_check "$SRC"); TRC=$?
TREE=$(printf '%s\n' "$TREEOUT" | sed -n 's/^tree=//p')
if [ $TRC -ne 0 ]; then
  echo "GATE: source tree is not clean at $ACTUAL (status $TRC); refusing to run"; printf '%s\n' "$TREEOUT"
  gate_inventory "$LANE" "run=$RUNID event=refused-dirty-tree sha=$ACTUAL"; exit 3
fi

SCOPE=(--locked --no-fail-fast)
if [ ${#PKGS[@]} -gt 0 ]; then for p in "${PKGS[@]}"; do SCOPE+=(-p "$p"); done; else SCOPE+=(--workspace); fi
if [ ${#PKGS[@]} -gt 0 ]; then P=$(IFS=,; echo "${PKGS[*]}")
else
  # Workspace scope: derive over the actual workspace MEMBERS (cargo metadata --no-deps), not "every local path crate".
  # in its own scope and a background job (see bg): a TERM runs the trap at once and the abort kills the scope.
  FUIGO_GATE_RUN=$RUNID bg cargo metadata --no-deps --format-version 1 --locked --offline > "$RUNDIR/members.json" 2>/dev/null < /dev/null; MMRC=$?; aux_check $MMRC
  P=""; [ $MMRC -ne 0 ] || P=$(python3 -c 'import sys,json; print(",".join(sorted(p["name"] for p in json.load(sys.stdin)["packages"])))' < "$RUNDIR/members.json")
  [ -n "$P" ] || { echo "GATE: cannot list workspace members"; gate_inventory "$LANE" "run=$RUNID event=members-failed"; exit 3; }
fi

{
echo "=== final-gate.sh (A.2.1) ==="
echo "run:            $RUNID  ($RUNDIR)"
echo "gate_sid:       $GSID   (abort: pkill -s $GSID)"
echo "requested_sha:  $SHA"
echo "actual_head:    $ACTUAL"
echo "tree:           $TREE  (clean, incl. untracked)"
echo "rustc:          $(rustc -vV | tr '\n' ' ')"
echo "cargo:          $(cargo --version)"
echo "protoc:         $(protoc --version 2>/dev/null || echo absent)"
echo "scope:          ${SCOPE[*]}"
echo "jobs:           $JOBS   network: $NET   lane: $LANE_NAME   timeout: ${TMO}s"
echo "RUST_MIN_STACK: $RUST_MIN_STACK"
echo "started:        $(date -u +%Y-%m-%dT%H:%M:%SZ)"
} | tee "$RUNDIR/header.txt"

# Phase 1 (network allowed, not part of the evidence): build the test executables and DERIVE the expected
# target count from this candidate (A.2.1 rule 2).
JSON="$RUNDIR/derive.json"
# The build runs in its own scope + backgrounded so that a TERM during the (long) build runs the trap at once
# (bash defers a trap until a FOREGROUND child exits) and the whole build tree is killed by cgroup.
FUIGO_GATE_RUN=$RUNID nice -n 10 setsid systemd-run --scope --quiet --collect --slice=system.slice --unit="$UNITBASE-build" \
  sh -c 'cat /proc/self/cgroup > "$1" || exit 97; [ ! -e "$2" ] || exit 96; shift 2; exec "$@"' gate-cg "$RUNDIR/cgroup-build.path" "$RUNDIR/abort.flag" \
  cargo test "${SCOPE[@]}" --no-run --message-format=json < /dev/null 9>&- > "$JSON" 2> "$RUNDIR/build.err" &
SID=$!; echo "$SID $(gate_pid_starttime "$SID")" > "$RUNDIR/launcher.id"
wait "$SID"; BRC=$?; SID=""; : > "$RUNDIR/launcher.id"
# nothing may outlive the build: leftovers are counted, and an unresolvable/unkillable build scope FAILS CLOSED (GATE_ORPHANS=unknown)
BORPH=$(gate_reap_scope "$RUNDIR/cgroup-build.path" "$SURVF" build); BKRC=$?
# (a build script can leave a marked helper in ANOTHER scope or none: the env-marker sweep covers every phase, not just the run)
BMN=$(gate_reap_marker "$RUNID" "$UNITBASE" "$SURVF" build); BMR=$?; BORPH=$((BORPH + BMN)); [ $BMR -eq 0 ] || BKRC=2
[ $BRC -eq 0 ] || { echo "GATE: build failed (exit $BRC); see $RUNDIR/build.err"; surv_note; echo "GATE: INADMISSIBLE (no run happened)"; gate_inventory "$LANE" "run=$RUNID event=build-failed"; exit 3; }
DERIVATION=$(P="$P" python3 "$HERE/derive.py" < "$JSON")
DERIVED=${DERIVATION%% *}
# Independent per-binary test counts (each binary's own --list), so a header's `running N tests` can be checked
# against something no child process can forge. Listing only; HOME is the lane's private home.
EXPECT="$RUNDIR/expected-n.txt"
LUNIT="$UNITBASE-list"
# --list EXECUTES candidate binaries, so it also runs in its own cgroup scope and must leave nothing behind.
FUIGO_GATE_RUN=$RUNID HOME="$B/$LANE_NAME/home" nice -n 10 systemd-run --scope --quiet --collect --slice=system.slice --unit="$LUNIT" \
    sh -c 'cat /proc/self/cgroup > "$1" || exit 97; [ ! -e "$2" ] || exit 96; shift 2; exec "$@"' gate-cg "$RUNDIR/cgroup-list.path" "$RUNDIR/abort.flag" \
    env P="$P" python3 "$HERE/list-counts.py" "$JSON" < /dev/null 9>&- > "$EXPECT" 2> "$RUNDIR/list-counts.err" &
SID=$!; echo "$SID $(gate_pid_starttime "$SID")" > "$RUNDIR/launcher.id"
wait "$SID"; LRC=$?; SID=""; : > "$RUNDIR/launcher.id"
LISTORPH=$(gate_reap_scope "$RUNDIR/cgroup-list.path" "$SURVF" list); LKRC=$?
LMN=$(gate_reap_marker "$RUNID" "$UNITBASE" "$SURVF" list); LMR=$?; LISTORPH=$((LISTORPH + LMN)); [ $LMR -eq 0 ] || LKRC=2
NEXE=$(printf '%s' "$DERIVATION" | sed -n 's/^[0-9]* exe=\([0-9]*\).*/\1/p')
NLISTED=$(grep -vc "^doc:" "$EXPECT" || true)
NDOCL=$(grep -c "^doc:" "$EXPECT" || true)
NDOC=$(printf '%s' "$DERIVATION" | sed -n 's/^[0-9]* exe=[0-9]* doc=\([0-9]*\).*/\1/p')
echo "expected-n:     $NLISTED binaries listed, derive says exe=$NEXE, doc-test libs $NDOCL of ${NDOC:-?} (list exit $LRC)" | tee -a "$RUNDIR/header.txt"
if [ $LRC -ne 0 ] || [ -z "$NEXE" ] || [ "$NLISTED" -ne "$NEXE" ] || [ "${NDOC:--1}" -ne "$NDOCL" ]; then
  echo "GATE: could not list every test binary's own test count ($NLISTED of ${NEXE:-?}); see $RUNDIR/list-counts.err"
  gate_inventory "$LANE" "run=$RUNID event=list-failed listed=$NLISTED exe=${NEXE:-?}"; surv_note; echo "GATE: INADMISSIBLE (no run happened)"; exit 3
fi
echo "derived:        $DERIVATION" | tee -a "$RUNDIR/header.txt"
# VISIBILITY of what this gate does NOT run: `cargo test` silently skips every test/bin target with required-features (e.g. fuigo-shell's
# test_startup_prefetch_* need `test-support`). The gate runs exactly the default-feature set (A.2.1 counts the same set), so those
# targets are listed here, in the log header and in verdict.txt, never silently dropped; rp.sh runs them in its second pass.
GATEDF="$RUNDIR/gated-targets.txt"; : > "$GATEDF"
FUIGO_GATE_RUN=$RUNID bg cargo metadata --no-deps --format-version 1 --locked --offline > "$RUNDIR/meta.json" 2>/dev/null < /dev/null; GMC=$?; aux_check $GMC
[ $GMC -eq 0 ] || { echo "GATE: cargo metadata for feature-gated discovery failed (exit $GMC); the run is INADMISSIBLE"; gate_inventory "$LANE" "run=$RUNID event=gated-discovery-failed"; cleanup_run; exit 3; }
python3 "$HERE/gated-targets.py" ${P//,/ } < "$RUNDIR/meta.json" > "$GATEDF" 2>/dev/null || { echo "GATE: cannot discover feature-gated targets (cargo metadata / gated-targets.py failed); the run is INADMISSIBLE"; gate_inventory "$LANE" "run=$RUNID event=gated-discovery-failed"; cleanup_run; exit 3; }
NGATED=$(grep -v '^#' "$GATEDF" | grep -c . || true)
if [ "${NGATED:-0}" -gt 0 ]; then
  echo "feature-gated:  $NGATED test target(s) are NOT run by this gate (skipped by cargo: required-features): $(grep -v '^#' "$GATEDF" | awk '{printf "%s/%s [%s]; ", $1, $3, $4}')" | tee -a "$RUNDIR/header.txt"
fi

# Phase 2: the run, through the slot runner, in its own session and its own cgroup scope, also tagged with
# FUIGO_GATE_RUN in its environment.
if [ "$NET" = none ]; then
  INNER=$(printf 'ip link set lo up && export CARGO_NET_OFFLINE=true && exec cargo test --offline %s' "$(printf '%q ' "${SCOPE[@]}")")
  RUN=(timeout -k 30 "$TMO" unshare -n -- /bin/sh -c "$INNER")
else
  RUN=(timeout -k 30 "$TMO" cargo test "${SCOPE[@]}")
fi
cp "$RUNDIR/header.txt" "$LOG"; echo "GATE_TREE=$TREE" >> "$LOG"
# fd 9 (the lane lock) is closed for the run so no descendant can `flock -u 9` it.
UNIT="$UNITBASE"
# The run executes in its own cgroup scope: survivors are found by cgroup membership, which survives setsid() AND
# environment clearing; FUIGO_GATE_RUN in the environment is a second, independent tag.
FUIGO_GATE_RUN=$RUNID setsid systemd-run --scope --quiet --collect --slice=system.slice --unit="$UNIT" \
  sh -c 'cat /proc/self/cgroup > "$1" || exit 97; [ ! -e "$2" ] || exit 96; shift 2; exec "$@"' gate-cg "$RUNDIR/cgroup.path" "$RUNDIR/abort.flag" \
  "$B/slot-run.sh" "$LANE_NAME" "${RUN[@]}" < /dev/null >> "$LOG" 2>&1 9>&- &
SID=$!; echo "$SID $(gate_pid_starttime "$SID")" > "$RUNDIR/launcher.id"
wait "$SID"; RC=$?; SID=""; : > "$RUNDIR/launcher.id"
# The slot is released only when the whole run is gone. Scan (cgroup AND env tag), fail closed, then kill.
CGD=$(gate_cg_resolve "$RUNDIR/cgroup.path"); CGRC=$?
case "$CGD" in */"$UNIT.scope") ;; *) [ $CGRC -ne 0 ] || { echo "cg-error: resolved scope '$CGD' is not $UNIT.scope" >&2; CGRC=2; };; esac
CKRC=0; CGKILLN=0
SREP=0
if [ $CGRC -eq 0 ]; then
  CGKILLN=$(gate_reap_scope "$RUNDIR/cgroup.path" "$SURVF" run); CKRC=$?   # recorded BEFORE each kill, in rounds
else CKRC=2; fi
KILLN=$(gate_reap_marker "$RUNID" "$UNIT.scope" "$SURVF" run); KRC=$?; SCANRC=$KRC
SURV=0   # (observations are counted by the reap helpers: CGKILLN / KILLN)
ORPH=$SURV; [ "${LISTORPH:-0}" -gt "$ORPH" ] && ORPH=$LISTORPH; [ "${LKRC:-0}" -ne 0 ] && CKRC=2; [ "${BKRC:-0}" -ne 0 ] && CKRC=2; [ "${SREP:-0}" -ne 0 ] && CKRC=2; [ "${KILLN:-0}" -gt "$ORPH" ] && ORPH=$KILLN; [ "${CGKILLN:-0}" -gt "$ORPH" ] && ORPH=$CGKILLN; [ "${BORPH:-0}" -gt "$ORPH" ] && ORPH=$BORPH
# The SHA must still identify what ran: same HEAD, same tree, still clean (another process may have switched --src).
TREEOUT2=$(gate_tree_check "$SRC"); TRC2=$?
HT2=$(gate_head_tree "$SRC"); HTRC2=$?
{
  echo
  if [ $CGRC -ne 0 ] || [ $SCANRC -ne 0 ] || [ $CKRC -ne 0 ] || [ $KRC -ne 0 ]; then
    echo "GATE_ORPHANS=unknown (cgroup scan $CGRC, env scan $SCANRC, cgroup kill $CKRC, env kill $KRC)"
  elif [ "$ORPH" -gt 0 ]; then echo "GATE_ORPHANS=$ORPH"; fi
  if [ $TRC2 -ne 0 ] || [ $HTRC2 -ne 0 ] || [ "$HT2" != "$ACTUAL $TREE" ]; then
    echo "GATE_TREE_DIRTY=status $TRC2/$HTRC2, now '$HT2' vs started '$ACTUAL $TREE': $(printf '%s' "$TREEOUT2" | tr '\n' ';')"
  fi
  echo "GATE_CARGO_EXIT=$RC"
  echo "GATE_DONE"
} >> "$LOG"

echo "finished:       $(date -u +%Y-%m-%dT%H:%M:%SZ)"
NSURV=$(grep -c '^== survivor' "$SURVF" || true)
{
  # WHICH processes outlived their phase (they were recorded before being killed): a bare count is not actionable
  [ "${NGATED:-0}" -le 0 ] || echo "feature-gated:  $NGATED test target(s) NOT run by this gate (required-features): $(grep -v '^#' "$GATEDF" | awk '{printf "%s/%s [%s]; ", $1, $3, $4}')"
  if [ "${NSURV:-0}" -gt 0 ]; then
    echo "survivors:      $NSURV process(es) outlived their phase and were killed; full details in $SURVF"
    gate_survivor_summary "$SURVF"
  fi
  "$HERE/gate-verify.sh" "$LOG" "$DERIVED" "$EXPECT"
} | tee "$RUNDIR/verdict.txt"
VRC=${PIPESTATUS[0]}
gate_inventory "$LANE" "run=$RUNID event=end verify_exit=$VRC cargo_exit=$RC survivors=${NSURV:-0} log_sha256=$(sha256sum "$LOG" | cut -d' ' -f1) derived=$DERIVED tree=$TREE"
exit $VRC
