#!/usr/bin/env bash
# abort-lib.sh -- sourced by rp.sh, iso.sh and final-gate.sh (P17-F3). Deployed next to rp.sh/iso.sh in /root/fuigo-builds.
#
# What an ABORT must do: leave no cargo / clippy / test process alive, delete the run's scratch, and never touch an
# innocent process. The rules, all of them learned from leaks:
#   * Abort by SESSION (`pkill -s <sid>`: signals the runner, which then cleans up), never by process group: `timeout` puts its
#     child in a NEW group, so `kill -- -<pgid>` of the script left `cargo clippy` running (P17-R). What the runner kills is
#     decided by SCOPE, not by session or pid numbers: EVERY command of the run (cargo, git, the isolation runs) executes in
#     its own systemd scope (bg), a cgroup path that is unique to this run and catches descendants that setsid() away.
#   * The script must be its OWN session, or `pkill -s <recorded sid>` would kill the caller's whole session.
#     abort_guard makes that so: a session leader is exec'd through a tiny python shim that resets SIGINT/SIGHUP/SIGQUIT
#     to default; anything else becomes a python SUPERVISOR that starts the real runner in a NEW session (the runner's
#     sid is therefore its own pid), forwards TERM/INT/HUP to it, propagates its exit status, and has the kernel TERM
#     the runner (PR_SET_PDEATHSIG) if the supervisor itself is SIGKILLed, so `kill -9 $!` of the launcher cannot leave
#     a run executing unattended. Python, not bash, on
#     purpose: a shell started with `&` inherits SIGINT IGNORED and bash can never trap a signal that was ignored on
#     entry, so a bash supervisor (or runner) would silently ignore `kill -INT`.
#   * bash defers a trap until the FOREGROUND command ends, so long commands run as background jobs that are `wait`ed on
#     (bg): a TERM/INT/HUP to the script runs the trap at once.
#   * The lane-lock fd (7) is closed for every child (`7>&-`) so an orphan can never hold the lane lock.
ABORT_LIB_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ABORT_PYSHIM='import os, signal, sys
for s in (signal.SIGINT, signal.SIGHUP, signal.SIGQUIT): signal.signal(s, signal.SIG_DFL)
os.execvp(sys.argv[1], sys.argv[1:])'

ABORT_PYSUP='import os, signal, subprocess, sys, time
for s in (signal.SIGINT, signal.SIGHUP, signal.SIGQUIT): signal.signal(s, signal.SIG_DFL)
st = {"p": None, "early": []}
def fwd(sig, frame):
    if st["p"] is None: st["early"].append(sig)
    else: st["p"].send_signal(sig)
for s in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP): signal.signal(s, fwd)
sup = os.getpid()
def die_with_supervisor():
    # runs in the CHILD between fork and exec. The child inherited the supervisor forwarding handlers, which would
    # swallow a SIGTERM (it only queues): put the DEFAULT action back first, so the kernel parent-death SIGTERM (and
    # the self-kill below) really terminate it. SIGKILL of the supervisor must not leave the runner running unattended.
    for s in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP): signal.signal(s, signal.SIG_DFL)
    import ctypes
    ctypes.CDLL(None, use_errno=True).prctl(1, int(signal.SIGTERM), 0, 0, 0)   # PR_SET_PDEATHSIG
    time.sleep(float(os.environ.get("ABORT_SUP_DELAY_IN_PREEXEC", "0")))      # test hook: widens the fork->exec window
    if os.getppid() != sup: os._exit(143)   # the supervisor was already gone before the prctl took effect
p = subprocess.Popen(["bash"] + sys.argv[1:], env=dict(os.environ, ABORT_GUARDED="1"), start_new_session=True, preexec_fn=die_with_supervisor)
time.sleep(float(os.environ.get("ABORT_SUP_DELAY_AFTER_SPAWN", "0")))   # test hook: widens the spawn->forward window
st["p"] = p
for sig in st["early"]: p.send_signal(sig)   # an abort that arrived while the runner was being spawned is NOT lost
while True:
    try: rc = p.wait(); break
    except InterruptedError: continue
sys.exit(rc if rc >= 0 else 128 - rc)'

# abort_guard <script-path> [args...] : call first thing, as `abort_guard "${BASH_SOURCE[0]}" "$@"`. Returns in the
# re-launched instance (a session leader, default signal dispositions); never returns in the original process.
abort_guard() {
  local self=$1; shift
  if [ "${ABORT_GUARDED:-}" = 1 ]; then unset ABORT_GUARDED; return 0; fi
  if [ "$(ps -o sid= -p $$ | tr -d ' ')" = "$$" ]; then
    ABORT_GUARDED=1 exec python3 -c "$ABORT_PYSHIM" bash "$self" "$@"
  fi
  exec python3 -c "$ABORT_PYSUP" "$self" "$@"
}

# abort_init <tag> <lane> : state for bg/abort_kill_all (tag names the transient units: fuigo-<tag>-<lane>-<pid>-<n>).
abort_init() { ABORT_TAG=$1; ABORT_LANE=$(printf '%s' "$2" | tr -c 'A-Za-z0-9' '-'); ABORT_SEQ=0; ABORT_CURU=""; ABORT_CHILD=""; ABORT_UNITS=()
  MYSID=$(ps -o sid= -p $$ | tr -d ' '); }

# abort_scope_gone <unit> : evidence that the scope has NO process left, read from its cgroup (not from systemd's state
# string, which says "deactivating"/"failed" for scopes that still hold processes and is empty when the bus query fails):
# the cgroup directory is gone, or its cgroup.events says `populated 0`. Waits up to ~5 s. FAILS CLOSED: an unusable
# cgroup mount, an unreadable cgroup.events or a still-populated cgroup is "not gone" (status 1).
abort_scope_gone() {
  local m=${ABORT_CG_MOUNT:-/sys/fs/cgroup} d i pop
  [ -r "$m/cgroup.controllers" ] && [ -d "$m/system.slice" ] || return 1
  d="$m/system.slice/$1.scope"
  for i in 1 2 3 4 5 6 7 8 9 10; do
    [ -e "$d" ] || return 0
    pop=$(sed -n 's/^populated //p' "$d/cgroup.events" 2>/dev/null)
    [ "$pop" = 0 ] && return 0
    sleep 0.5
  done
  return 1
}
# abort_contain_failed <status> : true if a bg status means containment failed (97 no systemd-run, 98 scope not empty).
# Callers must STOP on it: the evidence of such a run is not trustworthy and something may still be running.
abort_contain_failed() { [ "$1" = 97 ] || [ "$1" = 98 ]; }

# bg <cmd...> : run <cmd> in its OWN systemd scope as a background job and wait for it (return its status). The unit
# name is chosen HERE, in the parent shell (an assignment inside a background subshell would never reach the trap).
# When the command ends, whatever it left in its scope (a hung or setsid()ed child) is killed at once, and every unit is
# remembered so an abort kills ALL of them, not just the latest.
# abort_pid_starttime <pid> : field 22 of /proc/<pid>/stat (identity of a process together with its pid).
abort_pid_starttime() { local st rest F; st=$(cat "/proc/$1/stat" 2>/dev/null) || return 1; rest=${st##*) }; read -ra F <<< "$rest"; printf '%s' "${F[19]:-}"; }
bg() {
  # Containment is REQUIRED, not best-effort: without a scope a setsid()ed descendant would escape every abort/cleanup.
  command -v systemd-run >/dev/null || { echo "abort-lib: systemd-run is required (cannot contain the command); refusing to run it" >&2; return 97; }
  ABORT_SEQ=$((ABORT_SEQ+1)); ABORT_CURU="fuigo-$ABORT_TAG-$ABORT_LANE-$$-$ABORT_SEQ"; ABORT_UNITS+=("$ABORT_CURU")
  # the unit name is also written to a file (if the owner asked for one): a watchdog in ANOTHER process can then kill it too.
  # RECORDING MUST SUCCEED BEFORE LAUNCH: a command whose scope nobody can find again is not contained.
  if [ -n "${ABORT_UNITS_FILE:-}" ]; then
    echo "$ABORT_CURU" >> "$ABORT_UNITS_FILE" || { echo "abort-lib: cannot record unit $ABORT_CURU in $ABORT_UNITS_FILE; refusing to run the command (97)" >&2; return 97; }
  fi
  # ABORT FLAG (race-free, no pid involved): the command only starts if the flag file does not exist, and that check runs INSIDE
  # the new scope. abort_kill_all creates the flag BEFORE it kills any scope, so a launcher that registers its scope late either
  # sees the flag and never starts the command, or had already passed the check, which means its scope existed before the flag
  # was written and therefore before the first kill pass. (Killing the launcher by pid cannot be made safe: it can be signalled
  # between its fork and the pid assignment, and a reaped pid can be recycled.)
  if [ -n "${ABORT_FLAG:-}" ]; then
    systemd-run --scope --quiet --collect --slice=system.slice --unit="$ABORT_CURU" \
      sh -c '[ ! -e "$1" ] || exit 96; shift; exec "$@"' abort-flag "$ABORT_FLAG" "$@" 7>&- 9>&- & ABORT_CHILD=$!
  else
    systemd-run --scope --quiet --collect --slice=system.slice --unit="$ABORT_CURU" "$@" 7>&- 9>&- & ABORT_CHILD=$!
  fi
  # the launcher (the systemd-run client) is recorded as "pid starttime": an abort, or the watchdog of a SIGKILLed owner, must stop it
  # BEFORE it registers its scope and starts the command (a scope that does not exist yet cannot be killed)
  [ -z "${ABORT_LAUNCHER_FILE:-}" ] || echo "$ABORT_CHILD $(abort_pid_starttime "$ABORT_CHILD")" > "$ABORT_LAUNCHER_FILE"
  wait $ABORT_CHILD; local rc=$?; ABORT_CHILD=""
  [ -z "${ABORT_LAUNCHER_FILE:-}" ] || : > "$ABORT_LAUNCHER_FILE"
  systemctl kill --kill-whom=all --signal=SIGKILL "$ABORT_CURU.scope" >/dev/null 2>&1
  if ! abort_scope_gone "$ABORT_CURU"; then   # fail closed: a command that left something we cannot kill is not a clean run
    echo "abort-lib: scope $ABORT_CURU.scope still has live processes after SIGKILL; reporting failure (98)" >&2; return 98
  fi
  return $rc
}
# abort_kill_all : kill every scope of this run (see below). Idempotent.
# Returns 1 and sets ABORT_SURVIVORS if a scope is still active afterwards (the caller must NOT claim a clean abort).
abort_kill_all() {
  local u pass; ABORT_SURVIVORS=""
  # 0. raise the abort flag FIRST (see bg): no command can start after this point. Failing to raise it is an incomplete abort.
  if [ -n "${ABORT_FLAG:-}" ]; then : > "$ABORT_FLAG" 2>/dev/null || ABORT_SURVIVORS="$ABORT_SURVIVORS (abort flag $ABORT_FLAG could not be written)"; fi
  # EVERY command of the run executes in its own systemd scope (bg), so the scopes are the complete, identity-safe record of
  # what to kill (no pid or session number is ever trusted). Twice, 1 s apart: a scope that was still being registered when
  # the abort started exists on the second pass.
  for pass in 1 2; do
    for u in "${ABORT_UNITS[@]}"; do systemctl kill --kill-whom=all --signal=SIGKILL "$u.scope" >/dev/null 2>&1; done
    [ $pass = 1 ] && sleep 1
  done
  # evidence, read from the cgroups
  for u in "${ABORT_UNITS[@]}"; do abort_scope_gone "$u" || ABORT_SURVIVORS="$ABORT_SURVIVORS $u"; done
  [ -z "$ABORT_SURVIVORS" ]
}
