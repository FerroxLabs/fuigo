#!/usr/bin/env bash
# gate-lib.sh -- helpers sourced by final-gate.sh and exercised by gate-selftest.sh (so the self-test runs the
# REAL code paths). Every function fails CLOSED: an inspection error is a distinct non-zero status, never "none found".

. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/abort-lib.sh"   # ABORT_LIB_DIR (safe-kill.py lives next to us)

# gate_tree_check <dir> : status 0 = clean (no modified, staged, untracked OR IGNORED files); prints "tree=<hash>".
#   1 = dirty (prints the offending paths), 2 = could not inspect. Ignored files count: an ignored
#   .cargo/config.toml, build-script input or vendored file changes what is built without changing the SHA.
gate_tree_check() {
  local d=$1 st tree
  st=$(git -C "$d" status --porcelain --untracked-files=all --ignored=matching 2>&1) || { echo "tree-check error: $st"; return 2; }
  tree=$(git -C "$d" rev-parse 'HEAD^{tree}' 2>&1) || { echo "tree-check error: $tree"; return 2; }
  echo "tree=$tree"
  [ -z "$st" ] || { printf '%s\n' "$st"; return 1; }
  # `git update-index --assume-unchanged / --skip-worktree` hides modifications from status: refuse any such entry.
  local lv
  lv=$(git -C "$d" ls-files -v 2>&1) || { echo "tree-check error: ls-files failed: $lv"; return 2; }
  st=$(printf '%s\n' "$lv" | grep -v '^H ' || true)
  [ -z "$st" ] || { printf 'concealment flags set on tracked files:\n%s\n' "$(printf '%s' "$st" | head -5)"; return 1; }
  return 0
}

# gate_marker_pids <runid> [cgroup-scope-name] : prints the pid of every process whose environment carries FUIGO_GATE_RUN=<runid>.
# Marker-in-environment is inherited through fork/exec AND setsid(), so a child that leaves the session is
# still found. Status 2 if any /proc entry that still exists could not be read (fail closed).
gate_marker_pids() {
  local root=${GATE_PROC_ROOT:-/proc} id=$1 unit=${2:-} p rc=0 fd kv stat rest flags try ok cg
  compgen -G "$root/[0-9]*" > /dev/null || { echo "scan-error: no process entries under $root" >&2; return 2; }
  for p in "$root"/[0-9]*; do
    p=${p#"$root"/}
    [ "$p" = "$$" ] && continue
    ok=0
    # A process that is exiting or exec-ing can fail the read transiently: retry (up to ~2 s) before judging it.
    for try in $(seq 1 40); do
      if { exec {fd}< "$root/$p/environ"; } 2>/dev/null; then
        while IFS= read -r -d '' kv <&"$fd"; do
          [ "$kv" = "FUIGO_GATE_RUN=$id" ] && { echo "$p"; break; }
        done
        exec {fd}<&-
        ok=1; break
      fi
      [ -d "$root/$p" ] || { ok=1; break; }                       # gone
      if stat=$(cat "$root/$p/stat" 2>/dev/null); then
        rest=${stat##*) }; set -- $rest; flags=${7:-0}
        case "$1" in Z|X) ok=1; break;; esac                        # zombie / dead: no environment, cannot run
        [ $(( flags & 2097152 )) -ne 0 ] && { ok=1; break; }        # kernel thread (PF_KTHREAD): no environment
      fi
      # With a cgroup scope name given (e.g. fuigo-gate-X.scope): a process whose cgroup is readable and is NOT the run's scope cannot be part of the
      # run (the cgroup scan is the authority for members); an unreadable-env process OUTSIDE the scope is not ours.
      if [ -n "$unit" ] && cg=$(cat "$root/$p/cgroup" 2>/dev/null) && [ -n "$cg" ]; then
        case "$cg" in *"$unit"*) ;; *) ok=1; break;; esac
      fi
      sleep 0.05
    done
    # Still unreadable, still present, not a zombie/kthread: it could be a hidden survivor. Fail closed.
    [ $ok -eq 1 ] || { echo "scan-error: cannot read $root/$p/environ [$(head -c 80 "$root/$p/stat" 2>&1 | tr '\n' ' ') cg=$(head -1 "$root/$p/cgroup" 2>&1)]" >&2; rc=2; }
  done
  return $rc
}

# gate_kill_marker <runid> [cgroup-scope-name] : SIGKILL everything carrying the marker (through gate_kill_if_marked: pidfd, so a
# pid recycled between the scan and the signal is never hit), repeat until none. Prints the number killed.
# Status 0 = none left, 1 = some survive, 2 = inspection error.
gate_kill_marker() {
  local id=$1 unit=${2:-} pids rc total=0 i p
  for i in 1 2 3 4 5; do
    pids=$(gate_marker_pids "$id" "$unit"); rc=$?
    [ $rc -eq 0 ] || { echo "$total"; return 2; }
    [ -n "$pids" ] || { echo "$total"; return 0; }
    for p in $pids; do gate_kill_if_marked "$id" "$p" "" KILL; done
    total=$((total + $(echo "$pids" | wc -l))); sleep 1
  done
  echo "$total"; return 1
}

# gate_new_run_dir <lane-dir> : creates <lane>/runs/<UTC>-<pid>[-n]; refuses to reuse a directory. Prints it.
gate_new_run_dir() {
  local lane=$1 base d n=0
  mkdir -p "$lane/runs" || return 2
  base="$lane/runs/$(date -u +%Y%m%dT%H%M%SZ)-$$"
  d=$base
  until mkdir "$d" 2>/dev/null; do n=$((n+1)); [ $n -lt 100 ] || return 2; d="$base-$n"; done
  echo "$d"
}

# gate_inventory <lane-dir> <line...> : append-only run inventory (one line per event, never rewritten).
gate_inventory() { local lane=$1; shift; printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >> "$lane/runs.inventory"; }

# gate_lane_lock <lane-dir> : takes the per-lane lock on fd 9 for the life of the calling shell. 1 = busy.
gate_lane_lock() { mkdir -p "$1"; exec 9>>"$1/.lane.lock"; flock -n 9; }

# gate_head_tree <dir> : prints "<HEAD> <tree>" (status 2 if not inspectable).
gate_head_tree() { local h t; h=$(git -C "$1" rev-parse HEAD 2>/dev/null) && t=$(git -C "$1" rev-parse 'HEAD^{tree}' 2>/dev/null) || return 2; echo "$h $t"; }

# ---- cgroup tracking: survivors that cleared their environment AND left the session are still in the run's cgroup.
# The run's scope directory is NOT assumed: the wrapper inside the scope records /proc/self/cgroup to a file, and
# gate_cg_resolve turns that into the real directory (an existing-but-wrong root can therefore not hide a survivor).
GATE_CG_MOUNT=${GATE_CG_MOUNT:-/sys/fs/cgroup}
# gate_cg_resolve <file> : prints the scope directory. Status 2 if the record is missing/odd or the mount is unusable.
gate_cg_resolve() {
  local line path
  [ -r "$GATE_CG_MOUNT/cgroup.controllers" ] || { echo "cg-error: $GATE_CG_MOUNT is not a cgroup v2 mount" >&2; return 2; }
  # the real cgroup2 ROOT has no cgroup.max; any sub-hierarchy (e.g. system.slice) does and would double the path
  [ ! -e "$GATE_CG_MOUNT/cgroup.max" ] || { echo "cg-error: $GATE_CG_MOUNT is a sub-cgroup, not the cgroup2 root" >&2; return 2; }
  line=$(grep -m1 '^0::' "$1" 2>/dev/null) || { echo "cg-error: no cgroup record in $1" >&2; return 2; }
  path=${line#0::}
  case "$path" in /*.scope) ;; *) echo "cg-error: unexpected cgroup path '$path'" >&2; return 2;; esac
  echo "$GATE_CG_MOUNT$path"
}
# gate_cg_pids <scope-dir> : pids in the scope AND every nested cgroup below it. A scope with no processes is
# removed by systemd, so a missing dir = none. Status 2 on any read error (fail closed).
gate_cg_pids() {
  local d=$1 f out files try pop
  [ -d "$d" ] || return 0
  for try in 1 2 3 4 5; do
    local lines="" vanished=0
    files=$(find "$d" -name cgroup.procs 2>&1); local frc=$?
    if [ $frc -ne 0 ]; then [ -d "$d" ] || return 0; vanished=1
    elif [ -z "$files" ]; then [ -d "$d" ] || return 0; vanished=1
    else
      while IFS= read -r f; do
        if out=$(cat "$f" 2>/dev/null); then [ -z "$out" ] || lines="$lines$out"$'\n'
        else vanished=1; fi   # a nested cgroup disappeared between find and read: the snapshot is unreliable
      done <<< "$files"
    fi
    if [ $vanished -eq 0 ]; then
      pop=$(sed -n 's/^populated //p' "$d/cgroup.events" 2>/dev/null) || pop=""
      if [ -d "$d" ] && [ "$pop" != 0 ] && [ "$pop" != 1 ]; then echo "cg-error: cannot read populated state of $d" >&2; return 2; fi
      # populated (recursive) says members exist but none were enumerated: a survivor moved during the scan. Count it.
      if [ "$pop" = 1 ] && [ -z "$lines" ]; then lines="unknown-populated"$'\n'; fi
      printf '%s' "$lines"; return 0
    fi
    sleep 0.1
  done
  echo "cg-error: cgroup tree under $d kept changing / unreadable during the scan" >&2; return 2
}
# gate_cg_kill <scope-dir> : SIGKILL every member recursively (cgroup.kill) and wait for the scope to vanish.
# Prints the number of processes that were in it just before the kill. Status 0 gone, 1 survives, 2 error.
gate_cg_kill() {
  local d=$1 i n
  [ -d "$d" ] || { echo 0; return 0; }
  local pl; pl=$(gate_cg_pids "$d"); local prc=$?
  n=$(printf '%s\n' "$pl" | grep -c . || true)
  echo "$n"
  [ $prc -eq 0 ] || { echo 1 > "$d/cgroup.kill" 2>/dev/null; return 2; }
  echo 1 > "$d/cgroup.kill" 2>/dev/null || { [ -d "$d" ] && return 2; return 0; }
  for i in $(seq 1 100); do [ -d "$d" ] || return 0; sleep 0.1; done
  [ -z "$(gate_cg_pids "$d" 2>/dev/null)" ] && return 0
  return 1
}

# ---- abort handling (P17-F3). An abort must leave NO process of the run alive, on every path:
#   * INT/TERM/HUP to the gate: the trap calls gate_abort_run;
#   * SIGKILL of the gate (no trap can run): a detached watchdog (own session, not in any run scope, not tagged)
#     notices the gate is gone and calls gate_abort_run.
# Never abort by process GROUP: `timeout` and cargo put children in new groups. gate_abort_run goes by cgroup
# (every scope of the run, recursively, immune to setsid and env clearing), by unit name (covers the window before the
# wrapper recorded its cgroup path) and finally by the env marker.
GATE_LIB_PATH=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/gate-lib.sh
# gate_abort_run <rundir> <runid> <unitbase> : kills the LAUNCHER of the current phase (pid + start time + run marker, by pidfd: a
# launcher that has not yet registered its scope must not be allowed to), then every scope of the run: <unitbase>{,-build,-list}.scope,
# every auxiliary scope the gate recorded in <rundir>/aux.units (git, cargo metadata), and every cgroup recorded in the *.path
# files; then every process still carrying the run marker; the whole kill sequence TWICE, 1 s apart (a scope that was still being
# registered when the abort started exists on the second pass). NO pid or session NUMBER is trusted anywhere: scopes are cgroup
# paths unique to this run, and the marker is a run id no other process can carry. Status 0 only if EVERYTHING is verifiably gone:
# an unresolvable record, a failed cgroup kill on the final pass, a scope cgroup still populated afterwards, a launcher that
# could not be signalled, or a marker sweep that could not finish all yield a non-zero status (never "cleaned up").
gate_abort_run() {
  local rd=$1 id=$2 ub=$3 f d u rc=0 m=${GATE_CG_MOUNT:-/sys/fs/cgroup} pop pass lpid lst units
  : > "$rd/abort.flag" 2>/dev/null || rc=2   # FIRST: no launcher that registers its scope later may start its command (see abort-lib bg)
  for pass in 1 2; do
    if [ -r "$rd/launcher.id" ]; then
      read -r lpid lst < "$rd/launcher.id" 2>/dev/null
      if [ -n "${lpid:-}" ]; then gate_kill_if_marked "$id" "$lpid" "$lst" KILL; [ $? -ne 2 ] || { [ $pass = 1 ] || rc=2; }; fi
    fi
    units="$ub $ub-build $ub-list"; [ ! -r "$rd/aux.units" ] || units="$units $(cat "$rd/aux.units" 2>/dev/null)"
    for u in $units; do systemctl kill --kill-whom=all --signal=SIGKILL "$u.scope" >/dev/null 2>&1; done
    for f in cgroup-build.path cgroup-list.path cgroup.path; do
      [ -e "$rd/$f" ] || continue
      d=$(gate_cg_resolve "$rd/$f") || { [ $pass = 1 ] || rc=2; continue; }
      gate_cg_kill "$d" >/dev/null || { [ $pass = 1 ] || rc=$?; }
    done
    gate_kill_marker "$id" "$ub" >/dev/null || { [ $pass = 1 ] || rc=$?; }
    [ $pass = 1 ] && sleep 1
  done
  for u in $units; do   # evidence: no scope cgroup of this run may still be populated
    d="$m/system.slice/$u.scope"; [ -e "$d" ] || continue
    pop=$(sed -n 's/^populated //p' "$d/cgroup.events" 2>/dev/null)
    [ "$pop" = 0 ] || rc=1
  done
  return $rc
}
# gate_pid_alive <pid> : true if the process exists and is not a zombie (a SIGKILLed gate stays a zombie until reaped).
gate_pid_alive() {
  local st; st=$(cat "${GATE_PROC_ROOT:-/proc}/$1/stat" 2>/dev/null) || return 1
  st=${st##*) }; case "$st" in Z*|X*) return 1;; esac; return 0
}
# gate_watchdog <gate-pid> <rundir> <runid> <unitbase> <gate-starttime> [interval] : runs until the gate finishes normally (stop
# file) or dies; in the latter case kills the run (gate_abort_run). Liveness is IDENTITY, not a bare pid: the gate is the process
# with this pid AND this start time (a recycled pid is a dead gate).
gate_watchdog() {
  local gp=$1 rd=$2 id=$3 ub=$4 gst=${5:-} iv=${6:-1} rc
  echo $$ > "$rd/watchdog.pid"
  while gate_pid_alive "$gp" && { [ -z "$gst" ] || [ "$(gate_pid_starttime "$gp")" = "$gst" ]; } && [ ! -e "$rd/.wd-stop" ]; do sleep "$iv"; done
  [ ! -e "$rd/.wd-stop" ] || return 0
  gate_abort_run "$rd" "$id" "$ub"; rc=$?
  if [ $rc -eq 0 ]; then
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) gate pid $gp vanished: run $id killed by watchdog" >> "$rd/watchdog.log"
  else
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) gate pid $gp vanished: run $id kill INCOMPLETE (status $rc), processes may survive" >> "$rd/watchdog.log"
  fi
}
# gate_wd_start <rundir> <gate-pid> <runid> <unitbase> : detached watchdog (own session, no lane-lock fd, no stdio).
gate_wd_start() {
  rm -f "$1/.wd-stop"
  setsid bash -c '. "$1"; shift; gate_watchdog "$@"' gate-wd "$GATE_LIB_PATH" "$2" "$1" "$3" "$4" "$(gate_pid_starttime "$2")" < /dev/null > /dev/null 2>&1 9>&- &
}
# gate_wd_stop <rundir> : the gate is finishing (any exit path); the watchdog must not kill anything afterwards.
# The watchdog polls this stop file (<= 1 s) and exits by itself. It is NEVER signalled by a saved pid: that pid could by then
# belong to an unrelated process (the watchdog may have died early and its pid been reused during a long gate).
gate_wd_stop() { : > "$1/.wd-stop" 2>/dev/null; return 0; }
# gate_survivor_report <outfile> <phase> <via> <pid>... : append one block per surviving process to <outfile>: pid, ppid,
# sid, state, start time (UTC), the run marker from its environment, cwd, exe, cgroup path and the FULL command line, so a
# GATE_ORPHANS verdict says WHICH process outlived its phase. Call it BEFORE killing. A pid that vanished or whose details
# cannot be read gets a block saying so (never silently dropped). Status 1 if <outfile> cannot be written (fail closed:
# the caller must then treat the orphan state as unknown). "unknown-populated" (a populated cgroup whose members could not
# be enumerated) is recorded as such.
gate_survivor_report() {
  local out=$1 phase=$2 via=$3 root=${GATE_PROC_ROOT:-/proc} p st rest F ppid state sid stt btime hz start cmd cwd exe cg marker; shift 3
  hz=$(getconf CLK_TCK 2>/dev/null || echo 100); btime=$(awk '/^btime /{print $2}' "$root/stat" 2>/dev/null)
  local tok want
  for tok in "$@"; do
    [ -n "$tok" ] || continue
    p=${tok%%@*}; want=""; case $tok in *@*) want=${tok#*@};; esac    # pid, or pid@starttime (identity captured when it was found)
    if [ "$p" = unknown-populated ]; then
      printf '== survivor phase=%s via=%s pid=unknown ==\ncmdline=(a populated cgroup whose members could not be enumerated)\n\n' "$phase" "$via" >> "$out" || return 1; continue
    fi
    if ! st=$(cat "$root/$p/stat" 2>/dev/null); then
      printf '== survivor phase=%s via=%s pid=%s ==\ncmdline=(vanished before it could be inspected)\n\n' "$phase" "$via" "$p" >> "$out" || return 1; continue
    fi
    rest=${st##*) }; read -ra F <<< "$rest"; state=${F[0]:-?}; ppid=${F[1]:-?}; sid=${F[3]:-?}; stt=${F[19]:-}
    if [ -n "$want" ] && [ "$stt" != "$want" ]; then   # the pid now belongs to ANOTHER process: never describe it as the survivor
      printf '== survivor phase=%s via=%s pid=%s ==\ncmdline=(exited before it could be inspected; its pid was reused by another process, which is NOT described here)\n\n' "$phase" "$via" "$p" >> "$out" || return 1; continue
    fi
    start=unknown; [ -n "$btime" ] && [ -n "$stt" ] && start=$(date -u -d "@$(( btime + stt / hz ))" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown)
    cmd=$(tr '\0' ' ' < "$root/$p/cmdline" 2>/dev/null); [ -n "$cmd" ] || cmd="(empty: zombie, kernel thread or unreadable)"
    cwd=$(readlink "$root/$p/cwd" 2>/dev/null) || cwd="(unreadable)"
    exe=$(readlink "$root/$p/exe" 2>/dev/null) || exe="(unreadable)"
    cg=$(tr '\n' ' ' < "$root/$p/cgroup" 2>/dev/null); [ -n "$cg" ] || cg="(unreadable)"
    marker=""; envtxt=$(tr '\0' '\n' < "$root/$p/environ" 2>/dev/null)   # whole stream consumed first (grep -m1 in a pipe would SIGPIPE tr)
    while IFS= read -r kv; do case $kv in FUIGO_GATE_RUN=*) marker=$kv; break;; esac; done <<< "$envtxt"
    [ -r "$root/$p/environ" ] || marker="(environ unreadable)"; [ -n "$marker" ] || marker="(none: environment cleared or not tagged)"
    {
      printf '== survivor phase=%s via=%s pid=%s ppid=%s ==\n' "$phase" "$via" "$p" "$ppid"
      printf 'state=%s sid=%s start=%s\nmarker=%s\ncwd=%s\nexe=%s\ncgroup=%s\ncmdline=%s\n\n' "$state" "$sid" "$start" "$marker" "$cwd" "$exe" "$cg" "$cmd"
    } >> "$out" || return 1
  done
  return 0
}
# gate_survivor_summary <file> : one line per survivor block: phase, via, pid, ppid and the (truncated) command line.
gate_survivor_summary() { awk '/^== survivor/{h=$0; sub(/^== survivor /,"",h); sub(/ ==$/,"",h)} /^cmdline=/{c=substr($0,9,200); print "  " h "  " c}' "$1"; }

# gate_cg_freeze <scope-dir> : freeze the scope (cgroup v2 cgroup.freeze) so that its membership cannot change while it is
# inspected; waits up to 2 s for `frozen 1`. Status 0 frozen, 1 not (no such file / timeout): callers fall back to rescanning.
# cgroup.kill (SIGKILL) still works on a frozen cgroup.
gate_cg_freeze() {
  local d=$1 i
  [ -w "$d/cgroup.freeze" ] || return 1
  echo 1 > "$d/cgroup.freeze" 2>/dev/null || return 1
  for i in $(seq 1 20); do grep -q '^frozen 1$' "$d/cgroup.events" 2>/dev/null && return 0; sleep 0.1; done
  return 1
}
# gate_pid_starttime <pid> : field 22 of /proc/<pid>/stat (clock ticks since boot): with the pid it identifies a process.
gate_pid_starttime() { local st rest F; st=$(cat "${GATE_PROC_ROOT:-/proc}/$1/stat" 2>/dev/null) || return 1; rest=${st##*) }; read -ra F <<< "$rest"; printf '%s' "${F[19]:-}"; }
# gate_kill_if_marked <runid> <pid> [<starttime>] [<signal>] : signal <pid> (default KILL) only if it STILL carries
# FUIGO_GATE_RUN=<runid> (and, if given, has that start time), through a pidfd (safe-kill.py). Status 0 signalled, 3 not
# signalled (gone / no longer matches / pid recycled), 2 error.
gate_kill_if_marked() { python3 "$ABORT_LIB_DIR/safe-kill.py" marker "$1" "$2" "${4:-KILL}" ${3:+"$3"}; }

# gate_reap_scope <cgroup-record-file> [<report-file> <phase>] : kill everything left in the scope whose cgroup path the
# wrapper recorded. With a report file, every process is recorded (gate_survivor_report) BEFORE it is killed: the scope is
# FROZEN first (membership cannot change during the report; if freezing is impossible a second scan after the report adds
# any pid that appeared, by IDENTITY, not by count), then killed; rounds repeat (max 4) until a round finds it empty.
# Prints the number of processes OBSERVED over all rounds (a survivor that exits while being reported still counts: it
# outlived its phase). Status 0 = scope resolved and gone, 1 = survives, 2 = record missing / unusable / scan or report error
# (FAILS CLOSED: an unknown scope is never read as "nothing left").
gate_reap_scope() {
  local d n rc=0 prc=0 pids pids2 new total=0 round k u p
  d=$(gate_cg_resolve "$1") || { echo 0; return 2; }
  if [ -z "${2:-}" ]; then n=$(gate_cg_kill "$d"); rc=$?; echo "$n"; return $rc; fi
  for round in 1 2 3 4; do
    gate_cg_freeze "$d" || true
    pids=$(gate_cg_pids "$d") || prc=2
    k=$(printf '%s\n' "$pids" | grep -c . || true); total=$((total + k))
    [ "$k" -gt 0 ] && { gate_survivor_report "$2" "${3:-?}" cgroup $pids || prc=2; }
    pids2=$(gate_cg_pids "$d") || prc=2    # identity re-scan (a no-op on a frozen scope)
    new=""; for p in $pids2; do case " $(echo $pids) " in *" $p "*) ;; *) new="$new $p";; esac; done
    if [ -n "$new" ]; then
      u=$(printf '%s\n' $new | grep -c . || true); total=$((total + u)); gate_survivor_report "$2" "${3:-?}" cgroup $new || prc=2
    fi
    n=$(gate_cg_kill "$d"); rc=$?
    if [ "$n" -gt $((k + ${u:-0})) ]; then   # the kill scan saw more than both report scans together: say so
      total=$((total + n - k - ${u:-0}))
      printf '== survivor phase=%s via=cgroup pid=unknown ==\ncmdline=(%d additional process(es) appeared between the report scan and the kill and were killed without details)\n\n' "${3:-?}" $((n - k - ${u:-0})) >> "$2" || prc=2
    fi
    u=0
    [ "$k" -gt 0 ] || [ "$n" -gt 0 ] || break
  done
  echo "$total"; [ $rc -ne 0 ] || rc=$prc; return $rc
}
# gate_reap_marker <runid> <unit-scope> <report-file> <phase> : like gate_reap_scope for processes found by the ENV MARKER
# (those that left the cgroup): record each, then SIGKILL it through gate_kill_if_marked (pid + start time + marker re-checked
# through a pidfd, so a recycled pid is never signalled), in rounds until a scan finds none. Prints the number observed.
# Status 0 = none left, 1 = some survive after 4 rounds, 2 = a scan failed or the report could not be written.
gate_reap_marker() {
  local id=$1 unit=$2 out=$3 phase=$4 pids rc=0 total=0 round k p st kvs=()
  for round in 1 2 3 4; do
    pids=$(gate_marker_pids "$id" "$unit") || return 2
    k=$(printf '%s\n' "$pids" | grep -c . || true)
    [ "$k" -gt 0 ] || { echo "$total"; return $rc; }
    total=$((total + k)); kvs=()
    for p in $pids; do kvs+=("$p:$(gate_pid_starttime "$p")"); done    # identity right at the scan
    gate_survivor_report "$out" "$phase" env-marker "${kvs[@]/:/@}" || rc=2
    for p in "${kvs[@]}"; do gate_kill_if_marked "$id" "${p%%:*}" "${p#*:}"; [ $? -ne 2 ] || rc=2; done
    sleep 1
  done
  pids=$(gate_marker_pids "$id" "$unit") || rc=2
  [ -z "$pids" ] || rc=1
  echo "$total"; return $rc
}

# gate_scopes_populated <rundir> <unitbase> : status 0 if ANY scope cgroup of the run (<unitbase>{,-build,-list} and the units in
# <rundir>/aux.units) still has processes, or its state cannot be read (fail closed); 1 if all are gone/empty.
gate_scopes_populated() {
  local rd=$1 ub=$2 m=${GATE_CG_MOUNT:-/sys/fs/cgroup} u d pop units
  units="$ub $ub-build $ub-list"
  # missing tracking infrastructure is NOT "all gone": an unusable cgroup mount or an unreadable aux.units fails closed (0)
  [ -r "$m/cgroup.controllers" ] || [ -e "$m/system.slice" ] || return 0
  if [ -e "$rd/aux.units" ]; then [ -r "$rd/aux.units" ] || return 0; units="$units $(cat "$rd/aux.units" 2>/dev/null)"; fi
  for u in $units; do
    d="$m/system.slice/$u.scope"; [ -e "$d" ] || continue
    pop=$(sed -n 's/^populated //p' "$d/cgroup.events" 2>/dev/null)
    [ "$pop" = 0 ] || return 0
  done
  return 1
}
