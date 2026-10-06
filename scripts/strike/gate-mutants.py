#!/usr/bin/env python3
"""gate-mutants.py -- mutation harness for scripts/strike (R049). One edit per mutant, each run through gate-selftest.sh, serially.

usage: gate-mutants.py --check <tree>                               verify that every mutant's pattern still applies; runs nothing
       setsid gate-mutants.py [--full] [--timeout S] --work <dir> --out <file> <tree> [Mxx ...]
       gate-mutants.py --cleanup-from <out>.nonces                  reap what an interrupted harness left

<tree> is a checkout root (scripts/strike/ and rust-toolchain.toml). Each mutant is a private copy of it in a directory the harness
creates itself, <work>/mut-<Mxx>-<nonce>/. Default mode sets GATE_SELFTEST_SKIP_E2E=1; --full also runs the real final-gate.sh cases.
M01 (the unmutated control) runs first AND last; both must pass with nothing left behind, otherwise the run is STOPPED / not valid.

Verdicts: SURVIVED (exit 0, no FAIL line, empty stderr, full summary line); KILLED (non-zero exit and the FIRST FAIL line is the
assertion recorded for that mutant in EXPECT); KILLED-OTHER (non-zero exit with a different first assertion: a kill that a human must
attribute, it may also be an environmental failure); everything else (stderr-only failure, no summary, timeout, no scope, unconfirmed
nonce, leak, exception) is not a result and STOPS the harness.

THREAT MODEL. The harness runs as root on a shared build host next to other packets' live rp.sh / rpb.sh / iso.sh / final-gate.sh
runs, containers and ssh sessions. Co-tenants are NOT adversaries: nobody forges this harness's nonce. What must be impossible is
that a bug, a name collision, a recycled pid, a stale file or a mutant makes the harness (or the code it mutates) signal or delete
something that the mutant run it started did not create. It is NOT a sandbox: the self-test and the scripts under test run as root
exactly as they do in a normal self-test run (including their own cgroup and systemctl kills of the scopes they create); the mutants
only change which of the run's OWN processes the scripts treat as theirs (below).

WHAT THE HARNESS ITSELF MAY TOUCH
  * Every mutant run gets a fresh 20-digit NONCE (os.urandom). Before anything is started the harness checks that NOTHING on the
    host carries it yet (no scope, no lane entry, no process); if something does, it stops WITHOUT touching it. Then the nonce is
    written to <out>.nonces (the receipt). The self-test receives it as GATE_SELFTEST_NONCE and appends it to its run identity
    (FUIGO_SELFTEST_ID, SELFTEST_TAG, SELFTEST_UID): it becomes the END of every tagged fixture process name
    (`sleep NNNN.<digits><nonce>`), part of every unit and lane name the run creates through SELFTEST_UID/SELFTEST_TAG, and part of
    the environment of every process that inherits it. A name "carries the nonce" only if the nonce is NOT followed by another
    digit; since the nonce is always the end of a digit run and has a fixed length, one run's nonce is never found in another run's name.
  * Processes: SIGKILL only through a pidfd, and only if, read AFTER the pidfd is open, the process has GATE_SELFTEST_NONCE=<nonce>
    or FUIGO_SELFTEST_ID=st-<pid>-<n>-<nonce> in its environment, or its whole command line is `sleep <digits>.<digits><nonce>` (the
    tagged env-cleared fixtures; untagged env-cleared ones such as `/bin/sleep 300` live in scopes that carry the nonce). Never the
    harness, an ancestor of the harness, or pid 1. The harness's own child is signalled only through the pidfd opened right after
    it was spawned (SIGCHLD is reset to its default first, so the child cannot be reaped behind the harness's back).
  * systemd scopes: cgroup.kill is written ONLY to /sys/fs/cgroup/system.slice/<name> where <name> starts with `fuigo-` or
    `gatedemo5-helper-`, ends with `.scope` and carries the nonce. The self-test runs in `fuigo-mut-<nonce>.scope`; a run whose
    child was never seen inside that scope is not a result.
  * The scopes of a real final-gate.sh run (named after the gate's run id, `fuigo-gate-<utc>-<pid>`, without the nonce) are NEVER
    killed as a cgroup: their members are killed one by one by the process rule above, and a scope that is still populated
    afterwards is reported as a leak. They are only READ, and only for run directories inside real (non-symlink) lane directories
    whose name carries the nonce.
  * Files: entries of /root/fuigo-builds named `selftest-*` that carry the nonce and are real files or directories (a symlink is
    left alone and reported), and the harness's own <work>/mut-* directory, created with an exclusive mkdir.
  There is no pkill/pgrep, no kill by session or process group, no name pattern without the nonce, no `systemctl kill` in this file.

WHAT THE MUTANTS MAY TOUCH. No mutant changes a path that is deleted or a cgroup that is killed. Five mutants touch the identity
check of a signal: M45 and M46 weaken it to "the target carries THIS mutant run's nonce in its environment" (checked after
pidfd_open), never to "any pid"; M44 and M49 drop the start-time comparison but keep the run-marker check through a pidfd; M83 makes
safe-kill.py look for the key under FUIGO_GATE_RUN instead of the variable it was asked for (still marker + pidfd). In all five the
target must carry a marker value that only processes started by this self-test run (or by a gate it started) have.

FAIL CLOSED. The harness stops (exit 3, nothing further is started) when: a control does not pass; something already carries a new
nonce; the self-test does not confirm the nonce; the scope cannot be confirmed; a run times out or fails only through stderr;
anything of a run is alive, cannot be inspected, or cannot be deleted after cleanup; any unexpected error. The directory of the
offending run is kept. It must be started as a session leader (`setsid`), so that `pkill -s $(cat <out>.sid)` aborts exactly the
harness and the self-test it is running; then `--cleanup-from <out>.nonces`.
"""
import errno, os, re, secrets, shutil, signal, stat, subprocess, sys, time

B = '/root/fuigo-builds'
CG = '/sys/fs/cgroup/system.slice'
S = 'scripts/strike/'
UNIT_PREFIXES = ('fuigo-', 'gatedemo5-helper-')
# First FAIL line (prefix) each mutant produced when it was last killed (R049); a different first assertion is KILLED-OTHER, to be attributed by hand.
EXPECT = {
    'M02': 'final-gate: guard runs before the hook refusal; INT/TERM/HUP tra',
    'M03': 'abort by unit name kills the scope that never recorded a cgroup ',
    'M04': 'abort via cgroup record only: build + run scopes killed, unrecor',
    'M05': 'gate_pid_alive: a zombie (reaped by nobody) is NOT alive',
    'M06': 'watchdog: after gate_wd_stop a dying gate does NOT trigger a kil',
    'M07': 'kill-retry: attempt 1 killed 3 then scan-errored, attempt 2 kill',
    'M08': 'iso-resolve: integration-test function -> --test <file>',
    'M09': 'metadata: src/main.rs of package ptyctl-cli -> --bin ptyctl (the',
    'M10': "iso-resolve: a doctest of ANOTHER package's library is not resol",
    'M11': "metadata: the requested package's own header (matching executabl",
    'M12': "iso-resolve: a doctest of ANOTHER package's library is not resol",
    'M13': "iso.sh refused by the lane lock leaves the active run's output i",
    'M14': 'iso.sh: with ISO_NAMES_NEWLINE=1 a newline-separated name list k',
    'M15': 'iso.sh log stems are unique across the WHOLE list (a::same b::sa',
    'M16': 'iso.sh log stems: two names sharing a basename get distinct full',
    'M17': '[abort-lib leader TERM] after TERM: no fixture sleep survives (i',
    'M18': "[abort-lib an EARLIER command's scope (not just the latest) is c",
    'M19': '[abort-lib leader INT (signal ignored on entry via & -- the shim',
    'M21': 'final-gate refuses self-test hook GATE_CG_MOUNT set in the envir',
    'M22': '[abort-lib leader INT (signal ignored on entry via & -- the shim',
    'M23': 'bg without systemd-run refuses to run the command (97), never ru',
    'M24': 'bg reports 98 when the scope cannot be emptied (the command itse',
    'M25': 'abort_kill_all returns 1 and names the surviving scope when it c',
    'M26': 'gate_reap_scope with no cgroup record fails closed (2)',
    'M27': 'final-gate: every cgroup-recording wrapper fails closed (exit 97',
    'M28': "final-gate: the build scope's reap status feeds the orphan verdi",
    'M29': '[gate TERM mid-build] gate exits 143 and says it aborted',
    'M30': 'doctest-trailing-unpaired-running-rejected',
    'M33': '[abort-lib NON-leader: SIGKILL of the SUPERVISOR (kill -9 $! of ',
    'M34': "metadata: Doc-tests <crate> shared by two packages' libraries is",
    'M35': 'metadata: a package-relative tests/x.rs that exists in TWO packa',
    'M36': "abort_scope_gone: systemd says 'inactive' but the cgroup is stil",
    'M37': 'gate_abort_run propagates a failing cgroup kill (non-zero) even ',
    'M38': 'gate_abort_run: a scope that is still populated after the kills ',
    'M39': 'watchdog logs the auxiliary-scope kill as a complete kill',
    'M40': 'heuristic (no metadata) REFUSES a renamed bin instead of guessin',
    'M41': 'heuristic: tests/smoke.rs whose executable is another [[test]] n',
    'M42': 'gate_reap_scope: survivors that exit while being reported are st',
    'M43': 'gate_reap_scope: A replaced by B between scans (equal counts): B',
    'M44': 'launcher.id with the right pid and marker but a WRONG start time',
    'M45': "launcher.id naming a process WITHOUT this run's marker: left alo",
    'M46': 'gate_reap_marker never kills a process that lacks the run marker',
    'M47': 'gate_reap_scope recorded the 3 sleeps (+ the wrapper shell) with',
    'M48': '[planted survivor] the gate COMPLETED and rejected the run (exit',
    'M49': 'launcher.id with the right pid and marker but a WRONG start time',
    'M50': 'launcher.id with pid, start time and marker all matching: killed',
    'M51': 'watchdog: SIGKILLed gate -> the auxiliary scope recorded in aux.',
    'M52': 'aux scope fixture: a bg command is running and its unit is recor',
    'M57': 'final-gate.sh runs git clone/fetch/checkout and cargo metadata t',
    'M58': 'final-gate.sh runs git clone/fetch/checkout and cargo metadata t',
    'M59': 'final-gate: the launcher id (pid + start time) is written for al',
    'M64': 'rp.sh and iso.sh run every git fetch / worktree add / checkout t',
    'M65': 'rp.sh and iso.sh run every git fetch / worktree add / checkout t',
    'M66': 'delayed launcher: abort during the launch delay -> cleaned (143)',
    'M67': 'delayed launcher: abort during the launch delay -> cleaned (143)',
    'M68': 'gate_abort_run raises <rundir>/abort.flag first (also when run b',
    'M69': 'final-gate: all three phase wrappers check the abort flag inside',
    'M70': 'abort_kill_all kills a scope that appeared AFTER the first pass ',
    'M71': 'gated-targets: lists gated test and test-enabled bin targets wit',
    'M72': 'gated-targets: lists gated test and test-enabled bin targets wit',
    'M73': 'rp.sh: feature-pass failures are tagged [+features] in the merge',
    'M74': 'derive.py: default counts the exe and the lib doc-test run (2); ',
    'M75': 'final-gate: feature-gated targets are listed in the header and i',
    'M76': 'gated-targets: targets whose required-features are enabled by de',
    'M77': 'rp.sh / final-gate.sh: a failed gated-target discovery is fatal ',
    'M78': "iso-resolve (metadata): a gated target's selector carries its re",
    'M79': 'safe-kill: signal names keep their letters (INT is INT, not NT)',
    'M80': 'rp.sh / iso.sh pin FUIGO_BINARY to the fresh build; the pager bu',
    'M81': 'rp.sh / iso.sh pin FUIGO_BINARY to the fresh build; the pager bu',
    'M82': 'rp.sh: a failed checkout (or HEAD != the requested revision) is ',
}
STDERR_FAIL = 'the self-test wrote to stderr'
NKILL = """import os, signal, sys
# written by gate-mutants.py for M46: SIGKILL argv[1] only if it carries THIS mutant run's nonce (checked after pidfd_open)
n = os.environ.get("GATE_SELFTEST_NONCE"); pid = int(sys.argv[1])
if not n: sys.exit(3)
try: fd = os.pidfd_open(pid)
except OSError: sys.exit(3)
try:
    env = open("/proc/%d/environ" % pid, "rb").read().split(b"\\0")
    if (b"GATE_SELFTEST_NONCE=" + n.encode()) in env: signal.pidfd_send_signal(fd, signal.SIGKILL)
except OSError: pass
finally: os.close(fd)
"""
M = [
 ('M01-control-unmutated', None, []),
 ('M02-no-watchdog', S + 'final-gate.sh', [('gate_wd_start "$RUNDIR" "$$" "$RUNID" "$UNITBASE"\n', '')]),
 ('M03-abort-no-unit-kill', S + 'gate-lib.sh', [('    for u in $units; do systemctl kill --kill-whom=all --signal=SIGKILL "$u.scope" >/dev/null 2>&1; done\n', '')]),
 ('M04-abort-no-cgroup-record', S + 'gate-lib.sh', [('      d=$(gate_cg_resolve "$rd/$f") || { [ $pass = 1 ] || rc=2; continue; }\n      gate_cg_kill "$d" >/dev/null || { [ $pass = 1 ] || rc=$?; }', '      :')]),
 ('M05-pid-alive-counts-zombies', S + 'gate-lib.sh', [('st=${st##*) }; case "$st" in Z*|X*) return 1;; esac; return 0', 'return 0')]),
 ('M06-watchdog-ignores-stop-file', S + 'gate-lib.sh', [('  [ ! -e "$rd/.wd-stop" ] || return 0\n', '')]),
 ('M07-kill-retry-last-attempt-only', S + 'gate-selftest.sh', [('KT=$((KT + n))', 'KT=$n')]),
 ('M08-resolver-integration-test-as-lib', S + 'iso-resolve.py', [("if m2: return '--test ' + m2.group(2)", "if m2: return '--lib'")]),
 ('M09-resolver-ignores-metadata', S + 'iso-resolve.py', [('if meta is not None else selector(', 'if False else selector(')]),
 ('M10-resolver-names-split-at-space', S + 'iso-resolve.py', [("k = ln.find('test ' + n + ' ... ')", "k = ln.find('test ' + n.split()[0] + ' ... ')")]),
 ('M11-resolver-no-exe-identity', S + 'iso-resolve.py', [("if es is not None and es != t['name'].replace('-', '_'): continue", "if False: continue")]),
 ('M12-resolver-doc-any-package', S + 'iso-resolve.py', [("return '--doc' if rest.replace('-', '_') == pkg.replace('-', '_') else None", "return '--doc'")]),
 ('M13-iso-truncates-before-lock', S + 'iso.sh', [('mkdir -p $L0; exec 7>"$L0/.lane.lock"; flock -n 7 || exit 3\n', ': > $OUT\nmkdir -p $L0; exec 7>"$L0/.lane.lock"; flock -n 7 || exit 3\n')]),
 ('M14-iso-no-newline-name-split', S + 'iso.sh', [('if [ "${ISO_NAMES_NEWLINE:-}" = 1 ]; then', 'if false; then')]),
 ('M15-iso-stems-not-unique', S + 'iso.sh', [('  while [ -n "${USED[$u]:-}" ]; do n=$((n+1)); u=$c-$n; done', '  :')]),
 ('M16-iso-short-stem-always', S + 'iso.sh', [('[ "${BASEN[$b]:-1}" -gt 1 ] && b=$NM', ':')]),
 ('M17-abortlib-units-not-recorded', S + 'abort-lib.sh', [('ABORT_UNITS+=("$ABORT_CURU")\n', '\n')]),
 ('M18-abortlib-no-reap-and-latest-scope-only', S + 'abort-lib.sh', [
     ('  systemctl kill --kill-whom=all --signal=SIGKILL "$ABORT_CURU.scope" >/dev/null 2>&1\n  if ! abort_scope_gone', '  if ! abort_scope_gone'),
     ('  for u in "${ABORT_UNITS[@]}"; do systemctl kill --kill-whom=all --signal=SIGKILL "$u.scope" >/dev/null 2>&1; done\n', '  systemctl kill --kill-whom=all --signal=SIGKILL "$ABORT_CURU.scope" >/dev/null 2>&1\n')]),
 ('M19-abortlib-no-sigint-shim', S + 'abort-lib.sh', [('ABORT_GUARDED=1 exec python3 -c "$ABORT_PYSHIM" bash "$self" "$@"', 'ABORT_GUARDED=1 exec bash "$self" "$@"')]),
 ('M20-supervisor-handlers-after-spawn', S + 'abort-lib.sh', [
     ('for s in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP): signal.signal(s, fwd)\nsup = os.getpid()', 'sup = os.getpid()'),
     ('st["p"] = p\n', 'st["p"] = p\nfor s in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP): signal.signal(s, fwd)\n')]),
 ('M21-supervisor-exit-status-lost', S + 'abort-lib.sh', [('sys.exit(rc if rc >= 0 else 128 - rc)', 'sys.exit(0)')]),
 ('M22-guard-is-noop', S + 'abort-lib.sh', [('  if [ "${ABORT_GUARDED:-}" = 1 ]; then unset ABORT_GUARDED; return 0; fi', '  return 0')]),
 ('M23-bg-runs-uncontained-without-systemd', S + 'abort-lib.sh', [('  command -v systemd-run >/dev/null || { echo "abort-lib: systemd-run is required (cannot contain the command); refusing to run it" >&2; return 97; }\n', '')]),
 ('M24-bg-does-not-verify-scope-empty', S + 'abort-lib.sh', [('  if ! abort_scope_gone "$ABORT_CURU"; then', '  if false; then')]),
 ('M25-abort-kill-all-does-not-verify', S + 'abort-lib.sh', [('  for u in "${ABORT_UNITS[@]}"; do abort_scope_gone "$u" || ABORT_SURVIVORS="$ABORT_SURVIVORS $u"; done\n', '')]),
 ('M26-reap-scope-fails-open', S + 'gate-lib.sh', [('d=$(gate_cg_resolve "$1") || { echo 0; return 2; }', 'd=$(gate_cg_resolve "$1") || { echo 0; return 0; }')]),
 ('M27-wrapper-not-fail-closed', S + 'final-gate.sh', [('cat /proc/self/cgroup > "$1" || exit 97', 'cat /proc/self/cgroup > "$1"')]),
 ('M28-build-reap-status-not-wired', S + 'final-gate.sh', [('[ "${BKRC:-0}" -ne 0 ] && CKRC=2;', '')]),
 ('M29-gate-trap-without-cleanup', S + 'final-gate.sh', [("trap '' INT TERM HUP; cleanup_run; local rc=$?", "trap '' INT TERM HUP; local rc=0")]),
 ('M30-doc-trailing-running-check-removed(R029 fin pend<0)', S + 'gate-verify.sh', [('pairs<=2 && pend<0 && !dbad', 'pairs<=2 && !dbad')]),
 ('M31-doc-result-without-running-pend<0-branch(R029, equivalent mutant)', S + 'gate-verify.sh', [('if(pend<0) dbad=1; else { if($4+$6+$8+$10 != pend) dbad=1; pairs++; pend=-1 }', 'if($4+$6+$8+$10 != pend) dbad=1; pairs++; pend=-1')]),
 ('M32-supervisor-child-keeps-forwarding-handlers', S + 'abort-lib.sh', [('    for s in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP): signal.signal(s, signal.SIG_DFL)\n    import ctypes', '    import ctypes')]),
 ('M33-no-parent-death-signal', S + 'abort-lib.sh', [('    ctypes.CDLL(None, use_errno=True).prctl(1, int(signal.SIGTERM), 0, 0, 0)   # PR_SET_PDEATHSIG\n', '')]),
 ('M34-resolver-doc-owned-by-any-package', S + 'iso-resolve.py', [('        return \'--doc\' if owners == {pkg} else None', '        return \'--doc\' if pkg in owners else None')]),
 ('M35-resolver-cross-package-ambiguity-allowed', S + 'iso-resolve.py', [('    if set(found) != {pkg} or len(found[pkg]) != 1: return None', '    if pkg not in found or len(found[pkg]) != 1: return None')]),
 ('M36-scope-gone-reads-systemd-state', S + 'abort-lib.sh', [('    [ -e "$d" ] || return 0\n    pop=$(sed -n \'s/^populated //p\' "$d/cgroup.events" 2>/dev/null)\n    [ "$pop" = 0 ] && return 0\n', '    [ "$(systemctl is-active "$1.scope" 2>/dev/null)" = active ] || return 0\n')]),
 ('M37-gate-abort-ignores-cgroup-kill-status', S + 'gate-lib.sh', [('      gate_cg_kill "$d" >/dev/null || { [ $pass = 1 ] || rc=$?; }', '      gate_cg_kill "$d" >/dev/null')]),
 ('M38-gate-abort-no-populated-check', S + 'gate-lib.sh', [('    [ "$pop" = 0 ] || rc=1', '    :')]),
 ('M39-iso-auto-guesses-without-metadata', S + 'iso.sh', [('UNRESOLVED (no cargo metadata; not run)', 'UNRESOLVED (no cargo metadata; run anyway)')]),
 ('M40-heuristic-bin-exe-not-validated', S + 'iso-resolve.py', [("return '--bin ' + pkg if es is None or es == pkg.replace('-', '_') else None", "return '--bin ' + pkg")]),
 ('M41-heuristic-test-exe-not-validated', S + 'iso-resolve.py', [("if m2: return '--test ' + m2.group(2) if exe_stem(exe) is None or exe_stem(exe) == m2.group(2).replace('-', '_') else None", "if m2: return '--test ' + m2.group(2)")]),
 ('M42-reap-scope-count-from-kill-only', S + 'gate-lib.sh', [('    k=$(printf \'%s\\n\' "$pids" | grep -c . || true); total=$((total + k))\n    [ "$k" -gt 0 ] && { gate_survivor_report', '    k=$(printf \'%s\\n\' "$pids" | grep -c . || true)\n    [ "$k" -gt 0 ] && { gate_survivor_report'), ('    n=$(gate_cg_kill "$d"); rc=$?\n    if [ "$n" -gt $((k + ${u:-0})) ]', '    n=$(gate_cg_kill "$d"); rc=$?; total=$((total + n))\n    if [ "$n" -gt $((k + ${u:-0})) ]')]),
 ('M43-reap-scope-no-identity-rescan', S + 'gate-lib.sh', [('    pids2=$(gate_cg_pids "$d") || prc=2    # identity re-scan (a no-op on a frozen scope)', '    pids2=$pids')]),
 ('M44-safekill-ignores-starttime', S + 'safe-kill.py', [('            if st is not None and fields[19] != st: return 3', '            pass')]),
 ('M45-safekill-marker-weakened-to-any-process-of-this-mutant-run', S + 'safe-kill.py', [('            if (os.environ.get("SAFE_KILL_VAR", "FUIGO_GATE_RUN").encode() + b"=" + key.encode()) not in env: return 3', '            if "GATE_SELFTEST_NONCE" not in os.environ or (b"GATE_SELFTEST_NONCE=" + os.environ["GATE_SELFTEST_NONCE"].encode()) not in env: return 3')]),
 ('M46-reap-marker-no-marker-or-starttime-recheck-bounded-to-this-mutant-run', S + 'gate-lib.sh', [('    for p in "${kvs[@]}"; do gate_kill_if_marked "$id" "${p%%:*}" "${p#*:}"; [ $? -ne 2 ] || rc=2; done', '    for p in "${kvs[@]}"; do python3 "$GATE_MUT_NKILL" "${p%%:*}"; done')]),
 ('M47-survivors-not-recorded-before-kill', S + 'gate-lib.sh', [('    [ "$k" -gt 0 ] && { gate_survivor_report "$2" "${3:-?}" cgroup $pids || prc=2; }\n', '')]),
 ('M48-marker-read-via-grep-pipe', S + 'gate-lib.sh', [('    marker=""; envtxt=$(tr \'\\0\' \'\\n\' < "$root/$p/environ" 2>/dev/null)   # whole stream consumed first (grep -m1 in a pipe would SIGPIPE tr)\n    while IFS= read -r kv; do case $kv in FUIGO_GATE_RUN=*) marker=$kv; break;; esac; done <<< "$envtxt"', '    marker=$(tr \'\\0\' \'\\n\' < "$root/$p/environ" 2>/dev/null | grep -m1 \'^FUIGO_GATE_RUN=\') || marker=""')]),
 ('M49-abort-run-launcher-without-starttime', S + 'gate-lib.sh', [('gate_kill_if_marked "$id" "$lpid" "$lst" KILL', 'gate_kill_if_marked "$id" "$lpid" "" KILL')]),
 ('M50-abort-run-no-launcher-kill', S + 'gate-lib.sh', [('      if [ -n "${lpid:-}" ]; then gate_kill_if_marked "$id" "$lpid" "$lst" KILL; [ $? -ne 2 ] || { [ $pass = 1 ] || rc=2; }; fi', '      :')]),
 ('M51-abort-run-ignores-aux-units', S + 'gate-lib.sh', [('    units="$ub $ub-build $ub-list"; [ ! -r "$rd/aux.units" ] || units="$units $(cat "$rd/aux.units" 2>/dev/null)"', '    units="$ub $ub-build $ub-list"')]),
 ('M52-bg-does-not-record-aux-units', S + 'abort-lib.sh', [('    echo "$ABORT_CURU" >> "$ABORT_UNITS_FILE" ||', '    : ||')]),
 ('M57-gate-git-foreground', S + 'final-gate.sh', [('FUIGO_GATE_RUN=$RUNID bg git fetch --quiet --all', 'git fetch --quiet --all')]),
 ('M58-gate-members-not-scoped', S + 'final-gate.sh', [('FUIGO_GATE_RUN=$RUNID bg cargo metadata', 'cargo metadata')]),
 ('M59-launcher-id-not-written', S + 'final-gate.sh', [('SID=$!; echo "$SID $(gate_pid_starttime "$SID")" > "$RUNDIR/launcher.id"\nwait "$SID"; RC=$?', 'SID=$!\nwait "$SID"; RC=$?')]),
 ('M64-rp-git-foreground', S + 'rp.sh', [('bg git -C $R fetch -qf $BUNDLE', 'git -C $R fetch -qf $BUNDLE')]),
 ('M65-iso-git-foreground', S + 'iso.sh', [('  bg git -C $R worktree add', '  git -C $R worktree add')]),
 ('M66-bg-no-abort-flag-check', S + 'abort-lib.sh', [('sh -c \'[ ! -e "$1" ] || exit 96; shift; exec "$@"\' abort-flag', 'sh -c \'shift; exec "$@"\' abort-flag')]),
 ('M67-kill-all-does-not-raise-flag', S + 'abort-lib.sh', [('  if [ -n "${ABORT_FLAG:-}" ]; then : > "$ABORT_FLAG" 2>/dev/null || ABORT_SURVIVORS="$ABORT_SURVIVORS (abort flag $ABORT_FLAG could not be written)"; fi\n', '')]),
 ('M68-gate-abort-run-no-flag', S + 'gate-lib.sh', [('  : > "$rd/abort.flag" 2>/dev/null || rc=2   # FIRST', '  rc=$rc   # FIRST')]),
 ('M69-gate-phase-wrapper-no-flag-check', S + 'final-gate.sh', [('[ ! -e "$2" ] || exit 96; shift 2; exec "$@"\' gate-cg "$RUNDIR/cgroup.path"', 'shift 2; exec "$@"\' gate-cg "$RUNDIR/cgroup.path"')]),
 ('M70-abortlib-kill-all-one-pass', S + 'abort-lib.sh', [('  for pass in 1 2; do\n    for u in "${ABORT_UNITS[@]}"; do systemctl kill --kill-whom=all --signal=SIGKILL "$u.scope" >/dev/null 2>&1; done\n    [ $pass = 1 ] && sleep 1\n  done', '  for u in "${ABORT_UNITS[@]}"; do systemctl kill --kill-whom=all --signal=SIGKILL "$u.scope" >/dev/null 2>&1; done')]),
 ('M71-gated-targets-includes-ungated', S + 'gated-targets.py', [('        if not rf or all(r in on for r in rf): continue\n', '')]),
 ('M72-gated-targets-no-bin-test-flag', S + 'gated-targets.py', [('elif "bin" in kinds and t.get("test", True): flag = "--bin"', 'elif "bin" in kinds: flag = "--bin"')]),
 ('M73-rp-second-pass-merge-dropped', S + 'rp.sh', [('{ cat $B/$LANE-$LABEL-$P.failset; sed "s/^/[+features] /" $B/$LANE-$LABEL-$P-features.failset; } | sort -u', 'cat $B/$LANE-$LABEL-$P.failset | sort -u')]),
 ('M74-derive-nodoc-ignored', S + 'derive.py', [('if not nodoc and set(', 'if set(')]),
 ('M75-final-gate-silent-about-gated', S + 'final-gate.sh', [('  [ "${NGATED:-0}" -le 0 ] || echo "feature-gated:  $NGATED test target(s) NOT run by this gate (required-features): $(grep -v \'^#\' "$GATEDF" | awk \'{printf "%s/%s [%s]; ", $1, $3, $4}\')"\n', '')]),
 ('M76-gated-default-features-not-excluded', S + 'gated-targets.py', [('if not rf or all(r in on for r in rf): continue', 'if not rf: continue')]),
 ('M77-rp-discovery-failure-ignored', S + 'rp.sh', [('FEATURE-GATED DISCOVERY FAILED for $P (cargo metadata/gated-targets.py): run is INVALID"; abort_kill_all', 'x"; true')]),
 ('M78-iso-gated-features-dropped', S + 'iso-resolve.py', [("            if sel and rf: sel += ' --features '", "            if False: sel += ' --features '")]),
 ('M79-safekill-lstrip', S + 'safe-kill.py', [('argv[4].upper() if argv[4].upper().startswith("SIG") else "SIG" + argv[4].upper()', '"SIG" + argv[4].upper().lstrip("SIG")')]),
 ('M80-rp-no-binbuild', S + 'rp.sh', [('[ $BC = 0 ] || { say BINBUILD_FAIL; abort_kill_all', '[ true ] || { say BINBUILD_FAIL; abort_kill_all'), ('bg nice -n 10 cargo build --locked $PAGERFEAT -p fuigo-pager-bin --bin fuigo-pager', 'bg true; BCX=1; true')]),
 ('M81-rp-no-fuigo-binary-pin', S + 'rp.sh', [('  export FUIGO_BINARY=$CARGO_TARGET_DIR/debug/fuigo-pager;', '  :')]),
 ('M82-rp-checkout-unchecked', S + 'rp.sh', [('[ $GC -eq 0 ] && [ "$(git rev-parse HEAD)" = "$(git rev-parse $REF)" ] ||', 'true ||')]),
 ('M83-safekill-ignores-SAFE_KILL_VAR', S + 'safe-kill.py', [('os.environ.get("SAFE_KILL_VAR", "FUIGO_GATE_RUN").encode()', 'b"FUIGO_GATE_RUN"')]),
]


# ---------------------------------------------------------------- identity ----------------------------------------------------------------
class Unknown(Exception):
    """Something could not be inspected: the state of the run is unknown (never treated as 'clean')."""

def new_nonce():
    return ''.join(str(secrets.randbelow(10)) for _ in range(20))

def valid_nonce(n):
    return isinstance(n, str) and re.fullmatch(r'[0-9]{20}', n) is not None

def carries(name, nonce):
    """The nonce occurs in name and is not followed by a digit (it always ends a digit run, so no other run's name can contain it)."""
    return re.search(re.escape(nonce) + r'(?![0-9])', name) is not None

def proc_read(pid, what):
    """Bytes of /proc/<pid>/<what>; None if the process is gone; Unknown if it exists but cannot be read."""
    try:
        with open('/proc/%d/%s' % (pid, what), 'rb') as f: return f.read()
    except (FileNotFoundError, ProcessLookupError):
        return None
    except OSError as e:
        if e.errno in (errno.ESRCH, errno.ENOENT): return None
        raise Unknown('cannot read /proc/%d/%s: %s' % (pid, what, e))

def is_mine(pid, nonce):
    nb = nonce.encode()
    env = proc_read(pid, 'environ')
    if env:
        for e in env.split(b'\0'):
            if e == b'GATE_SELFTEST_NONCE=' + nb: return True
            if re.fullmatch(rb'FUIGO_SELFTEST_ID=st-[0-9]+-[0-9]+-' + nb, e): return True
    cmd = proc_read(pid, 'cmdline')
    if cmd:
        argv = cmd.split(b'\0')
        if argv and argv[-1] == b'': argv = argv[:-1]
        if len(argv) == 2 and argv[0] == b'sleep' and re.fullmatch(rb'[0-9]+\.[0-9]*' + nb, argv[1]): return True
    return False

def protected_pids():
    """The harness, every ancestor of it, and pid 1: never signalled, whatever their environment says."""
    out = {1, os.getpid()}; p = os.getpid()
    for _ in range(64):
        sta = proc_read(p, 'stat')
        if not sta: break
        pp = int(sta.rsplit(b') ', 1)[-1].split()[1])
        if pp <= 1: break
        out.add(pp); p = pp
    return out

def my_pids(nonce):
    try: names = os.listdir('/proc')
    except OSError as e: raise Unknown('cannot list /proc: %s' % e)
    prot = protected_pids()
    return [p for p in (int(n) for n in names if n.isdigit()) if p not in prot and is_mine(p, nonce)]

def kill_pid(pid, nonce):
    """SIGKILL through a pidfd. The identity is checked AFTER the pidfd is open: a pid recycled before the open fails the check, one
    recycled after it leaves the pidfd on the dead process (ESRCH)."""
    if pid in protected_pids(): return
    try: fd = os.pidfd_open(pid)
    except OSError: return
    try:
        if is_mine(pid, nonce):
            try: signal.pidfd_send_signal(fd, signal.SIGKILL)
            except ProcessLookupError: pass
    finally:
        os.close(fd)

def unit_ok(name, nonce):
    return name.endswith('.scope') and '/' not in name and name.startswith(UNIT_PREFIXES) and carries(name, nonce)

def named_units(nonce):
    try: names = os.listdir(CG)
    except OSError as e: raise Unknown('cannot list %s: %s' % (CG, e))
    return sorted(n for n in names if unit_ok(n, nonce))

def populated(name):
    """Hierarchical 'populated' of a scope under system.slice (False if the cgroup is gone)."""
    try:
        with open(os.path.join(CG, name, 'cgroup.events'), 'rb') as f: ev = f.read()
    except FileNotFoundError:
        return False
    except OSError as e:
        if e.errno == errno.ENODEV: return False      # removed while being read
        raise Unknown('cannot read cgroup.events of %s: %s' % (name, e))
    m = re.search(rb'^populated ([01])$', ev, re.M)
    if not m: raise Unknown('no populated line in cgroup.events of %s' % name)
    return m.group(1) == b'1'

def kill_unit(name, nonce):
    """cgroup.kill of one scope whose NAME carries the nonce (asserted again here)."""
    if not unit_ok(name, nonce): raise Unknown('refusing to kill %r: not a unit of run %s' % (name, nonce))
    try:
        with open(os.path.join(CG, name, 'cgroup.kill'), 'w') as f: f.write('1')
    except FileNotFoundError:
        return
    except OSError as e:
        if e.errno == errno.ENODEV: return
        raise Unknown('cannot write cgroup.kill of %s: %s' % (name, e))

def real_dir(p):
    """True for a real directory, False if absent or not a directory (incl. a symlink); Unknown if it cannot be inspected."""
    try: st = os.lstat(p)
    except FileNotFoundError: return False
    except OSError as e: raise Unknown('cannot lstat %s: %s' % (p, e))
    return stat.S_ISDIR(st.st_mode)

def my_lanes(nonce):
    try: names = os.listdir(B)
    except OSError as e: raise Unknown('cannot list %s: %s' % (B, e))
    return sorted(n for n in names if n.startswith('selftest-') and '/' not in n and carries(n, nonce))

def gate_scopes(nonce):
    """READ-ONLY: scopes of real final-gate.sh runs started by this mutant run (run dirs inside real lane dirs that carry the nonce)."""
    out = set()
    for lane in my_lanes(nonce):
        ld = os.path.join(B, lane); rd = os.path.join(ld, 'runs')
        if not real_dir(ld) or not real_dir(rd): continue
        try: rids = os.listdir(rd)
        except OSError as e: raise Unknown('cannot list %s: %s' % (rd, e))
        for rid in rids:
            if not real_dir(os.path.join(rd, rid)): continue
            ub = 'fuigo-gate-' + re.sub(r'[^A-Za-z0-9]', '-', rid)
            for sfx in ('', '-build', '-list'): out.add(ub + sfx + '.scope')
    return sorted(out)

def preexisting(nonce):
    """What already carries this nonce (must be nothing before a run starts). Raises Unknown if the host cannot be inspected."""
    found = ['scope:' + u for u in named_units(nonce)] + ['lane:' + l for l in my_lanes(nonce)] + ['pid:%d' % p for p in my_pids(nonce)]
    try: os.lstat(os.path.join(CG, 'fuigo-mut-%s.scope' % nonce)); found.append('own-scope-name')
    except FileNotFoundError: pass
    except OSError as e: raise Unknown('cannot inspect the own scope name: %s' % e)
    return found

def cleanup(nonce):
    """Reap everything of the run with this nonce. Returns (leak_count, description); a state that cannot be inspected is a leak."""
    if not valid_nonce(nonce): return 1, 'not a nonce'
    try:
        for attempt in range(6):
            for u in named_units(nonce): kill_unit(u, nonce)
            for p in my_pids(nonce): kill_pid(p, nonce)
            time.sleep(1.5)
            if not my_pids(nonce) and not [u for u in named_units(nonce) + gate_scopes(nonce) if populated(u)]: break
        left_u = [u for u in named_units(nonce) + gate_scopes(nonce) if populated(u)]
        left_p = my_pids(nonce)
        desc = []
        if left_u: desc.append('populated-scopes:' + ','.join(left_u))
        if left_p: desc.append('pids:' + ','.join(map(str, left_p)))
        n = len(left_u) + len(left_p)
        if n == 0:                                 # lane files only once nothing of the run is alive (a leak keeps its evidence)
            for lane in my_lanes(nonce):
                p = os.path.join(B, lane)
                if os.path.islink(p): n += 1; desc.append('symlink-left-alone:' + lane); continue
                if real_dir(p): shutil.rmtree(p, ignore_errors=True)
                else:
                    try: os.unlink(p)
                    except OSError: pass
                try: os.lstat(p); n += 1; desc.append('not-removed:' + lane)
                except FileNotFoundError: pass
        return n, ' '.join(desc)
    except (Unknown, OSError) as e:
        return 1, 'UNKNOWN(%s)' % e

# ---------------------------------------------------------------- mutants -----------------------------------------------------------------
def apply(tree, f, edits):
    if f is None: return None
    p = os.path.join(tree, f)
    s = open(p).read()
    for old, new in edits:
        if old not in s: return 'pattern not found in %s: %r' % (f, old[:70])
        s = s.replace(old, new)
    open(p, 'w').write(s)
    return None

def check(tree, quiet=False):
    bad = 0
    for name, f, edits in M:
        if f is None:
            if not quiet: print('ok       %s (control)' % name)
            continue
        s = open(os.path.join(tree, f)).read()
        miss = [old[:70] for old, new in edits if old not in s]
        if miss: bad += 1; print('MISSING  %s: %r' % (name, miss))
        elif not quiet: print('ok       %s (%s)' % (name, ' '.join(str(s.count(old)) for old, new in edits)))
    print('%d mutants, %d with a missing pattern' % (len(M), bad))
    return 2 if bad else 0

STOP = []           # non-empty = stop; holds the reason(s)

def log(outf, line):
    with open(outf, 'a') as o: o.write(line + '\n')

def in_own_scope(pid, unit):
    cg = proc_read(pid, 'cgroup')
    return cg is not None and cg.strip() == ('0::/system.slice/%s.scope' % unit).encode()

def child_kill(cfd):
    """SIGKILL our own child through the pidfd opened right after it was spawned (never by pid number)."""
    try: signal.pidfd_send_signal(cfd, signal.SIGKILL)
    except ProcessLookupError: pass

def run_one(tree, work, outf, full, tmo, name, f, edits, label=None):
    """Run one mutant. Returns the verdict. Anything that is not a result appends to STOP."""
    label = label or name
    short = name.split('-')[0]
    nonce = new_nonce()
    try: pre_ex = preexisting(nonce)
    except (Unknown, OSError) as e: pre_ex = ['UNKNOWN(%s)' % e]
    if pre_ex:                                             # a collision, or an uninspectable host: touch NOTHING
        log(outf, '%s | PREEXISTING %s | nothing was started, nothing was cleaned' % (label, ' '.join(pre_ex)))
        STOP.append('%s: nonce already in use or host not inspectable' % label); return 'PREEXISTING'
    d = os.path.join(work, 'mut-%s-%s' % (short, nonce))
    os.mkdir(d)                                           # exclusive: the directory is ours
    t = os.path.join(d, 'tree'); os.mkdir(os.path.join(d, 'tmp'))
    shutil.copytree(os.path.join(tree, 'scripts'), os.path.join(t, 'scripts'))
    shutil.copy(os.path.join(tree, 'rust-toolchain.toml'), t)
    with open(os.path.join(d, 'nkill.py'), 'w') as o: o.write(NKILL)
    e = apply(t, f, edits)
    if e:
        log(outf, '%s | ERROR %s' % (label, e)); shutil.rmtree(d, ignore_errors=True); STOP.append('%s: %s' % (label, e)); return 'ERROR'
    env = {k: os.environ[k] for k in ('PATH', 'HOME') if k in os.environ}          # nothing else is inherited
    env.update(GATE_SELFTEST_NONCE=nonce, GATE_SELFTEST_FAILFAST='1', TMPDIR=os.path.join(d, 'tmp'), GATE_MUT_NKILL=os.path.join(d, 'nkill.py'))
    if not full: env['GATE_SELFTEST_SKIP_E2E'] = '1'
    tag = short if label == name else short + '-' + re.sub(r'[^a-z]', '', label.rsplit('(', 1)[-1])     # M01-opening / M01-closing
    pre, err = os.path.join(work, 'mut-%s.out' % tag), os.path.join(work, 'mut-%s.err' % tag)
    unit = 'fuigo-mut-%s' % nonce
    if STOP:                                                # a stop that arrived while preparing: start nothing
        shutil.rmtree(d, ignore_errors=True); return 'NOT-STARTED'
    log(outf + '.nonces', nonce)                          # the receipt, BEFORE anything is started
    t0 = time.monotonic(); how = None; rc = None; scoped = False; cfd = None; left, desc = 1, 'cleanup did not run'
    try:
        with open(pre, 'w') as o, open(err, 'w') as er:
            p = subprocess.Popen(['systemd-run', '--scope', '--quiet', '--collect', '--slice=system.slice', '--unit=' + unit, '--',
                                  'bash', os.path.join(t, S + 'gate-selftest.sh'), B], stdin=subprocess.DEVNULL, stdout=o, stderr=er, cwd=t, env=env)
            cfd = os.pidfd_open(p.pid)                     # our child, not yet waited for (SIGCHLD is SIG_DFL): this pid IS the child
            try:
                while rc is None:
                    try: rc = p.wait(timeout=0.05 if not scoped else 1)
                    except subprocess.TimeoutExpired: pass
                    if rc is not None: break
                    if not scoped:
                        scoped = in_own_scope(p.pid, unit)
                        if not scoped and time.monotonic() - t0 > 30: how = 'NOSCOPE'
                    if time.monotonic() - t0 > tmo: how = 'TIMEOUT'
                    if STOP: how = how or 'INTERRUPTED'
                    if how:
                        if scoped: kill_unit(unit + '.scope', nonce)
                        child_kill(cfd)
                        try: rc = p.wait(timeout=60)
                        except subprocess.TimeoutExpired: how += '+CHILD-NOT-REAPED'; break
            finally:
                if p.returncode is None: child_kill(cfd)
    except BaseException as ex:                               # incl. Unknown, KeyboardInterrupt
        how = how or 'EXCEPTION(%s: %s)' % (type(ex).__name__, ex)
    finally:
        if cfd is not None: os.close(cfd)
        left, desc = cleanup(nonce)                        # nothing carried this nonce before the launch: whatever carries it now is this run's
    out = open(pre, errors='replace').read() if os.path.exists(pre) else ''
    errsz = os.path.getsize(err) if os.path.exists(err) else -1
    confirmed = re.search(r'^NOTE  mutant-harness run, identity u[0-9]*%s ' % nonce, out, re.M) is not None
    summ = re.findall(r'^selftest: .*$', out, re.M)
    fails = re.findall(r'^FAIL\s+(.*)$', out, re.M)
    if how: verdict = how
    elif not scoped: verdict = 'NOSCOPE(child never seen in its scope)'
    elif not confirmed: verdict = 'INVALID(self-test did not confirm the nonce)'
    elif not summ: verdict = 'UNCLEAR(no summary line)'
    elif rc == 0 and not fails and errsz == 0 and re.match(r'selftest: [0-9]+ passed, 0 failed ', summ[-1]): verdict = 'SURVIVED'
    elif rc != 0 and fails and not fails[0].startswith(STDERR_FAIL):
        verdict = 'KILLED' if short in EXPECT and fails[0].startswith(EXPECT[short]) else 'KILLED-OTHER'
    else: verdict = 'UNCLEAR'
    keep = bool(left) or verdict not in ('SURVIVED', 'KILLED', 'KILLED-OTHER')
    if not keep:
        shutil.rmtree(d, ignore_errors=True)
        try: os.lstat(d); gone = False
        except FileNotFoundError: gone = True
        except OSError: gone = False                       # cannot be inspected: not known to be gone
        if not gone: keep = True; left += 1; desc = (desc + ' not-removed-or-uninspectable:' + d).strip()
    log(outf, '%s | %s | exit=%s | %s | %ds | stderr=%dB leaked_after_cleanup=%d %s| %s' % (
        label, verdict, rc, summ[-1] if summ else 'NO SUMMARY', time.monotonic() - t0, errsz, left, desc + ' ' if desc else '',
        ' || '.join(x[:160] for x in fails[:6]) or 'NO FAIL LINE'))
    if keep: STOP.append('%s: %s leaked=%d %s' % (label, verdict, left, desc))     # the run's directory is kept as evidence
    return verdict

def main(argv):
    if '--check' in argv:
        return check(argv[argv.index('--check') + 1])
    if '--cleanup-from' in argv:
        rc = 0
        for n in open(argv[argv.index('--cleanup-from') + 1]).read().split():
            left, desc = cleanup(n); print('%s leaked_after_cleanup=%d %s' % (n, left, desc)); rc = rc or (3 if left else 0)
        return rc
    full = False; tmo = None; work = outf = None; pos = []
    i = 1
    while i < len(argv):
        a = argv[i]
        if a == '--full': full = True
        elif a == '--timeout': i += 1; tmo = int(argv[i])
        elif a == '--work': i += 1; work = os.path.abspath(argv[i])
        elif a == '--out': i += 1; outf = os.path.abspath(argv[i])
        elif a.startswith('--'): print(__doc__); return 2
        else: pos.append(a)
        i += 1
    if not pos or not work or not outf: print(__doc__); return 2
    tree = os.path.abspath(pos[0]); only = set(pos[1:])
    tmo = tmo or (3000 if full else 1800)
    st = os.path.join(tree, S, 'gate-selftest.sh')
    if 'GATE_SELFTEST_NONCE' not in open(st).read():
        print('refusing to run: %s does not support GATE_SELFTEST_NONCE (the harness could not identify its leftovers)' % st); return 2
    if not os.path.isdir(CG) or shutil.which('systemd-run') is None or os.geteuid() != 0:
        print('refusing to run: needs root, systemd-run and %s' % CG); return 2
    if os.getsid(0) != os.getpid():
        print('refusing to run: start it with setsid (it must be its own session leader, so that pkill -s <sid> aborts only this harness)'); return 2
    if os.path.realpath(work) != work or not real_dir(work):
        print('refusing to run: --work must be an existing real directory (no symlink in its path): %s' % work); return 2
    if check(tree, quiet=True) != 0: return 2
    known = {m[0].split('-')[0] for m in M}
    if only - known: print('unknown mutant(s): %s' % ' '.join(sorted(only - known))); return 2
    signal.signal(signal.SIGCHLD, signal.SIG_DFL)          # an inherited SIG_IGN would auto-reap children and free their pids
    with open(outf + '.sid', 'w') as o: o.write('%d\n' % os.getsid(0))
    for s in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP): signal.signal(s, lambda *_: STOP.append('signal'))
    ctl = M[0]; assert ctl[1] is None
    todo = [m for m in M if m[1] is not None and (not only or m[0].split('-')[0] in only)]
    runs = [(ctl, ctl[0] + ' (opening)')] + [(m, m[0]) for m in todo] + [(ctl, ctl[0] + ' (closing)')]   # the control brackets the run
    log(outf, '# mutants run %s on %s mode=%s timeout=%ds (%d mutants between two controls)' % (
        time.strftime('%FT%TZ', time.gmtime()), tree, 'full' if full else 'skip-e2e', tmo, len(todo)))
    res = []
    for (name, f, edits), label in runs:
        if STOP: break
        try:
            v = run_one(tree, work, outf, full, tmo, name, f, edits, label)
        except BaseException as ex:
            v = 'EXCEPTION'; STOP.append('%s: %s: %s' % (label, type(ex).__name__, ex))
        res.append(v)
        if f is None and v != 'SURVIVED' and not STOP: STOP.append('the control did not pass (%s): the results of this run are not valid' % v)
    tally = ', '.join('%s=%d' % (k, res.count(k)) for k in sorted(set(res)))
    log(outf, ('STOPPED after %d of %d runs (%s): %s' % (len(res), len(runs), tally, '; '.join(STOP))) if STOP else 'DONE (%s)' % tally)
    return 3 if STOP else 0

if __name__ == '__main__':
    sys.exit(main(sys.argv))
