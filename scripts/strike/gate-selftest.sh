#!/usr/bin/env bash
# gate-selftest.sh [logdir]  -- prove gate-verify.sh (A.2.1) against REAL logs already on the build box.
#
# Source logs (read-only, from the integrated-proof runs): $LOGDIR/ip-fuigo-shell.log (37 targets, 17 failing),
# ip-fuigo-pager.log (20 targets, 20 failing, one FAILED line interleaved), ip-fuigo-sampling-types.log (2 targets,
# green). Those logs predate the gate trailer, so each fixture gets the trailer the gate itself would write
# (GATE_CARGO_EXIT=<n> + GATE_DONE); the exit code of the originals was 101 (cargo's "error: N target failed")
# or 0 (no such line). Cut fixtures get a trailer too, so each is rejected on its STRUCTURAL defect, not
# merely for lacking a marker; the `nomarker` / `orphan` cases exercise the marker rules on their own.
# Derived counts: 37 (P17-R v2 derivation, 36 exe + 1 doc), 20 and 2 = headers of logs whose every header
# reached a result line; the end-to-end run in R029 re-derives sampling-types independently from cargo.
# Fixtures are generated into a fresh temp dir and deleted on exit. KEEP=<dir> retains them in a NEW run-unique
# subdirectory of <dir> (two invocations given the same KEEP never share fixtures); its path is printed at the end.
# Exit 0 only if every case behaves as expected.
#
# Skipped / erroring assertions FAIL the suite (Fable audit, HIGH): the suite re-runs itself with its stderr
# captured to a file and fails if anything at all reached stderr (a "command not found", a bash syntax or
# runtime error, a "Killed" job report); and a command_not_found_handle records every unknown command in a
# file that is checked at the end, so an assertion calling an undefined helper can never be silently skipped,
# not even inside a subshell or a command substitution.
set -uo pipefail
unset CDPATH    # an exported CDPATH makes `cd` print its target and would corrupt HERE
# HERMETIC ENVIRONMENT (Astra R36/R37). The suite must give the same verdict whatever the caller exported (NODOC, ISO_*, ABORT_*, FEAT,
# CARGO_BUILD_TARGET, GIT_CONFIG_COUNT, GIT_DIR, a locale, ...). Unless the environment already consists of the names below and
# nothing else, re-execute once under `env -i` with exactly: PATH and HOME (to find cargo/rustup, git, systemd-run), a fixed C locale,
# git cut off from host and user configuration, and the suite's own documented switches.
SELFTEST_ENV_OK='PATH HOME LC_ALL GIT_CONFIG_GLOBAL GIT_CONFIG_SYSTEM TMPDIR KEEP STRIKE_SLOTS GATE_SELFTEST_SKIP_E2E GATE_SELFTEST_FAILFAST GATE_SELFTEST_NONCE GATE_MUT_NKILL PWD OLDPWD SHLVL _'
selftest_env_clean() { local v
  [ "${LC_ALL:-}" = C ] && [ "${GIT_CONFIG_GLOBAL:-}" = /dev/null ] && [ "${GIT_CONFIG_SYSTEM:-}" = /dev/null ] || return 1
  for v in $(compgen -e); do case " $SELFTEST_ENV_OK " in *" $v "*) ;; *) return 1;; esac; done; return 0; }
if ! selftest_env_clean; then
  [ "${1:-}" != --reexec ] || { echo "selftest: the environment is still not clean after env -i (exported: $(compgen -e | tr '\n' ' ')); refusing to loop"; exit 2; }
  CLEAN=("PATH=$PATH" "HOME=${HOME:-/root}" LC_ALL=C GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null)
  for v in TMPDIR KEEP STRIKE_SLOTS GATE_SELFTEST_SKIP_E2E GATE_SELFTEST_FAILFAST GATE_SELFTEST_NONCE GATE_MUT_NKILL; do [ -z "${!v+x}" ] || CLEAN+=("$v=${!v}"); done
  exec env -i "${CLEAN[@]}" bash "${BASH_SOURCE[0]}" --reexec "$@"
fi
[ "${1:-}" != --reexec ] || shift
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# The inner pass is selected by a leading argument, not by an environment variable (an inherited variable could skip the stderr check).
if [ "${1:-}" != --inner ]; then
  ERRF=$(mktemp 2>/dev/null) || { echo "selftest: mktemp failed"; exit 2; }
  bash "${BASH_SOURCE[0]}" --inner "$@" 2> "$ERRF"; rc=$?
  if [ -s "$ERRF" ]; then
    echo "FAIL  the self-test wrote to stderr (an assertion errored or was skipped); suite FAILS:"
    sed 's/^/      /' "$ERRF"; rm -f "$ERRF"; exit 1
  fi
  rm -f "$ERRF"; exit $rc
fi
shift
. "$HERE/gate-lib.sh"
. "$HERE/abort-lib.sh"
LOGDIR=${1:-/root/fuigo-builds}
if [ -n "${KEEP:-}" ]; then mkdir -p "$KEEP" 2>/dev/null && W=$(mktemp -d "$KEEP/selftest.XXXXXXXXXX" 2>/dev/null) || { echo "selftest: cannot create a fixture directory under KEEP=$KEEP"; exit 2; }
else W=$(mktemp -d 2>/dev/null) || { echo "selftest: mktemp -d failed"; exit 2; }; trap '[ -n "${RETAIN_W:-}" ] || rm -rf "$W"' EXIT; fi
RETAIN_W=""   # non-empty while something that may still be running uses files under $W: the fixture directory is then NOT deleted on exit
# W is used as an ABSOLUTE path after `cd`, as a symlink target and inside grep/pgrep patterns: make it physical and refuse any
# character that is special in a pattern or to the shell (a relative or exotic KEEP/TMPDIR would silently break fixtures).
W=$(cd "$W" 2>/dev/null && pwd -P) || { echo "selftest: cannot resolve the fixture directory"; exit 2; }
case $W in /*) ;; *) echo "selftest: the fixture directory ($W) is not absolute"; exit 2;; esac
case $W in *[!A-Za-z0-9/._-]*) echo "selftest: the fixture directory ($W) may contain only [A-Za-z0-9/._-]; choose another KEEP/TMPDIR"; exit 2;; esac
NOPATH=$W/nonexistent   # a path that never exists, PRIVATE to this run (nothing below ever creates it): the negative fixtures' "missing" target
SH=$LOGDIR/ip-fuigo-shell.log PG=$LOGDIR/ip-fuigo-pager.log ST=$LOGDIR/ip-fuigo-sampling-types.log
for f in "$SH" "$PG" "$ST"; do [ -f "$f" ] || { echo "missing source log $f"; exit 2; }; done
pass=0; failn=0
CNF=$W/command-not-found.txt; : > "$CNF"
command_not_found_handle() { printf '%s\n' "$*" >> "$CNF"; echo "selftest: command not found: $1" >&2; return 127; }
chk() { if [ "$2" = "$3" ]; then pass=$((pass+1)); echo "PASS  $1"; else failn=$((failn+1)); echo "FAIL  $1 (got '$2' wanted '$3')"; [ "${GATE_SELFTEST_FAILFAST:-}" != 1 ] || { RETAIN_W=1; echo "selftest: $pass passed, $failn failed   (FAILFAST: stopped at the first failure; mutant mode; fixtures may still be running, $W is NOT deleted)"; exit 1; }; fi; }
# Every fixture process inherits FUIGO_SELFTEST_ID, so any name-selected pid is verified to be THIS run's before it is signalled or
# described (an unrelated host process with the same command line is never touched; Astra R27/R28 HIGH).
# GATE_SELFTEST_NONCE=<digits> is for the MUTANT harness only (gate-mutants.py): it is appended to this run's identity (marker, tag, and
# therefore every fixture process name, unit name and lane name), so the harness can find this run's leftovers and nothing else.
case ${GATE_SELFTEST_NONCE:-} in *[!0-9]*) echo "selftest: GATE_SELFTEST_NONCE must be digits only"; exit 2;; esac
# at most 32 digits: the tag is part of unit names (systemd limit 255) and of command lines the survivor summary cuts at 200 characters
[ "$(printf '%s' "${GATE_SELFTEST_NONCE:-}" | wc -c)" -le 32 ] || { echo "selftest: GATE_SELFTEST_NONCE must be at most 32 digits"; exit 2; }
export FUIGO_SELFTEST_ID="st-$$-$RANDOM${GATE_SELFTEST_NONCE:+-$GATE_SELFTEST_NONCE}"
# Fixture processes are named with a run-unique suffix (sleep NNNN.$SELFTEST_TAG) so a name match can only ever be this run's, including
# env-cleared fixtures that carry no marker and cannot be found by FUIGO_SELFTEST_ID.
export SELFTEST_TAG="$$$RANDOM$RANDOM${GATE_SELFTEST_NONCE:-}"   # digits only (it is part of a sleep duration); long and random so a recycled pid never reproduces it
SELFTEST_UID="u$SELFTEST_TAG"            # alphanumeric: part of every systemd unit name this run creates
[ -z "${GATE_SELFTEST_NONCE:-}" ] || echo "NOTE  mutant-harness run, identity $SELFTEST_UID (GATE_SELFTEST_NONCE in effect; NOT a release self-test)"
mine_pids() { local q e; for q in $(pgrep -u "$(id -u)" "$@" 2>/dev/null); do e=$({ tr '\0' '\n' < "/proc/$q/environ"; } 2>/dev/null); case $'\n'"$e"$'\n' in *$'\n'"FUIGO_SELFTEST_ID=$FUIGO_SELFTEST_ID"$'\n'*) echo "$q";; esac; done; return 0; }
# skill [-SIG] PID : signal a fixture THROUGH A PIDFD, and only if it still carries this run's FUIGO_SELFTEST_ID (a recycled pid is never hit)
skill() { local s=KILL rc; case ${1:-} in -*) s=${1#-}; [ "$s" = 9 ] && s=KILL; shift;; esac; [ -n "${1:-}" ] || return 0
  SAFE_KILL_VAR=FUIGO_SELFTEST_ID python3 "$HERE/safe-kill.py" marker "$FUIGO_SELFTEST_ID" "$1" "$s" > "$W/skill.err" 2>&1; rc=$?
  # 0 = signalled, 3 = gone or no longer ours (both fine); anything else is a real failure to clean up and is reported, never swallowed
  case $rc in 0|3) ;; *) failn=$((failn+1)); echo "FAIL  skill: could not signal pid $1 with $s (safe-kill exit $rc): $(tr '\n' ' ' < "$W/skill.err")";; esac; return 0; }
# skill_sid / skill_pgid -SIG ID : the equivalent of pkill -s / kill -- -PGID, but every member is verified (marker + pidfd) one by one
skill_sid() { local q; [ -n "${2:-}" ] || return 0; for q in $(ps -eo pid=,sid= | awk -v s="$2" '$2==s{print $1}'); do skill "$1" "$q"; done; return 0; }
skill_pgid() { local q; [ -n "${2:-}" ] || return 0; for q in $(ps -eo pid=,pgid= | awk -v s="$2" '$2==s{print $1}'); do skill "$1" "$q"; done; return 0; }
# ukill UNIT : SIGKILL a systemd scope this run created (the unit name carries this self-test's pid) and that became active after this run started
ST_START=$(date +%s)
# pstate PID STARTTIME : alive | zombie | dead for THAT process identity (a different start time = a different process = dead)
pstate() { local st f; st=$(cat "/proc/$1/stat" 2>/dev/null) || { echo dead; return; }; f=${st##*) }; [ "$(printf '%s' "$f" | awk '{print $20}')" = "$2" ] || { echo dead; return; }; case $f in Z*) echo zombie;; *) echo alive;; esac; }
ukill() { local u=$1 t i
  case $u in *"$SELFTEST_UID"*|*"-$SELFTEST_TAG-"*) ;; *) failn=$((failn+1)); echo "FAIL  ukill: refusing to signal unit '$u' (not named for this run)"; return 0;; esac
  t=$(systemctl show -p ActiveEnterTimestamp --value "$u" 2>/dev/null) || { failn=$((failn+1)); echo "FAIL  ukill: cannot query unit '$u'"; return 0; }
  [ -n "$t" ] && : || { abort_scope_gone "${u%.scope}" && return 0; failn=$((failn+1)); echo "FAIL  ukill: unit '$u' has no activation time but its cgroup is not verifiably empty"; return 0; }   # (NB: `date -d ""` is midnight, so test the string first)
  t=$(date -d "$t" +%s 2>/dev/null); [ -n "$t" ] || { failn=$((failn+1)); echo "FAIL  ukill: cannot parse the activation time of unit '$u'"; return 0; }
  [ "$t" -ge $((ST_START - 1)) ] || { failn=$((failn+1)); echo "FAIL  ukill: unit '$u' is older than this run, not signalled"; return 0; }
  systemctl kill --kill-whom=all --signal=SIGKILL "$u" > "$W/ukill.err" 2>&1 || { failn=$((failn+1)); echo "FAIL  ukill: systemctl kill $u failed: $(tr '\n' ' ' < "$W/ukill.err")"; return 0; }
  # emptiness is read from the cgroup itself (abort_scope_gone fails closed), not from systemd's state string
  abort_scope_gone "${u%.scope}" || { failn=$((failn+1)); echo "FAIL  ukill: unit '$u' is not verifiably empty 5 s after SIGKILL"; return 0; }
  return 0; }
mine_fx() { mine_pids -fx "$(printf '%s' "$1" | sed 's/\./\\./g')"; }
export GATE_ALLOW_NO_EXPECT=1   # structural fixtures below have no binaries to list; the mandatory-expectation rule is asserted explicitly

trailer() { printf '\nGATE_TREE=%s\nGATE_CARGO_EXIT=%s\nGATE_DONE\n' "${TREE:-0000000000000000000000000000000000000000}" "$1"; }
mk() { # mk <name> <source> <lines-expr: all|PERCENT:n|AFTERLAST:k> <exit|none> [orphan]
  local out=$W/$1.log src=$2 how=$3 rc=$4 total
  total=$(wc -l < "$src")
  case "$how" in
    all) cat "$src" > "$out";;
    PERCENT:*) head -n $(( total * ${how#PERCENT:} / 100 )) "$src" > "$out";;
    # cut k lines after the LAST header, i.e. inside the final binary before its `test result:` line
    AFTERLAST:*) head -n $(( $(grep -nE '^ +(Running|Doc-tests) ' "$src" | tail -1 | cut -d: -f1) + ${how#AFTERLAST:} )) "$src" > "$out";;
  esac
  [ "$rc" = none ] || trailer "$rc" >> "$out"
  echo "$out"
}
expect() { # expect <name> <log> <derived> <verifier-exit> <grep-in-output>... 
  local name=$1 log=$2 der=$3 want=$4; shift 4
  local out; out=$("$HERE/gate-verify.sh" "$log" "$der" "${EXP:-}" 2>&1); local rc=$?
  local ok=1
  [ "$rc" -eq "$want" ] || ok=0
  for pat in "$@"; do printf '%s\n' "$out" | grep -qE -- "$pat" || { ok=0; echo "   missing /$pat/"; }; done
  if [ $ok -eq 1 ]; then pass=$((pass+1)); echo "PASS  $name (verifier exit $rc)"; else failn=$((failn+1)); echo "FAIL  $name (verifier exit $rc, wanted $want)"; printf '%s\n' "$out" | sed 's/^/      /'; fi
}

# 1. complete logs: admissible
expect complete-shell        "$(mk complete-shell "$SH" all 101)" 37 1 'ADMISSIBLE: YES' 'target_headers: 37' 'unfinished:     0' 'failing_set:    17 '
expect complete-green        "$(mk complete-green "$ST" all 0)"   2  0 'ADMISSIBLE: YES' 'GATE: PASS'
# 2. cut at 75%: rejected (headers short, last binary unfinished)
expect cut75-shell           "$(mk cut75-shell "$SH" PERCENT:75 101)" 37 3 'ADMISSIBLE: NO' 'target_headers=[0-9]+ != derived=37'
# 3. cut inside the LAST binary: header count is already 37, only the unfinished check can catch it
expect cut-last-binary       "$(mk cut-last-binary "$SH" AFTERLAST:2 101)" 37 3 'ADMISSIBLE: NO' 'target_headers: 37' 'unfinished:     1' 'never reached a test result'
# 4. killed run, exit 143 (cut content) and exit 143 on otherwise complete content, plus 137 and 124
expect killed-143-cut        "$(mk killed-143-cut "$SH" PERCENT:75 143)" 37 3 'ADMISSIBLE: NO' 'signal 15'
expect killed-143-complete   "$(mk killed-143-complete "$SH" all 143)" 37 3 'ADMISSIBLE: NO' 'cargo_exit=143: killed by signal 15'
expect killed-137            "$(mk killed-137 "$SH" all 137)" 37 3 'signal 9'
expect timeout-124           "$(mk timeout-124 "$SH" all 124)" 37 3 'cargo_exit=124: timeout'
# 5. marker rules on their own
expect nomarker              "$(mk nomarker "$SH" all none)" 37 3 'GATE_DONE marker absent' 'cargo_exit not recorded'
orph=$(mk orphan "$SH" all 101); echo "test orphan_line ... ok" >> "$orph"
expect orphan-after-done     "$orph" 37 3 'output after GATE_DONE'
# 6. derived count from a "remembered number" that is wrong: a complete log must not pass against 36 or 52
expect wrong-derived-36      "$(mk wrong-derived-36 "$SH" all 101)" 36 3 'target_headers=37 != derived=36'
expect result-lines-52-not-a-count "$W/complete-shell.log" 52 3 'target_headers=37 != derived=52'
# 7. FAILED line interleaved: grep undercounts, the failures: block does not
PGL=$(mk interleaved-pager "$PG" all 101)
expect interleaved-pager     "$PGL" 20 1 'ADMISSIBLE: YES' 'failing_set:    20 ' 'failed_lines:   19 '
# the failing set must equal the block by an independent method (names between `failures:` and the summary, deduped)
grep -E '^test .* FAILED$' "$PGL" | sed -E 's/^test (.*) \.\.\. FAILED$/\1/' | sort -u > "$W/grep.set"
missing=$(comm -13 "$W/grep.set" "$PGL.failset" | head -3 | tr '\n' ' ')
echo "      names in failures: block but not in any '^test .* FAILED\$' line (first 3): ${missing:-<none by exact match; see R029>}"

# ---- A.2.1 rule 1, BLOCKER fix: a CHILD's `test result:` must not complete a parent that never produced its own.
sy() { printf '%s\n' "$@"; }   # synthetic log lines
HDR='     Running unittests src/lib.rs (/x/target/debug/deps/parent-1)'
HDR2='     Running tests/two.rs (/x/target/debug/deps/two-1)'
RES() { echo "test result: ok. $1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s"; }
syn() { local out=$W/$1.log; shift; { "$@"; trailer 0; } > "$out"; echo "$out"; }
a_child_only() { sy "$HDR" "running 2 tests" "running 1 test"; RES 1; }
b_delayed_hdr1_open() { sy "$HDR" "running 2 tests" "running 1 test" "$HDR2"; RES 1; sy "running 3 tests"; RES 3; }
c_delayed_hdr2_own_missing() { sy "$HDR" "running 2 tests"; RES 2; sy "$HDR2" "running 3 tests" "running 1 test"; RES 1; }
d_nested_ok() { sy "$HDR" "running 2 tests" "running 1 test"; RES 1; RES 2; }
e_middle_missing() { sy "$HDR" "running 2 tests" "$HDR2" "running 1 test"; RES 1; }
f_no_running_line() { sy "$HDR" "something else"; RES 1; }
expect child-summary-parent-missing   "$(syn child-only a_child_only)" 1 3 'ADMISSIBLE: NO' 'unfinished:     1'
expect delayed-child-hdr1-unfinished  "$(syn delayed1 b_delayed_hdr1_open)" 2 3 'unfinished:     1'
expect delayed-child-hdr2-own-missing "$(syn delayed2 c_delayed_hdr2_own_missing)" 2 3 'unfinished:     1'
expect nested-child-parent-present    "$(syn nested d_nested_ok)" 1 0 'ADMISSIBLE: YES' 'unfinished:     0'
expect middle-header-missing-result   "$(syn middle e_middle_missing)" 2 3 'unfinished:     1'
expect no-running-line                "$(syn norunning f_no_running_line)" 1 3 'unfinished:     1'
# real log, parent's own summary deleted (the lib's `test result: FAILED. 7177 passed...` line), child summaries left in place
awk '/^ +(Running|Doc-tests) /{c++} c==1 && /^test result: FAILED\. [0-9]{4,} passed/ && !d {d=1; next} {print}' "$W/complete-shell.log" > "$W/shell-parent-summary-deleted.log"
expect real-shell-parent-summary-deleted "$W/shell-parent-summary-deleted.log" 37 3 'ADMISSIBLE: NO' 'unfinished:     1'
# --- second audit round (Astra on 5d01d2d7): ordering, malformed summaries, running-after-result
g_delayed_before_running() { sy "$HDR"; RES 2; sy "running 2 tests"; }
h_malformed_bare() { sy "$HDR" "running 0 tests" "test result:"; }
i_malformed_prefix() { sy "$HDR" "running 2 tests" "test result: ok. 2garbage passed; nonsense failed; ? ignored; ! measured; 0 filtered out"; }
j_running_after_result() { sy "$HDR" "running 2 tests"; RES 2; sy "running 1 test"; }
k_same_n_child_exit0() { sy "$HDR" "running 2 tests" "running 2 tests"; RES 2; }
expect child-summary-before-own-running "$(syn g_before g_delayed_before_running)" 1 3 'unfinished:     1'
expect malformed-bare-result-line       "$(syn malf1 h_malformed_bare)" 1 3 'unfinished:     1'
expect malformed-numeric-prefix         "$(syn malf2 i_malformed_prefix)" 1 3 'unfinished:     1'
expect running-after-last-result        "$(syn runafter j_running_after_result)" 1 3 'unfinished:     1'
# KNOWN LIMIT (documented in R029, NOT a pass of the contract): a child whose totals equal the parent's N and a
# parent that exits 0 without its own summary cannot be told apart by text. Asserted so the limit is visible and
# any change in behaviour is noticed; with a non-zero cargo exit the same log can never PASS (checked next).
expect KNOWN-LIMIT-same-N-child-parent-exit0 "$(syn knownlimit k_same_n_child_exit0)" 1 0 'ADMISSIBLE: YES'
{ sed '/^GATE_CARGO_EXIT=/d;/^GATE_DONE$/d' "$W/knownlimit.log"; echo GATE_CARGO_EXIT=101; echo GATE_DONE; } > "$W/knownlimit101.log"
expect same-N-child-parent-crashed-is-not-PASS "$W/knownlimit101.log" 1 1 'GATE: FAIL'
# --- third audit round (Astra on ce243eb2)
RESN() { echo "test result: ok. $1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s"; }
l_suffix_garbage() { sy "$HDR" "running 2 tests" "test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered outBROKEN"; }
expect malformed-suffix-garbage         "$(syn suffix l_suffix_garbage)" 1 3 'unfinished:     1'
# delayed child pair under B's header while B itself printed nothing (B exited 0): totals need not match B's N
m_delayed_pair() { sy "$HDR"; echo "running 2 tests"; RES 2; sy "$HDR2"; echo "running 99 tests"; RES 99; }
printf 'parent-1 2\ntwo-1 3\n' > "$W/expect-ok.txt"
EXP="$W/expect-ok.txt" expect delayed-child-pair-vs-expected-N "$(syn delpair m_delayed_pair)" 2 3 'unfinished:     1'
expect KNOWN-LIMIT-delayed-pair-without-expected-N "$W/delpair.log" 2 0 'ADMISSIBLE: YES'
n_matching() { sy "$HDR"; echo "running 2 tests"; RES 2; sy "$HDR2"; echo "running 3 tests"; RES 3; }
EXP="$W/expect-ok.txt" expect expected-N-matches-accepted "$(syn matching n_matching)" 2 0 'ADMISSIBLE: YES' 'unfinished:     0'
printf 'parent-1 2\ntwo-1 4\n' > "$W/expect-bad.txt"
EXP="$W/expect-bad.txt" expect expected-N-mismatch-rejected "$W/matching.log" 2 3 'unfinished:     1'
printf 'parent-1 2\n' > "$W/expect-missing.txt"
EXP="$W/expect-missing.txt" expect binary-absent-from-expected-rejected "$W/matching.log" 2 3 'unfinished:     1'
# --- fourth audit round (Astra on b6cc1b43): expectation files must be usable; unparseable Running headers
: > "$W/expect-empty.txt"
EXP="$W/expect-empty.txt" expect empty-expected-N-file-rejected "$W/matching.log" 2 3 'is empty'
EXP="$W/no-such-file.txt" expect unreadable-expected-N-file-rejected "$W/matching.log" 2 3 'unreadable'
o_garbled_hdr() { sy "     Running unittests src/lib.rs (/x/target/debug/deps/parent-1)child-output" "running 99 tests"; RES 99; }
EXP="$W/expect-ok.txt" expect garbled-Running-header-with-expected-N "$(syn garbled o_garbled_hdr)" 1 3 'unfinished:     1'
# --- fifth audit round (Astra on f19636ec)
p_failed_no_names() { sy "$HDR" "running 2 tests" "test result: FAILED. 1 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s"; }
expect FAILED-result-without-failure-names-is-not-PASS "$(syn failednames p_failed_no_names)" 1 1 'GATE: FAIL' 'failed_results:  1'
printf 'parent-1 2\ntwo-1 3\n' > "$W/expect-dup.txt"
q_dup() { sy "$HDR"; echo "running 2 tests"; RES 2; sy "$HDR"; echo "running 2 tests"; RES 2; }
EXP="$W/expect-dup.txt" expect duplicate-binary-cannot-replace-missing "$(syn dupbin q_dup)" 2 3 'missing, or a binary ran more than once'
# --- sixth audit round (Astra on 7cbb73f5)
r_failed0() { sy "$HDR" "running 2 tests" "test result: FAILED. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s"; }
expect FAILED-status-with-zero-failed-is-not-PASS "$(syn failed0 r_failed0)" 1 1 'GATE: FAIL' 'failed_results:  1'
printf 'parent-1 2\ndoc:alpha -\ndoc:beta -\n' > "$W/expect-doc.txt"
t_dupdoc() { sy "$HDR" "running 2 tests"; RES 2; sy "   Doc-tests alpha" "running 0 tests"; RES 0; sy "   Doc-tests alpha" "running 0 tests"; RES 0; }
EXP="$W/expect-doc.txt" expect duplicate-doctests-cannot-replace-missing "$(syn dupdoc t_dupdoc)" 3 3 'missing, or a binary ran more than once'
u_okdoc() { sy "$HDR" "running 2 tests"; RES 2; sy "   Doc-tests alpha" "running 0 tests"; RES 0; sy "   Doc-tests beta" "running 0 tests"; RES 0; }
EXP="$W/expect-doc.txt" expect each-expected-doctest-once-accepted "$(syn okdoc u_okdoc)" 3 0 'ADMISSIBLE: YES'
# --- seventh audit round (Astra on 1d145de6)
( unset GATE_ALLOW_NO_EXPECT; "$HERE/gate-verify.sh" "$W/complete-green.log" 2 > "$W/noexp.out" 2>&1 ); chk "verifier without an expected-N file is INADMISSIBLE (3)" "$?" 3
grep -q 'mandatory' "$W/noexp.out" && { pass=$((pass+1)); echo "PASS  ... and says why"; } || { failn=$((failn+1)); echo "FAIL  mandatory-expectation reason missing"; }
# expectations supplied through a pipe (consumed once) must still be honoured
o=$("$HERE/gate-verify.sh" "$W/matching.log" 2 <(printf 'parent-1 2\ntwo-1 4\n') 2>&1); chk "process-substitution expectations are honoured (mismatch rejected)" "$?" 3
# existing sub-cgroup used as the cgroup mount must be refused
mkdir -p "$W/badmount"; : > "$W/badmount/cgroup.controllers"; : > "$W/badmount/cgroup.max"; printf '0::/system.slice/x.scope\n' > "$W/rec"
GATE_CG_MOUNT=$W/badmount gate_cg_resolve "$W/rec" >/dev/null 2>&1; chk "sub-cgroup used as mount is refused (2)" "$?" 2
# ---- other marker / format rules
{ cat "$W/complete-green.log" | sed '/^GATE_TREE=/d'; } > "$W/notree.log"
expect no-tree-recorded               "$W/notree.log" 2 3 'GATE_TREE=<tree hash> not recorded'
{ sed '/^GATE_DONE$/d' "$W/complete-green.log"; echo 'GATE_TREE_DIRTY=status 1: ?? x'; echo GATE_DONE; } > "$W/dirty.log"
expect tree-dirty-marker              "$W/dirty.log" 2 3 'GATE_TREE_DIRTY'
{ sed '/^GATE_CARGO_EXIT=/d;/^GATE_DONE$/d' "$W/complete-green.log"; echo 'GATE_ORPHANS=unknown (scan status 2, kill status 0)'; echo GATE_CARGO_EXIT=0; echo GATE_DONE; } > "$W/orphans.log"
expect orphans-marker                 "$W/orphans.log" 2 3 'GATE_ORPHANS'
{ sed '/^GATE_DONE$/d' "$W/complete-green.log"; echo GATE_CARGO_EXIT=0; echo GATE_DONE; } > "$W/dupexit.log"
expect duplicate-exit-record          "$W/dupexit.log" 2 3 'not recorded exactly once'
{ sed '/^GATE_CARGO_EXIT=/d' "$W/complete-green.log" | sed 's/^GATE_DONE$/GATE_CARGO_EXIT=101\nGATE_DONE/'; } > "$W/red-empty.log"
expect exit101-empty-failset-is-red   "$W/red-empty.log" 2 1 'ADMISSIBLE: YES' 'unexplained'
sed 's/$/\r/' "$W/complete-green.log" > "$W/crlf.log"
expect crlf-complete-accepted         "$W/crlf.log" 2 0 'ADMISSIBLE: YES' 'GATE: PASS'
sed 's/^\(test result:\)/\x1b[32m\1/' "$W/complete-green.log" > "$W/ansi.log"
expect ansi-complete-accepted         "$W/ansi.log" 2 0 'ADMISSIBLE: YES'
dt() { sy "$HDR" "running 2 tests"; echo "test x ... FAILED"; sy "" "failures:" "" "---- x stdout ----" "boom" "" "failures:" "    src/lib.rs - example (line 12)" "    tests::two" ""; echo "test result: FAILED. 0 passed; 2 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s"; }
expect doctest-names-in-failset       "$(syn doctest dt | sed 's/$//')" 1 1 'failing_set:    2 '
grep -qx 'src/lib.rs - example (line 12)' "$W/doctest.log.failset" && { pass=$((pass+1)); echo "PASS  doctest failset content exact"; } || { failn=$((failn+1)); echo "FAIL  doctest failset content"; }
# ---- Doc-tests PAIRING rule (Fable audit, MEDIUM). REAL log: an edition-2024 crate on toolchain 1.94.0 with two
# normal doctests (merged run: `running 2 tests`) and one compile_fail doctest (standalone run: `running 1 test`)
# under ONE `Doc-tests dtpair` header (generated on hetzner-dsm, see R029; committed as fixtures/, sha256 in R029).
DT2=$HERE/fixtures/doctest-two-pair-1.94.0.log
chk "real two-pair doctest fixture present with two running lines under one Doc-tests header" \
  "$(awk '/^ +Doc-tests /{d=1} d && /^running [0-9]+ tests?$/{c++} END{print c+0}' "$DT2")" 2
{ cat "$DT2"; trailer 0; } > "$W/dt2.log"
printf 'dtpair-dcf935d07e6b54b9 1\ndoc:dtpair -\n' > "$W/expect-dt2.txt"
EXP="$W/expect-dt2.txt" expect real-doctest-two-pairs-accepted "$W/dt2.log" 2 0 'ADMISSIBLE: YES' 'unfinished:     0' 'GATE: PASS'
# negative: the SECOND pair's totals do not match its N (1 -> 2 passed on the standalone result)
awk '/^test result:/{c++} c==3 && !d && /^test result:/{sub(/ 1 passed;/," 2 passed;"); d=1} {print}' "$W/dt2.log" > "$W/dt2-mismatch.log"
chk "mismatch fixture differs from the original in exactly one line" "$(diff "$W/dt2.log" "$W/dt2-mismatch.log" | grep -c '^>')" 1
EXP="$W/expect-dt2.txt" expect doctest-second-pair-totals-mismatch-rejected "$W/dt2-mismatch.log" 2 3 'unfinished:     1'
# negative: a trailing `running` with no result after the last pair
{ sed '/^GATE_TREE=/,$d' "$W/dt2.log"; echo "running 1 test"; trailer 0; } > "$W/dt2-trailing.log"
EXP="$W/expect-dt2.txt" expect doctest-trailing-unpaired-running-rejected "$W/dt2-trailing.log" 2 3 'unfinished:     1'
# negative: two `running` lines back to back (the first never paired), a result with no pending `running`, and 3 pairs
v_dt_unpaired_first() { sy "   Doc-tests alpha" "running 2 tests" "running 1 test"; RES 1; }
w_dt_orphan_result() { sy "   Doc-tests alpha" "running 1 test"; RES 1; RES 1; }
x_dt_three_pairs() { sy "   Doc-tests alpha" "running 1 test"; RES 1; sy "running 1 test"; RES 1; sy "running 1 test"; RES 1; }
y_dt_one_pair() { sy "   Doc-tests alpha" "running 3 tests"; RES 3; }
expect doctest-running-without-result-then-pair-rejected "$(syn dtv v_dt_unpaired_first)" 1 3 'unfinished:     1'
expect doctest-result-without-running-rejected           "$(syn dtw w_dt_orphan_result)" 1 3 'unfinished:     1'
expect doctest-three-pairs-rejected                      "$(syn dtx x_dt_three_pairs)" 1 3 'unfinished:     1'
expect doctest-single-pair-still-accepted                "$(syn dty y_dt_one_pair)" 1 0 'ADMISSIBLE: YES' 'unfinished:     0'
# the single-pair rule still holds for Running sections: a second pair under a test-binary header is rejected
z_running_two_pairs() { sy "$HDR" "running 2 tests"; RES 2; sy "running 1 test"; RES 1; }
expect running-section-two-pairs-still-rejected          "$(syn dtz z_running_two_pairs)" 1 3 'unfinished:     1'

# ---- final-gate.sh refuses self-test hooks from the environment (Fable audit, MEDIUM) and validates the sha.
# Each refusal happens before any lane/run directory is created: the lane name used here must not appear.
# --src is a fake checkout (a `.git` FILE, no repo) so that even a broken gate that got past these checks could never
# clone or build: it would stop at `git rev-parse HEAD`. Any lane dir it created is detected, then removed.
FGL=selftest-hook-$SELFTEST_UID-$RANDOM; mkdir -p "$W/fakesrc"; echo "gitdir: $NOPATH" > "$W/fakesrc/.git"
for hv in "GATE_CG_MOUNT=$W/fake" "GATE_PROC_ROOT=$W/fake" GATE_ALLOW_NO_EXPECT=1 GATE_ALLOW_NO_EXPECT=; do
  o=$(env -u GATE_ALLOW_NO_EXPECT -u GATE_CG_MOUNT -u GATE_PROC_ROOT "$hv" bash "$HERE/final-gate.sh" --src "$W/fakesrc" --lane "$FGL" 0123456789abcdef 1 2>&1); rc=$?
  chk "final-gate refuses self-test hook ${hv%%=*} set in the environment (${hv})" "$rc/$(printf '%s' "$o" | grep -c 'self-test hook')" "2/1"
done
o=$(env -u GATE_ALLOW_NO_EXPECT -u GATE_CG_MOUNT -u GATE_PROC_ROOT bash "$HERE/final-gate.sh" --src "$W/fakesrc" --lane "$FGL" XYZ-not-a-sha 1 2>&1); rc=$?
chk "final-gate rejects a non-hex sha (control: no hook set, gets past the hook check)" "$rc/$(printf '%s' "$o" | grep -c 'sha must match')" "2/1"
o=$(env -u GATE_ALLOW_NO_EXPECT -u GATE_CG_MOUNT -u GATE_PROC_ROOT bash "$HERE/final-gate.sh" --src "$W/fakesrc" --lane "$FGL" 0123456789a 1 2>&1); rc=$?
chk "final-gate rejects an 11-hex-digit sha" "$rc/$(printf '%s' "$o" | grep -c 'sha must match')" "2/1"
o=$(env -u GATE_ALLOW_NO_EXPECT -u GATE_CG_MOUNT -u GATE_PROC_ROOT bash "$HERE/final-gate.sh" --src "$W/fakesrc" --lane "$FGL" 0123456789abcdef0123456789abcdef012345678 1 2>&1); rc=$?
chk "final-gate rejects a 41-hex-digit sha" "$rc/$(printf '%s' "$o" | grep -c 'sha must match')" "2/1"
chk "no lane directory created by any refused invocation" "$([ -e "/root/fuigo-builds/$FGL" ] && echo created || echo none)" none
case "$FGL" in selftest-hook-*) rm -rf "/root/fuigo-builds/$FGL";; esac
chk "final-gate hard-sets the hooks after refusing them" \
  "$(grep -cE '^export GATE_CG_MOUNT=/sys/fs/cgroup GATE_PROC_ROOT=/proc$|^unset GATE_ALLOW_NO_EXPECT$' "$HERE/final-gate.sh")" 2

# ---- REAL process tests of the helpers final-gate.sh uses (no mocks of the code under test)
ID="selftest-$SELFTEST_UID-$RANDOM"
# a plain child, a setsid() child, and a double-fork-then-setsid grandchild, all tagged by environment only. They run in
# their own scope and are scanned WITH that scope's unit name, exactly as final-gate.sh scans: an unrelated tenant's
# unreadable process (a container runtime in D state, seen on this shared host) is then outside the scope and
# tolerated, instead of failing the scan closed and failing this suite for a reason that has nothing to do with it.
SU="fuigo-gate-selftest-fx-$SELFTEST_UID-$RANDOM"
FUIGO_GATE_RUN=$ID systemd-run --scope --quiet --collect --slice=system.slice --unit="$SU" bash -c 'sleep 300 & setsid sleep 300 & setsid bash -c "setsid sleep 300 < /dev/null > /dev/null 2>&1 & sleep 300" & wait' < /dev/null > /dev/null 2>&1 &
disown -a   # they are SIGKILLed below on purpose: no "Killed" job report on stderr (stderr must stay empty)
sleep 1
# Scans retry (<=5 x 1 s) if one fails closed with status 2 (a process that is briefly unreadable); a scan that never
# completes is an assertion FAILURE (its stderr is shown on stdout), never ignored. Scans that pass the fixtures' unit
# name are the production shape; the fail-closed behaviour of a UNIT-LESS (host-wide) scan is asserted separately below
# with a fake proc root, where it cannot depend on what other tenants are doing.
hostscan() { local i; HS_OUT=""; HS_RC=2; for i in 1 2 3 4 5; do HS_OUT=$(gate_marker_pids "$1" ${2:+"$2"} 2> "$W/hostscan.err"); HS_RC=$?; [ $HS_RC -eq 0 ] && return 0; sleep 1; done
  echo "      host-wide scan never completed: $(tr '\n' ' ' < "$W/hostscan.err")"; return $HS_RC; }
hostscan "$ID" "$SU.scope"; chk "unit-scoped env scan completes (status 0)" "$HS_RC" 0
NF=$(printf '%s\n' "$HS_OUT" | grep -c .)
chk "orphan-scan finds tagged procs incl. setsid() escapees (>=4)" "$([ "$NF" -ge 4 ] && echo yes || echo "no:$NF")" yes
# ANY of the found processes (not "the last one": the scan order is the lexical order of /proc entries) lives in another session
OUTSIDE=no; MYSESS=$(ps -o sid= -p $$ | tr -d ' ')
for q in $HS_OUT; do qs=$(ps -o sid= -p "$q" 2>/dev/null | tr -d ' '); if [ -n "$qs" ] && [ "$qs" != "$MYSESS" ]; then OUTSIDE=yes; fi; done
chk "some tagged proc is OUTSIDE this shell's session" "$OUTSIDE" yes
# fake proc root (synthetic pids are above PID_MAX_LIMIT 4194304: they can never be a real process nor this shell): entry 1 has a dangling environ (unreadable, not a zombie/kthread) -> must fail closed
FP=$W/fakeproc; mkdir -p "$FP/9004242"; ln -s "$NOPATH" "$FP/9004242/environ"
GATE_PROC_ROOT=$FP gate_marker_pids "$ID" >/dev/null 2>&1; chk "unreadable live process fails closed (status 2)" "$?" 2
mkdir -p "$FP/9004343"; printf '9004343 (x) Z 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 1 0 0\n' > "$FP/9004343/stat"; ln -s "$NOPATH" "$FP/9004343/environ"; rm -rf "$FP/9004242"
GATE_PROC_ROOT=$FP gate_marker_pids "$ID" >/dev/null 2>&1; chk "unreadable zombie is tolerated (status 0)" "$?" 0
mkdir -p "$FP/9004444"; ln -s "$NOPATH" "$FP/9004444/environ"; printf '0::/system.slice/other.scope\n' > "$FP/9004444/cgroup"
GATE_PROC_ROOT=$FP gate_marker_pids "$ID" "fuigo-gate-x.scope" >/dev/null 2>&1; chk "unreadable proc OUTSIDE the run scope is tolerated (status 0)" "$?" 0
printf '0::/system.slice/fuigo-gate-x.scope\n' > "$FP/9004444/cgroup"
GATE_PROC_ROOT=$FP gate_marker_pids "$ID" "fuigo-gate-x.scope" >/dev/null 2>&1; chk "unreadable proc INSIDE the run scope fails closed (status 2)" "$?" 2
printf '0::/system.slice/other.scope\n' > "$FP/9004444/cgroup"
GATE_PROC_ROOT=$FP gate_marker_pids "$ID" >/dev/null 2>&1; chk "without a unit, the same process fails closed (status 2)" "$?" 2
# A scan error (status 2) can come AFTER an attempt already killed processes (Fable LOW): the kills of EVERY attempt are
# accumulated (kill_retry, unit-tested below with a fake), so a shared host cannot turn "killed 4, then one noisy
# rescan" into a false "killed 1" suite failure.
kill_retry() { local i n; KT=0; KR=2; for i in 1 2 3 4 5; do n=$("$@" 2>> "$W/kill.err"); KR=$?; KT=$((KT + n)); [ $KR -ne 2 ] && break; sleep "${KILL_RETRY_SLEEP:-1}"; done; }
kill_retry gate_kill_marker "$ID" "$SU.scope"; KN=$KT
[ $KR -ne 2 ] || echo "      kill_marker scan never completed: $(tr '\n' ' ' < "$W/kill.err")"
chk "kill_marker returns 0" "$KR" 0
chk "kill_marker killed >=4 (accumulated over attempts)" "$([ "$KN" -ge 4 ] && echo yes || echo "no:$KN")" yes
hostscan "$ID" "$SU.scope"; chk "no tagged procs remain (scan status/count)" "$HS_RC/$(printf '%s\n' "$HS_OUT" | grep -c .)" 0/0
wait 2>/dev/null
# clean tree / dirty / untracked / not a repo
R=$W/repo; mkdir -p "$R"; git -C "$R" init -q; git -C "$R" -c user.name=t -c user.email=t@t commit -q --allow-empty -m i
echo a > "$R/f"; git -C "$R" add f; git -C "$R" -c user.name=t -c user.email=t@t commit -q -m f
o=$(gate_tree_check "$R"); chk "clean tree accepted" "$?" 0; chk "tree hash reported" "$(echo "$o" | grep -c '^tree=[0-9a-f]\{40\}$')" 1
echo b >> "$R/f"; gate_tree_check "$R" >/dev/null; chk "modified tracked file refused" "$?" 1
git -C "$R" checkout -q f; : > "$R/new"; gate_tree_check "$R" >/dev/null; chk "untracked file refused" "$?" 1
rm "$R/new"; echo c >> "$R/f"; git -C "$R" add f; gate_tree_check "$R" >/dev/null; chk "staged change refused" "$?" 1
( export GIT_CEILING_DIRECTORIES="${W%/*}"; gate_tree_check "$W" >/dev/null 2>&1 ); chk "not-a-repo fails closed (2)" "$?" 2
# an IGNORED file can change the build (e.g. .cargo/config.toml): it must be refused too (Fable audit, LOW)
git -C "$R" reset -q --hard; printf '.cargo/\n' > "$R/.gitignore"; git -C "$R" add .gitignore; git -C "$R" -c user.name=t -c user.email=t@t commit -q -m ign
gate_tree_check "$R" >/dev/null; chk "control: tree with a .gitignore and no ignored file is clean" "$?" 0
mkdir -p "$R/.cargo"; printf '[build]\nrustflags = ["--cfg", "evil"]\n' > "$R/.cargo/config.toml"
o=$(gate_tree_check "$R"); chk "ignored .cargo/config.toml is refused (1)" "$?" 1
chk "... and named in the output" "$(printf '%s\n' "$o" | grep -cE '^!! \.cargo/(config\.toml)?$')" 1
rm -rf "$R/.cargo"
# per-run directories, append-only inventory, per-lane lock
L=$W/lane; d1=$(gate_new_run_dir "$L"); d2=$(gate_new_run_dir "$L")
chk "two runs in the same second get distinct dirs" "$([ "$d1" != "$d2" ] && [ -d "$d1" ] && [ -d "$d2" ] && echo yes || echo no)" yes
echo keep > "$d1/suite.log"; d3=$(gate_new_run_dir "$L"); chk "earlier run's evidence untouched" "$(cat "$d1/suite.log")" keep
gate_inventory "$L" "run=a event=end"; gate_inventory "$L" "run=b event=end"; chk "inventory is append-only (2 lines)" "$(wc -l < "$L/runs.inventory" | tr -d ' ')" 2
( gate_lane_lock "$L"; sleep 4 ) & sleep 1
( gate_lane_lock "$L" ); chk "second gate on the same lane is refused" "$?" 1
( gate_lane_lock "$W/other-lane" ); chk "a different lane is not blocked" "$?" 0
wait

# --- cgroup tracking: a survivor that CLEARED ITS ENVIRONMENT and left the session is invisible to the env marker
# and to session kill, but is still in the run's cgroup scope, even in a NESTED cgroup below it.
if command -v systemd-run >/dev/null && [ -w "$GATE_CG_MOUNT" ]; then
  for mode in direct nested; do
    U="fuigo-gate-selftest-$SELFTEST_UID-$RANDOM"; REC=$W/cg-$mode.path
    if [ $mode = direct ]; then BODY='setsid env -i /bin/sleep 300 < /dev/null > /dev/null 2>&1 & exit 0'
    else BODY='d=/sys/fs/cgroup$(sed -n "s/^0:://p" /proc/self/cgroup); mkdir "$d/nest" && { setsid env -i /bin/sleep 300 < /dev/null > /dev/null 2>&1 & echo $! > "$d/nest/cgroup.procs"; }; exit 0'; fi
    systemd-run --scope --quiet --collect --slice=system.slice --unit="$U" sh -c 'cat /proc/self/cgroup > "$1"; shift; exec "$@"' gate-cg "$REC" sh -c "$BODY" < /dev/null > /dev/null 2>&1
    sleep 1
    CGD=$(gate_cg_resolve "$REC"); chk "[$mode] scope dir resolved from the process's own record" "$(basename "$CGD")" "$U.scope"
    CGP=$(gate_cg_pids "$CGD"); chk "[$mode] cgroup scan sees the env-cleared setsid() survivor" "$(echo "$CGP" | grep -c .)" 1
    chk "[$mode] env-marker scan alone does NOT see it (why cgroups are needed)" "$(hostscan "$U" "$U.scope"; printf '%s/%s' "$HS_RC" "$(printf '%s\n' "$HS_OUT" | grep -c .)")" 0/0
    KN=$(gate_cg_kill "$CGD"); KR=$?; chk "[$mode] cgroup kill returns 0 and reports 1 killed" "$KR/$KN" "0/1"
    chk "[$mode] survivor gone after cgroup kill" "$(gate_cg_pids "$CGD" | grep -c .)" 0
  done
else
  failn=$((failn+1)); echo "FAIL  cgroup tests: systemd-run or writable cgroup v2 not available"
fi
GATE_CG_MOUNT="$NOPATH" gate_cg_resolve "$W/cg-direct.path" >/dev/null 2>&1; chk "unusable cgroup mount fails closed (2)" "$?" 2
printf '0::/user.slice/not-a-scope\n' > "$W/bad.path"; gate_cg_resolve "$W/bad.path" >/dev/null 2>&1; chk "unexpected cgroup path fails closed (2)" "$?" 2
gate_cg_resolve "$W/does-not-exist" >/dev/null 2>&1; chk "missing cgroup record fails closed (2)" "$?" 2
GATE_PROC_ROOT="$NOPATH" gate_marker_pids "$ID" >/dev/null 2>&1; chk "missing /proc inventory fails closed (2)" "$?" 2
# traversal / inspection errors must fail closed, not read as "nothing found"
FB=$W/fakebin; mkdir -p "$FB"; printf '#!/bin/sh\nexit 1\n' > "$FB/find"; chmod +x "$FB/find"
mkdir -p "$W/fakescope"; : > "$W/fakescope/cgroup.procs"
( PATH="$FB:$PATH"; gate_cg_pids "$W/fakescope" >/dev/null 2>&1 ); chk "cgroup traversal failure fails closed (2)" "$?" 2
printf '#!/bin/sh\nif [ "$3" = ls-files ]; then echo boom >&2; exit 128; fi\nexec /usr/bin/git "$@"\n' > "$FB/git"; chmod +x "$FB/git"
R2=$W/repo2; mkdir -p "$R2"; git -C "$R2" init -q; git -C "$R2" -c user.name=t -c user.email=t@t commit -q --allow-empty -m i
gate_tree_check "$R2" >/dev/null; chk "control: fresh repo is clean" "$?" 0
( PATH="$FB:$PATH"; gate_tree_check "$R2" >/dev/null 2>&1 ); chk "git ls-files failure fails closed (2)" "$?" 2
# failure-set extraction error fails closed: make `sort` fail
printf '#!/bin/sh\nexit 2\n' > "$FB/sort"; chmod +x "$FB/sort"
o=$(PATH="$FB:$PATH" "$HERE/gate-verify.sh" "$W/complete-green.log" 2 2>&1); rc=$?
chk "failset extraction error is INADMISSIBLE (3)" "$rc" 3
# cgroup race: members exist (populated 1) but enumeration finds none -> counted, not erased
mkdir -p "$W/racescope/nest"; : > "$W/racescope/cgroup.procs"; : > "$W/racescope/nest/cgroup.procs"; printf 'populated 1\nfrozen 0\n' > "$W/racescope/cgroup.events"
chk "populated cgroup with no enumerated pids is counted as a survivor" "$(gate_cg_pids "$W/racescope" | grep -c .)" 1
printf 'populated 0\n' > "$W/racescope/cgroup.events"
chk "unpopulated cgroup reports none" "$(gate_cg_pids "$W/racescope" | grep -c .)" 0
# unreadable log fails closed (normalisation read error), cgroup.events read error fails closed
chmod 000 "$W/complete-green.log" 2>/dev/null; if [ "$(id -u)" != 0 ]; then echo "SKIP (not root) unreadable-log"; else
  o=$("$HERE/gate-verify.sh" "$W/nosuch.log" 2 2>&1); chk "missing log is a usage error (2)" "$?" 2; fi
chmod 644 "$W/complete-green.log"
mkdir -p "$W/evscope"; : > "$W/evscope/cgroup.procs"; printf 'garbage\n' > "$W/evscope/cgroup.events"
gate_cg_pids "$W/evscope" >/dev/null 2>&1; chk "unparseable cgroup.events fails closed (2)" "$?" 2
# git concealment flags
echo base > "$R/g"; git -C "$R" add g; git -C "$R" -c user.name=t -c user.email=t@t commit -q -m g
git -C "$R" update-index --assume-unchanged g; echo hidden >> "$R/g"
o=$(gate_tree_check "$R"); chk "assume-unchanged file hiding a modification is refused" "$?" 1
git -C "$R" update-index --no-assume-unchanged g; git -C "$R" checkout -q -- g
git -C "$R" update-index --skip-worktree g; gate_tree_check "$R" >/dev/null; chk "skip-worktree flag is refused" "$?" 1
git -C "$R" update-index --no-skip-worktree g; gate_tree_check "$R" >/dev/null; chk "tree clean again after flags removed" "$?" 0
# identity: HEAD/tree must be the same after the run
h1=$(gate_head_tree "$R"); git -C "$R" checkout -q -- f; git -C "$R" -c user.name=t -c user.email=t@t commit -q --allow-empty -m other; h2=$(gate_head_tree "$R")
chk "identity change between start and end is visible" "$([ "$h1" != "$h2" ] && echo yes || echo no)" yes
# the lane-lock fd is closed for the run: a descendant cannot release it with flock -u 9
( gate_lane_lock "$W/lane2"; sh -c 'flock -u 9' 9>&- 2>/dev/null; sleep 4 ) & sleep 1
( gate_lane_lock "$W/lane2" ); chk "descendant without fd 9 cannot release the lane lock" "$?" 1
wait
# ======================================================================================================================
# P17-F3. (1) iso-resolve.py / iso.sh auto mode, (2) abort kills everything: gate_abort_run, the watchdog, pid liveness,
# session-vs-group, and a REAL final-gate.sh aborted mid-build (TERM and SIGKILL), (3) kill-retry accumulation.
IR=$HERE/iso-resolve.py
cat > "$W/iso-fx.log" <<'LOG'
   Compiling pk v0.1.0
     Running unittests src/lib.rs (/t/target/debug/deps/pk-aa11)

running 2 tests
test unit::alpha ... ok
test unit::beta ... FAILED

failures:

---- unit::beta stdout ----
boom

failures:
    unit::beta

test result: FAILED. 1 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running unittests src/main.rs (/t/target/debug/deps/pk-bb22)

running 1 test
test binmain_one ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running unittests src/bin/tool-x.rs (/t/target/debug/deps/tool_x-cc33)

running 1 test
test bin_tool ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running tests/it_one.rs (/t/target/debug/deps/it_one-dd44)

running 4 tests
test plain_integration ... ok
test shared_name ... ok
child output here test interleaved_one ... FAILED
test other ... ok

failures:

---- lost_line_only stdout ----
x

failures:
    interleaved_one
    lost_line_only

test result: FAILED. 2 passed; 2 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running tests/it_two.rs (/t/target/debug/deps/it_two-ee55)

running 1 test
test shared_name ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running tests/nested/main.rs (/t/target/debug/deps/nested-ff66)

running 1 test
test in_nested ... ok

     Running unittests crates/pk/src/lib.rs (/t/target/debug/deps/pk-9977)

running 1 test
test ws_unit ... ok

     Running benches/b.rs (/t/target/release/deps/b-0a)

running 1 test
test bench_x ... ok

   Doc-tests pk

running 1 test
test docced ... ok
LOG
isor() { python3 "$IR" pk "$W/iso-fx.log" "$@" | tr '\t' '=' | tr '\n' ';'; }
chk "iso-resolve: lib unit test -> --lib" "$(isor unit::alpha)" "unit::alpha=--lib;"
chk "iso-resolve: lib test known only from a FAILED line + failures block -> --lib" "$(isor unit::beta)" "unit::beta=--lib;"
chk "iso-resolve: src/main.rs unit test -> --bin <pkg>" "$(isor binmain_one)" "binmain_one=--bin pk;"
chk "iso-resolve: src/bin/X.rs unit test -> --bin X" "$(isor bin_tool)" "bin_tool=--bin tool-x;"
chk "iso-resolve: integration-test function -> --test <file>" "$(isor plain_integration)" "plain_integration=--test it_one;"
chk "iso-resolve: FAILED line interleaved after other output still resolves" "$(isor interleaved_one)" "interleaved_one=--test it_one;"
chk "iso-resolve: a name known only from the failures block / stdout header resolves" "$(isor lost_line_only)" "lost_line_only=--test it_one;"
chk "iso-resolve: same name in two integration targets -> both selectors" "$(isor shared_name)" "shared_name=--test it_one;shared_name=--test it_two;"
chk "iso-resolve: tests/<dir>/main.rs -> --test <dir>" "$(isor in_nested)" "in_nested=--test nested;"
chk "iso-resolve: workspace-root-relative lib path -> --lib" "$(isor ws_unit)" "ws_unit=--lib;"
chk "iso-resolve: Doc-tests header -> --doc" "$(isor docced)" "docced=--doc;"
cat > "$W/iso-doc.log" <<'LOG'
   Doc-tests other
running 1 test
test src/lib.rs - theirs (line 3) ... ok
   Doc-tests pk
running 1 test
test src/lib.rs - ours (line 5) ... ok
LOG
chk "iso-resolve: a doctest of ANOTHER package's library is not resolved for -p pk" "$(python3 "$IR" pk "$W/iso-doc.log" 'src/lib.rs - theirs (line 3)' | tr '\t' '=' | tr '\n' ';')" "src/lib.rs - theirs (line 3)=!UNSUPPORTED Doc-tests other;"
chk "iso-resolve: the package's own doctest still resolves" "$(python3 "$IR" pk "$W/iso-doc.log" 'src/lib.rs - ours (line 5)' | tr '\t' '=' | tr '\n' ';')" "src/lib.rs - ours (line 5)=--doc;"
chk "iso-resolve: bench header is UNSUPPORTED, never a guess" "$(isor bench_x)" "bench_x=!UNSUPPORTED Running benches/b.rs (/t/target/release/deps/b-0a);"
chk "iso-resolve: unknown name -> !UNRESOLVED" "$(isor no_such_test)" "no_such_test=!UNRESOLVED;"
chk "iso-resolve: unreadable log exits 2" "$(python3 "$IR" pk "$W/nosuch.log" x >/dev/null 2>&1; echo $?)" 2
# the real fuigo-shell log: pick, with an independent awk, the first `test X ... ok` inside the tests/execution_acp.rs section
# and the first inside the library section, and check the resolver agrees.
RN1=$(awk '/^ +Running /{s=($2=="unittests") ? $2" "$3 : $2; next} s=="tests/execution_acp.rs" && /^test [^ ]+ \.\.\. ok$/{print $2; exit}' "$SH")
RN2=$(awk '/^ +Running /{s=($2=="unittests") ? $2" "$3 : $2; next} s=="unittests src/lib.rs" && /^test [^ ]+ \.\.\. ok$/{print $2; exit}' "$SH")
chk "real shell log: awk oracle found an integration-test name" "$([ -n "$RN1" ] && echo yes || echo no)" yes
chk "real shell log: integration-test function -> --test execution_acp" "$(python3 "$IR" fuigo-shell "$SH" "$RN1" | head -1 | cut -f2)" "--test execution_acp"
chk "real shell log: lib unit test -> --lib" "$(python3 "$IR" fuigo-shell "$SH" "$RN2" | head -1 | cut -f2)" "--lib"
# iso.sh auto mode, print-only (no lane, no build, no cargo)
isop() { ISO_PRINT_ONLY=1 ISO_RESOLVER="$IR" ISO_FROM_LOG="$W/iso-fx.log" bash "$HERE/iso.sh" lane-x pk "$@" 2>&1 | tr '\n' ';'; }
chk "iso.sh auto: integration test gets --test" "$(isop auto plain_integration sha1)" "plain_integration	cargo test --locked -p pk --test it_one -- --exact plain_integration;"
chk "iso.sh auto: two names, two targets (--lib and --bin)" "$(isop auto "unit::alpha bin_tool" sha1)" "unit::alpha	cargo test --locked -p pk --lib -- --exact unit::alpha;bin_tool	cargo test --locked -p pk --bin tool-x -- --exact bin_tool;"
chk "iso.sh auto: a name in two targets is isolated in both" "$(isop auto shared_name sha1)" "shared_name	cargo test --locked -p pk --test it_one -- --exact shared_name;shared_name	cargo test --locked -p pk --test it_two -- --exact shared_name;"
chk "iso.sh auto: unresolved name is reported, not run" "$(isop auto nope sha1)" "nope	!UNRESOLVED;"
chk "iso.sh auto without ISO_FROM_LOG is reported, not guessed" "$(ISO_PRINT_ONLY=1 ISO_RESOLVER="$IR" bash "$HERE/iso.sh" lane-x pk auto n sha1 2>&1 | tr '\n' ';')" "n	!UNRESOLVED (ISO_FROM_LOG unset or unreadable);"
chk "iso.sh auto with a failing resolver is reported, not skipped" "$(ISO_PRINT_ONLY=1 ISO_RESOLVER="$NOPATH" ISO_FROM_LOG="$W/iso-fx.log" bash "$HERE/iso.sh" lane-x pk auto n sha1 2>/dev/null | tr '\n' ';')" "n	!UNRESOLVED (resolver failed);"
chk "iso.sh explicit args are passed through unchanged (legacy mode)" "$(isop '--test foo' some_name sha1)" "some_name	cargo test --locked -p pk --test foo -- --exact some_name;"
chk "iso.sh legacy --lib passthrough" "$(isop '--lib' some_name sha1)" "some_name	cargo test --locked -p pk --lib -- --exact some_name;"

# ---- abort: gate_abort_run on three REAL scopes (build / list / run), one of them without a recorded cgroup path
if command -v systemd-run >/dev/null && [ -w /sys/fs/cgroup ]; then
  AID=selftest-abort-$SELFTEST_UID-$RANDOM; ARD=$W/abortrun; mkdir -p "$ARD"
  UB="fuigo-gate-$(printf '%s' "$AID" | tr -c 'A-Za-z0-9' '-')"
  mkscope() { # <unit> <recfile|NONE> <tag>: a scope holding a plain sleep, a setsid sleep and an env-cleared setsid sleep
    FUIGO_GATE_RUN=$AID systemd-run --scope --quiet --collect --slice=system.slice --unit="$1" \
      sh -c 'if [ "$1" != NONE ]; then cat /proc/self/cgroup > "$1"; fi; sleep "$2" & setsid sleep "$3" & env -i setsid sleep "$4" & wait' gate-cg "$2" "314$3.$SELFTEST_TAG" "315$3.$SELFTEST_TAG" "316$3.$SELFTEST_TAG" < /dev/null > /dev/null 2>&1 &
  }
  active() { [ "$(systemctl is-active "$1.scope" 2>/dev/null)" = active ] && echo active || echo gone; }
  mkscope "$UB-build" "$ARD/cgroup-build.path" 1; mkscope "$UB-list" NONE 2; mkscope "$UB" "$ARD/cgroup.path" 3
  disown -a; sleep 2
  chk "abort setup: three scopes active" "$(active "$UB-build")/$(active "$UB-list")/$(active "$UB")" active/active/active
  chk "abort setup: 9 sleeps running (3 per scope)" "$(pgrep -fc "sleep 31(41|42|43|51|52|53|61|62|63)\.$SELFTEST_TAG\$")" 9
  # phase A: unit-kill unavailable (fake systemctl that fails) -> the CGROUP path alone must kill the recorded scopes;
  # the scope with no recorded path survives, which is exactly why the by-unit kill exists.
  FB2=$W/fakesysctl; mkdir -p "$FB2"; printf '#!/bin/sh\nexit 1\n' > "$FB2/systemctl"; chmod +x "$FB2/systemctl"
  ( PATH="$FB2:$PATH"; gate_abort_run "$ARD" "$AID" "$UB" ) >/dev/null 2>&1; sleep 1
  chk "abort via cgroup record only: build + run scopes killed, unrecorded list scope still up" "$(active "$UB-build")/$(active "$UB-list")/$(active "$UB")" gone/active/gone
  gate_abort_run "$ARD" "$AID" "$UB" >/dev/null 2>&1; sleep 1
  chk "abort by unit name kills the scope that never recorded a cgroup path" "$(active "$UB-list")" gone
  chk "no sleep of the abort fixtures survives" "$(pgrep -fc "sleep 31(41|42|43|51|52|53|61|62|63)\.$SELFTEST_TAG\$")" 0
  # pid liveness: a zombie is dead, a sleeping process is alive
  # a REAL zombie: python forks a child that exits at once and the parent (which never waits) sleeps; the state must be Z first,
  # otherwise this case could pass with the zombie rule removed (a vanished pid is "dead" too: surviving mutant M05)
  ZF="$W/zombie.pid"; ( python3 -c 'import os,sys,time
p=os.fork()
if p==0: os._exit(0)
open(sys.argv[1],"w").write(str(p)); d=sys.argv[1]+".done"
for _ in range(240):
    if os.path.exists(d): break
    time.sleep(0.25)' "$ZF" < /dev/null > /dev/null 2>&1 ) 2> /dev/null & disown
  for i in $(seq 1 20); do [ -s "$ZF" ] && break; sleep 0.25; done; ZP=$(cat "$ZF"); sleep 0.5
  chk "zombie fixture is really in state Z" "$(awk '{print $3}' "/proc/$ZP/stat" 2>/dev/null)" Z
  chk "gate_pid_alive: a zombie (reaped by nobody) is NOT alive" "$(gate_pid_alive "$ZP" && echo alive || echo dead)" dead
  : > "$ZF.done"   # handshake: the parent may now exit (bounded wait of 60 s in the fixture)
  sleep 30 & LP=$!; disown
  chk "gate_pid_alive: a live process is alive" "$(gate_pid_alive "$LP" && echo alive || echo dead)" alive
  skill "$LP"
  # watchdog: a fake gate dies by SIGKILL (no trap can run) -> the detached watchdog kills the run's scope
  WID=selftest-wd-$SELFTEST_UID-$RANDOM; WRD=$W/wdrun; mkdir -p "$WRD"; WUB="fuigo-gate-$(printf '%s' "$WID" | tr -c 'A-Za-z0-9' '-')"
  sleep 300 & FG=$!; disown
  AID=$WID mkscope "$WUB" "$WRD/cgroup.path" 4; disown -a
  gate_wd_start "$WRD" "$FG" "$WID" "$WUB"; sleep 3
  chk "watchdog: gate alive -> run untouched" "$(active "$WUB")" active
  chk "watchdog: runs detached in its own session, not the test's" "$([ "$(ps -o sid= -p "$(cat "$WRD/watchdog.pid")" | tr -d ' ')" != "$(ps -o sid= -p $$ | tr -d ' ')" ] && echo own || echo same)" own
  skill -9 "$FG"
  for i in $(seq 1 15); do [ "$(active "$WUB")" = gone ] && break; sleep 1; done
  chk "watchdog: gate SIGKILLed -> run killed within 15 s" "$(active "$WUB")" gone
  # the log line comes AFTER the watchdog's marker sweep (a host-wide /proc scan: seconds under load), so wait for it
  for i in $(seq 1 60); do grep -q 'killed by watchdog' "$WRD/watchdog.log" 2>/dev/null && break; sleep 1; done
  chk "watchdog: logs the kill" "$(grep -c 'killed by watchdog' "$WRD/watchdog.log" 2>/dev/null)" 1
  # control: a normal finish (stop file) must disarm it
  WID2=selftest-wd2-$SELFTEST_UID-$RANDOM; WRD2=$W/wdrun2; mkdir -p "$WRD2"; WUB2="fuigo-gate-$(printf '%s' "$WID2" | tr -c 'A-Za-z0-9' '-')"
  sleep 300 & FG2=$!; disown
  AID=$WID2 mkscope "$WUB2" "$WRD2/cgroup.path" 5; disown -a
  gate_wd_start "$WRD2" "$FG2" "$WID2" "$WUB2"; sleep 2; gate_wd_stop "$WRD2"; skill -9 "$FG2"; sleep 4
  chk "watchdog: after gate_wd_stop a dying gate does NOT trigger a kill" "$(active "$WUB2")" active
  gate_abort_run "$WRD2" "$WID2" "$WUB2" >/dev/null 2>&1; sleep 1
  chk "watchdog control scope cleaned up" "$(active "$WUB2")" gone
else
  failn=$((failn+1)); echo "FAIL  abort tests: systemd-run or writable cgroup v2 not available"
fi
# session vs process group: why `kill -- -<pgid>` misses `timeout`'s child and `pkill -s` does not (the P17-R clippy leak)
setsid bash -c 'timeout 600 sleep 6161.$SELFTEST_TAG & wait' < /dev/null > /dev/null 2>&1 & GB=$!; disown; sleep 1
SP=$(mine_fx "sleep 6161.$SELFTEST_TAG" | head -1)
chk "timeout's child is in a DIFFERENT process group than the gate shell" "$([ -n "$SP" ] && [ "$(ps -o pgid= -p "$SP" | tr -d ' ')" != "$(ps -o pgid= -p "$GB" | tr -d ' ')" ] && echo different || echo same)" different
chk "same child is in the SAME session as the gate shell" "$([ "$(ps -o sid= -p "$SP" | tr -d ' ')" = "$(ps -o sid= -p "$GB" | tr -d ' ')" ] && echo same || echo different)" same
skill_pgid -TERM "$(ps -o pgid= -p "$GB" | tr -d ' ')"; sleep 1
chk "kill -- -<pgid> of the gate misses timeout's child (the old abort leaks)" "$(pgrep -fc "^sleep 6161\.$SELFTEST_TAG\$")" 1
skill_sid -TERM "$GB"; sleep 1
chk "pkill -s <sid> kills it" "$(pgrep -fc "^sleep 6161\.$SELFTEST_TAG\$")" 0
# kill-retry accumulation (Fable LOW b): kills made by an attempt that then reported a scan error must still count
fake_kill() { echo x >> "$W/fk.cnt"; case $(wc -l < "$W/fk.cnt") in 1) echo 3; return 2;; 2) echo 1; return 0;; esac; }
: > "$W/fk.cnt"; KILL_RETRY_SLEEP=0 kill_retry fake_kill
chk "kill-retry: attempt 1 killed 3 then scan-errored, attempt 2 killed 1 -> total 4 (not 1)" "$KT/$KR" "4/0"

# ---- abort-lib.sh (shared by rp.sh / iso.sh / final-gate.sh): a REAL mini runner that does what rp.sh/iso.sh do
cat > "$W/mini-abort.sh" <<'MINI'
#!/usr/bin/env bash
set -uo pipefail
. "$LIBDIR/abort-lib.sh"
abort_guard "${BASH_SOURCE[0]}" "$@"
LANE=$1 MARK=$2 MODE=${3:-}
[ "$MODE" != exit3 ] || exit 3
abort_init mini "$LANE"; echo "$MYSID" > "$MARK.sid"; echo "$$" > "$MARK.pid"; ABORT_FLAG="$MARK.flag"; rm -f "$ABORT_FLAG"
on_abort() { trap '' TERM INT HUP; abort_kill_all; echo cleaned > "$MARK.cleaned"; exit 143; }
trap on_abort TERM INT HUP
[ "$MODE" != quick-first ] || bg true
[ "$MODE" != bgs-only ] || { bg sh -c 'sleep 7022.$SELFTEST_TAG & wait'; exit 0; }
[ "$MODE" != late-launch ] || { PATH="$LATEBIN:$PATH"; bg sh -c 'sleep 7023.$SELFTEST_TAG & wait'; exit 0; }   # the launcher (systemd-run) is delayed 4 s before it registers its scope
[ "$MODE" != leak-first ] || bg sh -c 'setsid sleep 7016.$SELFTEST_TAG & exit 0'   # returns at once, leaving a setsid()ed child in ITS scope
bg sh -c 'sleep 7011.$SELFTEST_TAG & setsid sleep 7012.$SELFTEST_TAG & env -i setsid sleep 7013.$SELFTEST_TAG & wait'
MINI
mini_case() { # <label> <leader|nonleader> <TERM|INT|HUP|pkills> [mode]
  local lbl=$1 lead=$2 how=$3 mode=${4:-} M="$W/mini-$RANDOM" i pid sid
  rm -f "$M".*
  # The runner is ALWAYS started with INT, HUP and QUIT ignored (`trap ''` in the launching subshell; ignored signals are inherited
  # across exec): that is the state a runner is in when it is started in the background under nohup, and it is what abort_guard's shim /
  # supervisor must undo. Without this the precondition depended on how the SUITE itself was launched (ignored under `nohup ... &`,
  # default from a terminal or from gate-mutants.py), and the INT/HUP cases proved nothing in the latter (M19 survived there).
  if [ "$lead" = leader ]; then ( trap '' INT HUP QUIT; LIBDIR="$HERE" setsid bash "$W/mini-abort.sh" "mini-$SELFTEST_UID" "$M" $mode < /dev/null > /dev/null 2>&1; echo $? > "$M.rc" ) 2> /dev/null &
  else ( trap '' INT HUP QUIT; LIBDIR="$HERE" bash "$W/mini-abort.sh" "mini-$SELFTEST_UID" "$M" $mode < /dev/null > /dev/null 2>&1; echo $? > "$M.rc" ) 2> /dev/null & fi
  for i in $(seq 1 60); do [ -e "$M.sid" ] && [ "$(pgrep -fc "^sleep 701[123]\.$SELFTEST_TAG\$")" -ge 3 ] && break; sleep 0.5; done
  pid=$(cat "$M.pid" 2>/dev/null); sid=$(cat "$M.sid" 2>/dev/null)
  chk "[$lbl] runner's recorded sid is its own session (sid==pid), not the caller's" "$([ "$sid" = "$pid" ] && [ "$sid" != "$(ps -o sid= -p $$ | tr -d ' ')" ] && echo own || echo "no:$sid/$pid")" own
  chk "[$lbl] 3 fixture sleeps (plain, setsid, env-cleared setsid) running" "$(pgrep -fc "^sleep 701[123]\.$SELFTEST_TAG\$")" 3
  [ "$mode" != leak-first ] || chk "[$lbl] a command's leftovers (setsid sleep 7016.$SELFTEST_TAG) are reaped when the command ends, before the next one runs" "$(pgrep -fc "^sleep 7016\.$SELFTEST_TAG\$")" 0
  case $how in TERM|INT|HUP) skill -$how "$pid";; pkills) skill_sid -TERM "$sid";; sup*) skill -${how#sup} "$(ps -o ppid= -p "$pid" | tr -d ' ')";; esac
  for i in $(seq 1 40); do [ -e "$M.rc" ] && break; sleep 0.5; done
  for i in $(seq 1 20); do [ "$(pgrep -fc "^sleep 701[1-6]\.$SELFTEST_TAG\$")" = 0 ] && break; sleep 0.5; done
  chk "[$lbl] after $how: no fixture sleep survives (incl. the setsid ones, via the scope)" "$(pgrep -fc "^sleep 701[1-6]\.$SELFTEST_TAG\$")" 0
  for i in $(seq 1 40); do [ -e "$M.cleaned" ] && break; sleep 0.5; done   # SIGKILL of the supervisor: rc is written at once, the runner's cleanup follows
  chk "[$lbl] cleanup hook ran and the launcher exited ${EXPECT_RC:-143}" "$(cat "$M.cleaned" 2>/dev/null)/$(cat "$M.rc" 2>/dev/null)" cleaned/${EXPECT_RC:-143}
  return 0
}
if command -v systemd-run >/dev/null && [ -w /sys/fs/cgroup ]; then
  mini_case "abort-lib leader TERM" leader TERM
  mini_case "abort-lib leader INT (signal ignored on entry via & -- the shim must restore it)" leader INT
  mini_case "abort-lib leader HUP" leader HUP
  mini_case "abort-lib leader pkill -s" leader pkills
  mini_case "abort-lib NON-leader (supervisor path) pkill -s" nonleader pkills
  mini_case "abort-lib NON-leader TERM to the runner" nonleader TERM
  mini_case "abort-lib second command's scope (unit name must come from the parent shell)" leader TERM quick-first
  mini_case "abort-lib an EARLIER command's scope (not just the latest) is cleaned" leader TERM leak-first
  mini_case "abort-lib NON-leader: SIGINT sent to the SUPERVISOR (ignored on entry via &; python supervisor must handle it)" nonleader supINT
  mini_case "abort-lib NON-leader: SIGTERM to the SUPERVISOR" nonleader supTERM
  mini_case "abort-lib NON-leader: SIGHUP to the SUPERVISOR" nonleader supHUP
  EXPECT_RC=137 mini_case "abort-lib NON-leader: SIGKILL of the SUPERVISOR (kill -9 \$! of the launcher): the kernel TERMs the runner, which cleans up" nonleader supKILL
  # supervisor startup race: an abort that lands AFTER the runner was spawned but BEFORE the supervisor forwards (the
  # test hook widens that window to 2 s) must not be lost
  printf 'exec sleep 6020.%s\n' "$SELFTEST_TAG" > "$W/tiny.sh"
  ( ABORT_SUP_DELAY_AFTER_SPAWN=2 python3 -c "$ABORT_PYSUP" "$W/tiny.sh" < /dev/null > /dev/null 2>&1; echo $? > "$W/sup.rc" ) 2> /dev/null &
  for i in $(seq 1 40); do [ "$(pgrep -fc "^sleep 6020\.$SELFTEST_TAG\$")" -ge 1 ] && break; sleep 0.25; done
  SUPP=$(ps -o ppid= -p "$(mine_fx "sleep 6020.$SELFTEST_TAG" | head -1)" | tr -d ' ')
  [ -n "$SUPP" ] && [ "$(ps -o args= -p "$SUPP" | grep -c "$W/tiny.sh")" = 1 ] && skill -TERM "$SUPP"
  for i in $(seq 1 40); do [ -e "$W/sup.rc" ] && break; sleep 0.5; done
  chk "supervisor: TERM during the spawn window is queued and forwarded: runner dead, supervisor exits 143" "$(pgrep -fc "^sleep 6020\.$SELFTEST_TAG\$")/$(cat "$W/sup.rc" 2>/dev/null)" "0/143"
  # an abort that lands while a scope is still being registered: simulate with a systemctl whose FIRST kill call is the moment
  # the scope appears (with a setsid() child inside), i.e. AFTER the first scope-kill pass found nothing
  FSD2="$W/fakesd2"; mkdir -p "$FSD2"
  cat > "$FSD2/systemctl" <<FAKE
#!/bin/sh
if [ "\$1" = kill ] && [ ! -e "$W/late.flag" ]; then
  # the FIRST kill call: the scope only comes into existence NOW (after the first pass would have looked), and this call
  # does not kill it -- only a later pass can
  : > "$W/late.flag"; for a in "\$@"; do u=\$a; done; u=\${u%.scope}
  ( setsid systemd-run --scope --quiet --collect --slice=system.slice --unit="\$u" sh -c 'setsid sleep 7019.$SELFTEST_TAG & wait' < /dev/null > /dev/null 2>&1 & )
  for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do [ "\$(pgrep -fc '^sleep 7019\.$SELFTEST_TAG\$')" -ge 1 ] && break; sleep 0.25; done
  pgrep -fc '^sleep 7019\.$SELFTEST_TAG\$' > "$W/late.seen"
  exit 1
fi
exec $(command -v systemctl) "\$@"
FAKE
  chmod +x "$FSD2/systemctl"; rm -f "$W/late.flag"
  ( PATH="$FSD2:$PATH"; abort_init t "late$SELFTEST_UID"; MYSID=999999999; ABORT_UNITS=("fuigo-t-late$SELFTEST_UID-$$-1"); abort_kill_all; echo "rc=$? surv=[$ABORT_SURVIVORS]" ) > "$W/late.out" 2>&1
  chk "abort_kill_all kills a scope that appeared AFTER the first pass (the fixture existed: seen=1): second pass, rc 0, no survivors, no 'sleep 7019'" "$(cat "$W/late.seen" 2>/dev/null)/$(cat "$W/late.out")/$(pgrep -fc "^sleep 7019\.$SELFTEST_TAG\$")" "1/rc=0 surv=[]/0"
  ukill "fuigo-t-late$SELFTEST_UID-$$-1.scope"
  # gate_abort_run: a scope registered AFTER its first pass (env-cleared setsid child inside, no cgroup record, no marker):
  # only the second pass can kill it
  FSD3="$W/fakesd3"; mkdir -p "$FSD3"
  cat > "$FSD3/systemctl" <<FAKE
#!/bin/sh
if [ "\$1" = kill ] && [ ! -e "$W/late3.flag" ]; then
  : > "$W/late3.flag"; for a in "\$@"; do u=\$a; done; u=\${u%.scope}
  ( setsid systemd-run --scope --quiet --collect --slice=system.slice --unit="\$u" env -i /bin/sh -c 'setsid sleep 7020.$SELFTEST_TAG & wait' < /dev/null > /dev/null 2>&1 & )
  for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do [ "\$(pgrep -fc '^sleep 7020\.$SELFTEST_TAG\$')" -ge 1 ] && break; sleep 0.25; done
  pgrep -fc '^sleep 7020\.$SELFTEST_TAG\$' > "$W/late3.seen"
  exit 1
fi
exec $(command -v systemctl) "\$@"
FAKE
  chmod +x "$FSD3/systemctl"; rm -f "$W/late3.flag"; LID=selftest-late3-$SELFTEST_UID-$RANDOM; LRD=$W/late3rd; mkdir -p "$LRD"
  ( PATH="$FSD3:$PATH"; gate_abort_run "$LRD" "$LID" "fuigo-gate-late3-$SELFTEST_UID" > /dev/null 2>&1; echo $? > "$W/late3.rc" )
  chk "gate_abort_run kills a scope that appeared after its first pass (fixture existed; status 0; no 'sleep 7020')" "$(cat "$W/late3.seen" 2>/dev/null)/$(cat "$W/late3.rc")/$(pgrep -fc "^sleep 7020\.$SELFTEST_TAG\$")" "1/0/0"
  ukill "fuigo-gate-late3-$SELFTEST_UID.scope"
  # the launcher of the current phase is killed by IDENTITY (pid + start time + run marker, pidfd): a stale or foreign launcher.id is left alone
  ( FUIGO_GATE_RUN=selftest-ln-$SELFTEST_UID setsid sleep 6033.$SELFTEST_TAG < /dev/null > /dev/null 2>&1 ) 2> /dev/null &
  ( setsid sleep 6034.$SELFTEST_TAG < /dev/null > /dev/null 2>&1 ) 2> /dev/null &
  disown -a; sleep 1
  LSA=$(mine_fx "sleep 6033.$SELFTEST_TAG" | head -1); LSB=$(mine_fx "sleep 6034.$SELFTEST_TAG" | head -1); LTA=$(gate_pid_starttime "$LSA"); LTB=$(gate_pid_starttime "$LSB")
  mkdir -p "$W/lnrd"
  # (gate_abort_run also sweeps the env marker, which would kill the marked fixture before the launcher rule is exercised: stub that sweep)
  echo "$LSB $LTB" > "$W/lnrd/launcher.id"; ( gate_kill_marker() { echo 0; return 0; }; gate_abort_run "$W/lnrd" selftest-ln-$SELFTEST_UID fuigo-gate-ln-$SELFTEST_UID > /dev/null 2>&1 )
  chk "launcher.id naming a process WITHOUT this run's marker: left alone" "$(pgrep -fc "^sleep 6034\.$SELFTEST_TAG\$")" 1
  echo "$LSA $((LTA + 1))" > "$W/lnrd/launcher.id"; ( gate_kill_marker() { echo 0; return 0; }; gate_abort_run "$W/lnrd" selftest-ln-$SELFTEST_UID fuigo-gate-ln-$SELFTEST_UID > /dev/null 2>&1 )
  chk "launcher.id with the right pid and marker but a WRONG start time (recycled pid): left alone" "$(pgrep -fc "^sleep 6033\.$SELFTEST_TAG\$")" 1
  echo "$LSA $LTA" > "$W/lnrd/launcher.id"; ( gate_kill_marker() { echo 0; return 0; }; gate_abort_run "$W/lnrd" selftest-ln-$SELFTEST_UID fuigo-gate-ln-$SELFTEST_UID > /dev/null 2>&1 )
  chk "launcher.id with pid, start time and marker all matching: killed" "$(pgrep -fc "^sleep 6033\.$SELFTEST_TAG\$")" 0
  skill "$LSB"; sleep 0.3
  # watchdog stop never signals a saved pid (it could belong to an unrelated process by then)
  sleep 300 & UNREL=$!; disown; mkdir -p "$W/wdstop"; echo "$UNREL" > "$W/wdstop/watchdog.pid"; gate_wd_stop "$W/wdstop"
  chk "gate_wd_stop leaves the process of a stale watchdog.pid alone (stop-file protocol only)" "$([ -n "$UNREL" ] && kill -0 "$UNREL" 2>/dev/null && echo alive || echo killed)/$([ -e "$W/wdstop/.wd-stop" ] && echo stopfile)" "alive/stopfile"
  skill "$UNREL"
  # auxiliary scopes (git / cargo metadata through bg): their unit names are in aux.units, so the WATCHDOG of a SIGKILLed gate kills them too
  AXID=selftest-ax-$SELFTEST_UID-$RANDOM; AXRD=$W/axrun; mkdir -p "$AXRD"; AXUB="fuigo-gate-$(printf '%s' "$AXID" | tr -c 'A-Za-z0-9' '-')"
  ( setsid bash -c 'echo $$ > "$1"; sleep 300 & wait' fakegate "$W/ax.pid" < /dev/null > /dev/null 2>&1 ) 2> /dev/null &
  disown -a; for i in $(seq 1 20); do [ -s "$W/ax.pid" ] && break; sleep 0.25; done
  AXG=$(cat "$W/ax.pid")
  ( ABORT_UNITS_FILE="$AXRD/aux.units"; : > "$ABORT_UNITS_FILE"; abort_init ax "$AXID"; bg sh -c 'sleep 6032.$SELFTEST_TAG' > /dev/null 2>&1 ) 2> /dev/null &
  disown -a; for i in $(seq 1 40); do [ "$(pgrep -fc "^sleep 6032\.$SELFTEST_TAG\$")" -ge 1 ] && [ -s "$AXRD/aux.units" ] && break; sleep 0.25; done
  chk "aux scope fixture: a bg command is running and its unit is recorded in aux.units" "$(pgrep -fc "^sleep 6032\.$SELFTEST_TAG\$")/$(grep -c '^fuigo-ax-' "$AXRD/aux.units")" "1/1"
  gate_wd_start "$AXRD" "$AXG" "$AXID" "$AXUB"; sleep 2
  chk "watchdog: gate alive -> the auxiliary scope is untouched" "$(pgrep -fc "^sleep 6032\.$SELFTEST_TAG\$")" 1
  skill -9 "$AXG"; for i in $(seq 1 30); do [ "$(pgrep -fc "^sleep 6032\.$SELFTEST_TAG\$")" = 0 ] && break; sleep 1; done
  chk "watchdog: SIGKILLed gate -> the auxiliary scope recorded in aux.units is killed" "$(pgrep -fc "^sleep 6032\.$SELFTEST_TAG\$")" 0
  for i in $(seq 1 30); do grep -q 'killed by watchdog' "$AXRD/watchdog.log" 2>/dev/null && break; sleep 1; done
  chk "watchdog logs the auxiliary-scope kill as a complete kill" "$(grep -c 'killed by watchdog' "$AXRD/watchdog.log" 2>/dev/null)" 1
  # SIGKILL of the supervisor INSIDE the child's fork->exec window (hook: the child is held there for 8 s): the runner must never start
  printf ': > "%s/t2.ran"\nexec sleep 6021.%s\n' "$W" "$SELFTEST_TAG" > "$W/tiny2.sh"
  T2MARK=selftest-t2-$SELFTEST_UID-$RANDOM
  ( FUIGO_GATE_RUN=$T2MARK ABORT_SUP_DELAY_IN_PREEXEC=8 python3 -c "$ABORT_PYSUP" "$W/tiny2.sh" < /dev/null > /dev/null 2>&1 ) 2> /dev/null &
  disown -a   # the supervisor is SIGKILLed on purpose: no "Killed" job report on stderr
  # readiness handshake: the supervisor exists (marked, ours) AND already has its child; then the ACKNOWLEDGEMENT: the child is still the
  # forked PYTHON image (pre-exec: its argv is the supervisor's, after exec it would read 'bash .../tiny2.sh'), i.e. verifiably inside the hold
  T2P=""; T2C=""; T2PRE=no; for i in $(seq 1 40); do T2P=$(mine_pids -f "python3 -c .* $W/tiny2.sh" | head -1); [ -n "$T2P" ] && T2C=$(pgrep -P "$T2P" | head -1); [ -n "$T2C" ] && break; sleep 0.25; done
  [ -n "$T2C" ] && case $(tr '\0' ' ' < "/proc/$T2C/cmdline" 2>/dev/null) in 'python3 -c '*) T2PRE=preexec;; esac
  T2CST=$(gate_pid_starttime "${T2C:-0}" 2>/dev/null); T2ID=$([ -n "$T2CST" ] && echo id || echo noid)
  python3 "$HERE/safe-kill.py" marker "$T2MARK" "${T2P:-0}" KILL 2>/dev/null; T2R=$?
  for i in $(seq 1 20); do [ "$(pstate "$T2C" "$T2CST")" = alive ] || break; sleep 0.25; done
  T2DEAD=$([ -n "$T2CST" ] && pstate "$T2C" "$T2CST" || echo noid)   # alive | zombie | dead (a missing identity is never "dead")
  sleep 10   # past the 8 s hold: a runner that survived the supervisor would have executed by now
  chk "supervisor SIGKILLed during the child's fork->exec window: acknowledged pre-exec, child existed, kill landed (0), child died with the supervisor, the runner never executes (no 'sleep 6021', no t2.ran sentinel)" "$T2PRE/$([ -n "$T2C" ] && echo child)/$T2ID/$T2R/$T2DEAD/$(pgrep -fc "^sleep 6021\.$SELFTEST_TAG\$")/$([ -e "$W/t2.ran" ] && echo ran || echo never)" "preexec/child/id/0/dead/0/never"
  # containment is mandatory and cleanup is verified (fail closed)
  mkdir -p "$W/nosd"; for c in ps tr sleep true sh; do ln -sf "$(command -v $c)" "$W/nosd/$c"; done
  o=$( ( PATH="$W/nosd"; abort_init t "nosd$SELFTEST_UID"; bg true; echo "rc=$?" ) 2>&1 ); chk "bg without systemd-run refuses to run the command (97), never runs it uncontained" "$(printf '%s' "$o" | grep -c 'systemd-run is required')/$(printf '%s' "$o" | grep -c 'rc=97')" "1/1"
  FSD="$W/fakesd"; mkdir -p "$FSD"; printf '#!/bin/sh\n[ "$1" = kill ] && exit 1\nexec %s "$@"\n' "$(command -v systemctl)" > "$FSD/systemctl"; chmod +x "$FSD/systemctl"
  # MYSID=<nonexistent session>: abort_kill_all sweeps ITS session, which must never be the self-test's own
  # output goes to a FILE: the surviving fixture holds its stdout open, so a $( ) pipe would never see EOF
  ( PATH="$FSD:$PATH"; abort_init t "kfail$SELFTEST_UID"; MYSID=999999999; bg sh -c 'setsid sleep 7017.$SELFTEST_TAG & exit 0'; echo "bgrc=$?"; abort_kill_all; echo "akrc=$? surv=[$ABORT_SURVIVORS]" ) > "$W/kfail.out" 2>&1
  o=$(cat "$W/kfail.out")
  chk "bg reports 98 when the scope cannot be emptied (the command itself exited 0)" "$(printf '%s' "$o" | grep -c 'bgrc=98')" 1
  chk "abort_kill_all returns 1 and names the surviving scope when it cannot kill it" "$(printf '%s' "$o" | grep -c "akrc=1 surv=\[ fuigo-t-kfail$SELFTEST_UID-$$-1\]")" 1
  ukill "fuigo-t-kfail$SELFTEST_UID-$$-1.scope"; sleep 1
  chk "failure-injection fixture cleaned up (scope gone)" "$(active "fuigo-t-kfail$SELFTEST_UID-$$-1")" gone
  # containment evidence is read from the cgroup and FAILS CLOSED
  ABORT_CG_MOUNT="$NOPATH" abort_scope_gone some-unit; chk "abort_scope_gone with an unusable cgroup mount is NOT 'gone' (1)" "$?" 1
  abort_scope_gone fuigo-no-such-unit-$SELFTEST_UID; chk "abort_scope_gone: a unit with no cgroup is gone (0)" "$?" 0
  abort_contain_failed 97 && abort_contain_failed 98 && ! abort_contain_failed 0 && ! abort_contain_failed 1; chk "abort_contain_failed: 97 and 98 are containment failures, 0 and 1 are not" "$?" 0
  # gate_abort_run reports failure: a cgroup kill that fails, and a scope that stays populated, are NOT "killed"
  XID=selftest-ga-$SELFTEST_UID-$RANDOM; XRD=$W/gar; mkdir -p "$XRD"; XUB="fuigo-gate-$(printf '%s' "$XID" | tr -c 'A-Za-z0-9' '-')"
  AID=$XID mkscope "$XUB" "$XRD/cgroup.path" 8; disown -a; sleep 2
  ( gate_cg_kill() { echo 1; return 1; }; gate_abort_run "$XRD" "$XID" "$XUB" > /dev/null 2>&1; echo $? > "$W/gar1.rc" )
  chk "gate_abort_run propagates a failing cgroup kill (non-zero) even though the scope did die" "$([ "$(cat "$W/gar1.rc")" != 0 ] && echo nonzero || echo zero)" nonzero
  XID2=selftest-ga2-$SELFTEST_UID-$RANDOM; XRD2=$W/gar2; mkdir -p "$XRD2"; XUB2="fuigo-gate-$(printf '%s' "$XID2" | tr -c 'A-Za-z0-9' '-')"
  AID=$XID2 mkscope "$XUB2" "$XRD2/cgroup.path" 9; disown -a; sleep 2
  ( PATH="$FSD:$PATH"; gate_cg_kill() { echo 0; return 0; }; gate_abort_run "$XRD2" "$XID2" "$XUB2" > /dev/null 2>&1; echo $? > "$W/gar2.rc" )
  chk "gate_abort_run: a scope that is still populated after the kills is reported (non-zero), not cleaned up" "$([ "$(cat "$W/gar2.rc")" != 0 ] && echo nonzero || echo zero)" nonzero
  gate_abort_run "$XRD2" "$XID2" "$XUB2" > /dev/null 2>&1; chk "gate_abort_run with working kills returns 0 and the scope is gone" "$?/$(active "$XUB2")" "0/gone"
  LIBDIR="$HERE" bash "$W/mini-abort.sh" l "$W/mx" exit3 < /dev/null > /dev/null 2>&1; chk "supervisor propagates the runner's exit status (3, not 0)" "$?" 3
  LIBDIR="$HERE" setsid bash "$W/mini-abort.sh" l "$W/mx" exit3 < /dev/null > /dev/null 2>&1; chk "session-leader path propagates the exit status too (3)" "$?" 3
  # gate_reap_scope: the build scope must fail CLOSED
  gate_reap_scope "$W/does-not-exist.path" > /dev/null 2>&1; chk "gate_reap_scope with no cgroup record fails closed (2)" "$?" 2
  RID=selftest-reap-$SELFTEST_UID-$RANDOM; RUN_UNIT="fuigo-gate-$(printf '%s' "$RID" | tr -c 'A-Za-z0-9' '-')-build"
  AID=$RID mkscope "$RUN_UNIT" "$W/reap.path" 6; disown -a; sleep 2
  RN=$(gate_reap_scope "$W/reap.path"); RR=$?
  chk "gate_reap_scope kills a live build scope (wrapper sh + 3 sleeps = 4 procs), returns 0" "$RN/$RR" "4/0"
  chk "gate_reap_scope: scope gone" "$(active "$RUN_UNIT")" gone
fi
# iso-resolve with cargo metadata: exact cargo target names, never guessed
cat > "$W/iso-meta.json" <<'JSON'
{"packages":[
 {"name":"ptyctl-cli","targets":[
   {"name":"ptyctl","kind":["bin"],"src_path":"/w/crates/ptyctl-cli/src/main.rs"},
   {"name":"pty-scenario","kind":["bin"],"src_path":"/w/crates/ptyctl-cli/src/bin/pty_scenario.rs"},
   {"name":"ptyctl_cli","kind":["lib"],"src_path":"/w/crates/ptyctl-cli/src/lib.rs"},
   {"name":"it_one","kind":["test"],"src_path":"/w/crates/ptyctl-cli/tests/it_one.rs"}]},
 {"name":"other","targets":[{"name":"other","kind":["lib"],"src_path":"/w/crates/other/src/lib.rs"}]}]}
JSON
cat > "$W/iso-meta.log" <<'LOG'
     Running unittests src/main.rs (/t/target/debug/deps/ptyctl-aa)
running 1 test
test main_test ... ok
     Running unittests src/bin/pty_scenario.rs (/t/target/debug/deps/pty_scenario-bb)
running 1 test
test scen_test ... ok
     Running unittests crates/ptyctl-cli/src/lib.rs (/t/target/debug/deps/ptyctl_cli-cc)
running 1 test
test lib_test ... ok
     Running tests/it_one.rs (/t/target/debug/deps/it_one-dd)
running 1 test
test it_test ... ok
     Running unittests crates/other/src/lib.rs (/t/target/debug/deps/other-ee)
running 1 test
test other_test ... ok
     Running benches/b.rs (/t/target/release/deps/b-ff)
running 1 test
test bench_test ... ok
LOG
metar() { python3 "$IR" --metadata "$W/iso-meta.json" ptyctl-cli "$W/iso-meta.log" "$@" | tr '\t' '=' | tr '\n' ';'; }
chk "metadata: src/main.rs of package ptyctl-cli -> --bin ptyctl (the target name, not the package name)" "$(metar main_test)" "main_test=--bin ptyctl;"
chk "metadata: [[bin]] pty-scenario with an underscore file name -> --bin pty-scenario" "$(metar scen_test)" "scen_test=--bin pty-scenario;"
chk "metadata: workspace-root-relative lib path -> --lib" "$(metar lib_test)" "lib_test=--lib;"
chk "metadata: integration test -> --test it_one" "$(metar it_test)" "it_test=--test it_one;"
chk "metadata: a header of ANOTHER package is not guessed (UNSUPPORTED)" "$(metar other_test)" "other_test=!UNSUPPORTED Running unittests crates/other/src/lib.rs (/t/target/debug/deps/other-ee);"
chk "metadata: bench is UNSUPPORTED" "$(metar bench_test)" "bench_test=!UNSUPPORTED Running benches/b.rs (/t/target/release/deps/b-ff);"
chk "iso-resolve (metadata): doctest header matching the package's own lib target -> --doc" "$(python3 "$IR" --metadata "$W/iso-meta.json" other "$W/iso-doc.log" 'src/lib.rs - theirs (line 3)' | tr '\t' '=' | tr '\n' ';')" "src/lib.rs - theirs (line 3)=--doc;"
cat > "$W/iso-id.log" <<'LOG'
     Running unittests src/lib.rs (/t/target/debug/deps/other-abcd1234)
running 1 test
test shared_name ... ok
     Running unittests src/lib.rs (/t/target/debug/deps/wanted-ef567890)
running 1 test
test wanted_only ... ok
LOG
cat > "$W/iso-id.json" <<'JSON'
{"packages":[{"name":"wanted","targets":[{"name":"wanted","kind":["lib"],"src_path":"/w/crates/wanted/src/lib.rs"}]},
 {"name":"other","targets":[{"name":"other","kind":["lib"],"src_path":"/w/crates/other/src/lib.rs"}]}]}
JSON
chk "metadata: another package's relative src/lib.rs header is rejected by executable identity" "$(python3 "$IR" --metadata "$W/iso-id.json" wanted "$W/iso-id.log" shared_name | tr '\t' '=' | tr '\n' ';')" "shared_name=!UNSUPPORTED Running unittests src/lib.rs (/t/target/debug/deps/other-abcd1234);"
chk "metadata: the requested package's own header (matching executable) resolves" "$(python3 "$IR" --metadata "$W/iso-id.json" wanted "$W/iso-id.log" wanted_only | tr '\t' '=' | tr '\n' ';')" "wanted_only=--lib;"
chk "heuristic: another package's src/lib.rs header is rejected too" "$(python3 "$IR" wanted "$W/iso-id.log" shared_name | tr '\t' '=' | tr '\n' ';')" "shared_name=!UNSUPPORTED Running unittests src/lib.rs (/t/target/debug/deps/other-abcd1234);"
cat > "$W/iso-amb.json" <<'JSON'
{"packages":[
 {"name":"fuigo-sampler","targets":[{"name":"proxy_dispatch","kind":["test"],"src_path":"/w/crates/fuigo-sampler/tests/proxy_dispatch.rs"}]},
 {"name":"fuigo-extra-ca","targets":[{"name":"proxy_dispatch","kind":["test"],"src_path":"/w/crates/fuigo-extra-ca/tests/proxy_dispatch.rs"}]}]}
JSON
cat > "$W/iso-amb.log" <<'LOG'
     Running tests/proxy_dispatch.rs (/t/target/debug/deps/proxy_dispatch-aaaa1111)
running 1 test
test raw_control_proves_dns_guard ... ok
     Running crates/fuigo-sampler/tests/proxy_dispatch.rs (/t/target/debug/deps/proxy_dispatch-bbbb2222)
running 1 test
test sampler_only ... ok
LOG
chk "metadata: a package-relative tests/x.rs that exists in TWO packages is ambiguous, refused" "$(python3 "$IR" --metadata "$W/iso-amb.json" fuigo-sampler "$W/iso-amb.log" raw_control_proves_dns_guard | cut -f2 | tr '\n' ';')" "!UNSUPPORTED Running tests/proxy_dispatch.rs (/t/target/debug/deps/proxy_dispatch-aaaa1111);"
chk "metadata: the same file named with its crate directory is unambiguous" "$(python3 "$IR" --metadata "$W/iso-amb.json" fuigo-sampler "$W/iso-amb.log" sampler_only | cut -f2 | tr '\n' ';')" "--test proxy_dispatch;"
chk "metadata: ...but not for the OTHER package" "$(python3 "$IR" --metadata "$W/iso-amb.json" fuigo-extra-ca "$W/iso-amb.log" sampler_only | cut -f2 | tr '\n' ';')" "!UNSUPPORTED Running crates/fuigo-sampler/tests/proxy_dispatch.rs (/t/target/debug/deps/proxy_dispatch-bbbb2222);"
cat > "$W/iso-docamb.json" <<'JSON'
{"packages":[{"name":"wanted","targets":[{"name":"shared","kind":["lib"],"src_path":"/w/crates/wanted/src/lib.rs"}]},
 {"name":"other","targets":[{"name":"shared","kind":["lib"],"src_path":"/w/crates/other/src/lib.rs"}]},
 {"name":"solo","targets":[{"name":"solo","kind":["lib"],"src_path":"/w/crates/solo/src/lib.rs"}]}]}
JSON
printf '   Doc-tests shared\nrunning 1 test\ntest src/lib.rs - f (line 1) ... ok\n   Doc-tests solo\nrunning 1 test\ntest src/lib.rs - g (line 1) ... ok\n' > "$W/iso-docamb.log"
chk "metadata: Doc-tests <crate> shared by two packages' libraries is ambiguous, refused" "$(python3 "$IR" --metadata "$W/iso-docamb.json" wanted "$W/iso-docamb.log" 'src/lib.rs - f (line 1)' | cut -f2 | tr '\n' ';')" "!UNSUPPORTED Doc-tests shared;"
chk "metadata: a Doc-tests crate owned by exactly this package still resolves" "$(python3 "$IR" --metadata "$W/iso-docamb.json" solo "$W/iso-docamb.log" 'src/lib.rs - g (line 1)' | cut -f2 | tr '\n' ';')" "--doc;"
chk "metadata: unreadable metadata file exits 2" "$(python3 "$IR" --metadata "$W/nosuch.json" p "$W/iso-meta.log" x > /dev/null 2>&1; echo $?)" 2
chk "heuristic (no metadata) REFUSES a renamed bin instead of guessing --bin <package> (exe ptyctl != package ptyctl_cli)" "$(python3 "$IR" ptyctl-cli "$W/iso-meta.log" main_test | cut -f2)" "!UNSUPPORTED Running unittests src/main.rs (/t/target/debug/deps/ptyctl-aa)"
cat > "$W/iso-id2.log" <<'LOG'
     Running unittests src/main.rs (/t/target/debug/deps/other-abcd1234)
running 1 test
test other_main ... ok
     Running unittests src/main.rs (/t/target/debug/deps/wanted-ef567890)
running 1 test
test wanted_main ... ok
     Running tests/smoke.rs (/t/target/debug/deps/custom_smoke-abcd1234)
running 1 test
test custom_smoke_t ... ok
     Running tests/smoke.rs (/t/target/debug/deps/smoke-1234abcd)
running 1 test
test plain_smoke_t ... ok
     Running unittests src/bin/tool-x.rs (/t/target/debug/deps/tool_y-aaaa)
running 1 test
test wrong_bin ... ok
LOG
h2() { python3 "$IR" wanted "$W/iso-id2.log" "$@" | cut -f2 | tr '\n' ';'; }
chk "heuristic: another package's src/main.rs executable is rejected" "$(h2 other_main)" "!UNSUPPORTED Running unittests src/main.rs (/t/target/debug/deps/other-abcd1234);"
chk "heuristic: the package's own src/main.rs executable resolves" "$(h2 wanted_main)" "--bin wanted;"
chk "heuristic: tests/smoke.rs whose executable is another [[test]] name is rejected" "$(h2 custom_smoke_t)" "!UNSUPPORTED Running tests/smoke.rs (/t/target/debug/deps/custom_smoke-abcd1234);"
chk "heuristic: tests/smoke.rs with a matching executable resolves" "$(h2 plain_smoke_t)" "--test smoke;"
chk "heuristic: src/bin/tool-x.rs with a mismatching executable is rejected" "$(h2 wrong_bin)" "!UNSUPPORTED Running unittests src/bin/tool-x.rs (/t/target/debug/deps/tool_y-aaaa);"
# doctest names contain spaces: the real rustdoc fixture
DTF=$HERE/fixtures/doctest-two-pair-1.94.0.log
DTN='src/lib.rs - double (line 10)'
chk "real doctest fixture contains the name with spaces" "$(grep -c -F "test $DTN ... ok" "$DTF")" 1
chk "iso-resolve: a doctest name WITH SPACES resolves to --doc" "$(python3 "$IR" dtpair "$DTF" "$DTN" | tr '\t' '=')" "$DTN=--doc"
chk "iso.sh: legacy mixed-whitespace name list still splits on ALL whitespace (3 names, no opt-in)" "$(ISO_PRINT_ONLY=1 ISO_PRINT_LOGS=1 bash "$HERE/iso.sh" lane-x pk '--lib' $'unit::a unit::b\nunit::c' sha1 2>&1 | cut -f1 | tr '\n' ';')" "unit::a;unit::b;unit::c;"
chk "iso.sh: with ISO_NAMES_NEWLINE=1 a newline-separated name list keeps a doctest name whole" "$(ISO_NAMES_NEWLINE=1 ISO_PRINT_ONLY=1 ISO_RESOLVER="$IR" ISO_FROM_LOG="$DTF" bash "$HERE/iso.sh" lane-x dtpair auto "$DTN"$'\n'"src/lib.rs - add_one (line 4)" sha1 2>&1 | cut -f2 | tr '\n' ';')" "cargo test --locked -p dtpair --doc -- --exact $DTN;cargo test --locked -p dtpair --doc -- --exact src/lib.rs - add_one (line 4);"
# log-file stems: legacy short stem when unique, full name when two names share a basename; duplicates collapse
stems() { ISO_PRINT_ONLY=1 ISO_PRINT_LOGS=1 bash "$HERE/iso.sh" lane-x pk '--lib' "$1" sha1 2>&1 | cut -f2 | tr '\n' ';'; }
chk "iso.sh log stem: unique names keep the legacy short stem (module path stripped)" "$(stems 'a::one b::two')" "one;two;"
chk "iso.sh log stems: two names sharing a basename get distinct full stems (no overwritten evidence)" "$(stems 'a::same b::same')" "a__same;b__same;"
chk "iso.sh log stems are unique across the WHOLE list (a::same b::same a__same)" "$(stems 'a::same b::same a__same')" "a__same;b__same;a__same-2;"
chk "iso.sh: a duplicated name is isolated once" "$(stems 'x::dup x::dup')" "dup;"
# iso.sh must not wipe an active run's output when refused by the lane lock
ISOL=selftest-isolock-$SELFTEST_UID; mkdir -p "/root/fuigo-builds/$ISOL"; echo "active run output" > "/root/fuigo-builds/$ISOL.out"
( exec 7>"/root/fuigo-builds/$ISOL/.lane.lock"; flock -n 7 && { LIBDIR="$HERE" bash "$HERE/iso.sh" "$ISOL" pk '--lib' x sha1 < /dev/null > /dev/null 2>&1; echo $? > "$W/isolock.rc"; } )
chk "iso.sh refused by the lane lock exits 3" "$(cat "$W/isolock.rc" 2>/dev/null)" 3
chk "iso.sh refused by the lane lock leaves the active run's output intact" "$(cat "/root/fuigo-builds/$ISOL.out")" "active run output"
rm -rf "/root/fuigo-builds/$ISOL" "/root/fuigo-builds/$ISOL.out" "/root/fuigo-builds/$ISOL.sid"

# ---- survivors.txt (coordinator request): the gate must say WHICH processes outlived a phase, recorded BEFORE they are killed
SVW="$W/survivor-planted"; mkdir -p "$SVW"
( FUIGO_GATE_RUN=selftest-sv-$SELFTEST_UID setsid bash -c 'cd / && exec sleep 6041.$SELFTEST_TAG' < /dev/null > /dev/null 2>&1 ) 2> /dev/null &
disown -a; sleep 1
SVP=$(mine_fx "sleep 6041.$SELFTEST_TAG" | head -1)
chk "survivor fixture: planted process running" "$([ -n "$SVP" ] && echo yes || echo no)" yes
gate_survivor_report "$SVW/s.txt" run cgroup "$SVP"; chk "gate_survivor_report writes a block for a live process (status 0)" "$?" 0
SVPP=$(ps -o ppid= -p "$SVP" | tr -d ' ')
chk "survivors: header carries phase, via, pid and ppid" "$(grep -c "^== survivor phase=run via=cgroup pid=$SVP ppid=$SVPP ==$" "$SVW/s.txt")" 1
chk "survivors: FULL command line recorded" "$(grep -c "^cmdline=sleep 6041\.$SELFTEST_TAG \$" "$SVW/s.txt")" 1
chk "survivors: cwd recorded" "$(grep -c '^cwd=/$' "$SVW/s.txt")" 1
chk "survivors: env marker recorded" "$(grep -c "^marker=FUIGO_GATE_RUN=selftest-sv-$SELFTEST_UID\$" "$SVW/s.txt")" 1
chk "survivors: cgroup path recorded" "$(grep -c '^cgroup=0::/' "$SVW/s.txt")" 1
chk "survivors: start time is an ISO-8601 UTC stamp" "$(grep -cE '^state=[A-Za-z] sid=[0-9]+ start=[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:]{8}Z$' "$SVW/s.txt")" 1
chk "survivors: exe recorded" "$(grep -c '^exe=.*/sleep$' "$SVW/s.txt")" 1
chk "survivors: summary line shows the cmdline" "$(gate_survivor_summary "$SVW/s.txt" | grep -c "pid=$SVP ppid=$SVPP  sleep 6041.$SELFTEST_TAG")" 1
gate_survivor_report "$SVW/s2.txt" run env-marker 99999999 unknown-populated
chk "survivors: a vanished pid gets a block saying so, never dropped" "$(grep -c 'pid=99999999 ==$' "$SVW/s2.txt")/$(grep -c 'vanished before it could be inspected' "$SVW/s2.txt")" "1/1"
chk "survivors: a populated cgroup whose members could not be enumerated gets a block too" "$(grep -c 'pid=unknown ==$' "$SVW/s2.txt")/$(grep -c 'could not be enumerated' "$SVW/s2.txt")" "1/1"
: > "$W/not-a-dir"; gate_survivor_report "$W/not-a-dir/s.txt" run cgroup "$SVP" 2> /dev/null; chk "survivors: an unwritable report file fails closed (status 1)" "$?" 1
skill "$SVP"; sleep 0.5
# through gate_reap_scope: the survivors of a build scope are recorded BEFORE they are killed
SRID=selftest-sr-$SELFTEST_UID-$RANDOM; SRUN_UNIT="fuigo-gate-$(printf '%s' "$SRID" | tr -c 'A-Za-z0-9' '-')-build"
AID=$SRID mkscope "$SRUN_UNIT" "$W/sr.path" 7; disown -a; sleep 2
SRN=$(gate_reap_scope "$W/sr.path" "$W/sr.txt" build); SRR=$?
chk "gate_reap_scope with a report: killed 4, status 0, scope gone" "$SRN/$SRR/$(active "$SRUN_UNIT")" "4/0/gone"
chk "gate_reap_scope recorded the 3 sleeps (+ the wrapper shell) with their command lines BEFORE the kill" "$(grep -c "^cmdline=sleep 31[456]7\.$SELFTEST_TAG \$" "$W/sr.txt")/$(grep -c 'phase=build via=cgroup' "$W/sr.txt")" "3/4"
# observed survivors always invalidate the verdict, even if one exits while it is being reported (HIGH, round 10)
SXID=selftest-sx-$SELFTEST_UID-$RANDOM; SX_UNIT="fuigo-gate-$(printf '%s' "$SXID" | tr -c 'A-Za-z0-9' '-')-build"
AID=$SXID mkscope "$SX_UNIT" "$W/sx.path" 8; disown -a; sleep 2
SXN=$( gate_survivor_report() { ukill "$SX_UNIT.scope"; sleep 1; return 0; }; gate_reap_scope "$W/sx.path" "$W/sx.txt" build ); SXR=$?
chk "gate_reap_scope: survivors that exit while being reported are still COUNTED (>=4, status 0), so the verdict is not PASS" "$([ "$SXN" -ge 4 ] && echo counted || echo "no:$SXN")/$SXR" "counted/0"
# the kill scan sees MORE than the report did: a placeholder block says so (never silently dropped)
AID=$SXID mkscope "$SX_UNIT" "$W/sx2.path" 8; disown -a; sleep 2
SXN2=$( gate_cg_kill() { echo 99; return 0; }; gate_survivor_report() { return 0; }; gate_reap_scope "$W/sx2.path" "$W/sx2.txt" build ); SXR2=$?
chk "gate_reap_scope: extra processes seen only by the kill scan are counted and a placeholder block records them" "$([ "$SXN2" -ge 99 ] && echo counted)/$([ "$(grep -c 'additional process(es) appeared between the report scan and the kill' "$W/sx2.txt")" -ge 1 ] && echo placeholder)" "counted/placeholder"
ukill "$SX_UNIT.scope"; sleep 1
# gate_reap_marker: env-marker-only survivors (they left the cgroup) are recorded and killed, in rounds
MKID=selftest-mk-$SELFTEST_UID-$RANDOM
( FUIGO_GATE_RUN=$MKID setsid sleep 6050.$SELFTEST_TAG < /dev/null > /dev/null 2>&1 ) 2> /dev/null &
( FUIGO_GATE_RUN=$MKID setsid bash -c 'sleep 6051.$SELFTEST_TAG & wait' < /dev/null > /dev/null 2>&1 ) 2> /dev/null &
disown -a; sleep 1
MKN=$(gate_reap_marker "$MKID" "nounit-$SELFTEST_UID.scope" "$W/mk.txt" run); MKR=$?
chk "gate_reap_marker: 3 marked processes recorded (via=env-marker) and killed; none left" "$([ "$MKN" -ge 3 ] && echo counted)/$MKR/$(grep -c 'via=env-marker' "$W/mk.txt")/$(pgrep -fc "^sleep 605[01]\.$SELFTEST_TAG\$")" "counted/0/3/0"
# the marker is read even from a large environment (grep -m1 in a pipe under pipefail would lose it). The marker must come FIRST in the
# environment, followed by far more than a pipe buffer (64 KiB), so that a reader that stops at the first match makes the writer die of
# SIGPIPE: `env -i` with explicit arguments fixes that order (bash's own order of prefix assignments is a hash order; with the marker last
# the defect was invisible, and M48 survived on cb2958b8). FUIGO_SELFTEST_ID keeps the fixture this run's (skill / mine_fx).
BIGENV=$(head -c 100000 /dev/zero | tr '\0' 'x')   # (one env string is capped at 128 KiB: use several)
( env -i FUIGO_GATE_RUN=selftest-big-$SELFTEST_UID "PATH=$PATH" "FUIGO_SELFTEST_ID=$FUIGO_SELFTEST_ID" B1=$BIGENV B2=$BIGENV B3=$BIGENV B4=$BIGENV setsid sleep 6052.$SELFTEST_TAG < /dev/null > /dev/null 2>&1 ) 2> /dev/null & disown -a; sleep 1
chk "survivors: large-environment fixture has the marker FIRST, followed by > 64 KiB" "$(q=$(mine_fx "sleep 6052.$SELFTEST_TAG" | head -1); [ -n "$q" ] && head -c 200 "/proc/$q/environ" 2>/dev/null | tr '\0' '\n' | head -1)/$(q=$(mine_fx "sleep 6052.$SELFTEST_TAG" | head -1); [ -n "$q" ] && [ "$(wc -c < "/proc/$q/environ")" -gt 300000 ] && echo big)" "FUIGO_GATE_RUN=selftest-big-$SELFTEST_UID/big"
BIGP=$(mine_fx "sleep 6052.$SELFTEST_TAG" | head -1); gate_survivor_report "$W/big.txt" run cgroup "$BIGP"; gate_kill_if_marked "selftest-big-$SELFTEST_UID" "$BIGP" "" KILL
chk "survivors: the run marker is recorded for a process with a very large environment" "$(grep -c "^marker=FUIGO_GATE_RUN=selftest-big-$SELFTEST_UID\$" "$W/big.txt")" 1
# gate_kill_if_marked: identity (start time) AND marker are re-checked through a pidfd; a recycled pid is never signalled
KMID=selftest-km-$SELFTEST_UID-$RANDOM
( FUIGO_GATE_RUN=$KMID setsid sleep 6060.$SELFTEST_TAG < /dev/null > /dev/null 2>&1 ) 2> /dev/null &
( FUIGO_GATE_RUN=selftest-km-other-$SELFTEST_UID setsid sleep 6061.$SELFTEST_TAG < /dev/null > /dev/null 2>&1 ) 2> /dev/null &
disown -a; sleep 1
KP1=$(mine_fx "sleep 6060.$SELFTEST_TAG" | head -1); KP2=$(mine_fx "sleep 6061.$SELFTEST_TAG" | head -1); KS1=$(gate_pid_starttime "$KP1"); KS2=$(gate_pid_starttime "$KP2")
gate_kill_if_marked "$KMID" "$KP1" "$((KS1 + 1))"; KR1=$?
gate_kill_if_marked "$KMID" "$KP2" "$KS2"; KR2=$?
chk "gate_kill_if_marked: a different start time (= a recycled pid) is NOT killed (3); a process without this run's marker is NOT killed (3)" "$KR1/$KR2/$(pgrep -fc "^sleep 606[01]\.$SELFTEST_TAG\$")" "3/3/2"
gate_kill_if_marked "$KMID" "$KP1" "$KS1"; KR3=$?; sleep 0.5
chk "gate_kill_if_marked: same pid + start time + marker is killed (0)" "$KR3/$(pgrep -fc "^sleep 6060\.$SELFTEST_TAG\$")" "0/0"
gate_kill_if_marked "$KMID" 99999999 1; chk "gate_kill_if_marked: a vanished pid is reported as not killed (3), never an error" "$?" 3
skill "$KP2"
# cgroup freeze: the membership is frozen while it is inspected, and cgroup.kill still kills a frozen scope
FZID=selftest-fz-$SELFTEST_UID-$RANDOM; FZ_UNIT="fuigo-gate-$(printf '%s' "$FZID" | tr -c 'A-Za-z0-9' '-')-build"
AID=$FZID mkscope "$FZ_UNIT" "$W/fz.path" 8; disown -a; sleep 2
FZD=$(gate_cg_resolve "$W/fz.path"); gate_cg_freeze "$FZD"; FZR=$?
chk "gate_cg_freeze freezes the scope (status 0, frozen 1)" "$FZR/$(grep -c '^frozen 1$' "$FZD/cgroup.events")" "0/1"
FZN=$(gate_cg_kill "$FZD"); FZK=$?
chk "cgroup.kill still empties a FROZEN scope" "$FZN/$FZK/$(active "$FZ_UNIT")" "4/0/gone"
# equal-count replacement between scans (A forks B and exits): the second scan adds B by IDENTITY, so both are recorded
RQ=$W/rq; mkdir -p "$RQ/scope"; printf '0::/system.slice/fuigo-gate-rq.scope\n' > "$RQ/rq.path"
( gate_cg_resolve() { echo "$RQ/scope"; }; gate_cg_freeze() { return 1; }; echo 0 > "$RQ/n"
  gate_cg_pids() { local c; c=$(cat "$RQ/n"); echo $((c+1)) > "$RQ/n"; case $c in 0) echo 9004001;; 1) echo 9004002;; *) :;; esac; return 0; }
  gate_cg_kill() { if [ -e "$RQ/killed" ]; then echo 0; else : > "$RQ/killed"; echo 2; fi; return 0; }   # first kill: both A and B were there
  gate_reap_scope "$RQ/rq.path" "$RQ/rq.txt" build > "$RQ/rq.out" )
chk "gate_reap_scope: A replaced by B between scans (equal counts): BOTH are recorded and counted (2), no placeholder" "$(grep -c 'pid=9004001 ' "$RQ/rq.txt")/$(grep -c 'pid=9004002 ' "$RQ/rq.txt")/$(cat "$RQ/rq.out")/$(grep -c 'additional process' "$RQ/rq.txt")" "1/1/2/0"
# safe-kill.py (pidfd): usage and vanished-pid behaviour (marker mode itself is covered by the gate_kill_if_marked cases above)
python3 "$HERE/safe-kill.py" marker selftest-none 99999999 KILL; chk "safe-kill: a vanished pid is 'not signalled' (3), not an error" "$?" 3
python3 "$HERE/safe-kill.py" bogus x 1 KILL 2> /dev/null; chk "safe-kill: bad usage is an error (2)" "$?" 2
python3 "$HERE/safe-kill.py" session 1 1 KILL 2> /dev/null; chk "safe-kill: the removed session mode is refused (2): no session NUMBER is trusted anywhere" "$?" 2
chk "no code path signals a process by session id any more" "$(grep -cE 'pgrep -s|abort_kill_session|gate_kill_session' "$HERE/gate-lib.sh" "$HERE/abort-lib.sh" "$HERE/final-gate.sh" "$HERE/rp.sh" "$HERE/iso.sh" | awk -F: '{s+=$2} END{print s}')" 0
# watchdog liveness is identity (pid + start time): a live process that is NOT the original gate (wrong start time) = the gate is dead
WI=selftest-wi-$SELFTEST_UID-$RANDOM; WIRD=$W/wirun; mkdir -p "$WIRD"; WIUB="fuigo-gate-$(printf '%s' "$WI" | tr -c 'A-Za-z0-9' '-')"
sleep 300 & WIP=$!; disown; WIST=$(gate_pid_starttime "$WIP")
AID=$WI mkscope "$WIUB" "$WIRD/cgroup.path" 9; disown -a; sleep 2
( gate_watchdog "$WIP" "$WIRD" "$WI" "$WIUB" "$((WIST + 1))" 1 > /dev/null 2>&1 )
chk "watchdog: the pid is alive but its start time differs (recycled pid) -> treated as a dead gate: the run is killed" "$(active "$WIUB")/$(grep -c 'killed by watchdog' "$WIRD/watchdog.log" 2>/dev/null)" "gone/1"
skill "$WIP"
# control: matching start time keeps the watchdog waiting (it is stopped by the stop file)
WI2=selftest-wi2-$SELFTEST_UID-$RANDOM; WIRD2=$W/wirun2; mkdir -p "$WIRD2"; sleep 300 & WIP2=$!; disown; WIST2=$(gate_pid_starttime "$WIP2")
( gate_watchdog "$WIP2" "$WIRD2" "$WI2" "fuigo-gate-none-$SELFTEST_UID" "$WIST2" 1 > /dev/null 2>&1 ) & WWP=$!; sleep 3
chk "watchdog: pid + start time match -> still waiting (3 s)" "$([ -n "$WWP" ] && kill -0 "$WWP" 2>/dev/null && echo waiting || echo exited)" waiting
: > "$WIRD2/.wd-stop"; wait "$WWP" 2>/dev/null; skill "$WIP2"
# an abort during a stalled helper command (git fetch / worktree add) is NOT deferred until it finishes, and kills it by scope
BM="$W/mini-bgs"; rm -f "$BM".*
( LIBDIR="$HERE" setsid bash "$W/mini-abort.sh" "mini-bgs-$SELFTEST_UID" "$BM" bgs-only < /dev/null > /dev/null 2>&1; echo $? > "$BM.rc" ) 2> /dev/null &
for i in $(seq 1 40); do [ "$(pgrep -fc "^sleep 7022\.$SELFTEST_TAG\$")" -ge 1 ] && [ -s "$BM.pid" ] && break; sleep 0.25; done
chk "bg helper: the stalled command (sleep 7022.$SELFTEST_TAG) is running under the runner" "$(pgrep -fc "^sleep 7022\.$SELFTEST_TAG\$")" 1
skill -TERM "$(cat "$BM.pid" 2>/dev/null)"
for i in $(seq 1 30); do [ -e "$BM.rc" ] && break; sleep 0.5; done
chk "bg helper: TERM runs the abort trap at once (not after the command finishes): cleaned, exit 143, command killed" "$(cat "$BM.cleaned" 2>/dev/null)/$(cat "$BM.rc" 2>/dev/null)/$(pgrep -fc "^sleep 7022\.$SELFTEST_TAG\$")" "cleaned/143/0"
chk "rp.sh and iso.sh run every git fetch / worktree add / checkout through bg (a scope each)" "$(grep -c 'bg git' "$HERE/rp.sh")/$(grep -c 'bg git' "$HERE/iso.sh")/$(grep -cE '(^|[^g] )git (-C [^ ]+ )?(fetch|worktree add|checkout)' "$HERE/rp.sh" "$HERE/iso.sh" | awk -F: '{s+=$2} END{print s}')" "4/2/0"
chk "final-gate.sh runs git clone/fetch/checkout and cargo metadata through bg" "$(grep -cF 'FUIGO_GATE_RUN=$RUNID bg git' "$HERE/final-gate.sh")/$(grep -c 'bg cargo metadata' "$HERE/final-gate.sh")" "3/2"
# a LAUNCHER that has not registered its scope yet (systemd-run delayed) must be stopped by the abort: otherwise it starts the command after cleanup
LATEBIN="$W/latebin"; mkdir -p "$LATEBIN"; printf '#!/bin/sh\nsleep 4\nexec %s "$@"\n' "$(command -v systemd-run)" > "$LATEBIN/systemd-run"; chmod +x "$LATEBIN/systemd-run"
LM="$W/mini-late"; rm -f "$LM".*
( LATEBIN="$LATEBIN" LIBDIR="$HERE" setsid bash "$W/mini-abort.sh" "mini-late-$SELFTEST_UID" "$LM" late-launch < /dev/null > /dev/null 2>&1; echo $? > "$LM.rc" ) 2> /dev/null &
for i in $(seq 1 40); do [ -s "$LM.pid" ] && break; sleep 0.25; done; sleep 1
skill -TERM "$(cat "$LM.pid" 2>/dev/null)"
for i in $(seq 1 40); do [ -e "$LM.rc" ] && break; sleep 0.5; done
sleep 7   # well past the 4 s launcher delay: a surviving launcher would have started the command by now
chk "delayed launcher: abort during the launch delay -> cleaned (143) and the command NEVER starts (no 'sleep 7023')" "$(cat "$LM.cleaned" 2>/dev/null)/$(cat "$LM.rc" 2>/dev/null)/$(pgrep -fc "^sleep 7023\.$SELFTEST_TAG\$")" "cleaned/143/0"
for u in $(systemctl list-units --all --type=scope --no-legend 2>/dev/null | awk -v p="fuigo-mini-mini-late-$SELFTEST_UID-" 'index($1,p)==1{print $1}'); do ukill "$u"; done   # only this run's scopes
# bg refuses to run a command whose scope it cannot record; records and clears the launcher file; hands the run marker to the command
( : > "$W/not-a-dir"; ABORT_UNITS_FILE="$W/not-a-dir/aux.units"; abort_init t "rec$SELFTEST_UID"; bg sh -c ': > "$1"' x "$W/rec.ran" > /dev/null 2>&1; echo "rc=$?" > "$W/rec.rc" ) 2> /dev/null
chk "bg: an unrecordable unit => the command is NOT run and the status is 97" "$(cat "$W/rec.rc")/$([ -e "$W/rec.ran" ] && echo ran || echo notrun)" "rc=97/notrun"
( ABORT_LAUNCHER_FILE="$W/launcher.rec"; ABORT_UNITS_FILE="$W/units.rec"; : > "$ABORT_UNITS_FILE"; abort_init t "rec2$SELFTEST_UID"; FUIGO_GATE_RUN=selftest-env-$SELFTEST_UID bg sh -c 'echo "$FUIGO_GATE_RUN" > "$1"; cp "$2" "$3"' x "$W/env.seen" "$W/launcher.rec" "$W/launcher.during" > /dev/null 2>&1 )
chk "bg: the launcher is recorded as 'pid starttime' while the command runs, then cleared; the unit is in the units file; FUIGO_GATE_RUN reaches the command" "$(grep -cE '^[0-9]+ [0-9]+$' "$W/launcher.during")/$(wc -c < "$W/launcher.rec" | tr -d ' ')/$(grep -c "^fuigo-t-rec2$SELFTEST_UID-" "$W/units.rec")/$(cat "$W/env.seen")" "1/0/1/selftest-env-$SELFTEST_UID"
chk "final-gate: auxiliary commands carry the run marker, their containment failures are fatal (aux_check) and the launcher file is armed" "$(grep -cF 'FUIGO_GATE_RUN=$RUNID bg ' "$HERE/final-gate.sh")/$(grep -o 'aux_check \$' "$HERE/final-gate.sh" | wc -l | tr -d ' ')/$(grep -c '^ABORT_LAUNCHER_FILE=' "$HERE/final-gate.sh")" "5/5/1"
chk "rp.sh / iso.sh: every bg command is followed by contain_check" "$(grep -o 'contain_check \$' "$HERE/rp.sh" | wc -l | tr -d ' ')/$(grep -o 'contain_check \$' "$HERE/iso.sh" | wc -l | tr -d ' ')" "12/5"
# the ABORT FLAG: with the flag raised a command never starts (bg returns 96, race-free, no pid involved); without it it runs
( ABORT_FLAG="$W/flag.raised"; : > "$ABORT_FLAG"; abort_init t "flg$SELFTEST_UID"; bg sh -c ': > "$1"' x "$W/flag.ran" > /dev/null 2>&1; echo "rc=$?" > "$W/flag.rc" ) 2> /dev/null
chk "abort flag raised: the command does NOT start (bg status 96)" "$(cat "$W/flag.rc")/$([ -e "$W/flag.ran" ] && echo ran || echo notrun)" "rc=96/notrun"
( ABORT_FLAG="$W/flag.absent"; abort_init t "flg2$SELFTEST_UID"; bg sh -c ': > "$1"' x "$W/flag.ran2" > /dev/null 2>&1; echo "rc=$?" > "$W/flag.rc2" ) 2> /dev/null
chk "abort flag absent: the command runs (control)" "$(cat "$W/flag.rc2")/$([ -e "$W/flag.ran2" ] && echo ran || echo notrun)" "rc=0/ran"
( ABORT_FLAG="$W/flag.byabort"; abort_init t "flg3$SELFTEST_UID"; abort_kill_all > /dev/null 2>&1 ); chk "abort_kill_all raises the abort flag" "$([ -e "$W/flag.byabort" ] && echo raised || echo not)" raised
mkdir -p "$W/flagrd"; gate_abort_run "$W/flagrd" selftest-flag-$SELFTEST_UID fuigo-gate-flag-$SELFTEST_UID > /dev/null 2>&1; chk "gate_abort_run raises <rundir>/abort.flag first (also when run by the watchdog)" "$([ -e "$W/flagrd/abort.flag" ] && echo raised || echo not)" raised
chk "final-gate: all three phase wrappers check the abort flag inside their scope (exit 96)" "$(grep -c 'exit 96; shift 2' "$HERE/final-gate.sh")/$(grep -c 'abort.flag" \\$' "$HERE/final-gate.sh")" "3/3"
# the abort flag is per invocation and never deleted by a later invocation of the same lane
chk "rp.sh / iso.sh: the abort flag name is unique per invocation (<lane>.abort.<epoch>.<pid>) and no later run deletes it" "$(grep -c 'ABORT_FLAG="$B/$LANE.abort.$(date +%s).$$"' "$HERE/rp.sh")/$(grep -c 'ABORT_FLAG="$B/$LANE.abort.$(date +%s).$$"' "$HERE/iso.sh")/$(grep -c 'rm -f "$ABORT_FLAG"' "$HERE/rp.sh" "$HERE/iso.sh" "$HERE/final-gate.sh" | awk -F: '{s+=$2} END{print s}')" "1/1/0"
# survivor report: a pid reused by ANOTHER process (start time differs from the one captured at the scan) is not described as the survivor
sleep 300 & RPID=$!; disown; RST=$(gate_pid_starttime "$RPID")
gate_survivor_report "$W/reuse.txt" run env-marker "$RPID@$((RST + 1))"
chk "survivors: pid reused by another process (start time mismatch) -> a 'reused' block, the replacement's command is NOT described" "$(grep -c 'its pid was reused by another process' "$W/reuse.txt")/$(grep -c 'cmdline=sleep 300' "$W/reuse.txt")" "1/0"
gate_survivor_report "$W/reuse2.txt" run env-marker "$RPID@$RST"; chk "survivors: pid@starttime that matches is described normally" "$(grep -c '^cmdline=sleep 300 $' "$W/reuse2.txt")" 1
skill "$RPID"
# the watchdog must stay armed while a scope of the run is still populated
mkdir -p "$W/pop/system.slice/fuigo-gate-popt.scope"; printf 'populated 1\n' > "$W/pop/system.slice/fuigo-gate-popt.scope/cgroup.events"
( GATE_CG_MOUNT="$W/pop"; gate_scopes_populated "$W/pop" fuigo-gate-popt ); chk "gate_scopes_populated: a populated scope is reported (0)" "$?" 0
printf 'populated 0\n' > "$W/pop/system.slice/fuigo-gate-popt.scope/cgroup.events"
( GATE_CG_MOUNT="$W/pop"; gate_scopes_populated "$W/pop" fuigo-gate-popt ); chk "gate_scopes_populated: an empty scope is not (1)" "$?" 1
printf 'garbage\n' > "$W/pop/system.slice/fuigo-gate-popt.scope/cgroup.events"
( GATE_CG_MOUNT="$W/pop"; gate_scopes_populated "$W/pop" fuigo-gate-popt ); chk "gate_scopes_populated: an unreadable state fails closed (0)" "$?" 0
( GATE_CG_MOUNT="$NOPATH"; gate_scopes_populated "$W/pop" fuigo-gate-popt ); chk "gate_scopes_populated: an unusable cgroup mount fails closed (0)" "$?" 0
chk "final-gate: the EXIT trap keeps the watchdog armed while a scope is populated" "$(grep -c 'gate_scopes_populated "$RUNDIR" "$UNITBASE"' "$HERE/final-gate.sh")" 1
chk "rp.sh / iso.sh never delete abort flags (no -delete, no rm of the flag, no pruning)" "$(grep -cE -- '-delete|rm -f "\$ABORT_FLAG"|mmin' "$HERE/rp.sh" "$HERE/iso.sh" | awk -F: '{s+=$2} END{print s}')" 0
# ---- feature-gated test targets (P60): `cargo test -p P` silently skips targets with required-features; they must be LISTED and run
cat > "$W/gt-meta.json" <<'JSON'
{"packages":[
 {"name":"fuigo-shell","targets":[
   {"name":"fuigo_shell","kind":["lib"],"required-features":[],"test":true},
   {"name":"test_startup_prefetch_a","kind":["test"],"required-features":["test-support"]},
   {"name":"test_startup_prefetch_b","kind":["test"],"required-features":["test-support","extra"]},
   {"name":"plain_it","kind":["test"],"required-features":[]},
   {"name":"gated-bin","kind":["bin"],"required-features":["tools"],"test":true},
   {"name":"gated-bin-notest","kind":["bin"],"required-features":["tools"],"test":false},
   {"name":"an_example","kind":["example"],"required-features":["tools"]},
   {"name":"a_bench","kind":["bench"],"required-features":["tools"]}]},
 {"name":"other","targets":[{"name":"o_it","kind":["test"],"required-features":["x"]}]},
 {"name":"clean","targets":[{"name":"c_it","kind":["test"],"required-features":[]}]}]}
JSON
chk "gated-targets: lists gated test and test-enabled bin targets with their features, in order" "$(python3 "$HERE/gated-targets.py" fuigo-shell < "$W/gt-meta.json" | grep -v '^#' | tr '\n' ';')" "fuigo-shell --test test_startup_prefetch_a test-support;fuigo-shell --test test_startup_prefetch_b test-support,extra;fuigo-shell --bin gated-bin tools;"
chk "gated-targets: the --features line is the union, package-qualified (so it is valid with several -p)" "$(python3 "$HERE/gated-targets.py" fuigo-shell < "$W/gt-meta.json" | sed -n 's/^#features //p')" "fuigo-shell fuigo-shell/extra,fuigo-shell/test-support,fuigo-shell/tools"
chk "gated-targets: examples, benches, bins with test=false and un-gated targets are NOT listed" "$(python3 "$HERE/gated-targets.py" fuigo-shell < "$W/gt-meta.json" | grep -cE 'an_example|a_bench|notest|plain_it|fuigo_shell ')" 0
chk "gated-targets: only the requested packages; a package without gated targets prints nothing" "$(python3 "$HERE/gated-targets.py" clean < "$W/gt-meta.json" | wc -l | tr -d ' ')/$(python3 "$HERE/gated-targets.py" other < "$W/gt-meta.json" | grep -c '^other ')" "0/1"
printf '{"reason":"compiler-artifact","package_id":"path+file:///w/p#p@0.1.0","target":{"kind":["lib"],"name":"p","doctest":true},"profile":{"test":false},"executable":null}\n{"reason":"compiler-artifact","package_id":"path+file:///w/p#p@0.1.0","target":{"kind":["test"],"name":"t"},"profile":{"test":true},"executable":"/x/t-1"}\n' > "$W/dv.json"
chk "derive.py: default counts the exe and the lib doc-test run (2); NODOC=1 counts only the test executable (1)" "$(P=p python3 "$HERE/derive.py" < "$W/dv.json" | cut -d' ' -f1)/$(P=p NODOC=1 python3 "$HERE/derive.py" < "$W/dv.json" | cut -d' ' -f1)" "2/1"
chk "rp.sh: second pass wiring (list, features from the targets only, own derived count, own log, failset merged, no --all-features)" "$(grep -c 'gated-targets.py' "$HERE/rp.sh")/$(grep -c 'NODOC=1 python3' "$HERE/rp.sh")/$(grep -c -- '-features.log' "$HERE/rp.sh")/$(grep -c 'sort -u .*failset.m' "$HERE/rp.sh")/$(grep -c -- '--all-features' "$HERE/rp.sh" | tr -d ' ')" "1/1/1/1/0"
chk "final-gate: feature-gated targets are listed in the header and in verdict.txt (never silently dropped)" "$(grep -c 'gated-targets.py' "$HERE/final-gate.sh")/$(grep -c 'feature-gated:' "$HERE/final-gate.sh")" "1/2"
cat > "$W/gt-meta2.json" <<'JSON'
{"packages":[{"name":"fuigo-shell","targets":[{"name":"test_startup_prefetch_a","kind":["test"],"required-features":["test-support"],"src_path":"/w/crates/fuigo-shell/tests/test_startup_prefetch_a.rs"}]}]}
JSON
printf '     Running tests/test_startup_prefetch_a.rs (/t/target/debug/deps/test_startup_prefetch_a-aa)\nrunning 1 test\ntest pf_test ... ok\n' > "$W/gt-log2.log"
chk "safe-kill: signal names keep their letters (INT is INT, not NT)" "$(python3 "$HERE/safe-kill.py" marker x 99999999 INT; echo $?)/$(python3 "$HERE/safe-kill.py" marker x 99999999 SIGSTOP; echo $?)" "3/3"
chk "rp.sh: feature-pass failures are tagged [+features] in the merged failset (identity kept)" "$(grep -c 'sed "s/^/\[+features\] /"' "$HERE/rp.sh")" 1
chk "rp.sh waits on the disk guard (live rp.sh sources it) through a scoped job" "$(grep -c 'bash $B/disk-guard.sh' "$HERE/rp.sh")" 1
chk "rp.sh / iso.sh build fuigo-pager fresh per side/sha, record exit+sha256, exit 5 on failure; rp.sh honours FEAT" "$(grep -c 'binbuild exit=' "$HERE/rp.sh")/$(grep -c 'binbuild exit=' "$HERE/iso.sh")/$(grep -c 'exit 5' "$HERE/rp.sh")/$(grep -c 'exit 5' "$HERE/iso.sh")/$(grep -c 'FEAT=${FEAT:-}' "$HERE/rp.sh")" "1/1/1/1/1"
chk "rp.sh / iso.sh pin FUIGO_BINARY to the fresh build; the pager build takes PAGERFEAT, not the package FEAT" "$(grep -c 'export FUIGO_BINARY=' "$HERE/rp.sh")/$(grep -c 'export FUIGO_BINARY=' "$HERE/iso.sh")/$(grep -c 'build --locked $PAGERFEAT' "$HERE/rp.sh")/$(grep -c 'build --locked $FEAT' "$HERE/rp.sh")" "1/1/1/0"
chk "rp.sh: a failed checkout (or HEAD != the requested revision) is fatal before anything is built (the condition itself, mutant M82)" "$(grep -c 'CHECKOUT FAILED or HEAD' "$HERE/rp.sh")/$(grep -cF '[ $GC -eq 0 ] && [ "$(git rev-parse HEAD)" = "$(git rev-parse $REF)" ] ||' "$HERE/rp.sh")" "1/1"
# default-enabled features: a target whose required-features are all on by default is NOT skipped by cargo test
cat > "$W/gt2.json" <<'JSON'
{"packages":[{"name":"v","features":{"default":["audio"],"audio":["codec"],"codec":[],"extra":[]},
 "targets":[{"name":"probe","kind":["bin"],"required-features":["audio"],"test":true},
            {"name":"viacodec","kind":["test"],"required-features":["codec"]},
            {"name":"needsextra","kind":["test"],"required-features":["extra"]}]}]}
JSON
chk "gated-targets: targets whose required-features are enabled by default (directly or transitively) are not listed" "$(python3 "$HERE/gated-targets.py" v < "$W/gt2.json" | grep -v '^#' | tr '\n' ';')" "v --test needsextra extra;"
chk "gated-targets: invalid metadata is a FAILURE (non-zero), never 'no gated targets'" "$(echo '' | python3 "$HERE/gated-targets.py" v > /dev/null 2>&1; echo $?)" 1
chk "iso-resolve (metadata): a gated target's selector carries its required features" "$(python3 "$IR" --metadata "$W/gt-meta2.json" fuigo-shell "$W/gt-log2.log" pf_test | cut -f2)" "--test test_startup_prefetch_a --features fuigo-shell/test-support"
chk "rp.sh / final-gate.sh: a failed gated-target discovery is fatal (INVALID / INADMISSIBLE)" "$(grep -c 'FEATURE-GATED DISCOVERY FAILED' "$HERE/rp.sh")/$(grep -c 'gated-discovery-failed' "$HERE/final-gate.sh")" "2/2"
# surviving mutants M36 / M46 (full-mode run): evidence of emptiness comes from the CGROUP, never from systemd's state string; the marker reaper
# never signals a process that lacks the marker (a recycled pid)
mkdir -p "$W/sg/system.slice/fuigo-sg-1.scope"; printf 'populated 1\n' > "$W/sg/system.slice/fuigo-sg-1.scope/cgroup.events"; : > "$W/sg/cgroup.controllers"
mkdir -p "$W/fakesc"; printf '#!/bin/sh\n[ "$1" = is-active ] && { echo inactive; exit 3; }\nexit 0\n' > "$W/fakesc/systemctl"; chmod +x "$W/fakesc/systemctl"
( PATH="$W/fakesc:$PATH"; ABORT_CG_MOUNT="$W/sg" abort_scope_gone fuigo-sg-1 ); chk "abort_scope_gone: systemd says 'inactive' but the cgroup is still populated -> NOT gone (1)" "$?" 1
( FUIGO_GATE_RUN=selftest-unm-$SELFTEST_UID setsid sleep 300 < /dev/null > /dev/null 2>&1 ) 2> /dev/null & disown -a; sleep 0.5
UNM=$(mine_fx 'sleep 300' | while read -r q; do { tr '\0' '\n' < /proc/$q/environ; } 2>/dev/null | grep -qx "FUIGO_GATE_RUN=selftest-unm-$SELFTEST_UID" && echo $q; done | head -1); UNMT=$(gate_pid_starttime "$UNM")
( gate_marker_pids() { [ -e "$W/rm.once" ] || { : > "$W/rm.once"; echo "$UNM"; }; return 0; }; rm -f "$W/rm.once"; gate_reap_marker selftest-nomark-$SELFTEST_UID "nounit-$SELFTEST_UID.scope" "$W/rm.txt" run > /dev/null 2>&1 )
chk "gate_reap_marker never kills a process that lacks the run marker (recycled pid): it is still alive" "$([ -n "$UNMT" ] && [ "$(gate_pid_starttime "$UNM")" = "$UNMT" ] && echo alive || echo killed)" alive
gate_kill_if_marked "selftest-unm-$SELFTEST_UID" "$UNM" "$UNMT" KILL
chk "final-gate: the launcher id (pid + start time) is written for all three phases and cleared after each (mutant M59)" "$(grep -c 'echo "$SID $(gate_pid_starttime "$SID")" > "$RUNDIR/launcher.id"' "$HERE/final-gate.sh")/$(grep -c ': > "$RUNDIR/launcher.id"' "$HERE/final-gate.sh")" "3/3"
# structural pins on final-gate.sh wiring (the behaviour behind each is unit-tested above)
chk "final-gate: the build scope's reap status feeds the orphan verdict (fails closed)" "$(grep -c 'BORPH=$(gate_reap_scope "$RUNDIR/cgroup-build.path" "$SURVF" build); BKRC=$?' "$HERE/final-gate.sh")/$(grep -c '\[ "${BKRC:-0}" -ne 0 \] && CKRC=2' "$HERE/final-gate.sh")" "1/1"
chk "final-gate: an abort whose cleanup is incomplete says so and is inventoried (aborted-incomplete)" "$(grep -c 'event=aborted-incomplete' "$HERE/final-gate.sh")" 1
chk "rp.sh stops on a containment failure after every bg command (fetch loop, fetch, worktree add, checkout, derive, test, clippy)" "$(grep -o 'contain_check \$' "$HERE/rp.sh" | wc -l | tr -d ' ')" 12
chk "iso.sh stops on a containment failure after every bg command (fetch loop, worktree add, cargo metadata, isolation run)" "$(grep -o 'contain_check \$' "$HERE/iso.sh" | wc -l | tr -d ' ')" 5
chk "iso.sh auto mode refuses to guess without cargo metadata (opt-in ISO_ALLOW_HEURISTIC=1) and skips the names" "$(grep -c 'auto mode REFUSES to guess' "$HERE/iso.sh")/$(grep -c 'UNRESOLVED (no cargo metadata; not run)' "$HERE/iso.sh")" "1/1"
chk "final-gate: survivors are recorded before any kill: build/list/run via gate_reap_scope, env-marker via gate_reap_marker, summary in verdict.txt, also on the build-failed and list-failed exits" "$(grep -c 'gate_reap_scope "$RUNDIR/cgroup-build.path" "$SURVF" build' "$HERE/final-gate.sh")/$(grep -c 'gate_reap_scope "$RUNDIR/cgroup-list.path" "$SURVF" list' "$HERE/final-gate.sh")/$(grep -c 'gate_reap_scope "$RUNDIR/cgroup.path" "$SURVF" run' "$HERE/final-gate.sh")/$(grep -c 'gate_reap_marker "$RUNID" "$UNIT.scope" "$SURVF" run' "$HERE/final-gate.sh")/$(grep -c 'gate_survivor_summary "$SURVF"' "$HERE/final-gate.sh")/$(grep -c 'surv_note; echo "GATE: INADMISSIBLE (no run happened)"' "$HERE/final-gate.sh")" "1/1/1/1/2/2"
chk "final-gate: the EXIT sweep fails the gate (exit 3) when it finds/cannot inspect anything and keeps the watchdog armed in that case" "$(grep -c '^      exit 3$' "$HERE/final-gate.sh")/$(grep -c '^  gate_wd_stop "$RUNDIR"; exit $rc$' "$HERE/final-gate.sh")" "1/1"
chk "final-gate: build and list phases also sweep the env marker; EXIT sweeps before the watchdog is disarmed" "$(grep -c 'gate_reap_marker "$RUNID" "$UNITBASE" "$SURVF" build' "$HERE/final-gate.sh")/$(grep -c 'gate_reap_marker "$RUNID" "$UNITBASE" "$SURVF" list' "$HERE/final-gate.sh")/$(grep -c '^trap final_sweep EXIT$' "$HERE/final-gate.sh")" "1/1/1"
chk "final-gate: a failed survivor report makes the orphan state unknown (fail closed)" "$(grep -c '\[ "${SREP:-0}" -ne 0 \] && CKRC=2' "$HERE/final-gate.sh")" 1
chk "final-gate: every cgroup-recording wrapper fails closed (exit 97) -- 3 scopes" "$(grep -c 'cat /proc/self/cgroup > "$1" || exit 97' "$HERE/final-gate.sh")" 3
chk "final-gate: guard runs before the hook refusal; INT/TERM/HUP trap installed; watchdog started; abort goes through gate_abort_run (scopes + marker, no session)" "$(grep -c '^abort_guard "${BASH_SOURCE\[0\]}" "$@"$' "$HERE/final-gate.sh")/$(grep -c "INT TERM HUP$" "$HERE/final-gate.sh")/$(grep -c '^gate_wd_start "$RUNDIR" "$$" "$RUNID" "$UNITBASE"$' "$HERE/final-gate.sh")/$(grep -c 'gate_abort_run "$RUNDIR" "$RUNID" "$UNITBASE"' "$HERE/final-gate.sh")" "1/1/1/1"
# ---- STALE BINARY class (P08): like fuigo-test-support, the test builds the pager binary only if the file is ABSENT. Parent and tip
# share one CARGO_TARGET_DIR, so at the tip the PARENT-built binary exists and is reused. Old rp.sh must FAIL the tip expectation
# (tip changes the binary's output); the new rp.sh (fresh binary build per side) must PASS.
SB=$W/stalebin; mkdir -p "$SB/pager/src/bin" "$SB/t/tests" "$SB/t/src"
printf '[workspace]\nmembers = ["pager","t"]\nresolver = "2"\n' > "$SB/Cargo.toml"
printf '[package]\nname = "fuigo-pager-bin"\nversion = "0.0.0"\nedition = "2021"\n[[bin]]\nname = "fuigo-pager"\npath = "src/bin/p.rs"\n' > "$SB/pager/Cargo.toml"
echo 'fn main(){ println!("v1"); }' > "$SB/pager/src/bin/p.rs"
printf '[package]\nname = "stalebintest"\nversion = "0.0.0"\nedition = "2021"\n' > "$SB/t/Cargo.toml"; echo '' > "$SB/t/src/lib.rs"
cat > "$SB/t/tests/t.rs" <<'RS'
#[test]
fn binary_matches_expected_version() {
    let want = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/EXPECT")).unwrap();
    let bin = match std::env::var("FUIGO_BINARY") { Ok(p) => std::path::PathBuf::from(p), Err(_) => std::path::PathBuf::from(std::env::var("CARGO_TARGET_DIR").unwrap()).join("debug/fuigo-pager") };
    if !bin.exists() {   // exactly fuigo-test-support's ensure_local_fuigo_binary(): build only if ABSENT
        assert!(std::process::Command::new("cargo").args(["build", "--locked", "-p", "fuigo-pager-bin", "--bin", "fuigo-pager"]).status().unwrap().success());
    }
    let out = std::process::Command::new(&bin).output().unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), want.trim());
}
RS
echo v1 > "$SB/t/EXPECT"; cp "$HERE/../../rust-toolchain.toml" "$SB/" 2>/dev/null
( cd "$SB" && PATH="/root/.cargo/bin:$PATH" cargo generate-lockfile --offline > /dev/null 2>&1 && git init -q -b main && git add -A && git -c user.name=t -c user.email=t@t commit -q -m parent \
  && echo 'fn main(){ println!("v2"); }' > pager/src/bin/p.rs && echo v2 > t/EXPECT && git -c user.name=t -c user.email=t@t commit -qam tip && git bundle create "$W/stalebin.bundle" main > /dev/null 2>&1 )
SBPAR=$(git -C "$SB" rev-parse HEAD~1 2>/dev/null)
stale_run() { # <label> <rp.sh path> : prints "<parent exit>/<tip exit>", plus "/REFS-NOT-REMOVED" if this run's refs could not be cleaned up
  local ln=selftest-stale-$1-$SELFTEST_UID-$RANDOM out res r refs R0=/root/fuigo-builds/integration/src-p15r
  setsid env -u GATE_ALLOW_NO_EXPECT -u GATE_CG_MOUNT -u GATE_PROC_ROOT "$2" "$ln" "$SBPAR" main "$W/stalebin.bundle" stalebintest < /dev/null > /dev/null 2>&1
  out=/root/fuigo-builds/$ln.out
  res="$(sed -n 's/.*parent stalebintest exit=\([0-9]*\).*/\1/p' "$out")/$(sed -n 's/.*tip stalebintest exit=\([0-9]*\).*/\1/p' "$out")"
  rm -rf "/root/fuigo-builds/$ln" "/root/fuigo-builds/$ln".* "/root/fuigo-builds/$ln"-* 2>/dev/null   # delimited: never a longer lane name that merely starts with this one
  # rp.sh (old and new) hard-codes the SHARED integration repository and leaves refs/remotes/rb-<lane>/* there (the worktree itself is
  # removed by rp.sh): delete exactly this run-unique lane's refs (the 2-commit fixture's objects stay until gc), waiting up to 20 s for
  # a ref lock held by somebody else, then VERIFY the namespace is empty: a leftover changes the printed result, so the assertion fails.
  refs=$(git -C "$R0" for-each-ref --format='%(refname)' "refs/remotes/rb-$ln/" 2>/dev/null) || refs=ENUMERATION-FAILED
  for r in $refs; do [ "$r" = ENUMERATION-FAILED ] || git -C "$R0" -c core.packedRefsTimeout=20000 -c core.filesRefLockTimeout=20000 update-ref -d "$r" > /dev/null 2>&1; done
  refs=$(git -C "$R0" for-each-ref --format='%(refname)' "refs/remotes/rb-$ln/" 2>/dev/null) || refs=ENUMERATION-FAILED
  [ -z "$refs" ] || res="$res/REFS-NOT-REMOVED"
  printf '%s' "$res"
}
# rp.sh.bak is the PRE-PACKET deployed rp.sh (not in git); its identity is pinned, so replacing it cannot turn 0/101 into something else unnoticed
RPBAK_SHA=28299238eee6b50b09c1ce328085a7f2d20444cbd99e1ee51c16af7de85cd53b
if [ "${#SBPAR}" = 40 ] && [ -x /root/fuigo-builds/rp.sh.bak ] && [ "$(sha256sum < /root/fuigo-builds/rp.sh.bak 2>/dev/null | cut -d' ' -f1)" = "$RPBAK_SHA" ]; then
  chk "[stale binary] OLD rp.sh: parent passes, tip FAILS its expectation (stale parent binary reused)" "$(stale_run old /root/fuigo-builds/rp.sh.bak)" "0/101"
  chk "[stale binary] NEW rp.sh: both sides pass (tip tested against the tip binary)" "$(stale_run new "$HERE/rp.sh")" "0/0"
  printf '#!/bin/sh\necho v1\n' > "$W/stale-v1-bin"; chmod +x "$W/stale-v1-bin"
  chk "[stale binary] NEW rp.sh with a poisoned inherited FUIGO_BINARY (stale v1 binary): still 0/0, the pin overrides it" "$(FUIGO_BINARY="$W/stale-v1-bin" stale_run poison "$HERE/rp.sh")" "0/0"
else
  chk "[stale binary] fixture built and /root/fuigo-builds/rp.sh.bak present with the pinned sha256 ($RPBAK_SHA)" "no" "yes"
fi
# GATE_SELFTEST_SKIP_E2E=1 is for MUTANT runs only (R049): it skips the cases that build and run a real final-gate.sh (minutes each).
# The release self-test never sets it; a run with it set says so and cannot be mistaken for the full suite.
if [ "${GATE_SELFTEST_SKIP_E2E:-}" = 1 ]; then echo "SKIP  real final-gate.sh end-to-end cases (GATE_SELFTEST_SKIP_E2E=1: mutant mode, NOT the full suite)"; else
# ---- REAL final-gate.sh aborted mid-BUILD. The demo crate's build.rs sleeps 6001 s, so the gate is in phase 1 (the
# cargo build) when it is aborted. TERM (trap path) and SIGKILL (watchdog path): afterwards NO process of the run may
# exist (env marker AND cgroup AND the sleep itself), the scopes must be gone, and the lane lock must be free.
DEMO=$W/gatedemo; mkdir -p "$DEMO/src"
printf '[package]\nname = "gatedemo"\nversion = "0.0.0"\nedition = "2021"\n' > "$DEMO/Cargo.toml"
echo 'pub fn f() {}' > "$DEMO/src/lib.rs"
printf 'fn main() { std::process::Command::new("sleep").arg("6001.%s").status().unwrap(); }\n' "$SELFTEST_TAG" > "$DEMO/build.rs"
[ -f "$HERE/../../rust-toolchain.toml" ] && cp "$HERE/../../rust-toolchain.toml" "$DEMO/"
( cd "$DEMO" && PATH="/root/.cargo/bin:$PATH" cargo generate-lockfile --offline >/dev/null 2>&1 && git init -q && git add -A && git -c user.name=t -c user.email=t@t commit -q -m demo )
DSHA=$(git -C "$DEMO" rev-parse HEAD 2>/dev/null)
chk "demo crate repo created" "${#DSHA}" 40
gate_abort_case() { # <label> <TERM|KILL>
  local lbl=$1 how=$2 LN GP rc i RUNID2 found sc
  # an earlier asynchronous gate of this suite that never exited (RETAIN_W) shares the demo crate and the build script's process name:
  # this case could not tell its own gate from that one, so it is not run and says so (a failure, never a silent skip)
  [ -z "$RETAIN_W" ] || { chk "[$lbl] can run: no earlier gate of this suite is still alive" "an earlier gate is still alive: case not run" "yes"; return 0; }
  local GAF=$W/ga-$how   # output / exit-status files of THIS invocation only (a late wrapper of an earlier case can never satisfy this one)
  LN=selftest-abort-$SELFTEST_UID-$RANDOM; rm -f "$GAF.out" "$GAF.rc"
  local rw=$RETAIN_W; RETAIN_W=1   # armed while the asynchronous gate may be alive; released only once its wrapper recorded the exit
  # the subshell absorbs bash's "Killed"/"Terminated" job report (stderr must stay empty) and records the gate's exit code
  ( setsid env -u GATE_ALLOW_NO_EXPECT -u GATE_CG_MOUNT -u GATE_PROC_ROOT bash "$HERE/final-gate.sh" --src "$DEMO" --lane "$LN" --pkg gatedemo "$DSHA" 4 < /dev/null > "$GAF.out" 2>&1; echo $? > "$GAF.rc" ) 2> /dev/null &
  for i in $(seq 1 60); do GP=$(cat /root/fuigo-builds/$LN/runs/*/sid 2>/dev/null | head -1); [ -n "$GP" ] && break; sleep 1; done
  found=0; for i in $(seq 1 240); do pgrep -fx "sleep 6001\\.$SELFTEST_TAG" > /dev/null && { found=1; break; }; [ -e "$GAF.rc" ] && break; sleep 1; done
  chk "[$lbl] gate reached its build phase (the build script's sleep is running)" "$found" 1
  chk "[$lbl] the gate printed its sid and wrote runs/<id>/sid (sid == gate pid, it is a session leader)" "$([ -n "${GP:-}" ] && kill -0 "$GP" 2>/dev/null && echo alive)/$(grep -c "abort: pkill -s $GP" "$GAF.out")" "alive/1"
  RUNID2=$(basename "$(ls -d /root/fuigo-builds/$LN/runs/*/ 2>/dev/null | head -1)")
  if [ "$how" = TERM ]; then skill_sid -TERM "$GP"; else skill -9 "$GP"; fi
  for i in $(seq 1 60); do [ -e "$GAF.rc" ] && break; sleep 1; done; rc=$(cat "$GAF.rc" 2>/dev/null)
  for i in $(seq 1 30); do pgrep -fx "sleep 6001\\.$SELFTEST_TAG" > /dev/null || break; sleep 1; done
  chk "[$lbl] no 'sleep 6001' (the build tree) survives the abort" "$(pgrep -fc "^sleep 6001\.$SELFTEST_TAG\$")" 0
  # scoped exactly as final-gate.sh scans (unit prefix): an unreadable process OUTSIDE the run's cgroups is not ours
  hostscan "$RUNID2" "fuigo-gate-$(printf '%s' "$RUNID2" | tr -c 'A-Za-z0-9' '-')"; chk "[$lbl] no process carries the run's env marker (scan status/count)" "$HS_RC/$(printf '%s\n' "$HS_OUT" | grep -c .)" 0/0
  if scl=$(systemctl list-units --all --type=scope --no-legend 2>/dev/null); then sc=$(printf '%s\n' "$scl" | grep -c "fuigo-gate-$(printf '%s' "$RUNID2" | tr -c 'A-Za-z0-9' '-')"); else sc=enumeration-failed; fi
  chk "[$lbl] no systemd scope of the run remains" "$sc" 0
  chk "[$lbl] the lane lock is free again" "$(flock -n "/root/fuigo-builds/$LN/.lane.lock" true && echo free || echo held)" free
  if [ "$how" = TERM ]; then
    chk "[$lbl] gate exits 143 and says it aborted" "$rc/$(grep -c 'GATE: aborted' "$GAF.out")" "143/1"
    chk "[$lbl] inventory records event=aborted" "$(grep -c 'event=aborted' "/root/fuigo-builds/$LN/runs.inventory")" 1
  else
    for i in $(seq 1 60); do grep -q 'killed by watchdog' "/root/fuigo-builds/$LN/runs/$RUNID2/watchdog.log" 2>/dev/null && break; sleep 1; done
    chk "[$lbl] watchdog wrote its log" "$(grep -c 'killed by watchdog' "/root/fuigo-builds/$LN/runs/$RUNID2/watchdog.log" 2>/dev/null)" 1
  fi
  if [ -e "$GAF.rc" ]; then RETAIN_W=$rw; case "$LN" in selftest-abort-*) rm -rf "/root/fuigo-builds/$LN";; esac
  else chk "[$lbl] the gate exited, so its lane /root/fuigo-builds/$LN and the fixture directory $W can be removed" "still-running: both left in place" "exited"; fi
}
# ---- REAL final-gate.sh with a PLANTED SURVIVOR: the demo crate's build script leaves a detached `setsid sleep 6040.$SELFTEST_TAG` (stdio nulled)
# behind. The gate must record it in survivors.txt (phase=build, via=cgroup, its cmdline and the run marker) BEFORE killing it.
DEMO3=$W/gatedemo3; cp -r "$DEMO" "$DEMO3"; rm -rf "$DEMO3/.git"
printf 'fn main() { if std::env::var("GATEDEMO_PLANT").is_ok() { use std::process::{Command, Stdio}; Command::new("setsid").args(["sleep", "6040.%s"]).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap(); } }\n' "$SELFTEST_TAG" > "$DEMO3/build.rs"
( cd "$DEMO3" && git init -q && git add -A && git -c user.name=t -c user.email=t@t commit -q -m demo3 )
D3SHA=$(git -C "$DEMO3" rev-parse HEAD 2>/dev/null)
# a FAILING build whose script leaves a marked helper in ANOTHER systemd scope (outside the build scope): only the env-marker sweep finds it
DEMO5=$W/gatedemo5; cp -r "$DEMO3" "$DEMO5"; rm -rf "$DEMO5/.git"
printf 'fn main() { if std::env::var("GATEDEMO_PLANT").is_ok() { use std::process::{Command, Stdio}; let u = format!("gatedemo5-helper-%s-{}", std::process::id()); Command::new("systemd-run").args(["--scope", "--quiet", "--collect", "--slice=system.slice", &format!("--unit={}", u), "sleep", "6044.%s"]).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap(); std::thread::sleep(std::time::Duration::from_secs(2)); std::process::exit(1); } }\n' "$SELFTEST_TAG" "$SELFTEST_TAG" > "$DEMO5/build.rs"
( cd "$DEMO5" && git init -q && git add -A && git -c user.name=t -c user.email=t@t commit -q -m demo5 )
D5SHA=$(git -C "$DEMO5" rev-parse HEAD 2>/dev/null)
if [ "${#D5SHA}" = 40 ] && command -v systemd-run >/dev/null; then
  LN5=selftest-hscope-$SELFTEST_UID-$RANDOM
  GATEDEMO_PLANT=1 setsid env -u GATE_ALLOW_NO_EXPECT -u GATE_CG_MOUNT -u GATE_PROC_ROOT bash "$HERE/final-gate.sh" --src "$DEMO5" --lane "$LN5" --pkg gatedemo "$D5SHA" 4 < /dev/null > "$W/gh.out" 2>&1; GH5=$?
  VF5=$(ls /root/fuigo-builds/$LN5/runs/*/verdict.txt 2>/dev/null | head -1)
  chk "[helper in another scope] gate exits 3 (build failed)" "$GH5" 3
  chk "[helper in another scope] found by the env marker (phase=build via=env-marker) and listed in verdict.txt with its command line" "$([ -n "$VF5" ] && grep -c "phase=build via=env-marker pid=[0-9]*.*sleep 6044\.$SELFTEST_TAG" "$VF5" || echo none)" 1
  chk "[helper in another scope] killed before the gate exited (no 'sleep 6044')" "$(pgrep -fc "^sleep 6044\.$SELFTEST_TAG\$")" 0
  for u in $(systemctl list-units --all --type=scope --no-legend 2>/dev/null | awk -v p="gatedemo5-helper-$SELFTEST_TAG-" 'index($1,p)==1{print $1}'); do ukill "$u"; done
  case "$LN5" in selftest-hscope-*) rm -rf "/root/fuigo-builds/$LN5";; esac
fi
# a FAILING build that also leaves a detached child: the survivor must still appear in verdict.txt (the gate exits before the verdict)
DEMO4=$W/gatedemo4; cp -r "$DEMO3" "$DEMO4"; rm -rf "$DEMO4/.git"
sed -i 's|spawn().unwrap(); } }|spawn().unwrap(); std::process::exit(1); } }|' "$DEMO4/build.rs"
( cd "$DEMO4" && git init -q && git add -A && git -c user.name=t -c user.email=t@t commit -q -m demo4 )
D4SHA=$(git -C "$DEMO4" rev-parse HEAD 2>/dev/null)
if [ "${#D4SHA}" = 40 ] && command -v systemd-run >/dev/null; then
  LN4=selftest-bfail-$SELFTEST_UID-$RANDOM
  GATEDEMO_PLANT=1 setsid env -u GATE_ALLOW_NO_EXPECT -u GATE_CG_MOUNT -u GATE_PROC_ROOT bash "$HERE/final-gate.sh" --src "$DEMO4" --lane "$LN4" --pkg gatedemo "$D4SHA" 4 < /dev/null > "$W/gb.out" 2>&1; GB4=$?
  VF4=$(ls /root/fuigo-builds/$LN4/runs/*/verdict.txt 2>/dev/null | head -1)
  chk "[failing build + survivor] gate exits 3 INADMISSIBLE and says build failed" "$GB4/$(grep -c 'GATE: build failed' "$W/gb.out")" "3/1"
  chk "[failing build + survivor] verdict.txt exists and lists the survivor (phase=build, sleep 6040.$SELFTEST_TAG)" "$([ -n "$VF4" ] && grep -c "phase=build via=cgroup pid=[0-9]*.*sleep 6040\.$SELFTEST_TAG" "$VF4" || echo none)" 1
  chk "[failing build + survivor] the survivor was killed" "$(pgrep -fc "^sleep 6040\.$SELFTEST_TAG\$")" 0
  case "$LN4" in selftest-bfail-*) rm -rf "/root/fuigo-builds/$LN4";; esac
fi
if [ "${#D3SHA}" = 40 ] && command -v systemd-run >/dev/null; then
  LN3=selftest-surv-$SELFTEST_UID-$RANDOM; rm -f "$W/gs.out" "$W/gs.rc"
  RW3=$RETAIN_W; RETAIN_W=1   # armed BEFORE the asynchronous gate starts (its --src and wrapper files are under $W); released only once it exited
  ( GATEDEMO_PLANT=1 setsid env -u GATE_ALLOW_NO_EXPECT -u GATE_CG_MOUNT -u GATE_PROC_ROOT bash "$HERE/final-gate.sh" --src "$DEMO3" --lane "$LN3" --pkg gatedemo "$D3SHA" 4 < /dev/null > "$W/gs.out" 2>&1; echo $? > "$W/gs.rc" ) 2> /dev/null &
  GS3=""; for i in $(seq 1 300); do SF=$(ls /root/fuigo-builds/$LN3/runs/*/survivors.txt 2>/dev/null | head -1); [ -n "$SF" ] && grep -q '^== survivor' "$SF" 2>/dev/null && break; [ -e "$W/gs.rc" ] && break; sleep 1; done
  RUN3=$(basename "$(ls -d /root/fuigo-builds/$LN3/runs/*/ 2>/dev/null | head -1)")
  chk "[planted survivor] survivors.txt exists and names a survivor" "$(grep -c '^== survivor' "$SF" 2>/dev/null)" 1
  chk "[planted survivor] phase=build via=cgroup, the full command line 'sleep 6040'" "$(grep -c '^== survivor phase=build via=cgroup pid=' "$SF" 2>/dev/null)/$(grep -c "^cmdline=sleep 6040\.$SELFTEST_TAG \$" "$SF" 2>/dev/null)" "1/1"
  chk "[planted survivor] run marker and the build scope's cgroup path recorded" "$(grep -c "^marker=FUIGO_GATE_RUN=$RUN3\$" "$SF" 2>/dev/null)/$(grep -c '^cgroup=0::/system.slice/fuigo-gate-.*-build.scope' "$SF" 2>/dev/null)" "1/1"
  chk "[planted survivor] start time and cwd recorded" "$(grep -cE '^state=. sid=[0-9]+ start=20[0-9]{2}-' "$SF" 2>/dev/null)/$(grep -c '^cwd=/' "$SF" 2>/dev/null)" "1/1"
  # The gate runs to its (INADMISSIBLE) end by itself. Its test phase takes a HOST test slot (slot-run.sh), which production runs can hold
  # for a long time: wait up to 30 min. A gate that is still running then is reported as exactly that (not as a fixture mismatch), is
  # aborted by identity (TERM to the verified members of its own session; it cleans up after itself), and its lane is removed only once it exited.
  for i in $(seq 1 1800); do [ -e "$W/gs.rc" ] && break; sleep 1; done
  if [ ! -e "$W/gs.rc" ]; then
    GP3=$(cat /root/fuigo-builds/$LN3/runs/*/sid 2>/dev/null | head -1); skill_sid -TERM "$GP3"
    for i in $(seq 1 180); do [ -e "$W/gs.rc" ] && break; sleep 1; done
    chk "[planted survivor] the gate finished within 30 min (it was still running, e.g. queued for a host test slot; it was aborted)" "unfinished" "finished"
  fi
  chk "[planted survivor] the gate COMPLETED and rejected the run (exit 3, INADMISSIBLE), it did not pass" "$(cat "$W/gs.rc" 2>/dev/null)/$(grep -c 'INADMISSIBLE' "$W/gs.out")" "3/1"
  chk "[planted survivor] the planted process was killed (no 'sleep 6040')" "$(pgrep -fc "^sleep 6040\.$SELFTEST_TAG\$")" 0
  if [ -e "$W/gs.rc" ]; then RETAIN_W=$RW3; case "$LN3" in selftest-surv-*) rm -rf "/root/fuigo-builds/$LN3";; esac
  else chk "[planted survivor] the gate exited (after the abort), so its lane /root/fuigo-builds/$LN3 and the fixture directory $W can be removed" "still-running: both left in place" "exited"; fi
fi
if [ "${#DSHA}" = 40 ] && command -v systemd-run >/dev/null; then
  gate_abort_case "gate TERM mid-build" TERM
  gate_abort_case "gate SIGKILL mid-build (watchdog)" KILL
fi

fi
if [ -s "$CNF" ]; then failn=$((failn+1)); echo "FAIL  unknown command(s) called, their assertions never ran: $(tr '\n' ';' < "$CNF")"; fi
echo
echo "selftest: $pass passed, $failn failed   (fixtures: $W)"
[ $failn -eq 0 ]
