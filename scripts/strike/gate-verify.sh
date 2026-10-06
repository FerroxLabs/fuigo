#!/usr/bin/env bash
# gate-verify.sh <log> <derived> [expected-n-file]   -- judge ONE gate log by Contract A.2.1 (docs/strike/contracts/A-release-acceptance.md)
#
# COMPLETENESS IS CHECKED BEFORE CORRECTNESS (R011). A log is ADMISSIBLE only if ALL hold:
#   1. target_headers (cargo `^ +(Running|Doc-tests) ` lines, log captured with 2>&1) == <derived>
#      and every header reaches its own `test result:` line before the next header / end of log;
#   2. exactly one `GATE_CARGO_EXIT=<n>` line, n neither 124 (timeout) nor >=128 (signal);
#   3. the `GATE_DONE` marker is the LAST non-empty line (anything appended after it means an
#      orphaned test binary was still writing).
# `^running N tests` and `^test result:` are NEVER used as a target count (tests that drive child
# test processes print both again: 52 each on fuigo-shell against 37 targets).
# The failing set is the `failures:` block, NEVER a count of FAILED lines (an interleaved FAILED
# line is missed by grep: fuigo-pager 19 by grep against 20 in the block).
#
# Output: key=value lines; failing set to <log>.failset.
# Exit: 0 admissible and green | 1 admissible but red | 3 INADMISSIBLE (not evidence) | 2 usage.
set -uo pipefail
LOG=${1:?usage: gate-verify.sh <log> <derived> [expected-n-file]}; DERIVED=${2:?usage: gate-verify.sh <log> <derived> [expected-n-file]}
EXPECT=${3:-}   # lines "<exe-basename> <N>" from list-counts.py: independent per-binary test counts
[ -f "$LOG" ] || { echo "gate-verify: no such log $LOG" >&2; exit 2; }
case "$DERIVED" in ''|*[!0-9]*) echo "gate-verify: derived must be an integer" >&2; exit 2;; esac

# Work on a normalised copy (CR and ANSI colour stripped) so CRLF / coloured logs are judged by content.
NEXPECT=0; EXPECT_ERR=""; EXPCOPY=$(mktemp)
if [ -z "$EXPECT" ]; then
  [ "${GATE_ALLOW_NO_EXPECT:-0}" = 1 ] || EXPECT_ERR="no expected-N file given: independent per-binary counts are mandatory (GATE_ALLOW_NO_EXPECT=1 is for structural self-tests only)"
elif ! cat "$EXPECT" > "$EXPCOPY" 2>/dev/null; then EXPECT_ERR="expected-N file $EXPECT unreadable"
else NEXPECT=$(grep -c . "$EXPCOPY" || true); [ "$NEXPECT" -gt 0 ] || EXPECT_ERR="expected-N file $EXPECT is empty (listing failed): independent counts unavailable"; fi
NORM=$(mktemp); AWKOUT=$(mktemp); trap 'rm -f "$NORM" "$EXPCOPY" "$AWKOUT"' EXIT
if ! sed -e 's/\r$//' -e 's/\x1b\[[0-9;]*[A-Za-z]//g' "$LOG" > "$NORM"; then
  echo "ADMISSIBLE: NO"; echo "  reason: could not read/normalise the log (partial read)"; echo "GATE: INADMISSIBLE (not evidence of anything)"; exit 3
fi
LOGSHA=$(sha256sum "$LOG" | cut -d' ' -f1) || { echo "ADMISSIBLE: NO"; echo "  reason: cannot hash the log"; exit 3; }
# A.2.1 rule 1 (corrected, see R029). A header is FINISHED only if, between it and the next header/EOF:
#   - its own first `running N tests` line appears (and, when an expected-N file is given, N equals the count the
#     binary itself reports under `--list`: this closes the delayed-child-pair path), and
#   - AFTER that line, the LAST well-formed `test result: (ok|FAILED). P passed; F failed; I ignored; M measured; X
#     filtered out` line has P+F+I+M == N, and no `running` line follows that last result.
# Results seen before the target's own `running` line (a delayed child summary) do not count; malformed summaries
# do not count. Text alone CANNOT prove who printed a result line: a child whose totals equal the parent's N, with
# the parent exiting 0 without its own summary, is indistinguishable. That residual is only reachable with
# cargo_exit==0 (a crashed or aborted parent makes cargo exit non-zero, which can never PASS). It is documented in
# R029 as a limit of log-based verification. `running`/`result` line COUNTS are not compared: real fuigo-shell
# logs carry child output whose counts differ.
# `Doc-tests` sections follow a PAIRING rule instead (Fable audit, MEDIUM): edition-2024 rustdoc prints one
# `running N` / `test result:` pair for the merged doctests and a second pair for standalone ones (compile_fail,
# should_panic with edition-specific attributes, ...) under ONE header. A Doc-tests header is FINISHED only if
# each `running N` is followed, before any other `running` line, by a well-formed result whose P+F+I+M == N; there
# are 1 or 2 such pairs; no `running` is left unpaired at the end; and no well-formed result appears without a
# pending `running`. Running (test-binary) sections keep the single-pair rule above.
awk -v expect="$EXPCOPY" '
  BEGIN{ while((getline l < expect)>0){ split(l,a," "); if(a[1] ~ /^doc:/) docexp[a[1]]=1; else { expn[a[1]]=a[2]; ne++ } } }
  function fin(){ if(!b) return; if(isdoc){ if(!(pairs>=1 && pairs<=2 && pend<0 && !dbad)) u++ } else if(!(R>=1 && S>=1 && lastT==firstN && !runAfter && ownOk)) u++ }
  /^ +Doc-tests /{ seen["doc:" $2]++ }
  /^ +(Running|Doc-tests) /{ fin(); b=1; n++; R=0; S=0; firstN=-1; lastT=-2; runAfter=0; ownOk=1; want="";
      isdoc=($1=="Doc-tests"); pairs=0; pend=-1; dbad=0;
      if($1=="Running"){ if(match($0,/\(\/[^)]*\)$/)){ pth=substr($0,RSTART+1,RLENGTH-2); k=split(pth,pp,"/"); want=pp[k]; seen[want]++ } else if(ne>0) ownOk=0 } next }
  b && isdoc && /^running [0-9]+ tests?$/ { if(pend>=0) dbad=1; pend=$2+0; next }
  b && isdoc && /^test result: (ok|FAILED)\. [0-9]+ passed; [0-9]+ failed; [0-9]+ ignored; [0-9]+ measured; [0-9]+ filtered out; finished in [0-9]+\.[0-9]+s$/ {
      if(pend<0) dbad=1; else { if($4+$6+$8+$10 != pend) dbad=1; pairs++; pend=-1 }
      if($3=="FAILED." || $6+0>0) red++; next }
  b && /^running [0-9]+ tests?$/ { R++; if(R==1){ firstN=$2+0; if(want!="" && (want in expn) && expn[want]!=firstN) ownOk=0; if(want!="" && !(want in expn) && ne>0) ownOk=0 } else if(S>=1) runAfter=1; next }
  b && R>=1 && /^test result: (ok|FAILED)\. [0-9]+ passed; [0-9]+ failed; [0-9]+ ignored; [0-9]+ measured; [0-9]+ filtered out; finished in [0-9]+\.[0-9]+s$/ {
      S++; runAfter=0; lastT=$4+$6+$8+$10; if($3=="FAILED." || $6+0>0) red++; next }
  END{ fin(); for(k in expn) if(seen[k]!=1) inv++; for(k in docexp) if(seen[k]!=1) inv++; for(k in seen) if(seen[k]>1) inv++; print n+0, u+0, red+0, inv+0 }' "$NORM" > "$AWKOUT"; AWKRC=$?
read -r HEADERS UNFINISHED REDRES INVMIS < "$AWKOUT"
[ $AWKRC -eq 0 ] && [ -n "${HEADERS:-}" ] || { echo "ADMISSIBLE: NO"; echo "  reason: header parser failed (awk exit $AWKRC)"; echo "GATE: INADMISSIBLE (not evidence of anything)"; exit 3; }
FAILSET="$LOG.failset"
FSERR=""
awk '/^failures:$/{f=1;next} f&&/^ +[^ ]/{sub(/^ +/,""); print} f&&/^$/{f=0}' "$NORM" > "$FAILSET.raw" || FSERR="failure-set extraction (awk) failed"
sort -u "$FAILSET.raw" > "$FAILSET" || FSERR="failure-set extraction (sort) failed"
rm -f "$FAILSET.raw"
NFAIL=$(wc -l < "$FAILSET" | tr -d ' ')
# informational only -- shows the undercount the block-based set avoids
FAILED_LINES=$(grep -cE '^test .* FAILED$' "$LOG" || true)

EXITS=$(grep -E '^GATE_CARGO_EXIT=[0-9]+$' "$NORM" | cut -d= -f2)
NEXITS=$(printf '%s' "$EXITS" | grep -c . || true)
CARGO_EXIT=${EXITS##*$'\n'}
LAST=$(grep -v '^[[:space:]]*$' "$NORM" | tail -n 1)

WHY=()
[ "$HEADERS" -eq "$DERIVED" ] || WHY+=("target_headers=$HEADERS != derived=$DERIVED")
[ -z "$EXPECT_ERR" ] || WHY+=("$EXPECT_ERR")
[ -z "$FSERR" ] || WHY+=("$FSERR")
[ "${INVMIS:-0}" -eq 0 ] || WHY+=("$INVMIS expected binar(y/ies) missing, or a binary ran more than once: duplicates cannot stand in for missing targets")
[ "$UNFINISHED" -eq 0 ] || WHY+=("$UNFINISHED header(s) never reached a test result: line (cut inside a binary, or aborted)")
if [ "$NEXITS" -ne 1 ]; then WHY+=("cargo_exit not recorded exactly once (found $NEXITS)")
elif [ "$CARGO_EXIT" -eq 124 ]; then WHY+=("cargo_exit=124: timeout")
elif [ "$CARGO_EXIT" -ge 128 ]; then WHY+=("cargo_exit=$CARGO_EXIT: killed by signal $((CARGO_EXIT-128))"); fi
grep -q '^GATE_ORPHANS=' "$NORM" && WHY+=("test processes survived the run, or the survivor scan failed (GATE_ORPHANS)")
grep -q '^GATE_TREE_DIRTY=' "$NORM" && WHY+=("source tree was dirty before or after the run (GATE_TREE_DIRTY)")
[ "$(grep -c '^GATE_TREE=' "$NORM")" -eq 1 ] || WHY+=("GATE_TREE=<tree hash> not recorded exactly once")
if ! grep -qx 'GATE_DONE' "$NORM"; then WHY+=("GATE_DONE marker absent")
elif [ "$LAST" != "GATE_DONE" ]; then WHY+=("output after GATE_DONE: an orphaned process kept writing"); fi

echo "log:            $LOG"
echo "log_sha256:     $LOGSHA"
echo "tree:           $(grep -m1 "^GATE_TREE=" "$NORM" | cut -d= -f2)"
echo "target_headers: $HEADERS"
echo "derived:        $DERIVED"
echo "unfinished:     $UNFINISHED"
echo "cargo_exit:     ${CARGO_EXIT:-none}"
echo "done_marker:    $(grep -qx GATE_DONE "$NORM" && echo present || echo absent)"
echo "failed_results:  ${REDRES:-0}   (test result: FAILED / non-zero failed counts)"
echo "failing_set:    $NFAIL   (from the failures: block -> $FAILSET)"
echo "failed_lines:   $FAILED_LINES   (informational: grep '^test .* FAILED\$', never the gate)"
if [ ${#WHY[@]} -gt 0 ]; then
  echo "ADMISSIBLE: NO"
  for w in "${WHY[@]}"; do echo "  reason: $w"; done
  echo "GATE: INADMISSIBLE (not evidence of anything)"
  exit 3
fi
echo "ADMISSIBLE: YES"
if [ "$CARGO_EXIT" -eq 0 ] && [ "$NFAIL" -eq 0 ] && [ "${REDRES:-0}" -gt 0 ]; then echo "GATE: FAIL (a test result reports failures but the failures: block is empty: inconsistent log)"; exit 1; fi
if [ "$CARGO_EXIT" -eq 0 ] && [ "$NFAIL" -eq 0 ]; then echo "GATE: PASS"; exit 0; fi
if [ "$NFAIL" -eq 0 ]; then echo "GATE: FAIL (cargo_exit=$CARGO_EXIT with an empty failing set: unexplained, e.g. a compile error or an abort)"; exit 1; fi
if [ "$CARGO_EXIT" -eq 0 ]; then echo "GATE: FAIL (cargo_exit=0 but failures: block non-empty: inconsistent log)"; exit 1; fi
echo "GATE: FAIL ($NFAIL failing; see failing set)"; cat "$FAILSET" | sed 's/^/  /'
exit 1
