#!/usr/bin/env bash
# release-gate.sh [final-gate.sh options] <sha> <jobs>
#
# The release gate: the default-test gate AND the ignored PTY suite, both on the same <sha>, one after the other in the
# same lane (the second run reuses the first one's build). Each is a full final-gate.sh run with its own run directory,
# log and A.2.1 verdict:
#   1. final-gate.sh [options] <sha> <jobs>          the workspace (or --pkg) tests a plain `cargo test` runs
#   2. final-gate.sh --pty [options] <sha> <jobs>    the `#[ignore]`d tests that drive the real pager binary in a PTY,
#                                                    listed in scripts/strike/pty-targets.txt
# A plain `cargo test` skips every ignored test, so a gate that only ran (1) never exercised the terminal UI end to end.
#
# The release passes only if BOTH verdicts are `ADMISSIBLE: YES` / `GATE: PASS`. Exit status is the worst of the two
# (0 pass, 1 admissible but red, 3 inadmissible, 2 usage). --pkg and --pty are refused here: (1) takes --pkg through
# final-gate.sh directly, and (2) is always the fixed pty-targets.txt list. Options such as --network none|host, --src,
# --lane and --timeout apply to both runs.
set -uo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
for a in "$@"; do
  case "$a" in
    --pkg|--pty) echo "release-gate: $a is not accepted (run final-gate.sh directly for a partial gate)" >&2; exit 2;;
  esac
done
[ $# -ge 2 ] || { echo "usage: release-gate.sh [final-gate.sh options] <sha> <jobs>" >&2; exit 2; }
"$HERE/final-gate.sh" "$@"; RC1=$?
# an aborted run (TERM/INT/HUP => 143) means someone stopped the gate: do not start the second half behind their back
[ "$RC1" -ne 143 ] || { echo "RELEASE-GATE: aborted during the default-test run (exit 143); the PTY run was not started"; exit 143; }
"$HERE/final-gate.sh" --pty "$@"; RC2=$?
echo "RELEASE-GATE: default tests exit=$RC1, ignored PTY suite exit=$RC2   (0 = PASS, 1 = admissible but red, 3 = INADMISSIBLE)"
RC=$RC1; [ "$RC2" -le "$RC" ] || RC=$RC2   # the larger code is the worse one: 3 > 2 > 1 > 0
if [ "$RC" -eq 0 ]; then echo "RELEASE-GATE: PASS"; else echo "RELEASE-GATE: NOT PASSED"; fi
exit $RC
