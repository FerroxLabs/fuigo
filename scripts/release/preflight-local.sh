#!/usr/bin/env bash
# Preflight: every cheap check the release workflow runs before its long builds, runnable without GitHub.
# The same script runs in .github/workflows/preflight.yml and from the pre-squash replay. No network beyond
# the optional cargo fetch of --compile-check.
#
#   scripts/release/preflight-local.sh [--compile-check] [--require-shellcheck]
#
#   --compile-check               also `cargo check --profile release-dist -p fuigo-pager-bin` (type-checks the dist feature set;
#                         a full LTO link does not fit 20 min. Needs toolchain and protoc; off by default locally)
#   --require-shellcheck  fail (not skip) when shellcheck is missing; the workflow sets it, because a skipped
#                         a skipped check is how an SC2016 info reached a 5-hour dry run in 1.0.45
#
# Prints one `PREFLIGHT <step> ok|FAIL` line per step and `PREFLIGHT: PASS|FAIL`; every step runs even when an
# earlier one fails, so one run shows the whole damage. Exit 0 only when all steps pass.
set -uo pipefail
cd "$(cd "$(dirname "$0")/../.." && pwd)" || exit 2
CCHK=0; REQ_SC=0
for a in "$@"; do
  case $a in
    --compile-check) CCHK=1 ;;
    --require-shellcheck) REQ_SC=1 ;;
    *) echo "usage: $0 [--compile-check] [--require-shellcheck]" >&2; exit 2 ;;
  esac
done
# A shellcheck binary the shared build box keeps outside the system packages (see install-shellcheck.sh).
SHARED_BIN=${PREFLIGHT_BIN_DIR:-/root/fuigo-builds/shared/bin}
[ -d "$SHARED_BIN" ] && PATH=$SHARED_BIN:$PATH
NPM=crates/codegen/fuigo-pager/npm/fuigo
LOGDIR=$(mktemp -d "${TMPDIR:-/tmp}/preflight.XXXXXX"); trap 'rm -rf "$LOGDIR"' EXIT
failed=()
step() { # <name> <command...>
  local n=$1; shift
  if "$@" > "$LOGDIR/$n.log" 2>&1; then echo "PREFLIGHT $n ok"
  else echo "PREFLIGHT $n FAIL"; sed 's/^/    | /' "$LOGDIR/$n.log" | tail -40; failed+=("$n"); fi
}

# The release workflow's "Check versions" and "Test same-version reinstall" steps (job publish).
step npm-postinstall   bash -c "cd $NPM && node scripts/test-postinstall.js"
step npm-provenance    bash -c "cd $NPM && node scripts/test-release-provenance.js"
step release-scripts   bash -c "cd $NPM && ../../../../../scripts/release/test-release-scripts.sh"
step npm-check-version bash -c "cd $NPM && node scripts/sync-version.js --check"
# (package-notices.js --check is not run: the packaged LICENSE copies exist only after `assemble`, so it fails on a clean checkout.)
step npm-reinstall     bash -c "cd $NPM && node scripts/test-reinstall.js"
# The release workflow's signed-binary tripwire tests and the Linux floor checker tests.
step signed-binary-test python3 scripts/release/test-check-signed-binary.py
step linux-floor-test   python3 scripts/release/test_check_linux_floor.py
step memory-bench-test  python3 -m unittest discover -s scripts/memory-bench -p test_stream_parser.py
# Leak guard (self-test, then the tree).
step leak-guard-test   scripts/release/test-check-token-leaks.sh
step leak-guard        python3 -I scripts/release/check-token-leaks.py
# Workflow hygiene: every `uses:` in every workflow pinned to a full commit SHA.
step action-pins bash -c '! grep -hE "^\s*-?\s*uses:" .github/workflows/*.yml | grep -vE "uses: *\./" | grep -vE "uses: *[^ @]+@[0-9a-f]{40}( |$)"'
# Lint the release scripts that are clean today (the rest, and scripts/strike and scripts/ci, are not yet
# clean; see NOTES). This is what the 1.0.45 dry run tripped on.
if command -v shellcheck > /dev/null; then
  step shellcheck bash -c 'cd scripts/release && shellcheck registry-release-inputs.sh github-release-assets.sh test-release-scripts.sh preflight-local.sh test-check-token-leaks.sh public-squash.sh install-shellcheck.sh pr-ci-replay.sh'
elif [ "$REQ_SC" = 1 ]; then
  echo "PREFLIGHT shellcheck FAIL (not installed, --require-shellcheck)"; failed+=(shellcheck)
else
  echo "PREFLIGHT shellcheck SKIP (not installed; the workflow requires it)"
fi
if [ "$CCHK" = 1 ]; then
  step compile-check bash -c 'cargo check --locked --profile release-dist -p fuigo-pager-bin'
fi

if [ ${#failed[@]} -eq 0 ]; then echo "PREFLIGHT: PASS"; exit 0; fi
echo "PREFLIGHT: FAIL (${failed[*]})"; exit 1
