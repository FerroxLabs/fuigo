#!/usr/bin/env bash
# Pre-squash replay: the Linux pull_request CI checks that the final gate (scripts/strike/final-gate.sh, tests only)
# does not cover, run locally before any public squash.
#
#   scripts/release/pr-ci-replay.sh [--receipts DIR] [--no-preflight] [preflight-local.sh flags...]
#
# Steps, in workflow order:
#   lint.yml          fmt (`cargo fmt --all -- --check`) and deny (`cargo deny check advisories bans sources`, skipped
#                     with a FAIL when cargo-deny is missing)
#   dispatch-policy.yml  every run step: the dispatch lint positive and negative controls (the negative must fail with
#                     all four disallowed-method diagnostics), session-writer crates and controls, the shipping
#                     clippy, and the compatibility, crossterm and GCS test runs
#   preflight         scripts/release/preflight-local.sh with the remaining flags (e.g. --require-shellcheck)
# Not covered here: macos-tests.yml and windows-process-check.yml (OS-specific, judged by the real PR checks);
# binary-driven-tests.yml is covered by final-gate.sh.
#
# Cargo flags come from the environment (CARGO_TARGET_DIR, CARGO_BUILD_JOBS, RUST_MIN_STACK, PROTOC ...). Set
# PR_CI_WRAP to a command prefix for every cargo-running step, e.g. PR_CI_WRAP="/root/fuigo-builds/slot-run.sh <lane>".
# Prints one `PR_CI <step> ok|FAIL` line per step and `PR_CI_REPLAY: PASS|FAIL`; every step runs even after a failure.
# Exit 0 only when every step passes.
# The step functions below run only through step(), which shellcheck cannot see.
# shellcheck disable=SC2317
set -uo pipefail
cd "$(cd "$(dirname "$0")/../.." && pwd)" || exit 2
RECEIPTS=dispatch-receipts; PREFLIGHT=1; PF_ARGS=()
while [ $# -gt 0 ]; do
  case $1 in
    --receipts) [ $# -ge 2 ] || { echo "usage: $0 [--receipts DIR] [--no-preflight] [preflight flags...]" >&2; exit 2; }
      RECEIPTS=$2; shift 2 ;;
    --no-preflight) PREFLIGHT=0; shift ;;
    *) PF_ARGS+=("$1"); shift ;;
  esac
done
mkdir -p "$RECEIPTS" || exit 2
RECEIPTS=$(cd "$RECEIPTS" && pwd)
# Word splitting of the prefix is intended: it is a command plus its arguments.
read -r -a WRAP <<< "${PR_CI_WRAP:-}"
failed=()
step() { # <name> <command...>; output to $RECEIPTS/<name>.log
  local n=$1; shift
  if "$@" > "$RECEIPTS/$n.log" 2>&1; then echo "PR_CI $n ok"
  else echo "PR_CI $n FAIL"; tail -40 "$RECEIPTS/$n.log" | sed 's/^/    | /'; failed+=("$n"); fi
}
run() { if [ ${#WRAP[@]} -gt 0 ]; then "${WRAP[@]}" "$@"; else "$@"; fi; }
negative() { # dispatch lint negative control: must fail, and name all four disallowed methods
  if run cargo clippy --locked -p fuigo-extra-ca --example dispatch_lint_control --no-deps -- --cfg f06_raw_dispatch \
      -D clippy::disallowed_methods > "$RECEIPTS/negative.log" 2>&1; then
    echo 'Unchecked dispatch unexpectedly compiled'; return 1
  fi
  local m rc=0
  for m in 'reqwest::RequestBuilder::send' 'reqwest::Client::execute' 'reqwest::blocking::RequestBuilder::send' \
      'reqwest::blocking::Client::execute'; do
    grep -F "error: use of a disallowed method \`$m\`" "$RECEIPTS/negative.log" || { echo "missing diagnostic: $m"; rc=1; }
  done
  return "$rc"
}
deny() {
  command -v cargo-deny > /dev/null || { echo 'cargo-deny not installed'; return 1; }
  run cargo deny check advisories bans sources
}

echo "PR_CI head $(git rev-parse HEAD 2>/dev/null) tree $(git rev-parse 'HEAD^{tree}' 2>/dev/null)"
step fmt run cargo fmt --all -- --check
step deny deny
step dispatch-positive run cargo clippy --locked -p fuigo-extra-ca --example dispatch_lint_control --no-deps -- \
  -D clippy::disallowed_methods
step dispatch-negative negative
step session-writer-crates scripts/ci/session-writer-crates.sh
step session-writer-controls run scripts/ci/session-writer-controls.sh "$RECEIPTS/controls"
step shipping run cargo clippy --locked --workspace --lib --bins --no-deps -- -D clippy::disallowed_methods
step compatibility run cargo test --locked -p fuigo-extra-ca -p ptyctl-cli -- --test-threads=1
step crossterm run cargo test --locked -p crossterm --lib -- --test-threads=1
step gcs-auth run cargo test --locked -p gcloud-auth -p gcloud-metadata --lib -- --test-threads=1
step gcs-storage run cargo test --locked -p fuigo-file-utils --lib gcs_ -- --test-threads=1
if [ "$PREFLIGHT" = 1 ]; then step preflight scripts/release/preflight-local.sh ${PF_ARGS[@]+"${PF_ARGS[@]}"}; fi

if [ ${#failed[@]} -eq 0 ]; then echo "PR_CI_REPLAY: PASS"; exit 0; fi
echo "PR_CI_REPLAY: FAIL (${failed[*]})"; exit 1
