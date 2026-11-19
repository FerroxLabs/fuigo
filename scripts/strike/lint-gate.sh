#!/usr/bin/env bash
# lint-gate.sh <src-dir>
#
# Lint and dependency pre-steps of the private release gate (called by final-gate.sh, workspace scope only).
# Every step runs (a failure does not hide the next one) and the exit status is non-zero if ANY step failed.
#   1. cargo fmt --all -- --check
#   2. cargo clippy --locked --workspace --all-targets -- -D warnings
#   3. scripts/strike/lint-ratchet.sh   (unwrap/expect/await_holding_lock: own crates 0, inherited crates may not rise)
#   4. cargo deny check                 (advisories, bans, licenses, sources; policy in deny.toml)
# HARD RULE: runs cargo, so on the Hetzner build box only. Needs `cargo-deny` on PATH (or CARGO_DENY=<path>);
# a missing tool FAILS the gate (a skipped check is not a pass).
set -uo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
SRC=${1:?usage: lint-gate.sh <src-dir>}
cd "$SRC" || exit 2
FAIL=0
step() {
  local name=$1; shift
  echo "== lint-gate: $name: $*"
  "$@"; local rc=$?
  echo "== lint-gate: $name: exit $rc"
  [ $rc -eq 0 ] || FAIL=1
}
DENY=${CARGO_DENY:-$(command -v cargo-deny || true)}
step fmt cargo fmt --all -- --check
step clippy cargo clippy --locked --workspace --all-targets -- -D warnings
step ratchet "$HERE/lint-ratchet.sh"
if [ -n "$DENY" ]; then step deny "$DENY" --log-level warn check
else echo "== lint-gate: deny: cargo-deny not found (install: cargo install --locked cargo-deny, or set CARGO_DENY)"; FAIL=1; fi
[ $FAIL -eq 0 ] && echo "== lint-gate: PASS" || echo "== lint-gate: FAIL"
exit $FAIL
