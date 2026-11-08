#!/usr/bin/env bash
# Negative controls of design F5 §9.3: each one must FAIL with its expected diagnostic.
#   five clippy fixtures (examples/f5_raw_session_write.rs, compiled with --cfg f5_raw_session_write) and one fixture
#   for the raw-path scan of scripts/ci/session-writer-crates.sh (a temp copy with a hand-built session path).
# Usage: session-writer-controls.sh [receipt-dir]   (run from the repo root; cargo flags come from CARGO_* env)
set -euo pipefail
OUT=${1:-session-writer-receipts}; mkdir -p "$OUT"; OUT=$(cd "$OUT" && pwd)
REPO=$(cd "$(dirname "$0")/../.." && pwd); cd "$REPO"
LOCKED=${F5_CARGO_LOCKED---locked}
control() {
  local pkg=$1; shift
  cargo clippy $LOCKED -p "$pkg" --example f5_raw_session_write --no-deps -- -D clippy::disallowed_methods
  if cargo clippy $LOCKED -p "$pkg" --example f5_raw_session_write --no-deps -- --cfg f5_raw_session_write \
      -D clippy::disallowed_methods >"$OUT/f5-control-$pkg.log" 2>&1; then
    echo "FAIL: $pkg: the raw session write compiled"; exit 1
  fi
  local m
  for m in "$@"; do
    grep -F "error: use of a disallowed method \`$m\`" "$OUT/f5-control-$pkg.log" ||
      { echo "FAIL: $pkg: no disallowed-method error for $m"; exit 1; }
  done
  echo "ok: $pkg control fails as expected"
}
control fuigo-shell std::fs::write std::fs::DirBuilder::create
control fuigo-tools tokio::fs::rename
control fuigo-session-events std::fs::OpenOptions::append
control fuigo-shell-terminal fuigo_config::paths::create_file_owner_only
control fuigo-file-utils fuigo_config::paths::sessions_cwd_dir_in

# Raw-path scan control: a temp copy where an unlisted crate hand-builds a session path.
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
tar -c --exclude=./.git --exclude=./target . | tar -x -C "$TMP"
printf 'pub fn x(home: &std::path::Path) -> std::path::PathBuf {\n    home.join("sessions")\n}\n' \
  >"$TMP/crates/codegen/fuigo-file-utils/src/x.rs"
if "$TMP/scripts/ci/session-writer-crates.sh" "$TMP" >"$OUT/f5-control-scan.log" 2>&1; then
  echo "FAIL: the raw-path scan passed a hand-built session path"; exit 1
fi
grep -F 'error: raw-path scan: new hand-built session path fuigo-file-utils:src/x.rs:join("sessions")' "$OUT/f5-control-scan.log" ||
  { echo "FAIL: the raw-path scan failed without the expected message"; exit 1; }
echo "ok: raw-path scan control fails as expected"
echo "session-writer controls: 6 of 6 fail as expected"
