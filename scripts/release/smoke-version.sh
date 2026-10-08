#!/usr/bin/env bash
# Binary identity check, same assertion as the build job's Smoke test. Usage: <binary>
set -euo pipefail
ACTUAL=$("$1" --version | tr -d '\r')
EXPECTED=$(grep -m1 '^version' crates/codegen/fuigo-version/Cargo.toml | cut -d'"' -f2)
COMMIT=$(git rev-parse HEAD); COMMIT=${COMMIT:0:12}
echo "$ACTUAL"
[ "$ACTUAL" = "fuigo $EXPECTED ($COMMIT)" ] || { echo "::error::binary identity mismatch: expected fuigo $EXPECTED ($COMMIT)"; exit 1; }
