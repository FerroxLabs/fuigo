#!/usr/bin/env bash
# scripts/fuzz/run-all.sh <minutes> [target...]
# Per-release fuzz run: every target in fuzz/ for <minutes>, one core each, in parallel, niced. Run on the build box.
# Needs a nightly toolchain and cargo-fuzz (CARGO_HOME/RUSTUP_HOME may point at private copies); the pinned workspace
# toolchain is not touched. A crash leaves fuzz/artifacts/<target>/crash-*; minimise it, fix the bug, add a regression
# test, and copy the minimised input to fuzz/regressions/<target>/ (the replay step below then keeps it fixed).
# Exit: 0 clean, 1 a target crashed or the replay failed.
set -u
MIN=${1:?usage: run-all.sh <minutes> [target...]}; shift
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$ROOT/fuzz" || exit 2
TARGETS=${*:-tool_json_split acp_reader sanitizer no_proxy}
export RUST_MIN_STACK=${RUST_MIN_STACK:-16777216}
# Toolchain: use a system nightly + cargo-fuzz if both exist; otherwise install them ON DEMAND into a lane-local dir
# ($FUZZ_HOME, default fuzz/.toolchain, about 1 GB, git-ignored; delete it when done: the build box disk is tight).
# The pinned workspace toolchain is never touched. FUZZ_NO_PLUS=1: cargo on PATH is already the nightly one.
TC=(+nightly)
if [ -n "${FUZZ_NO_PLUS:-}" ]; then
  TC=()
elif ! { command -v cargo-fuzz >/dev/null 2>&1 && rustup toolchain list 2>/dev/null | grep -q '^nightly'; }; then
  FUZZ_HOME=${FUZZ_HOME:-$ROOT/fuzz/.toolchain}
  export CARGO_HOME="$FUZZ_HOME/cargo" RUSTUP_HOME="$FUZZ_HOME/rustup"
  if [ ! -x "$CARGO_HOME/bin/cargo-fuzz" ]; then
    echo "run-all.sh: installing nightly + cargo-fuzz into $FUZZ_HOME (lane-local; delete it when finished)"
    mkdir -p "$CARGO_HOME" "$RUSTUP_HOME"
    RUSTUP_BIN=$(command -v rustup || echo /root/.cargo/bin/rustup)
    "$RUSTUP_BIN" toolchain install nightly --profile minimal --no-self-update >"$FUZZ_HOME/install.log" 2>&1 || { echo "nightly install failed, see $FUZZ_HOME/install.log"; exit 2; }
    PATH=$(echo "$RUSTUP_HOME"/toolchains/nightly-*/bin):$PATH nice -n 10 cargo install cargo-fuzz --locked --target-dir "$FUZZ_HOME/install-target" >>"$FUZZ_HOME/install.log" 2>&1 || { echo "cargo-fuzz install failed, see $FUZZ_HOME/install.log"; exit 2; }
    rm -rf "$FUZZ_HOME/install-target"
  fi
  export PATH=$(echo "$RUSTUP_HOME"/toolchains/nightly-*/bin):$CARGO_HOME/bin:$PATH
  TC=()
fi
rc=0; pids=()
mkdir -p logs
# Vendor-token-shaped sanitizer seeds are written here at run time from split strings, so no tracked file holds an
# unsplit token shape (scripts/release/check-token-leaks.py). gen/ is git-ignored and replayed like seeds/.
mkdir -p gen/sanitizer
printf %s%s ghp_ "$(printf %036d 0 | tr 0 a)" > gen/sanitizer/ghp
printf %s%s sk_ "live_$(printf %024d 0 | tr 0 x)" > gen/sanitizer/sk_live
printf %s%s AIza "Sy$(printf %033d 0 | tr 0 A)" > gen/sanitizer/aiza
# 1. Replay every committed seed and regression input once (a regression fails here at once, before the long run).
for t in $TARGETS; do
  dirs=(); for d in "seeds/$t" "gen/$t" "regressions/$t"; do [ -d "$d" ] && dirs+=("$d"); done
  [ ${#dirs[@]} -gt 0 ] || continue
  nice -n 15 cargo "${TC[@]}" fuzz run "$t" "${dirs[@]}" -- -runs=0 > "logs/$t.replay.log" 2>&1 || { echo "REPLAY FAILED: $t"; rc=1; }
done
# 2. Long run, one core per target; new corpus goes to corpus/<t> (not committed), seeds are read-only extras.
for t in $TARGETS; do
  mkdir -p "corpus/$t"; extra=(); [ -d "seeds/$t" ] && extra+=("seeds/$t"); [ -d "gen/$t" ] && extra+=("gen/$t"); [ -d "regressions/$t" ] && extra+=("regressions/$t")
  setsid nice -n 15 cargo "${TC[@]}" fuzz run "$t" "corpus/$t" "${extra[@]}" -- -max_total_time=$((MIN*60)) -timeout=10 -rss_limit_mb=2048 > "logs/$t.log" 2>&1 &
  pids+=($!)
done
for p in "${pids[@]}"; do wait "$p" || rc=1; done
# Idempotence is not blocking (fuzz/fuzz_targets/sanitizer.rs header): a target prints IDEMPOTENCE_WARN once per
# distinct input and goes on; the count (replay plus long run) is reported here, it does not change the exit code.
for t in $TARGETS; do
  warns=$(cat "logs/$t.replay.log" "logs/$t.log" 2>/dev/null | grep -c '^IDEMPOTENCE_WARN')
  echo "== $t: $(grep -E '^#[0-9]+.*(DONE|pulse)' "logs/$t.log" | tail -1)"
  echo "   IDEMPOTENCE_WARN: $warns"
  ls artifacts/$t 2>/dev/null | sed "s/^/   ARTIFACT: /"
done
exit $rc
