#!/usr/bin/env bash
# Per-release benchmark gate (gap G1). Runs on the Docker host (Hetzner), never on a dev Mac.
#
#   FUIGO_API_KEY=... scripts/bench/run-gate.sh <candidate> <baseline>
#
# <candidate>/<baseline> is either `npm:<version>` (e.g. npm:1.0.44) or the path of a linux-x64 fuigo-native binary.
# Same model, provider key, subset, limits and image recipe for both arms; the ONLY difference is the fuigo binary.
# Runs the 12-task subset (scripts/bench/subset12.txt) N=2 times per arm, interleaved base,cand,base,cand, one attempt at a
# time (gateway + one agent container = at most 2 containers). Verdict: FAIL if candidate solved tasks drop by more than 2
# (verdict.py); cost per solved task rising more than 10% is a warning only. Exit 0 PASS, 1 FAIL, 2 INCOMPLETE.
#
# Environment
#   FUIGO_API_KEY   required; provider (Flux) key. Read from env only, piped to the harness on stdin, never in argv/logs.
#   HB_ROOT         hardbench checkout with harness-1028/, tasks/<id>/ and deps/<deps_id>/out (default /root/hardbench;
#                   see stage-deps.sh). Not part of the fuigo repo.
#   GATE_OUT        output dir (default $HB_ROOT/../runs/gate-<utc>); must not exist.
#   GATE_CAP_USD    ledger cap per harness invocation (default 8; four invocations -> hard ceiling 4x)
#   GATE_TOTAL_USD  stop launching invocations once the sum of ledger reservations passes this (default 30)
#   GATE_REPS       repeats per arm (default 2; the verdict needs 2)
#   GATE_TIME_LIMIT per-attempt seconds (default 1200, as on 2026-10-13)
#   GATE_ORIGIN     provider origin (default https://api.fluxrouter.ai/anthropic)
set -uo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
CAND=${1:?candidate: npm:<ver> or path}; BASE=${2:?baseline: npm:<ver> or path}
: "${FUIGO_API_KEY:?set FUIGO_API_KEY in the environment}"
HB_ROOT=${HB_ROOT:-/root/hardbench}
TS=$(date -u +%Y%m%dT%H%M%SZ)
GATE_OUT=${GATE_OUT:-$(dirname "$HB_ROOT")/runs/gate-$TS}
CAP=${GATE_CAP_USD:-8}; TOTAL=${GATE_TOTAL_USD:-30}; REPS=${GATE_REPS:-2}; TL=${GATE_TIME_LIMIT:-1200}
export GATE_ORIGIN=${GATE_ORIGIN:-https://api.fluxrouter.ai/anthropic}
[ -e "$GATE_OUT" ] && { echo "refusing existing $GATE_OUT" >&2; exit 64; }
mkdir -p "$GATE_OUT" && chmod 700 "$GATE_OUT"
TASKS=$(grep -v '^#' "${GATE_TASKS_FILE:-$HERE/subset12.txt}" | grep -v '^$' | tr '\n' ' ')
[ -n "${TASKS// /}" ] || { echo "empty task list" >&2; exit 64; }
for t in $TASKS; do [ -f "$HB_ROOT/tasks/$t/validation.json" ] || { echo "task missing: $t" >&2; exit 64; }; done
exec > >(tee -a "$GATE_OUT/gate.log") 2>&1
echo "gate $TS candidate=$CAND baseline=$BASE reps=$REPS cap/inv=$CAP total=$TOTAL tasks=$(echo $TASKS | wc -w)"

BEFORE=$(docker ps -aq --filter label=fuigo.benchmark=true | sort)
cleanup() {  # remove only benchmark containers this run created
  for c in $(docker ps -aq --filter label=fuigo.benchmark=true | sort | comm -13 <(echo "$BEFORE") -); do docker rm -f "$c" >/dev/null 2>&1; done
}
trap cleanup EXIT

build_image() {  # <arm> <spec> -> prints image tag
  local arm=$1 spec=$2 ctx; ctx=$(mktemp -d "$GATE_OUT/ctx-$arm.XXXX"); mkdir -p "$ctx/native"
  cp "$HERE/Dockerfile.gate" "$ctx/Dockerfile"
  local ver=${spec#npm:}
  if [ "$spec" = "$ver" ]; then  # a binary path: launcher from the newest published package, native swapped in
    ver=${GATE_LAUNCHER_VERSION:-$(npm view fuigo version)} && cp "$spec" "$ctx/native/fuigo-native" && cp "$HERE/overlay.js" "$ctx/native/overlay.js" || return 1
  fi
  docker build -q -t "fuigo-gate:$arm-$TS" --build-arg "FUIGO_VERSION=$ver" "$ctx" >/dev/null || return 1
  rm -rf "$ctx"; echo "fuigo-gate:$arm-$TS"
}
IMG_base=$(build_image base "$BASE") || { echo "image build failed (baseline)"; exit 3; }
IMG_cand=$(build_image cand "$CAND") || { echo "image build failed (candidate)"; exit 3; }
for a in base cand; do v=IMG_$a; echo "$a image ${!v}: $(docker run --rm --network none --entrypoint fuigo "${!v}" --version | head -1)"; done

python3 "$HERE/mk-gate-harness.py" "$HB_ROOT/harness-1028" "$HB_ROOT/harness-gate-$TS" || exit 3
RUNNER="$HB_ROOT/harness-gate-$TS/run_suite.py"

spent() { python3 - "$GATE_OUT" <<'P'
import json,glob,sys
t=0
for f in glob.glob(sys.argv[1]+'/*-r[0-9]*/ledger/budget.json'):
    t+=float(json.load(open(f)).get('reserved_usd',0))
print(round(t,2))
P
}
rc_all=0
for rep in $(seq 1 "$REPS"); do
  for arm in base cand; do
    if python3 -c "import sys; sys.exit(0 if float('$(spent)') < $TOTAL else 1)"; then :; else
      echo "total spend ceiling $TOTAL reached; stopping before $arm-r$rep"; rc_all=2; break 2; fi
    v=IMG_$arm; run="$GATE_OUT/$arm-r$rep"
    echo "== $arm r$rep start $(date -u +%FT%TZ)"
    printf '%s' "$FUIGO_API_KEY" | python3 "$RUNNER" --profile anthropic --engines fuigo --tasks $TASKS \
      --repetitions 1 --seed "$((900 + rep))" --image "${!v}" --tasks-root "$HB_ROOT/tasks" --deps-root "$HB_ROOT/deps" \
      --out "$run" --live --key-stdin --cap-usd "$CAP" --time-limit "$TL" > "$GATE_OUT/$arm-r$rep.out" 2>&1
    rc=$?; echo "== $arm r$rep exit=$rc end $(date -u +%FT%TZ) spent_total=$(spent)"
    [ $rc -ne 0 ] && rc_all=2
  done
done
python3 "$HERE/verdict.py" "$GATE_OUT" "$GATE_OUT/verdict.json" "$GATE_OUT/verdict.md"; vrc=$?
cat "$GATE_OUT/verdict.md"
for a in base cand; do v=IMG_$a; docker rmi "${!v}" >/dev/null 2>&1; done
rm -rf "$HB_ROOT/harness-gate-$TS"
[ $vrc -ne 0 ] && exit $vrc
exit $rc_all
