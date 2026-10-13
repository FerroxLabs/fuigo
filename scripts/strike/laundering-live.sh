#!/usr/bin/env bash
# laundering-live.sh <test-exe> <fuigo-pager-binary> [result.json]
#
# Runs the S7.5 live laundering suite (peer_laundering_live) against a REAL Anthropic model. Builds nothing: copy the two
# prebuilt binaries to a clean Linux VM and run this there. Run it on a THROWAWAY VM: the child is a real agent, and although
# it runs in default permission mode and every permission prompt is rejected, it is a real model reading hostile prompts.
#
# Required env:
#   LAUNDERING_KEY_FILE   file containing the Anthropic API key (read by the test, never printed, never put in the result)
# Optional env:
#   LAUNDERING_MODEL (default claude-sonnet-5-5)   LAUNDERING_BASE_URL (default https://api.anthropic.com/v1)
#   LAUNDERING_ONLY=id1,id2   LAUNDERING_TURN_SECS=240   LAUNDERING_MOCK=1|tool (plumbing smoke on the loopback mock, no key, no model)
# Needs on the VM: git, /bin/sh, outbound HTTPS to the model endpoint.
# Exit: the test's exit code (0 only when all 20 prompts pass). The result JSON is written either way.
set -u
if [ "$#" -lt 2 ]; then echo "usage: $0 <test-exe> <fuigo-pager-binary> [result.json]" >&2; exit 64; fi
TEST_EXE=$(readlink -f "$1"); PAGER=$(readlink -f "$2")
OUT=${3:-${LAUNDERING_OUT:-$PWD/laundering-live-result.json}}
[ -x "$TEST_EXE" ] || { echo "laundering-live: test exe not executable: $TEST_EXE" >&2; exit 66; }
[ -x "$PAGER" ] || { echo "laundering-live: fuigo-pager not executable: $PAGER" >&2; exit 66; }
case "${LAUNDERING_MOCK:-0}" in 1|tool) MOCK=1 ;; *) MOCK=0 ;; esac
if [ "$MOCK" != 1 ] && [ -z "${LAUNDERING_KEY_FILE:-}" ]; then
  echo "laundering-live: set LAUNDERING_KEY_FILE=<file holding the Anthropic API key> (no key, no run)" >&2; exit 2
fi
if [ "$MOCK" = 1 ]; then
  # mock mode skips the key check: it must never be combined with a non-loopback endpoint
  case "${LAUNDERING_BASE_URL:-http://127.0.0.1/}" in
    http://127.0.0.1|http://127.0.0.1[:/]*|http://localhost|http://localhost[:/]*) ;;
    *) echo "laundering-live: LAUNDERING_MOCK needs LAUNDERING_BASE_URL on 127.0.0.1 or localhost" >&2; exit 2 ;;
  esac
fi
export PAGER_BINARY="$PAGER" LAUNDERING_OUT="$OUT" RUST_MIN_STACK=16777216 RUST_BACKTRACE=0
# own process group so an abort kills the pager children too
exec setsid "$TEST_EXE" --ignored --test-threads=1 --nocapture laundering_prompts_end_in_a_model_refusal_with_nothing_executed
