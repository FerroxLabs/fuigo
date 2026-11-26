#!/bin/bash
# Integration test: VS Code (headless, xvfb) + this extension + the real `fuigo agent stdio` + the scripted mock model.
# usage (from editors/vscode, after `npm run build && npm run compile-tests`):
#   FUIGO_BIN=/path/to/fuigo test/integration/run.sh [run-dir]
# Downloads VS Code once (network), then runs the test inside an empty network namespace (loopback only), so no
# model call can leave the box. Requires root or user namespaces for `unshare -n`; set NO_UNSHARE=1 to skip it.
# VSIX=path/to/fuigo-x.y.z.vsix tests the packaged extension (installed into VS Code) instead of the dev folder;
# VSCODE_VERSION=1.128.0 picks the VS Code build (default 1.94.2, the engines.vscode floor).
set -euo pipefail
HERE=$(cd "$(dirname "$0")/../.." && pwd)
: "${FUIGO_BIN:?set FUIGO_BIN to a fuigo binary}"
R=$(realpath -m "${1:-$HERE/.vscode-test/run}")

if [ "${INNER:-}" != 1 ]; then
  rm -rf "$R"; mkdir -p "$R/home/.fuigo" "$R/home/vscode-user/User" "$R/tmp" "$R/work/.vscode"
  cp "$HERE/test/fixtures/workspace/hello.txt" "$R/work/"
  # fuigo.path is honoured from user settings only. The workspace sets a decoy, which the extension must ignore.
  printf '{ "fuigo.path": "%s" }\n' "$FUIGO_BIN" > "$R/home/vscode-user/User/settings.json"
  printf '#!/bin/sh\ntouch "$0.ran"\n' > "$R/work/decoy-fuigo"; chmod +x "$R/work/decoy-fuigo"
  printf '{ "fuigo.path": "%s" }\n' "$R/work/decoy-fuigo" > "$R/work/.vscode/settings.json"
  printf '.vscode/\n' > "$R/work/.gitignore"
  git -C "$R/work" init -q
  git -C "$R/work" -c user.email=t@example.invalid -c user.name=t add -A
  git -C "$R/work" -c user.email=t@example.invalid -c user.name=t commit -qm init
  (cd "$HERE" && node out-test/test/integration/runTest.js download)
  export INNER=1
  if [ "${NO_UNSHARE:-}" = 1 ]; then exec "$0" "$R"; fi
  exec unshare -n -- "$0" "$R"
fi

ip link set lo up 2>/dev/null || true
PORT=18$((RANDOM % 900 + 100))
export HOME=$R/home FUIGO_HOME=$R/home/.fuigo TMPDIR=$R/tmp USERPROFILE=$R/home
for k in FUIGO_CLI_CHAT_PROXY_BASE_URL FUIGO_API_BASE_URL FUIGO_MODELS_BASE_URL FUIGO_FEEDBACK_BASE_URL FUIGO_TRACE_UPLOAD_URL \
  FUIGO_MANAGED_CONFIG_URL FUIGO_CODE_WEB_URL FUIGO_CONVERSATIONS_BASE_URL; do export "$k=http://127.0.0.1:$PORT/v1"; done
export FUIGO_API_KEY=test-key-not-real FUIGO_TELEMETRY_ENABLED=false FUIGO_TELEMETRY_TRACE_UPLOAD=false FUIGO_FEEDBACK_ENABLED=false \
  FUIGO_TRACE_UPLOAD=false FUIGO_INSTRUMENTATION=disabled OTEL_SDK_DISABLED=true FUIGO_DISABLE_AUTOUPDATER=1 \
  FUIGO_PROMPT_SUGGESTIONS=false FUIGO_TURN_SUMMARY=0 NO_PROXY=127.0.0.1,localhost FUIGO_FOLDER_TRUST=0 \
  GIT_CONFIG_NOSYSTEM=1 GIT_TERMINAL_PROMPT=0 RUST_LOG=${RUST_LOG:-info} MOCK_ADMIN=http://127.0.0.1:$PORT \
  MOCK_LOG=$R/mock-requests.jsonl
unset ANTHROPIC_API_KEY OPENAI_API_KEY XAI_API_KEY FUIGO_CONFIG FUIGO_CONFIG_PATH || true

python3 "$HERE/test/fixtures/mock-model.py" "$PORT" > "$R/mock.out" 2>&1 &
MOCK_PID=$!
trap 'kill $MOCK_PID 2>/dev/null || true' EXIT
for _ in $(seq 50); do curl -s -o /dev/null "http://127.0.0.1:$PORT/v1/models" && break; sleep 0.2; done

cd "$HERE"
timeout 900 xvfb-run -a node out-test/test/integration/runTest.js run "$R/work"
