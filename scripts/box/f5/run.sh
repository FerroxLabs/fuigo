#!/usr/bin/env bash
# B-F5 box test (design F5 §9.4): harness, trace evaluation, negative controls, cases B1-B12.
#
# Usage (as root on Linux): scripts/box/f5/run.sh <case> [<evidence root>]
#   cases: b1 b2 b3 b4 b4-noncap b5 b6 b7 b8 b9 b10 b11 b12 c-pause c-unmarked c-rapid c-image
# Runs the real release binary ($FUIGO_BIN) in a private mount + network + pid namespace: tmpfs /tmp holds HOME,
# FUIGO_HOME and the workspace; only loopback is up (leader socket, echo MCP server). Leader mode is on: one
# `agent leader` process, every client is `agent --leader stdio`. No model key and no model turn: the clients only
# initialize, open, grant, close and load. Raw evidence lands in <evidence root>/<case>/; verdict.txt is the result.
# The pid namespace ends with this script, so nothing it started outlives it.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
CASE=$1
OUTROOT=${2:-/root/fuigo-builds/u41/box-f5}
BIN=${FUIGO_BIN:-/root/fuigo-builds/u41/target/release/fuigo-pager}
if [ "${F5_INNER:-}" != 1 ]; then
  OUT=$OUTROOT/$CASE
  rm -rf "$OUT"; mkdir -p "$OUT"
  exec unshare -m -n -p --fork --mount-proc -- env F5_INNER=1 FUIGO_BIN="$BIN" F5_OUT="$OUT" bash "$0" "$CASE" "$OUTROOT"
fi
OUT=$F5_OUT
ip link set lo up
mount --make-rprivate /
mount -t tmpfs -o mode=1777 tmpfs /tmp
ROOT=/tmp/f5
export HOME=$ROOT/home FUIGO_HOME=$ROOT/home/.fuigo
WS=$ROOT/ws/repo
# A second process (B6, B9, B10) traces to its own dir, p2/f5-marks (driver.py second_process, passrule.py): made
# here, before the watch, so the recursive watch covers it from the start.
mkdir -p "$FUIGO_HOME/f5-marks" "$FUIGO_HOME/f5-acks" "$FUIGO_HOME/p2/f5-marks" "$FUIGO_HOME/p2/f5-acks" \
  "$FUIGO_HOME/hooks" "$WS" "$ROOT/markers"

# ---- fixture (rev 1): untrusted git repo with every project surface ----
git init -q "$WS"
echo "F5 MARKER TOP-LEVEL AGENTS" > "$WS/AGENTS.md"
mkdir -p "$WS/sub" && echo "F5 MARKER NESTED AGENTS" > "$WS/sub/AGENTS.md"
echo "f5 nested note" > "$WS/sub/notes.txt"
cp "$HERE/echo_mcp.py" "$WS/echo_mcp.py"
# B12: the handshake must still be running at close, so the echo server answers `initialize` after 4 s.
ECHO_ARGS=; [ "$CASE" = b12 ] && ECHO_ARGS=',"--init-delay","4"'
cat > "$WS/.mcp.json" <<JSON
{"mcpServers":{"f5echo":{"command":"python3","args":["$WS/echo_mcp.py"$ECHO_ARGS]}}}
JSON
mkdir -p "$WS/.fuigo/hooks" "$WS/.fuigo/skills/f5-box-skill" "$WS/.fuigo/agents"
cat > "$WS/.fuigo/hooks/f5-session-start.json" <<JSON
{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"touch $ROOT/markers/session-start.\$\$"}]}]}}
JSON
printf -- '---\nname: f5-box-skill\ndescription: F5 box fixture skill\n---\nSay F5 SKILL MARKER.\n' > "$WS/.fuigo/skills/f5-box-skill/SKILL.md"
printf -- '---\nname: f5-box-agent\ndescription: F5 box fixture subagent\n---\nYou are the F5 box subagent.\n' > "$WS/.fuigo/agents/f5-box-agent.md"
# The background bash job (terminal log) needs a model turn to start a tool; it is B12's, not started here.
# B4: the stuck shutdown is a held writer (FUIGO_F5_PAUSE, below). The user SessionEnd hook is dispatched without
# blocking the close; since F13 it runs (before, the closed process scope killed it unrun). It sleeps past the hold and
# then writes to its own path, outside the session folder (design F5 §5.6: a hook is a user command and writes where
# the user chose), so the pass rule still sees no write in the session folder and the driver sees the marker.
END_SLEEP=0
case "$CASE" in b4|b4-noncap) END_SLEEP=20 ;; esac
if [ "$END_SLEEP" -gt 0 ]; then
  cat > "$ROOT/f5-session-end.sh" <<SH
#!/bin/bash
M=$ROOT/markers
date +%s.%N > \$M/hook-start.\$\$
cat > \$M/hook-stdin.\$\$
sleep $END_SLEEP
sid=\$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("session_id", ""))' < \$M/hook-stdin.\$\$)
echo "\$sid" > \$M/session-end-ran
date +%s.%N > \$M/session-end-done
SH
  chmod +x "$ROOT/f5-session-end.sh"
  cat > "$FUIGO_HOME/hooks/f5-session-end.json" <<JSON
{"hooks":{"SessionEnd":[{"hooks":[{"type":"command","command":"$ROOT/f5-session-end.sh","timeout":120}]}]}}
JSON
fi
(cd "$ROOT" && find . -not -path './home/.fuigo/f5-*' -not -path './home/.fuigo/p2*' | sort) > "$OUT/fixture.txt"

# The leader creates sessions/<encoded-repo>/ fresh; `inotifywait -m -r` adds a watch on a new directory only after it
# reads its IN_CREATE, so under load the first files in it can be missed (c-rapid then misses its violation). Make the
# tree the leader will use now, before the watch: the dirname is fuigo_config::paths::encode_cwd_dirname (URL-encoding
# of the cwd, every byte but A-Za-z0-9 - _ . ~ percent-encoded, '/' included; the workspace path here is short, far
# under its 255-byte limit), mode 0700 as the product makes it.
ENC=$(python3 -c 'import sys,urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "$WS")
mkdir -p -m 700 "$FUIGO_HOME/sessions" "$FUIGO_HOME/sessions/$ENC"

# ---- one recursive watch on FUIGO_HOME before session/new; acks written by watch.py ----
# c-pause: the watcher writes into the paused path (bypass). b4*: the first chat_history.jsonl (b4) or updates.jsonl
# (b4-noncap) syscall after the driver
# arms the pause at close is held for F5_HOLD s with no write: past the 8 s close budget plus the 10 s a load waits for
# a closing writer (LOAD_WAIT_TIMEOUT), so the immediate load answers `still closing`.
PAUSE_NAME= PAUSE_ARM= BYPASS_NAME= HOLD=
case "$CASE" in
  c-pause) PAUSE_NAME=${F5_PAUSE_NAME:-summary.json}; BYPASS_NAME=$PAUSE_NAME ;;
  b4|b5|b9) PAUSE_NAME=chat_history.jsonl PAUSE_ARM=pause-arm HOLD=${F5_HOLD:-22} ;;
  b4-noncap) PAUSE_NAME=updates.jsonl PAUSE_ARM=pause-arm HOLD=${F5_HOLD:-22} ;;
esac
inotifywait -m -r -e create,modify,close_write,moved_from,moved_to,delete,delete_self,attrib \
  --format '%w%f|%e' "$FUIGO_HOME" 2>"$OUT/inotify.err" \
  | F5_PAUSE="$BYPASS_NAME" F5_HOLD="$HOLD" python3 -u "$HERE/watch.py" "$FUIGO_HOME" "$OUT" &
WATCH_PIPE=$!
timeout 10 bash -c "until grep -q 'Watches established' '$OUT/inotify.err'; do sleep 0.05; done" \
  || { echo "watch setup failed" > "$OUT/verdict.txt"; exit 1; }

# ---- leader mode on ----
export FUIGO_LEADER_SOCKET=$FUIGO_HOME/leader.sock FUIGO_F5_TRACE_DIR=$FUIGO_HOME/f5-marks
export FUIGO_API_KEY=test-key-for-ci FUIGO_FOLDER_TRUST=1 FUIGO_TEST_VERSION=0.0-sim RUST_LOG=fuigo_shell=debug,fuigo_hooks=debug
for v in FUIGO_CLI_CHAT_PROXY_BASE_URL FUIGO_API_BASE_URL FUIGO_MODELS_BASE_URL FUIGO_FEEDBACK_BASE_URL FUIGO_TRACE_UPLOAD_URL; do
  export "$v=http://127.0.0.1:9"
done
# A model turn (b2 mid-turn, b3 prompt after reload, b12 background bash): a scripted fake model on loopback
# (fake_model.py) serves Chat Completions and /models; the driver appends its steps to $F5_MODEL_SCRIPT. No key.
case " b2 b3 b8 b12 probe " in *" $CASE "*)
  export F5_MODEL_SCRIPT=$ROOT/fake-model.jsonl; : > "$F5_MODEL_SCRIPT"
  python3 -u "$HERE/fake_model.py" 18089 "$F5_MODEL_SCRIPT" "$OUT" 2>"$OUT/fake-model.err" &
  timeout 10 bash -c "until [ -f '$OUT/fake-model.ready' ]; do sleep 0.05; done" || echo "fake model missing" >> "$OUT/harness.log"
  export FUIGO_CLI_CHAT_PROXY_BASE_URL=http://127.0.0.1:18089/v1 FUIGO_MODELS_BASE_URL=http://127.0.0.1:18089/v1 ;;
esac
(cd "$WS" && exec env ${PAUSE_NAME:+FUIGO_F5_PAUSE=$PAUSE_NAME} ${PAUSE_ARM:+FUIGO_F5_PAUSE_ARM=$PAUSE_ARM} "$BIN" agent leader --no-exit-on-disconnect \
  --relay-on-demand --no-auto-update </dev/null >/dev/null 2>"$OUT/leader.log") &
LEADER=$!
timeout 30 bash -c "until [ -S '$FUIGO_LEADER_SOCKET' ]; do sleep 0.05; done" || echo "leader socket missing" >> "$OUT/harness.log"

set +e
python3 -u "$HERE/driver.py" "$CASE" "$OUT" "$WS" "$BIN" "$LEADER" > "$OUT/driver.log" 2>&1
DRIVER_RC=$?
set -e
sleep 1.5
kill -TERM "$LEADER" 2>/dev/null || true
for _ in $(seq 100); do kill -0 "$LEADER" 2>/dev/null || break; sleep 0.1; done
kill -KILL "$LEADER" 2>/dev/null || true
wait "$LEADER" 2>/dev/null || true
sleep 0.5
INOTIFY_PID=$(cat /proc/[0-9]*/stat 2>/dev/null | awk '$2=="(inotifywait)"{print $1}' | head -1)
[ -n "$INOTIFY_PID" ] && kill -TERM "$INOTIFY_PID"
wait "$WATCH_PIPE" 2>/dev/null || true
ls -1 "$FUIGO_HOME/f5-marks" | sort -t. -k1,1 > "$OUT/marks.txt"
ls -1 "$FUIGO_HOME/p2/f5-marks" | sort -t. -k1,1 > "$OUT/marks-p2.txt"
(cd "$FUIGO_HOME" && find . -not -path './f5-*' -not -path './p2/f5-*' | sort) > "$OUT/home-tree.txt"
ls "$ROOT/markers" > "$OUT/markers.txt"
cp -r "$FUIGO_HOME/sessions" "$OUT/sessions" 2>/dev/null || true
python3 "$HERE/passrule.py" "$FUIGO_HOME" "$OUT" > "$OUT/rule.txt" 2>&1 || true
python3 "$HERE/verdict.py" "$CASE" "$OUT" "$DRIVER_RC" > "$OUT/verdict.txt"
cat "$OUT/verdict.txt"
