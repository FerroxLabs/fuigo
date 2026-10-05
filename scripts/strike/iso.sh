#!/usr/bin/env bash
# iso.sh <lane> <pkg> <testbin-filter-args|auto> "<names>" <sha>... — 3x --exact isolation per sha
# Deployed copy: /root/fuigo-builds/iso.sh (this file is the reviewed source). CLI and $OUT format unchanged except:
#
# NAMES: whitespace-separated, exactly as before. With ISO_NAMES_NEWLINE=1 the argument is split on NEWLINES only, so names
# with spaces (doctests: `src/lib.rs - double (line 10)`) can be isolated, one per line. (Never inferred from the argument:
# a legacy list that merely contains a newline must keep splitting on all whitespace.)
#
# AUTO MODE (P17-F3): when <testbin-filter-args> is the word `auto`, the cargo target selector of EACH name is resolved
# from the log it failed in: set ISO_FROM_LOG=<log> (a gate suite.log / rp.sh log). The selector comes from the
# `Running tests/X.rs` / `Running unittests src/lib.rs` / `Doc-tests` header that precedes the name (iso-resolve.py), so
# an integration-test function gets `--test X` (a bare `cargo test <name>` or `--lib` would run zero tests of it). A
# name that resolves to several targets is isolated in each; one that resolves to none is reported UNRESOLVED and
# skipped (never silently "passed"). ISO_PRINT_ONLY=1 prints the resolved command per name (ISO_PRINT_LOGS=1: the log-file stem per name) and exits before touching
# the lane, so the resolution can be checked (and self-tested) without a build. ISO_RESOLVER overrides the resolver path.
#
# ABORT: `pkill -s <sid>`; the sid is on the first line of <lane>.out and in <lane>.sid. Same discipline as rp.sh
# (own session, lane-lock fd closed for children, every cargo run in its own systemd scope, trap removes the worktree
# and target dir, writes ABORTED, exits 143). Never abort by process group (`timeout` makes a new group).
set -uo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
. "$HERE/abort-lib.sh"
[ "${ISO_PRINT_ONLY:-}" = 1 ] || abort_guard "${BASH_SOURCE[0]}" "$@"
LANE=$1 PKG=$2 TESTARGS=$3 NAME=$4; shift 4
B=/root/fuigo-builds; L0=$B/$LANE; R=$B/integration/src-p15r; OUT=$B/$LANE.out
RESOLVER=${ISO_RESOLVER:-$HERE/iso-resolve.py}
# targets_for <name>: one cargo selector string per line ("" = none needed); "!UNRESOLVED"/"!UNSUPPORTED ..." marks failures.
# Auto mode needs the metadata: if `cargo metadata` fails the names are reported UNRESOLVED (ISO_ALLOW_HEURISTIC=1 opts into
# path-layout guessing, which cannot tell same-named tests of two workspace packages apart).
# ISO_META (set per sha below, or by the caller): `cargo metadata --no-deps` JSON of the checkout under test; with it the
# resolver uses the exact cargo target names ([[bin]] names, [lib] paths) instead of guessing from file names.
ISO_META=${ISO_META:-}
if [ "${ISO_NAMES_NEWLINE:-}" = 1 ]; then mapfile -t NAMES < <(printf '%s\n' "$NAME" | sed '/^$/d'); else set -f; NAMES=($NAME); set +f; fi   # all whitespace (incl. newlines), no globbing: exactly the old `for NM in $NAME`
# de-duplicate names, then derive a collision-free log stem per name: the legacy short stem (${NM##*:}) when it is unique
# among the names, the full sanitised name when two names share a basename (a::same b::same would overwrite each other's logs)
declare -A SEEN; UN=(); for NM in "${NAMES[@]}"; do [ -z "${SEEN[$NM]:-}" ] && { SEEN[$NM]=1; UN+=("$NM"); }; done; NAMES=("${UN[@]}")
declare -A BASEN; for NM in "${NAMES[@]}"; do b=${NM##*:}; BASEN[$b]=$(( ${BASEN[$b]:-0} + 1 )); done
# final stems are made UNIQUE across the whole list (a::same b::same a__same would otherwise still collide): first come
# keeps its stem, a later clash gets -2, -3, ...
declare -A STEM USED
for NM in "${NAMES[@]}"; do
  b=${NM##*:}; [ "${BASEN[$b]:-1}" -gt 1 ] && b=$NM
  c=$(printf '%s' "$b" | tr -c 'A-Za-z0-9_.-' '_'); n=1; u=$c
  while [ -n "${USED[$u]:-}" ]; do n=$((n+1)); u=$c-$n; done
  USED[$u]=1; STEM[$NM]=$u
done
stem() { printf '%s' "${STEM[$1]}"; }
targets_for() {
  if [ "$TESTARGS" = auto ]; then
    [ -n "${ISO_FROM_LOG:-}" ] && [ -r "$ISO_FROM_LOG" ] || { echo "!UNRESOLVED (ISO_FROM_LOG unset or unreadable)"; return; }
    local o; o=$(python3 "$RESOLVER" ${ISO_META:+--metadata "$ISO_META"} "$PKG" "$ISO_FROM_LOG" "$1") || { echo "!UNRESOLVED (resolver failed)"; return; }
    [ -n "$o" ] || { echo "!UNRESOLVED (resolver printed nothing)"; return; }
    printf '%s\n' "$o" | cut -f2-
  else printf '%s\n' "$TESTARGS"; fi
}
if [ "${ISO_PRINT_ONLY:-}" = 1 ]; then
  if [ "${ISO_PRINT_LOGS:-}" = 1 ]; then for NM in "${NAMES[@]}"; do printf '%s\t%s\n' "$NM" "$(stem "$NM")"; done; exit 0; fi
  for NM in "${NAMES[@]}"; do
    while IFS= read -r T; do
      case "$T" in '!'*) printf '%s\t%s\n' "$NM" "$T";; *) printf '%s\tcargo test --locked -p %s %s -- --exact %s\n' "$NM" "$PKG" "$T" "$NM";; esac
    done < <(targets_for "$NM")
  done; exit 0
fi
mkdir -p $L0; exec 7>"$L0/.lane.lock"; flock -n 7 || exit 3
: > $OUT   # only after the lane lock: a refused second run must not wipe the active run's output
export PATH="$HOME/.cargo/bin:$PATH" RUST_MIN_STACK=16777216 CARGO_TERM_COLOR=never RG_BIN_PATH=/usr/bin/rg CARGO_BUILD_JOBS=16
say(){ echo "$(date -u +%FT%TZ) $*" >> $OUT; }
abort_init iso "$LANE"; echo "$MYSID" > "$B/$LANE.sid"
# UNIQUE per invocation and never reused or deleted by a later one: a launcher aborted by an earlier run of this lane that is still
# unregistered must keep seeing ITS flag even after the lane is locked again. Flags are NEVER deleted (a few bytes each): no
# launcher lifetime bound exists that would make age-based pruning safe.
ABORT_FLAG="$B/$LANE.abort.$(date +%s).$$"   # raised by abort_kill_all before any scope is killed (see abort-lib bg)
say "pid=$$ sid=$MYSID pkg=$PKG name=$NAME"
SRC=""; CARGO_TARGET_DIR=""
on_abort() {
  trap '' TERM INT HUP; say "ABORTED by signal (sid=$MYSID); killing session and scope, removing target dir and worktree"
  abort_kill_all; AK=$?
  cd /; [ -z "$CARGO_TARGET_DIR" ] || rm -rf "$CARGO_TARGET_DIR"; [ -z "$SRC" ] || git -C $R worktree remove --force "$SRC" 2>/dev/null
  if [ $AK -eq 0 ]; then say "ABORTED: cleaned up"; else say "ABORTED: cleanup INCOMPLETE, scopes still active:$ABORT_SURVIVORS"; fi
  exit 143
}
contain_check() { abort_contain_failed "$1" || return 0
  say "CONTAINMENT FAILURE: a command exited $1 (97 = no systemd-run, 98 = its scope was not empty after SIGKILL); run is INVALID"
  abort_kill_all; cd /; [ -z "$CARGO_TARGET_DIR" ] || rm -rf "$CARGO_TARGET_DIR"; [ -z "$SRC" ] || git -C $R worktree remove --force "$SRC" 2>/dev/null; exit 4; }
trap on_abort TERM INT HUP
for b in $B/int-*.bundle $B/*.bundle; do bg git -C $R fetch -qf $b "+refs/heads/*:refs/remotes/rbi/$(basename $b .bundle)/*" 2>/dev/null; contain_check $?; done
for SHA in "$@"; do
  SRC=$L0/src-$SHA; export CARGO_TARGET_DIR=$L0/target-$SHA
  bg git -C $R worktree add -q --detach $SRC $SHA; C=$?; contain_check $C
  [ $C -ne 0 ] || { cd $SRC; bg nice -n 10 cargo build --locked -p fuigo-pager-bin --bin fuigo-pager > $B/$LANE-$SHA-binbuild.log 2>&1; BC=$?; contain_check $BC   # fresh pager binary for THIS sha (fuigo-test-support only builds it if absent)
    say "  $SHA binbuild exit=$BC fuigo-pager sha256=$(sha256sum $CARGO_TARGET_DIR/debug/fuigo-pager 2>/dev/null | cut -c1-16)"
    [ $BC = 0 ] || { say BINBUILD_FAIL; abort_kill_all; cd /; rm -rf "$CARGO_TARGET_DIR"; git -C $R worktree remove --force "$SRC" 2>/dev/null; exit 5; }
    export FUIGO_BINARY=$CARGO_TARGET_DIR/debug/fuigo-pager; say "  $SHA FUIGO_BINARY pinned to $FUIGO_BINARY"; }   # fuigo_binary() prefers this env var over the target dir: pin the fresh build
  [ $C -eq 0 ] || { say "WTFAIL $SHA"; SRC=""; continue; }
  cd $SRC
  NOMETA=0
  if [ "$TESTARGS" = auto ]; then
    ISO_META=$L0/meta-$SHA.json
    bg timeout 300 cargo metadata --no-deps --format-version 1 --locked --offline > "$ISO_META" 2> "$ISO_META.err"; MRC=$?; contain_check $MRC; [ $MRC -eq 0 ] || {
      ISO_META=""
      if [ "${ISO_ALLOW_HEURISTIC:-}" = 1 ]; then say "  $SHA cargo metadata unavailable (see $L0/meta-$SHA.json.err): ISO_ALLOW_HEURISTIC=1, resolving from the path layout only (cannot tell same-named tests of two packages apart)"
      else NOMETA=1; say "  $SHA cargo metadata unavailable (see $L0/meta-$SHA.json.err): auto mode REFUSES to guess targets (set ISO_ALLOW_HEURISTIC=1 to allow path-layout resolution)"; fi; }
  fi
  for NM in "${NAMES[@]}"; do
    [ $NOMETA -eq 0 ] || { say "  $SHA $NM UNRESOLVED (no cargo metadata; not run)"; continue; }
    mapfile -t TGTS < <(targets_for "$NM"); K=0
    [ ${#TGTS[@]} -gt 0 ] || { say "  $SHA $NM UNRESOLVED (no target lines) (not run)"; continue; }
    for T in "${TGTS[@]}"; do
      K=$((K+1)); SFX=""; [ "$TESTARGS" = auto ] && [ ${#TGTS[@]} -gt 1 ] && SFX="@t$K"
      case "$T" in '!'*) say "  $SHA $NM UNRESOLVED $T (not run)"; continue;; esac
      for i in 1 2 3; do
        LG=$B/$LANE-$SHA-$(stem "$NM")$SFX-$i.log
        bg $B/slot-run.sh $LANE nice -n 10 timeout 1800 cargo test --locked -p $PKG $T -- --exact "$NM" > $LG 2>&1; C=$?; contain_check $C
        say "  $SHA $NM run$i exit=$C $(grep -E '^test result:' $LG | grep -v ' 0 passed; 0 failed' | tr '\n' ' ')"
      done
    done
  done
  cd /; rm -rf $CARGO_TARGET_DIR; git -C $R worktree remove --force $SRC; SRC=""; CARGO_TARGET_DIR=""
done
say DONE
