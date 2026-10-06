#!/usr/bin/env bash
# rp.sh <lane> <parent-sha> <tip-ref-in-bundle> <bundle> <pkgs...> — generic post-rebase re-proof, tip + parent, A.2.1 checks.
# Deployed copy: /root/fuigo-builds/rp.sh (this file is the reviewed source). CLI and $OUT line format are unchanged; the only
# addition is a second pass for packages that have feature-gated test targets (see "SECOND PASS" below), which adds two lines; also folds in the live disk-guard (`. $B/disk-guard.sh`) and makes rpf.sh (FEAT= variant) and rpb.sh (fresh pager binary) unnecessary: both are built in.
#
# ABORT (P17-F3): `pkill -s <sid>` where <sid> is on the first line of /root/fuigo-builds/<lane>.out ("pid=.. sid=..")
# and in /root/fuigo-builds/<lane>.sid. Never `kill -- -<pgid>`: `timeout` runs its child in a NEW process group, so a
# group kill leaves cargo/clippy running (seen at P17-R). The script is always its own session: if it was not started
# as a session leader it re-launches itself under `setsid --wait` and forwards TERM/INT/HUP, so the recorded sid is
# never the caller's. Every long command also runs in its own systemd scope, so a test that setsid()s away is still
# killed. On abort (TERM/INT/HUP) it kills the session and scope, deletes its target dir and worktree, writes
# "ABORTED" (no DONE: an aborted run is not a finished one) and exits 143. The lane-lock fd (7) is closed for every
# child so an orphan can never hold the lane lock.
set -uo pipefail
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/abort-lib.sh"
abort_guard "${BASH_SOURCE[0]}" "$@"
LANE=$1 PARENT=$2 TIPREF=$3 BUNDLE=$4; shift 4; PKGS="$*"; PAGERFEAT=${PAGERFEAT:-}   # extra flags for the PAGER build only (FEAT is package-specific and would break it)
FEAT=${FEAT:-}   # optional extra cargo flags, e.g. FEAT="--features x" (rpf.sh behaviour)
B=/root/fuigo-builds; RPDIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd); L0=$B/$LANE; SRC=$L0/src; R=$B/integration/src-p15r
mkdir -p $L0; exec 7>"$L0/.lane.lock"; flock -n 7 || exit 3
export CARGO_TARGET_DIR="$L0/target" PATH="$HOME/.cargo/bin:$PATH" RUST_MIN_STACK=16777216 CARGO_TERM_COLOR=never RG_BIN_PATH=/usr/bin/rg CARGO_BUILD_JOBS=16
OUT=$B/$LANE.out; : > $OUT; say(){ echo "$(date -u +%FT%TZ) $*" >> $OUT; }
abort_init rp "$LANE"; echo "$MYSID" > "$B/$LANE.sid"
# UNIQUE per invocation and never reused or deleted by a later one: a launcher aborted by an earlier run of this lane that is still
# unregistered must keep seeing ITS flag even after the lane is locked again. Flags are NEVER deleted (a few bytes each): no
# launcher lifetime bound exists that would make age-based pruning safe.
ABORT_FLAG="$B/$LANE.abort.$(date +%s).$$"   # raised by abort_kill_all before any scope is killed (see abort-lib bg)
say "pid=$$ sid=$MYSID pkgs=$PKGS"
MADE_WT=0
on_abort() {
  trap '' TERM INT HUP; say "ABORTED by signal (sid=$MYSID); killing session and scope, removing target dir and worktree"
  abort_kill_all; AK=$?
  cd /; rm -rf "$CARGO_TARGET_DIR" "$B/$LANE-derive.json"; [ $MADE_WT -eq 0 ] || git -C $R worktree remove --force $SRC 2>/dev/null
  if [ $AK -eq 0 ]; then say "ABORTED: cleaned up"; else say "ABORTED: cleanup INCOMPLETE, scopes still active:$ABORT_SURVIVORS"; fi
  exit 143
}
# a command whose scope could not be emptied (98) or that could not be contained at all (97) invalidates the run: stop,
# clean up, say so, exit 4 (no DONE line). Never let it pass as an ordinary exit code.
contain_check() { abort_contain_failed "$1" || return 0
  say "CONTAINMENT FAILURE: a command exited $1 (97 = no systemd-run, 98 = its scope was not empty after SIGKILL); run is INVALID"
  abort_kill_all; cd /; rm -rf "$CARGO_TARGET_DIR" "$B/$LANE-derive.json"; git -C $R worktree remove --force $SRC 2>/dev/null; exit 4; }
trap on_abort TERM INT HUP
# disk guard (coordinator's live rp.sh sources $B/disk-guard.sh here): never start a run while / is nearly full. Run as a scoped job
# so an abort during the wait is not deferred.
if [ -f $B/disk-guard.sh ]; then bg env LANE=$LANE bash $B/disk-guard.sh; DG=$?; contain_check $DG; [ $DG -eq 0 ] || { say "DISK GUARD FAILED (exit $DG): not starting"; exit 4; }; fi
for b in $B/int-*.bundle; do bg git -C $R fetch -qf $b "+refs/heads/*:refs/remotes/rbi/$(basename $b .bundle)/*" 2>/dev/null; contain_check $?; done
bg git -C $R fetch -qf $BUNDLE "+refs/heads/*:refs/remotes/rb-$LANE/*"; C=$?; contain_check $C; [ $C -eq 0 ] || { say FETCHFAIL; exit 2; }
MADE_WT=1   # set BEFORE the (foreground, trap-deferring) worktree add, so an abort that lands during it still removes it
if [ ! -d $SRC ]; then bg git -C $R worktree add -q --detach $SRC $PARENT; C=$?; contain_check $C; [ $C -eq 0 ] || { MADE_WT=0; say WTFAIL; exit 2; }; fi
cd $SRC; TIP=$(git rev-parse refs/remotes/rb-$LANE/$TIPREF)
git merge-base --is-ancestor $PARENT $TIP || { say "TIP NOT ON PARENT"; exit 2; }
say "toolchain_digest=$(rustc -vV | sha256sum | cut -d' ' -f1) parent=$PARENT tip=$TIP"
HU(){ awk '/^ +(Running|Doc-tests) /{n++; if(o)u++; o=1; next} /^test result:/{o=0} END{if(o)u++; print n+0, u+0}' "$1"; }
FS(){ awk '/^failures:$/{f=1;next} f&&/^ +[A-Za-z0-9_:]+$/{print $1} f&&/^$/{f=0}' "$1" | sort -u; }
for LABEL in parent tip; do
  REF=$PARENT; [ $LABEL = tip ] && REF=$TIP; bg git checkout -q --detach $REF; GC=$?; contain_check $GC; [ $GC -eq 0 ] && [ "$(git rev-parse HEAD)" = "$(git rev-parse $REF)" ] || { say "CHECKOUT FAILED or HEAD != $REF for $LABEL: run is INVALID"; abort_kill_all; cd /; rm -rf "$CARGO_TARGET_DIR"; git -C $R worktree remove --force $SRC 2>/dev/null; exit 2; }; say "=== $LABEL $(git rev-parse HEAD) dirty=$(git status --porcelain | wc -l)"
  # FRESH fuigo-pager PER SIDE (P08): fuigo-test-support builds the pager binary only if the file is ABSENT, and parent and tip share
  # one CARGO_TARGET_DIR, so at the tip every binary-driven test would silently run the PARENT binary. Build it explicitly after
  # each checkout; record exit and sha256; a failed build is fatal with its own exit code (5).
  bg nice -n 10 cargo build --locked $PAGERFEAT -p fuigo-pager-bin --bin fuigo-pager > $B/$LANE-$LABEL-binbuild.log 2>&1; BC=$?; contain_check $BC; say "  $LABEL binbuild exit=$BC fuigo-pager sha256=$(sha256sum $CARGO_TARGET_DIR/debug/fuigo-pager 2>/dev/null | cut -c1-16)"; [ $BC = 0 ] || { say BINBUILD_FAIL; abort_kill_all; cd /; rm -rf "$CARGO_TARGET_DIR"; git -C $R worktree remove --force $SRC 2>/dev/null; exit 5; }
  # PIN the binary under test: fuigo_binary() prefers $FUIGO_BINARY over the target dir, so an inherited value (parent/release build)
  # would make both sides test the same stale executable while we log hashes of unused ones. Always set it to the fresh build.
  export FUIGO_BINARY=$CARGO_TARGET_DIR/debug/fuigo-pager; say "  $LABEL FUIGO_BINARY pinned to $FUIGO_BINARY"
  for P in $PKGS; do
    bg nice -n 10 cargo test --locked -p $P $FEAT --no-run --message-format=json > $B/$LANE-derive.json 2>/dev/null; contain_check $?
    D=$(P=$P python3 $RPDIR/derive.py < $B/$LANE-derive.json | cut -d' ' -f1)
    LG=$B/$LANE-$LABEL-$P.log; SKIP=""; [ $P = fuigo-shell ] && [ -n "${P29SKIP:-}" ] && SKIP="-- --skip session::workflow::manager::tests"
    bg $B/slot-run.sh $LANE nice -n 10 timeout 3600 cargo test --locked --no-fail-fast -p $P $FEAT $SKIP > $LG 2>&1; C=$?; contain_check $C; echo DONE >> $LG; FS $LG > $B/$LANE-$LABEL-$P.failset
    say "  $LABEL $P exit=$C derived=$D hu=$(HU $LG) failures=$(wc -l < $B/$LANE-$LABEL-$P.failset) skip='${SKIP}' sha256=$(sha256sum $LG | cut -d' ' -f1)"
    # SECOND PASS (feature-gated test targets). `cargo test -p P` silently SKIPS every test/bin target with required-features
    # (fuigo-shell's test_startup_prefetch_* need `test-support`): a regression there passed every per-package re-proof. We list
    # them (cargo metadata), name them in the log, and run exactly those targets with exactly the features they declare (not
    # the all-features switch, which can enable exclusive or platform features and rebuilds the normal targets). Own derived count
    # (derive.py NODOC=1), own header check, own log; failures are merged into the package's failset so only-tip/only-parent
    # cover them. No gated targets => no extra output at all (the format above is unchanged).
    bg nice -n 10 cargo metadata --no-deps --format-version 1 --locked --offline > $B/$LANE-meta.json 2>/dev/null; MC=$?; contain_check $MC; [ $MC -eq 0 ] || { say "FEATURE-GATED DISCOVERY FAILED for $P (cargo metadata exit $MC): run is INVALID"; abort_kill_all; cd /; rm -rf "$CARGO_TARGET_DIR"; git -C $R worktree remove --force $SRC 2>/dev/null; exit 4; }
    # discovery must SUCCEED before "no gated targets" can be believed: a failed/empty metadata or helper run would otherwise silently
    # disable the second pass (exit 4, no DONE)
    python3 $RPDIR/gated-targets.py $P < $B/$LANE-meta.json > $B/$LANE-gated.txt 2>/dev/null || { say "FEATURE-GATED DISCOVERY FAILED for $P (cargo metadata/gated-targets.py): run is INVALID"; abort_kill_all; cd /; rm -rf "$CARGO_TARGET_DIR"; git -C $R worktree remove --force $SRC 2>/dev/null; exit 4; }
    GT=$(grep -v '^#' $B/$LANE-gated.txt | grep -c . || true)
    if [ "$GT" -gt 0 ]; then
      GF=$(sed -n "s/^#features $P //p" $B/$LANE-gated.txt); GA=$(grep -v '^#' $B/$LANE-gated.txt | awk '{printf "%s %s ", $2, $3}')
      say "  $LABEL $P feature-gated targets skipped by the pass above ($GT): $(grep -v '^#' $B/$LANE-gated.txt | awk '{printf "%s %s [%s]; ", $2, $3, $4}') -> second pass with --features $GF"
      bg nice -n 10 cargo test --locked -p $P --features $GF $GA --no-run --message-format=json > $B/$LANE-derive2.json 2>/dev/null; contain_check $?
      D2=$(P=$P NODOC=1 python3 $RPDIR/derive.py < $B/$LANE-derive2.json | cut -d' ' -f1)
      LG2=$B/$LANE-$LABEL-$P-features.log
      bg $B/slot-run.sh $LANE nice -n 10 timeout 3600 cargo test --locked --no-fail-fast -p $P --features $GF $GA $SKIP > $LG2 2>&1; C2=$?; contain_check $C2; echo DONE >> $LG2
      FS $LG2 > $B/$LANE-$LABEL-$P-features.failset; { cat $B/$LANE-$LABEL-$P.failset; sed "s/^/[+features] /" $B/$LANE-$LABEL-$P-features.failset; } | sort -u > $B/$LANE-$LABEL-$P.failset.m && mv $B/$LANE-$LABEL-$P.failset.m $B/$LANE-$LABEL-$P.failset
      say "  $LABEL $P+features exit=$C2 derived=$D2 hu=$(HU $LG2) failures=$(wc -l < $B/$LANE-$LABEL-$P-features.failset) (merged into the failset above) sha256=$(sha256sum $LG2 | cut -d' ' -f1)"
    fi
  done
  bg nice -n 10 timeout 3600 cargo clippy --locked --all-targets $FEAT $(for P in $PKGS; do printf -- '-p %s ' $P; done) > $B/$LANE-$LABEL-clippy.log 2>&1; C=$?; contain_check $C
  awk '/^(warning|error)(\[|:)/{w=$0; next} w && /^ +--> /{f=$2; sub(/:[0-9]+:[0-9]+$/,"",f); sub(/.*\/src\//,"src/",f); print w " @ " f; w=""}' $B/$LANE-$LABEL-clippy.log | sort -u > $B/$LANE-$LABEL-clippy.warnset
  say "  $LABEL clippy exit=$C warnset=$(wc -l < $B/$LANE-$LABEL-clippy.warnset)"
done
for P in $PKGS; do say "$P only-tip: $(comm -13 $B/$LANE-parent-$P.failset $B/$LANE-tip-$P.failset | tr '\n' ' ')| only-parent: $(comm -23 $B/$LANE-parent-$P.failset $B/$LANE-tip-$P.failset | tr '\n' ' ')"; done
say "clippy new: $(comm -13 $B/$LANE-parent-clippy.warnset $B/$LANE-tip-clippy.warnset | tr '\n' ';') gone: $(comm -23 $B/$LANE-parent-clippy.warnset $B/$LANE-tip-clippy.warnset | wc -l)"
rm -rf $CARGO_TARGET_DIR $B/$LANE-derive.json $B/$LANE-derive2.json $B/$LANE-meta.json $B/$LANE-gated.txt; git -C $R worktree remove --force $SRC; say DONE
