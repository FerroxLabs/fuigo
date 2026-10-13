#!/usr/bin/env bash
# Build the PUBLIC release commit for a strike release: one commit on top of the
# last public release, whose tree is the release candidate's tree minus every
# raw Astra (codex exec) transcript, with local home, Mac volume, build-box and Windows user paths redacted in what is kept.
#
# Sean's rule (handoff UPDATE 211): raw Astra transcripts never enter public
# history. A squash is used, not a history filter, because the strike history
# (v1.0.20..candidate) also holds transcript blobs that were deleted before the
# tip; only a squash guarantees none of them is reachable from the public branch.
#
# Usage (in a THROWAWAY clone or a private checkout; never on a shared branch):
#   scripts/release/public-squash.sh <candidate-rev> <public-parent-rev> <message-file>
# Prints the new commit id on the last line. Creates no ref; the caller decides.
#
# A file under docs/strike/audits/ is RAW when its bytes contain the codex exec
# banner or session header (content rule, not a filename rule: some verdict-only
# outputs are .txt and some briefs are .md).
set -euo pipefail
G=/usr/bin/git
cand=$("$G" rev-parse --verify "$1^{commit}")
parent=$("$G" rev-parse --verify "$2^{commit}")
msgfile=$3
# Built from pieces so this file does not contain the paths it redacts (it would
# otherwise rewrite itself, and the release plan, in the public tree).
home_re=$(printf '/%s/%s' Users seandonahoe)
# Mac volume prefix, its project folder (longest first), and the build-box prefix.
vol_re=$(printf '/%s/%s' Volumes Mando)
proj_re=$(printf '%s/%s' "$vol_re" WaylandBots)
build_re=$(printf '/%s/%s' root fuigo-builds)
# The build-box prefix is a live path for the scripts the public tree ships
# (scripts/, crates/, ...); it is redacted in docs/ only and reported elsewhere.
build_scope=docs/
# Owner's Windows user dir (docs only): WSL mount form and backslash form, each
# matched only when a path separator follows the name, so longer names such as
# fixtures that merely start with the same letters are left alone.
bs='\'
win_fs=$(printf '/mnt/c/%s/%s' Users seand)
win_bk=$(printf 'C:%s%s%s%s' "$bs" Users "$bs" seand)
win_bk_sed=$(printf '%s' "$win_bk" | sed 's/\\/&&/g')

idx=$(mktemp "${TMPDIR:-/tmp}/public-squash-index.XXXXXX")
trap 'rm -f "$idx" "$idx.blob"' EXIT
export GIT_INDEX_FILE=$idx
"$G" read-tree "$cand"

dropped=0; redacted=0
while IFS=$'\t' read -r meta path; do
  sha=${meta##* }
  # Blob to a file first: `cat-file | grep -q` dies of SIGPIPE under pipefail and
  # would silently classify a transcript as kept.
  "$G" cat-file blob "$sha" > "$idx.blob"
  if LC_ALL=C /usr/bin/grep -q -a -E 'OpenAI Codex v|session id:|workdir:' "$idx.blob"; then
    "$G" rm -q --cached -- "$path"; echo "DROP $path"; dropped=$((dropped+1))
  fi
done < <("$G" ls-tree -r "$cand" -- docs/strike/audits)

# Redact local paths in kept files. $1 = pathspec, $2 = sed script, rest = -F
# patterns for the candidate search. Blobs go through the index; LC_ALL=C sed is
# byte-safe, and a file is rewritten only if it contains one of the literals.
redact_pass() {
  local scope=$1 script=$2 path mode new p; shift 2
  local pats=()
  for p in "$@"; do pats+=(-e "$p"); done
  while IFS= read -r path; do
    mode=$("$G" ls-files -s -- "$path" | cut -d' ' -f1)
    new=$("$G" show ":$path" | LC_ALL=C sed "$script" | "$G" hash-object -w --stdin)
    "$G" update-index --cacheinfo "$mode,$new,$path"; echo "REDACT $path"; redacted=$((redacted+1))
  done < <("$G" grep --cached -l -F "${pats[@]}" -- "$scope" || true)
}
# Home and Mac volume everywhere (longest prefix first); build prefix in docs/ only.
redact_pass . "s#$home_re#~#g;s#$proj_re#<project>#g;s#$vol_re#<volume>#g" "$home_re" "$vol_re"
redact_pass "$build_scope" "s#$build_re#<build>#g" "$build_re"
redact_pass "$build_scope" "s#$win_fs\\(/\\)#~\\1#g;s#$win_bk_sed\\(\\\\\\)#~\\1#g" "$win_fs/" "$win_bk$bs"

tree=$("$G" write-tree)
# Each check is label|literal|pathspec; labels do not reveal the path.
for chk in "home path|$home_re|." "volume path|$vol_re|." "build path|$build_re|$build_scope" "windows user path|$win_fs/|$build_scope" "windows user path|$win_bk$bs|$build_scope"; do
  IFS='|' read -r label lit scope <<END_CHK
$chk
END_CHK
  # Exit 1 means "no match"; anything else (a bad pathspec, a git error) must not pass as clean.
  rc=0; "$G" grep -q -F "$lit" "$tree" -- "$scope" || rc=$?
  if [ "$rc" -eq 0 ]; then echo "FAIL: $label still present" >&2; exit 1; fi
  if [ "$rc" -ne 1 ]; then echo "FAIL: $label check could not run (git grep exit $rc)" >&2; exit 1; fi
done
commit=$("$G" commit-tree "$tree" -p "$parent" -F "$msgfile")
echo "dropped=$dropped redacted=$redacted tree=$tree"
echo "$commit"
