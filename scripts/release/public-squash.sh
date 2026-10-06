#!/usr/bin/env bash
# Build the PUBLIC release commit for a strike release: one commit on top of the
# last public release, whose tree is the release candidate's tree minus every
# raw Astra (codex exec) transcript, with local home paths redacted in what is kept.
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
# Built from pieces so this file does not contain the path it redacts (it would
# otherwise rewrite itself, and the release plan, in the public tree).
home_re=$(printf '/%s/%s' Users seandonahoe)

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

# Redact local home paths in every kept file (anywhere in the tree).
while IFS= read -r path; do
  mode=$("$G" ls-files -s -- "$path" | cut -d' ' -f1)
  new=$("$G" show ":$path" | LC_ALL=C sed "s#$home_re#~#g" | "$G" hash-object -w --stdin)
  "$G" update-index --cacheinfo "$mode,$new,$path"; echo "REDACT $path"; redacted=$((redacted+1))
done < <("$G" grep --cached -l -F "$home_re" -- . || true)

tree=$("$G" write-tree)
if "$G" grep -q -F "$home_re" "$tree" -- ; then echo "FAIL: home path still present" >&2; exit 1; fi
commit=$("$G" commit-tree "$tree" -p "$parent" -F "$msgfile")
echo "dropped=$dropped redacted=$redacted tree=$tree"
echo "$commit"
