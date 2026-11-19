#!/usr/bin/env bash
# lint-ratchet.sh [--update]
#
# Falling-count ratchet for the three panic-path lints (clippy::unwrap_used, clippy::expect_used,
# clippy::await_holding_lock) over SHIPPED code (--lib --bins; test code is exempt).
#
#   * Our own crates (the crates that do not exist at the upstream fork point; see scripts/strike/own-crates.txt)
#     deny all three lints in source (`#![deny(...)]` in their crate roots), so their count must be 0.
#   * Inherited crates may not get worse: their per-crate count is recorded in
#     scripts/strike/lint-ratchet-baseline.txt (`<crate> <count>`, crates at 0 are omitted) and the script fails
#     when any count rises above its baseline or when a crate that is not in the baseline has any site.
#   * A count that FELL is reported; run `lint-ratchet.sh --update` to lock the lower number in.
#
# HARD RULE: this runs cargo, so it runs on the Hetzner build box (final-gate.sh calls it), never on a Mac.
set -uo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
BASE="$HERE/lint-ratchet-baseline.txt"
UPDATE=0
[ "${1:-}" = "--update" ] && UPDATE=1
cd "$ROOT" || exit 2
OUT=$(mktemp) || exit 2
ERR=$(mktemp) || exit 2
trap 'rm -f "$OUT" "$ERR"' EXIT
cargo clippy --locked --workspace --lib --bins --keep-going --message-format=json \
  -- -W clippy::unwrap_used -W clippy::expect_used -W clippy::await_holding_lock > "$OUT" 2> "$ERR"
RC=$?
# clippy exits non-zero on a hard error (a lint level `deny` hit, a compile error): that is a failure here too.
if [ $RC -ne 0 ]; then echo "lint-ratchet: cargo clippy failed (exit $RC)"; tail -n 40 "$ERR"; exit 1; fi
python3 - "$OUT" "$BASE" "$UPDATE" <<'PY'
import json, re, sys
out, base, update = sys.argv[1], sys.argv[2], sys.argv[3] == "1"
LINTS = {"clippy::unwrap_used", "clippy::expect_used", "clippy::await_holding_lock"}
seen, counts = set(), {}
def pkg_name(pid):
    m = re.search(r"#(?:[^@/]*/)?([A-Za-z0-9_.-]+)@", pid) or re.match(r"^(\S+) ", pid)
    if m:
        return m.group(1)
    m = re.search(r"/([A-Za-z0-9_.-]+)#", pid)
    return m.group(1) if m else pid
for line in open(out, encoding="utf-8", errors="replace"):
    try:
        j = json.loads(line)
    except ValueError:
        continue
    if j.get("reason") != "compiler-message":
        continue
    m = j["message"]
    code = (m.get("code") or {}).get("code")
    if code not in LINTS:
        continue
    span = next((s for s in m.get("spans", []) if s.get("is_primary")), None)
    if span is None:
        continue
    pkg = pkg_name(j["package_id"])
    key = (pkg, code, span["file_name"], span["line_start"], span["column_start"])
    if key in seen:
        continue
    seen.add(key)
    counts[pkg] = counts.get(pkg, 0) + 1
baseline = {}
for line in open(base, encoding="utf-8") if not update else []:
    line = line.strip()
    if line and not line.startswith("#"):
        k, v = line.rsplit(None, 1)
        baseline[k] = int(v)
if update:
    hdr = [
        "# Per-crate count of clippy::unwrap_used / expect_used / await_holding_lock in shipped code (--lib --bins).",
        "# Inherited crates only; crates not listed must be at 0. Maintained by scripts/strike/lint-ratchet.sh.",
        "# The count may only fall: lower it with `scripts/strike/lint-ratchet.sh --update`, never raise it by hand.",
    ]
    with open(base, "w", encoding="utf-8") as f:
        f.write("\n".join(hdr) + "\n")
        for k in sorted(counts):
            f.write(f"{k} {counts[k]}\n")
    print(f"lint-ratchet: baseline written, {sum(counts.values())} sites in {len(counts)} crates")
    sys.exit(0)
bad = [(k, counts.get(k, 0), baseline.get(k, 0)) for k in sorted(set(counts) | set(baseline)) if counts.get(k, 0) > baseline.get(k, 0)]
fell = [(k, counts.get(k, 0), baseline[k]) for k in sorted(baseline) if counts.get(k, 0) < baseline[k]]
for k, now, was in fell:
    print(f"lint-ratchet: {k} fell {was} -> {now}: run scripts/strike/lint-ratchet.sh --update to lock it in")
for k, now, was in bad:
    print(f"lint-ratchet: FAIL {k}: {now} sites, baseline {was}")
    for key in sorted(s for s in seen if s[0] == k):
        print(f"    {key[1]} {key[2]}:{key[3]}:{key[4]}")
print(f"lint-ratchet: {sum(counts.values())} sites in {len(counts)} crates (baseline {sum(baseline.values())}), {len(bad)} crate(s) over baseline")
sys.exit(1 if bad else 0)
PY
