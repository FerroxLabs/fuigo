#!/usr/bin/env bash
# Session-writer enforcement, checks 2 and 3 of design F5 §5.4.3 (no build). Usage: session-writer-crates.sh [repo]
#  2. Crate set: every crate in session-writer-crates.toml has a clippy.toml that is a key-wise superset of the root
#     clippy.toml (minus `producers`) plus `raw-write-ban`; the root file bans every producer; an unlisted crate with its
#     own clippy.toml bans every producer too, so it cannot escape check 1 by shadowing the root file.
#  3. Raw-path scan: non-test sources of unlisted crates must not hand-build session paths beyond the frozen baseline
#     scripts/ci/session-path-baseline.txt (one `crate:file:pattern: reason` per line).
set -euo pipefail
REPO=$(cd "${1:-$(dirname "$0")/../..}" && pwd)
META=$(mktemp); trap 'rm -f "$META"' EXIT
(cd "$REPO" && cargo metadata --no-deps --format-version 1 --offline >"$META" 2>/dev/null) ||
  (cd "$REPO" && cargo metadata --no-deps --format-version 1 >"$META")
python3 - "$REPO" "$META" <<'PY'
import json, pathlib, re, sys, tomllib
repo = pathlib.Path(sys.argv[1]); meta = json.load(open(sys.argv[2])); errs = []
cfg = tomllib.load(open(repo / "session-writer-crates.toml", "rb"))
listed, producers, ban = set(cfg["crates"]), set(cfg["producers"]), set(cfg["raw-write-ban"])
crates = {p["name"]: pathlib.Path(p["manifest_path"]).parent for p in meta["packages"]}
def load(p): return tomllib.load(open(p, "rb"))
def paths(t): return {e["path"] if isinstance(e, dict) else e for e in t.get("disallowed-methods", [])}
root = load(repo / "clippy.toml")
for p in sorted(producers - paths(root)): errs.append(f"root clippy.toml: producer {p} is not banned")
want_keys = {k: v for k, v in root.items() if k != "disallowed-methods"}
want = (paths(root) - producers) | ban
for c in sorted(listed):
    if c not in crates: errs.append(f"{c}: listed in session-writer-crates.toml but not a workspace crate"); continue
    f = crates[c] / "clippy.toml"
    if not f.exists(): errs.append(f"{c}: listed crate has no clippy.toml"); continue
    t = load(f)
    for k, v in want_keys.items():
        if t.get(k) != v: errs.append(f"{c}/clippy.toml: key {k} missing or differs from the root clippy.toml")
    for p in sorted(want - paths(t)): errs.append(f"{c}/clippy.toml: missing disallowed-methods entry {p}")
for c, d in sorted(crates.items()):
    if c in listed: continue
    for name in ("clippy.toml", ".clippy.toml"):
        if (d / name).exists() and (d / name).resolve() != (repo / name).resolve():
            for p in sorted(producers - paths(load(d / name))):
                errs.append(f"{c}/{name}: shadows the root clippy.toml without the producer ban {p}")
PATTERNS = ['join("sessions")', '"sessions/"', "SESSION_WRITER_LOCK_FILE", "CHAT_HISTORY_FILE", "UPDATES_FILE"]
def is_test(rel):
    return any(s in ("tests", "benches", "examples") for s in rel.parts) or re.search(r"(^|_)tests?(_\w+)?\.rs$|test_util", rel.name)
def strip_cfg_test(lines):  # drop `#[cfg(test)] mod ... { ... }` blocks
    out, skip, depth, opened = [], False, 0, False
    for i, l in enumerate(lines):
        if not skip and l.strip().startswith("#[cfg(test)]") and i + 1 < len(lines) and re.match(r"\s*(pub(\(\w+\))? )?mod ", lines[i + 1]):
            skip, depth, opened = True, 0, False
        if skip:
            depth += l.count("{") - l.count("}"); opened = opened or "{" in l
            if (opened and depth <= 0) or (not opened and l.rstrip().endswith(";") and "mod " in l): skip = False
            continue
        out.append(l)
    return out
hits = set()
for c, d in sorted(crates.items()):
    if c in listed or not (d / "src").is_dir(): continue
    for f in sorted((d / "src").rglob("*.rs")):
        rel = f.relative_to(d)
        if is_test(rel): continue
        text = "\n".join(strip_cfg_test(f.read_text(errors="replace").splitlines()))
        hits |= {(c, str(rel), p) for p in PATTERNS if p in text}
base = {}
for n, l in enumerate((repo / "scripts/ci/session-path-baseline.txt").read_text().splitlines(), 1):
    if not l.strip() or l.startswith("#"): continue
    m = re.match(r"([^:]+):([^:]+):(.+?): (\S.*)$", l)
    if not m: errs.append(f"session-path-baseline.txt:{n}: not crate:file:pattern: reason"); continue
    base[m.groups()[:3]] = m.group(4)
for h in sorted(hits - base.keys()):
    errs.append("raw-path scan: new hand-built session path %s:%s:%s (list the crate, or review it into "
                "scripts/ci/session-path-baseline.txt with a reason)" % h)
for h in sorted(base.keys() - hits): print("note: stale baseline entry %s:%s:%s" % h)
for e in errs: print("error:", e)
print(f"session-writer-crates: {len(listed)} listed, {len(crates)} workspace crates, {len(hits)} scan hits, "
      f"{len(base)} baseline entries, {len(errs)} errors")
sys.exit(1 if errs else 0)
PY
