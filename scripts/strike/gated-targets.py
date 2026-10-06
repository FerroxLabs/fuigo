#!/usr/bin/env python3
"""gated-targets.py <pkg>...   (stdin: `cargo metadata --no-deps --format-version 1` of the checkout)

Prints one line per test target of the named packages that a plain `cargo test -p <pkg>` SILENTLY SKIPS because it has
`required-features` (e.g. fuigo-shell's test_startup_prefetch_* need `test-support`):
    <pkg> <flag> <target> <features,comma-separated>        flag = --test | --bin
and, last, one summary line per package with gated targets:
    #features <pkg> <pkg>/f1,<pkg>/f2,...                   (the --features argument for a second pass)
Targets whose required-features are all enabled by the package's default features are not listed (cargo runs them).
Only targets cargo actually runs under `cargo test` are listed: kind `test`, and `bin` targets whose `test` flag is true.
Examples and benches are not run by `cargo test` and are not listed. Why a second pass and not --all-features: all-features
can enable mutually exclusive or platform-specific features and changes the build of the normal targets; the second pass
enables ONLY the features the skipped targets themselves declare, and runs ONLY those targets.
"""
import sys, json
want = set(sys.argv[1:])
meta = json.load(sys.stdin)
for pk in sorted(meta.get("packages", []), key=lambda p: p["name"]):
    if pk["name"] not in want: continue
    feats = set()
    # features enabled by default (transitive closure of `default`): a target whose required-features are all enabled by default
    # is NOT skipped by a plain `cargo test -p <pkg>`
    fmap = pk.get("features", {}); on = set(); todo = list(fmap.get("default", []))
    while todo:
        f = todo.pop()
        if f in on or f not in fmap: continue
        on.add(f); todo.extend(fmap[f])
    for t in pk.get("targets", []):
        rf = t.get("required-features") or []
        kinds = t.get("kind", [])
        if not rf or all(r in on for r in rf): continue
        if "test" in kinds: flag = "--test"
        elif "bin" in kinds and t.get("test", True): flag = "--bin"
        else: continue
        print(pk["name"], flag, t["name"], ",".join(rf))
        feats.update(rf)
    if feats: print("#features", pk["name"], ",".join("%s/%s" % (pk["name"], f) for f in sorted(feats)))
