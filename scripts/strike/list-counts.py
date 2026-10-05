#!/usr/bin/env python3
"""list-counts.py <derive.json> -- independent per-binary test counts for gate-verify.sh (A.2.1 rule 1).

For every test executable named in `cargo test --no-run --message-format=json`, runs `<exe> --list --format terse`
and prints `<exe-basename> <N>` and one `doc:<crate> -` line per doc-tested library of the selected packages (env P, as for derive.py) where N = number of `: test` lines (libtest's `running N tests` counts every test,
ignored included, so N here must equal it). A binary that cannot be listed is omitted; gate-verify then treats its
header as UNFINISHED when any expectation file is in force (fail closed). Binaries are only listed, never run.
"""
import sys, json, os, subprocess
seen = set()
want = os.environ.get("P", "*")
wanted = None if want == "*" else set(want.split(","))
docs = set()
def pkg_name(pid):
    if "#" in pid:
        tail = pid.split("#")[-1]
        return tail.split("@")[0] if "@" in tail else pid.split("#")[0].rstrip("/").split("/")[-1]
    return pid.split(" ")[0]
for line in open(sys.argv[1]):
    try: m = json.loads(line)
    except ValueError: continue
    if m.get("reason") != "compiler-artifact": continue
    t = m.get("target", {}); nm = pkg_name(m.get("package_id", ""))
    if (wanted is None or nm in wanted) and set(t.get("kind", [])) & {"lib", "rlib", "proc-macro"} and t.get("doctest"):
        docs.add("doc:" + t.get("name", "").replace("-", "_"))
    if not m.get("profile", {}).get("test") or not m.get("executable"): continue
    exe = m["executable"]
    if exe in seen: continue
    seen.add(exe)
    cwd = os.path.dirname(m.get("manifest_path", exe)) or "."
    try:
        r = subprocess.run([exe, "--list", "--format", "terse"], cwd=cwd, capture_output=True, text=True, timeout=300,
                           stdin=subprocess.DEVNULL)
    except Exception as e:
        print("list-counts: %s: %s" % (os.path.basename(exe), e), file=sys.stderr); continue
    if r.returncode != 0:
        print("list-counts: %s exit %d" % (os.path.basename(exe), r.returncode), file=sys.stderr); continue
    n = sum(1 for l in r.stdout.splitlines() if l.endswith(": test"))
    print(os.path.basename(exe), n)
for d in sorted(docs): print(d, "-")
