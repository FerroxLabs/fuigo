#!/usr/bin/env python3
"""derive.py -- Contract A.2.1 rule 2: derive the expected target count FROM THE CANDIDATE.

stdin : `cargo test --locked ... --no-run --message-format=json`
env P : a comma-separated list of package names (final-gate.sh always passes one: the --pkg names, or for the
        workspace scope the members listed by `cargo metadata --no-deps`), or `*` = every package whose id is
        a local path source (ad-hoc use only; final-gate.sh never passes it).
stdout: `<count> exe=<n> doc=<n> <sorted target names>`; the FIRST field is the number compared
        with cargo's `Running`/`Doc-tests` headers.
count = test executables + one doc-test run per lib/rlib/proc-macro target that has doc-tests enabled
        (ONE `Doc-tests` header per library, even when edition-2024 rustdoc prints two running/result pairs
        under it).
P=* is only meaningful for a `--workspace` build: with `-p X` cargo also emits artifacts for X's local
dependencies, so `*` would count their libraries too (observed: 26 instead of 2 for fuigo-sampling-types).
Checked against real `-p` runs of 1 and 5 packages (R029); still NOT checked against a full `--workspace`
run (no full gate was run, R029 limit (e)).
A target built for BOTH the lib and test profiles is counted once per executable path.
env NODOC=1 : count only test executables (used for rp.sh's second, feature-gated pass, which selects `--test`/`--bin`
        targets and runs no doc-tests, although the library artifact is still built as a dependency).
"""
import sys, json, os

nodoc = os.environ.get("NODOC") == "1"
want = os.environ.get("P", "*")
wanted = None if want == "*" else set(want.split(","))
exes, docs, names = set(), set(), []

def pkg_name(pid):
    if "#" in pid:                       # path+file:///x/y#name@ver  |  path+file:///x/name#ver
        tail = pid.split("#")[-1]
        if "@" in tail:
            return tail.split("@")[0]
        return pid.split("#")[0].rstrip("/").split("/")[-1]
    return pid.split(" ")[0]             # "name ver (path+file://...)"

def is_local(pid):
    return "path+file://" in pid

for line in sys.stdin:
    try:
        m = json.loads(line)
    except ValueError:
        continue
    if m.get("reason") != "compiler-artifact":
        continue
    pid = m.get("package_id", "")
    name = pkg_name(pid)
    if wanted is None:
        if not is_local(pid):
            continue
    elif name not in wanted:
        continue
    t = m.get("target", {})
    if m.get("profile", {}).get("test") and m.get("executable"):
        if m["executable"] not in exes:
            exes.add(m["executable"])
            names.append("%s/%s:%s" % (name, "/".join(t.get("kind", [])), t.get("name")))
    # cargo doc-tests lib, rlib AND proc-macro targets (Astra HIGH-6: "lib" alone under-counts)
    if not nodoc and set(t.get("kind", [])) & {"lib", "rlib", "proc-macro"} and t.get("doctest"):
        docs.add(name)

print(len(exes) + len(docs), "exe=%d doc=%d" % (len(exes), len(docs)), " ".join(sorted(names)))
