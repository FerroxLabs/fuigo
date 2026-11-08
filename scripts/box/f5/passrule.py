"""The B-F5 pass rule (design F5 §9.4), judged from the raw inotify log and the mark names in it.

Mutation events only (the watch's mask). Every event under `sessions/**/<id>/` (the `<id>` folder's own entry included)
must fall between a `b` and an `e` mark with the same path hash of a generation that claimed `<id>` (rule 1), inside
that generation's claim/free window (rule 2), or between an `rb`/`re` pair with the same path hash on `summary.json` or
`summary.json.lock` (a `summary.json.<uuid>.tmp` sibling is judged as `summary.json`). Windows of different generations
of one id never overlap (rule 3). `<parent>/subagents/<child>/` counts as the parent's. Excepted by name: the pager's
`images/image-<uuid-v4>.<ext>` (+ temp), `mermaid/*`, the `images/` and `mermaid/` directories, `session_writer.lock`.
A watched directory's own events (`<dir>/|...`) are judged as `<dir>`. Held handles: an IN_CLOSE_WRITE with no window of
its own is the close of a handle the writer opened (a lock sidecar from `open_lock`, an append handle); it counts when
an earlier window of an owning generation opened that path (or, for `summary.json` / `summary.json.lock`, an earlier
`rb`/`re` section), and rule 2 then needs the close before the id's next claim after that generation's free.
Not before the free itself (F5-B6): the kernel emits IN_CLOSE_WRITE when the LAST reference to the open file
description goes, and a child that another thread forks (a hook, an MCP server, `git`) copies every descriptor and
holds those references until its exec closes the O_CLOEXEC ones. So a handle our thread closed inside its window, or
before free, can report its close after it, when that child execs (box B4/B9 under strace: parent close, free mark,
child execve, then the event). The close-before-free order is proven in process instead (`f5b5_*` tests read
/proc/self/fd at the free). A pure close carries no bytes; a bypass write still shows its IN_MODIFY or IN_CREATE,
which this never excuses, and a close after the next claim (an old generation's handle alive in the new one's
tenure) still fails.
The run also fails on IN_Q_OVERFLOW, an unacknowledged or timed-out `d` mark, and any `x` mark.

Processes (B6, B9, B10 run a second `fuigo`). Every process counts writer generations and mark sequence numbers from 1,
so each process writes its marks to its own trace dir: the leader to `<FUIGO_HOME>/f5-marks` (process `p1`, acks in
`f5-acks`), the second process to `<FUIGO_HOME>/p2/f5-marks` (process `p2`, acks in `p2/f5-acks`). A generation is the
pair (process, gen), and every rule above is judged per (process, id). Rule 3 reads:
- within one process, the claim/free spans of two generations of one id never overlap, and no window of one lies in
  another's span outside its own (the in-process slot is exclusive);
- across processes, the claim/free spans of two generations of one id that WROTE (made at least one `b`/`e` window)
  never overlap, and no window of any generation lies inside another process's writing generation's span. A
  generation with no window is a claim the other process's OS hold refused (`HELD_ELSEWHERE`, design §5.2: the
  in-process slot is taken, the OS hold attach fails, the writer drops and frees having written nothing); its span is
  counted as `refused_cross_process` and is not an overlap, because it never held the id. Any write it made would give
  it a window and so be judged.
Writes `rule.json` into the evidence dir and prints a summary; exit 0 on pass.
"""
import json
import os
import re
import sys

from f5lib import path_hash

home, out = sys.argv[1], sys.argv[2]
sessions = home + "/sessions/"
# trace dir -> (process tag, its ack dir)
PROCS = {home + "/f5-marks/": ("p1", home + "/f5-acks/"), home + "/p2/f5-marks/": ("p2", home + "/p2/f5-acks/")}
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
IMAGE = re.compile(r"^images/image-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.[A-Za-z0-9]+(\..*tmp.*)?$")
SUMMARY_TMP = re.compile(r"^(.*/summary\.json)\..+\.tmp$")

lines = [l.rstrip("\n") for l in open(os.path.join(out, "inotify.log"))]
events = []
for i, line in enumerate(lines):
    path, _, ev = line.rpartition("|")
    events.append((i, path.rstrip("/") if path.endswith("/") else path, ev.split(",")))


def proc_of(path, which):
    """(process tag, name) when `path` is directly inside a trace dir (which=0) or an ack dir (which=1)."""
    for mdir, (tag, adir) in PROCS.items():
        d = mdir if which == 0 else adir
        if path.startswith(d) and "/" not in path[len(d):]:
            return tag, path[len(d):]
    return None, None


def gname(g):
    return "%s:%d" % g


claims, frees, bopen, windows, ropen, rwindows = {}, {}, {}, [], {}, []
dmarks, acked, xmarks, dto, pmarks = [], set(), [], [], []
overflow = [i for i, p, ev in events if "Q_OVERFLOW" in ev]
for i, path, ev in events:
    if "CREATE" not in ev:
        continue
    tag, name = proc_of(path, 1)
    if tag:
        acked.add("%s:%s" % (tag, name))
        continue
    tag, name = proc_of(path, 0)
    if not tag:
        continue
    n = name.split(".")
    kind = n[0]
    if kind in ("claim", "free"):
        gen, sid = (tag, int(n[-1])), ".".join(n[1:-1])
        (claims if kind == "claim" else frees)[(sid, gen)] = i
    elif kind == "b":
        bopen[((tag, int(n[1])), n[2], n[3])] = i
    elif kind == "e":
        key = ((tag, int(n[1])), n[2], n[3])
        windows.append({"gen": key[0], "seq": key[1], "hash": key[2], "b": bopen.pop(key, -1), "e": i})
    elif kind == "rb":
        ropen[(tag, n[1], n[2])] = i
    elif kind == "re":
        rwindows.append({"proc": tag, "seq": n[1], "hash": n[2], "b": ropen.pop((tag, n[1], n[2]), -1), "e": i})
    elif kind == "d":
        dmarks.append(("%s:d.%s.%s" % (tag, n[1], n[2]), i))
    elif kind == "dto":
        dto.append(i)
    elif kind == "x":
        xmarks.append(("%s:%s" % (tag, name), i))
    elif kind == "p":
        pmarks.append(("%s:%s" % (tag, name), i))
unclosed = [{"gen": gname(k[0]), "seq": k[1], "hash": k[2], "b": v} for k, v in bopen.items()]
unacked = [d for d, _ in dmarks if d not in acked]
ids = {sid for sid, _ in claims}
gens_of = {}
for sid, gen in claims:
    gens_of.setdefault(sid, set()).add(gen)


def owning_id(path):
    rel = path[len(sessions):].split("/")
    for k, comp in enumerate(rel):
        if comp in ids or UUID.match(comp):
            return comp, "/".join(rel[k + 1:])
    return None, None


def excepted(rel):
    return (rel in ("images", "mermaid", "session_writer.lock") or IMAGE.match(rel) is not None
            or rel.startswith("mermaid/"))


def released_in_tenure(sid, w, i):
    """A held handle's close at event `i` is its generation's: it opened the path inside its claim and the close comes
    before the id's next claim (any process) after that generation's free (see the docstring for why not the free)."""
    if not claims.get((sid, w["gen"]), 10**12) < w["b"]:
        return False
    free = frees.get((sid, w["gen"]), 10**12)
    later = [c for (s, _), c in claims.items() if s == sid and c > free]
    return i < min(later, default=10**12)


r1, r2, in_scope, excepted_n, out_scope, closes, deferred = [], [], 0, 0, 0, 0, 0
for i, path, ev in events:
    if not path.startswith(sessions):
        continue
    sid, rel = owning_id(path)
    if sid is None:
        out_scope += 1
        continue
    if excepted(rel):
        excepted_n += 1
        continue
    in_scope += 1
    h = path_hash(path)
    cands = [w for w in windows if w["hash"] == h and w["b"] < i < w["e"] and w["gen"] in gens_of.get(sid, ())]
    m = SUMMARY_TMP.match(path)
    rpath = m.group(1) if m else path
    if os.path.basename(rpath) in ("summary.json", "summary.json.lock"):
        rh = path_hash(rpath)
        if any(w["hash"] == rh and w["b"] < i < w["e"] for w in rwindows):
            continue
        if not cands and ev == ["CLOSE_WRITE", "CLOSE"] and any(w["hash"] == rh and w["e"] < i for w in rwindows):
            # A summary section's lock or file handle, released late by a forked child's exec (see the docstring).
            closes += 1
            deferred += 1
            continue
    if not cands and ev == ["CLOSE_WRITE", "CLOSE"]:
        opened = [w for w in windows if w["hash"] == h and w["e"] < i and w["gen"] in gens_of.get(sid, ())]
        if opened:
            closes += 1
            if not any(released_in_tenure(sid, w, i) for w in opened):
                r2.append({"line": i + 1, "event": lines[i], "id": sid, "held_handle_close": True})
            elif not any(i < frees.get((sid, w["gen"]), 10**12) for w in opened):
                deferred += 1
            continue
    if not cands:
        r1.append({"line": i + 1, "event": lines[i], "id": sid})
        continue
    ok2 = False
    for w in cands:
        c, f = claims.get((sid, w["gen"]), 10**12), frees.get((sid, w["gen"]), 10**12)
        if c < w["b"] and w["e"] < f:
            ok2 = True
    if not ok2:
        r2.append({"line": i + 1, "event": lines[i], "id": sid, "gens": sorted(gname(w["gen"]) for w in cands)})

# Rule 3, per id: see the docstring (in-process: every generation; cross-process: generations that wrote).
r3, refused = [], []
for sid, gens in gens_of.items():
    span = {g: (claims[(sid, g)], frees.get((sid, g), 10**12)) for g in gens}
    ws = [w for w in windows if w["gen"] in gens]
    wrote = {w["gen"] for w in ws}
    order = sorted(gens)
    for x, g1 in enumerate(order):
        for g2 in order[x + 1:]:
            a, b = span[g1], span[g2]
            if not (a[0] < b[1] and b[0] < a[1]):
                continue
            if g1[0] == g2[0] or (g1 in wrote and g2 in wrote):
                r3.append({"id": sid, "claim_free_overlap": [gname(g1), gname(g2)], "spans": [a, b]})
            else:
                refused.append({"id": sid, "gens": [gname(g1), gname(g2)], "spans": [a, b],
                                "wrote": [gname(g) for g in (g1, g2) if g in wrote]})
    for w in ws:
        own = span[w["gen"]]
        for g in gens:
            if g == w["gen"] or not (span[g][0] < w["b"] < span[g][1]):
                continue
            if g[0] != w["gen"][0] and g not in wrote:
                continue
            if g[0] != w["gen"][0] or not (own[0] < w["b"] < own[1]):
                r3.append({"id": sid, "window": dict(w, gen=gname(w["gen"])), "inside_gen": gname(g)})

# Coverage (a missed watch must never be a silent pass): `inotifywait -m -r` can miss a directory created in a race. A
# claimed session folder with no event strictly inside it was never watched; and when the run recorded the final tree
# (run.sh: home-tree.txt) every path under a session folder must have at least one recorded event, its CREATE.
unwatched = sorted(sid for sid in ids if not any(owning_id(p)[0] == sid and owning_id(p)[1] for _, p, _ in events
                                                 if p.startswith(sessions)))
uncovered = []
tree = os.path.join(out, "home-tree.txt")
if os.path.exists(tree):
    evpaths = {p for _, p, _ in events}
    for t in (l.rstrip("\n") for l in open(tree)):
        full = home + t[1:] if t.startswith("./") else None
        if not full or not full.startswith(sessions) or owning_id(full)[1] in (None, ""):
            continue
        if full not in evpaths and not any(e.startswith(full + "/") for e in evpaths):
            uncovered.append(full)

fail_reasons = []
if unwatched: fail_reasons.append("coverage: no watch event inside session folder(s) %s" % unwatched)
if uncovered: fail_reasons.append("coverage: %d path(s) in the final tree with no recorded event, first %s" % (len(uncovered), uncovered[:3]))
if r1: fail_reasons.append("rule 1: %d unmarked mutation event(s)" % len(r1))
if r2: fail_reasons.append("rule 2: %d event(s) in a window outside its generation's claim/free" % len(r2))
if r3: fail_reasons.append("rule 3: %d overlap(s) between generations" % len(r3))
if overflow: fail_reasons.append("IN_Q_OVERFLOW at lines %s" % overflow)
if unacked: fail_reasons.append("unacknowledged d marks: %s" % unacked)
if dto: fail_reasons.append("d-mark ack timeouts: %d" % len(dto))
if xmarks: fail_reasons.append("x-detector marks: %s" % [x for x, _ in xmarks])
result = {
    "pass": not fail_reasons,
    "rules_1_3_pass": not (r1 or r2 or r3),
    "coverage_gaps": {"unwatched_ids": unwatched, "uncovered_paths": uncovered[:20]},
    "fail_reasons": fail_reasons,
    "counts": {"events": len(events), "in_scope": in_scope, "excepted": excepted_n, "out_of_id_scope": out_scope,
               "held_handle_closes": closes, "deferred_closes": deferred, "windows": len(windows), "rwindows": len(rwindows), "claims": len(claims),
               "frees": len(frees), "processes": sorted({g[0] for _, g in claims}),
               "refused_cross_process": len(refused), "d_marks": len(dmarks), "d_acked": len(dmarks) - len(unacked),
               "unclosed_windows": len(unclosed)},
    "claims": {"%s.%s" % (k[0], gname(k[1])): v + 1 for k, v in claims.items()},
    "frees": {"%s.%s" % (k[0], gname(k[1])): v + 1 for k, v in frees.items()},
    "x_marks": xmarks, "p_marks": pmarks, "refused_cross_process": refused[:20],
    "rule1": r1[:40], "rule2": r2[:40], "rule3": r3[:40], "unclosed": unclosed[:20],
}
json.dump(result, open(os.path.join(out, "rule.json"), "w"), indent=1)
print("PASS RULE:", "PASS" if result["pass"] else "FAIL", "| rules 1-3:", "pass" if result["rules_1_3_pass"] else "FAIL")
for r in fail_reasons:
    print("  -", r)
for v in r1[:5]:
    print("  r1 line %d: %s" % (v["line"], v["event"]))
print("  counts:", json.dumps(result["counts"]))
sys.exit(0 if result["pass"] else 1)
