#!/usr/bin/env python3
"""1.0.47 S2 (SL-06) design §3 E2: the at-rest path inventory.

Every file Fuigo writes under `$FUIGO_HOME/sessions/**` or `$FUIGO_HOME/logs/**` must go through the at-rest layer
(`fuigo_secrets::at_rest`, or a `SessionWriter`, which uses it). This check covers PATH ACQUISITION, lexically:

  1. Roots have single producers (`fuigo_config::paths::sessions_root`/`sessions_root_in`/`logs_dir` and the cwd/session
     producers). A hand-built join of "logs"/"sessions"/`LOG_DIR`/`DEFAULT_LOG_DIR`/`SESSIONS_DIR` (or a
     "logs/..."/"sessions/..." literal path) fails, as does an unmarked `tempdir_in`/`tempfile_in`/`NamedTempFile::new_in`
     (a staging dir can sit under a root). A line that is not under a root says so: `// at-rest: outside-roots <why>`.
  2. Every call of a root producer (and of the by-path constructors `new_at`/`open_at`, `OutputLog::ByPath`) is listed in
     `at-rest-inventory.toml`, keyed by file, enclosing function, producer and its ordinal in that function, with a class:
     writer | at-rest | verbatim:RewindStore | verbatim:PermissionGrants | read-only | media | outside-roots.
     A new, moved or second call fails until it is classified; a listed site that no longer exists fails too.
  3. In the enclosing function of a site classed writer, at-rest or media, a raw open-for-write (`fs::write(`,
     `File::create`, `.write(true)`, `.append(true)`, `create_new(true)`, `tokio::io::copy(`, `fs::copy(`, `to_writer(`,
     `NamedTempFile::`, `owner_only::create(`) must write layer output: a transforming call (`transform_whole(`,
     `transform_owned(`, `at_rest_text(`, `AtRestFile::records/stream(`, `AtRestStream::new(`, ...) in its own statement,
     or a binding whose latest assignment before it is one (a reassignment or shadowing drops it). Otherwise it carries an
     `// at-rest:` marker. A site classed at-rest whose function
     never names the layer fails.

What it does NOT see (stated, not hidden): a root path carried in a struct field or argument to a function elsewhere
and written raw there. That is what the canary census (design E3, test 7: every file under the roots is a known name
and none holds the canary) is for.

Usage: at-rest-roots.py [--root DIR] [--inventory FILE] [--print]   (exit 1 on any failure)
       at-rest-roots.py --selftest                                  (negative controls, design test 10)
"""
import os
import re
import sys

PRODUCERS = [
    "sessions_cwd_dir", "sessions_cwd_dir_in", "ensure_sessions_cwd_dir", "ensure_sessions_cwd_dir_in",
    "find_session_dir_by_id", "find_persisted_session_dir", "session_dir", "sessions_root", "sessions_root_in",
    "logs_dir", "new_at", "open_at",
]
PRODUCER_RE = re.compile(r"(?<![\w.])(?:[\w:]+::)?(" + "|".join(PRODUCERS) + r")\s*\(|(OutputLog::ByPath)\b")
METHOD_PRODUCER_RE = re.compile(r"\.(open_at|new_at)\s*\(")
JOIN_RE = re.compile(
    r"\.join\(\s*(?:\"(?:logs|sessions)(?:/[^\"]*)?\"|(?:[\w:]+::)?(?:DEFAULT_LOG_DIR|LOG_DIR|SESSIONS_DIR|LOGS_DIR)\b)"
    r"|\"(?:\.fuigo/)?(?:logs|sessions)/[^\"]*\""
)
TEMP_RE = re.compile(r"\b(?:tempdir_in|tempfile_in|NamedTempFile::new_in)\s*\(")
RAW_RE = re.compile(
    r"fs::write\(|File::create(?:_new)?\(|\.write\(true\)|\.append\(true\)|create_new\(true\)|tokio::io::copy\(|"
    r"fs::copy\(|to_writer\(|NamedTempFile::|owner_only::create\("
)
LAYER_RE = re.compile(r"at_rest|transform_whole|AtRestFile|AtRestStream|at_rest_text")
# The calls that actually transform (a name such as `at_rest_bytes` is not one, Astra code review Medium 3).
CALL_RE = re.compile(
    r"\b(?:transform_whole|transform_owned|at_rest_text|at_rest_for)\s*\(|\bAtRestFile::(?:records|stream)\s*\("
    r"|\bAtRestStream::new\s*\(|\bscrubbed_non_blocking\s*\("
)
MARK = "// at-rest:"
STRING_RE = re.compile(r'"(?:\\.|[^"\\])*"')
CLASSES = {"writer", "at-rest", "verbatim:RewindStore", "verbatim:PermissionGrants", "read-only", "media", "outside-roots"}
FN_RE = re.compile(r"^\s*(?:pub(?:\([\w:]+\))?\s+)?(?:const\s+)?(?:async\s+)?(?:unsafe\s+)?(?:extern\s+\"C\"\s+)?fn\s+(\w+)")
# The producers' own definitions.
DEFINERS = {"crates/codegen/fuigo-config/src/paths.rs"}


# Crates whose "logs"/"sessions" are not Fuigo's roots (git's logs/, Codex's sessions/, ptyctl's state) or that are
# test harnesses driving a Fuigo binary from outside.
OTHER_TREES = ("crates/codegen/fuigo-fast-worktree/", "crates/codegen/fuigo-foreign-sessions/",
               "crates/codegen/ptyctl-cli/", "crates/codegen/fuigo-pager-pty-harness/")


def is_test_file(rel):
    base = os.path.basename(rel)
    return (rel.startswith(OTHER_TREES) or base == "build.rs" or "/testkit/" in rel or "_tests/" in rel or base.endswith("_tests.rs") or base == "tests.rs" or "/tests/" in rel or "/benches/" in rel
            or "/examples/" in rel or base.startswith("test_") or "test_support" in rel or "test-support" in rel
            or "/fuigo-test-" in rel)


def statement_bounds(lines, i):
    """The first and last line of the statement that holds lines[i] (a statement ends at `;`, `{` or `}`)."""
    start = i
    while start > 0 and not lines[start - 1].rstrip().endswith((";", "{", "}")):
        start -= 1
    end = i
    while end + 1 < len(lines) and not lines[end].rstrip().endswith((";", "{", "}")):
        end += 1
    return start, end


def through_layer(body, i):
    """Whether the raw write at body[i] writes layer output: a transforming call (CALL_RE, not merely a layer-ish name)
    is in the write's own statement, or the statement uses a binding whose LATEST assignment before it is such a call.
    A reassignment or shadowing to anything else drops that provenance (Astra code review Medium 3), and a layer call
    merely nearby does not count (Astra code review: `contains_any(b"")` next to `fs::write(.., raw)` passed)."""
    lines = [STRING_RE.sub('""', strip_comment(l)) for _, l in body]
    start, end = statement_bounds(lines, i)
    statement = " ".join(lines[start:end + 1])
    if CALL_RE.search(statement):
        return True
    provenance = {}
    j = 0
    while j < start:
        s, e = statement_bounds(lines, j)
        e = min(e, start - 1)
        text = " ".join(lines[s:e + 1])
        m = re.match(r"\s*(?:let\s+(?:mut\s+)?)?([a-z_]\w*)\s*(?::[^=]*)?=(?!=)", text)
        if m:
            provenance[m.group(1)] = bool(CALL_RE.search(text[m.end():]))
        j = e + 1
    words = set(re.findall(r"\b[a-z_]\w*\b", statement))
    return any(provenance.get(w) for w in words)


def strip_comment(line):
    # Drop a `//` comment that is not inside a string literal (good enough for this lexical check).
    out, in_str, i = [], False, 0
    while i < len(line):
        c = line[i]
        if c == '"' and (i == 0 or line[i - 1] != "\\"):
            in_str = not in_str
        if not in_str and line.startswith("//", i):
            break
        out.append(c)
        i += 1
    return "".join(out)


def code_lines(text):
    """(line number, raw line, code) for non-test code. A column-0 `#[cfg(test)]` (or `#[cfg(all(test, ...))]`) item
    that opens a block is skipped through its column-0 closing `}`; a one-line `mod x;` under it is skipped too."""
    lines = text.split("\n")
    out = []
    skipping = False
    pending_test = False
    for n, raw in enumerate(lines, 1):
        if skipping:
            if raw.startswith("}"):
                skipping = False
            continue
        if raw.startswith("#[cfg(test)]") or raw.startswith("#[cfg(all(test"):
            pending_test = True
            continue
        if pending_test:
            if raw.startswith("#["):
                continue
            pending_test = False
            if raw.rstrip().endswith(";"):
                continue
            if raw.rstrip().endswith("{") and not raw.startswith(" "):
                skipping = True
                continue
        out.append((n, raw, strip_comment(raw)))
    return out


def functions(lines):
    """Map each line number to (enclosing fn name, body line range) by brace depth."""
    owner = {}
    stack = []  # (name, depth at open, start line)
    depth = 0
    spans = {}
    pending = None
    for n, raw, code in lines:
        m = FN_RE.match(code)
        if m:
            pending = (m.group(1), n)
        for ch in code:
            if ch == "{":
                depth += 1
                if pending:
                    stack.append((pending[0], depth, pending[1]))
                    pending = None
            elif ch == "}":
                if stack and stack[-1][1] == depth:
                    name, _, start = stack.pop()
                    spans.setdefault(start, (name, start, n))
                depth -= 1
        if pending and code.rstrip().endswith(";"):
            pending = None  # a declaration without a body (trait method)
        owner[n] = stack[-1] if stack else None
    return owner, spans


def scan(root, inventory_path, fail):
    sites = {}
    bodies = {}
    for dirpath, dirnames, filenames in os.walk(os.path.join(root, "crates")):
        dirnames[:] = [d for d in dirnames if d not in ("target", "tests", "benches", "examples")]
        for f in filenames:
            if not f.endswith(".rs"):
                continue
            path = os.path.join(dirpath, f)
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            if is_test_file(rel):
                continue
            text = open(path, encoding="utf-8", errors="replace").read()
            lines = code_lines(text)
            raw_by_n = {n: raw for n, raw, _ in lines}
            owner, spans = functions(lines)
            ordinals = {}
            for n, raw, code in lines:
                marked = MARK in raw or MARK in raw_by_n.get(n - 1, "")
                if rel not in DEFINERS and not marked:
                    if JOIN_RE.search(code):
                        fail(f"{rel}:{n}: hand-built root path (use fuigo_config::paths::sessions_root/logs_dir, or mark "
                             f"`{MARK} outside-roots <why>`): {raw.strip()}")
                    if TEMP_RE.search(code):
                        fail(f"{rel}:{n}: temp file/dir created in a caller-chosen dir; mark `{MARK} <class> <why>`: "
                             f"{raw.strip()}")
                definition = FN_RE.match(code)
                bare = STRING_RE.sub('""', code)  # a producer named inside a string literal is not a call
                for m in list(PRODUCER_RE.finditer(bare)) + list(METHOD_PRODUCER_RE.finditer(bare)):
                    producer = m.group(1) or (m.group(2) if m.lastindex and m.lastindex >= 2 else None) or m.group(0)
                    if rel in DEFINERS or (definition and definition.start(1) <= m.start() < definition.end(1) + 1
                                           and definition.group(1) == producer):
                        continue  # the producer's own definition, not a call
                    fn = owner.get(n)
                    fn_name = fn[0] if fn else "<module>"
                    k = (rel, fn_name, producer)
                    ordinals[k] = ordinals.get(k, 0) + 1
                    key = f"{rel} {fn_name} {producer} {ordinals[k]}"
                    sites[key] = (n, raw.strip())
                    if fn:
                        start = fn[2]
                        bodies[key] = [(m2, raw_by_n[m2]) for m2 in range(start, spans.get(start, (0, 0, start))[2] + 1)
                                       if m2 in raw_by_n]
    inventory = {}
    if inventory_path and os.path.exists(inventory_path):
        for n, line in enumerate(open(inventory_path, encoding="utf-8"), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r'^"([^"]+)"\s*=\s*"([^"]+)"\s*(?:#.*)?$', line)
            if not m:
                fail(f"{inventory_path}:{n}: not `\"<file> <fn> <producer> <ordinal>\" = \"<class>\"`")
                continue
            key, cls = m.groups()
            if cls not in CLASSES:
                fail(f"{inventory_path}:{n}: unknown class {cls}")
            inventory[key] = cls
    for key, (n, raw) in sorted(sites.items()):
        rel = key.split(" ")[0]
        cls = inventory.get(key)
        if cls is None:
            fail(f"{rel}:{n}: unclassified root-producer call `{key}`; add it to at-rest-inventory.toml: {raw}")
            continue
        body = bodies.get(key, [])
        if cls in ("writer", "at-rest", "media", "read-only"):
            for i, (m2, line) in enumerate(body):
                if RAW_RE.search(strip_comment(line)) and MARK not in line and (i == 0 or MARK not in body[i - 1][1]):
                    if not through_layer(body, i):
                        fail(f"{rel}:{m2}: raw write in `{key}` (class {cls}) not through the at-rest layer; route it, or "
                             f"mark `{MARK} <why>`: {line.strip()}")
        if cls == "at-rest" and body and not any(LAYER_RE.search(l) for _, l in body):
            fail(f"{rel}:{n}: `{key}` is classed at-rest but its function never uses the at-rest layer")
    for key in sorted(set(inventory) - set(sites)):
        fail(f"at-rest-inventory.toml: `{key}` is listed but no such call exists (moved or removed: update the list)")
    return sites


def main(argv):
    root = "."
    inventory = None
    show = "--print" in argv
    if "--root" in argv:
        root = argv[argv.index("--root") + 1]
    inventory = os.path.join(root, "at-rest-inventory.toml")
    if "--inventory" in argv:
        inventory = argv[argv.index("--inventory") + 1]
    failures = []
    sites = scan(root, inventory, failures.append)
    if show:
        for key in sorted(sites):
            print(f'"{key}" = "?"')
        return 0
    for f in failures:
        print(f"at-rest-roots: {f}")
    print(f"at-rest-roots: {len(sites)} root-producer call sites, {len(failures)} failures")
    return 1 if failures else 0


def selftest():
    """Design test 10: each negative control must fail the check; the clean fixture must pass."""
    import tempfile
    clean = '''
fn writes_log() {
    let dir = fuigo_config::paths::logs_dir();
    let bytes = fuigo_secrets::at_rest::transform_whole(b"x");
    std::fs::write(dir.join("a.log"), &bytes).unwrap();
}
'''
    controls = {
        "unclassified producer": clean + "fn other() { let d = fuigo_config::paths::sessions_root(); }\n",
        "second call in one function": clean.replace(
            "let dir = fuigo_config::paths::logs_dir();",
            "let dir = fuigo_config::paths::logs_dir();\n    let again = fuigo_config::paths::logs_dir();"),
        "hand-built join(\"logs\")": clean + "fn j() { let p = fuigo_config::fuigo_home().join(\"logs\"); }\n",
        "join(DEFAULT_LOG_DIR)": clean + "fn j() { let p = home.join(DEFAULT_LOG_DIR); }\n",
        "literal logs/ path": clean + "fn j() { let p = home.join(\"logs/mcp\"); }\n",
        "tempdir_in under a sessions cwd": clean + "fn t(cwd: &Path) { tempfile::Builder::new().tempdir_in(cwd); }\n",
        "raw write labelled at-rest (alias)": '''
fn writes_log() {
    let dir = fuigo_config::paths::logs_dir();
    let alias = dir.clone();
    std::fs::write(alias.join("a.log"), b"raw").unwrap();
    let a = 1;
    let b = 2;
    let c = 3;
    let _ = fuigo_secrets::at_rest::contains_any(b"");
}
''',
        "adjacent unused layer call": '''
fn writes_log() {
    let dir = fuigo_config::paths::logs_dir();
    let _ = fuigo_secrets::at_rest::contains_any(b"");
    std::fs::write(dir.join("a.log"), b"raw").unwrap();
}
''',
        "binding reassigned to raw bytes": '''
fn writes_log() {
    let dir = fuigo_config::paths::logs_dir();
    let mut bytes = fuigo_secrets::at_rest::transform_whole(b"x").into_owned();
    bytes = b"raw".to_vec();
    std::fs::write(dir.join("a.log"), &bytes).unwrap();
}
''',
        "binding shadowed by raw bytes": '''
fn writes_log() {
    let dir = fuigo_config::paths::logs_dir();
    let bytes = fuigo_secrets::at_rest::transform_whole(b"x");
    let bytes = b"raw";
    std::fs::write(dir.join("a.log"), bytes).unwrap();
}
''',
        "layer-named variable, no transforming call": '''
fn writes_log() {
    let dir = fuigo_config::paths::logs_dir();
    let at_rest_bytes = b"raw";
    std::fs::write(dir.join("a.log"), at_rest_bytes).unwrap();
}
''',
        "at-rest label without the layer": '''
fn writes_log() {
    let dir = fuigo_config::paths::logs_dir();
    let mut f = std::fs::OpenOptions::new().append(true).open(dir.join("a.log")).unwrap();
}
''',
    }
    inv = '"crates/x/src/lib.rs writes_log logs_dir 1" = "at-rest"\n'
    ok = True
    for name, body in [("clean fixture", clean)] + list(controls.items()):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "crates/x/src"))
            open(os.path.join(d, "crates/x/src/lib.rs"), "w").write(body)
            open(os.path.join(d, "at-rest-inventory.toml"), "w").write(inv)
            failures = []
            scan(d, os.path.join(d, "at-rest-inventory.toml"), failures.append)
            expect_fail = name != "clean fixture"
            if bool(failures) != expect_fail:
                ok = False
                print(f"selftest FAILED: {name}: {'no failure' if expect_fail else failures}")
            else:
                print(f"selftest ok: {name}" + (f" -> {failures[0][:100]}" if failures else ""))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(selftest() if "--selftest" in sys.argv else main(sys.argv[1:]))
