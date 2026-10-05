#!/usr/bin/env python3
"""iso-resolve.py [--metadata <cargo-metadata.json>] <pkg> <gate-log> <test-name>...

Resolve, for each test name, the `cargo test` target selector that runs it, from the `Running ...` / `Doc-tests ...`
header that PRECEDES the name in a libtest log (a gate suite.log, an rp.sh log, ...). Used by iso.sh in `auto` mode so
that isolation also covers integration-test functions, which need `--test <file>` (a bare `--lib` would not find them).

Output, one line per (name, target) found:  <name><TAB><selector>   e.g.  foo<TAB>--test execution_acp
A name is located by (first match inside a section wins; a section = everything between two headers):
  `test <name> ... ok|FAILED|ignored`   (the name may be preceded by interleaved output on the same line)
  `---- <name> stdout ----`             (failure detail)
  an indented entry of the `failures:` block (the authoritative failing set; its `test ... FAILED` line can be lost
  to interleaving).
If the name occurs in several sections (e.g. a child test process printing its own libtest headers), EVERY distinct
selector is printed so the caller isolates each. A name found nowhere prints `<name><TAB>!UNRESOLVED`; a header that
cannot be mapped (benches, examples, unknown layout) prints `<name><TAB>!UNSUPPORTED <header>`.
Names may contain spaces (doctest names such as `src/lib.rs - double (line 10)`): one argument each.
With --metadata (the output of `cargo metadata --no-deps --format-version 1` run in the checkout that will be tested)
the target is looked up EXACTLY: the header's source path is matched against the `src_path` of <pkg>'s targets and the
cargo target NAME and kind are used (`[[bin]] name = ..` and `[lib] path = ..` need not look like the file or package);
a header with no match there is !UNSUPPORTED, never guessed. Without --metadata the path layout is used:
With metadata, a header path that matches targets of MORE THAN ONE package (package-relative `tests/x.rs` in two crates)
is ambiguous and is reported !UNSUPPORTED; without metadata that ambiguity cannot be seen at all, which is why iso.sh
requires metadata in auto mode. Both modes check the executable printed in the header (`.../deps/<crate>-<hash>`) against the target they resolved, so
a workspace log's `Running unittests src/lib.rs (.../other-abcd)` is never taken for the requested package's lib.
Selector mapping (path relative to the package OR the workspace root; both end the same way):
  unittests .../src/lib.rs            -> --lib
  unittests .../src/main.rs           -> --bin <pkg>
  unittests .../src/bin/X.rs | X/main.rs -> --bin X
  [.../]tests/X.rs | tests/X/main.rs  -> --test X
  Doc-tests <crate>                   -> --doc (only if <crate> is <pkg>'s library: a workspace log also holds the
                                         other packages' doctests, which `-p <pkg>` could never run)
Exit 0 always when the log is readable (the caller decides what UNRESOLVED means); 2 on usage/read errors.
"""
import re, sys

HDR = re.compile(r'^\s+(Running|Doc-tests)\s+(.*?)\s*(?:\((.*)\))?\s*$')

def exe_stem(exe):
    """crate name of a test executable path: .../deps/<crate_name>-<hash> -> crate_name (None if no path was printed)"""
    if not exe: return None
    b = exe.rstrip('/').rsplit('/', 1)[-1]
    return b.rsplit('-', 1)[0] if '-' in b else b


def selector(kind, rest, pkg, exe=None):
    if kind == 'Doc-tests':
        return '--doc' if rest.replace('-', '_') == pkg.replace('-', '_') else None
    m = re.match(r'^unittests\s+(\S+)$', rest)
    if m:
        p = m.group(1)
        if re.search(r'(^|/)src/lib\.rs$', p):
            es = exe_stem(exe)   # a workspace log also holds other packages' src/lib.rs: the executable names the crate
            return '--lib' if es is None or es == pkg.replace('-', '_') else None
        es = exe_stem(exe)
        if re.search(r'(^|/)src/main\.rs$', p):   # default bin target = the package name (a [[bin]] rename needs --metadata)
            return '--bin ' + pkg if es is None or es == pkg.replace('-', '_') else None
        m2 = re.search(r'(^|/)src/bin/([^/]+?)(\.rs|/main\.rs)$', p)
        if m2: return '--bin ' + m2.group(2) if es is None or es == m2.group(2).replace('-', '_') else None
        return None
    m = re.match(r'^(\S+)$', rest)
    if m:
        m2 = re.search(r'(^|/)tests/([^/]+?)(\.rs|/main\.rs)$', m.group(1))
        if m2: return '--test ' + m2.group(2) if exe_stem(exe) is None or exe_stem(exe) == m2.group(2).replace('-', '_') else None
    return None

def meta_selector(kind, rest, pkg, meta, exe=None):
    """exact selector from cargo metadata, or None. A header path that could belong to SEVERAL packages of the workspace
    (package-relative `tests/x.rs` present in two of them) is ambiguous and is refused, never guessed."""
    libk = ('lib', 'rlib', 'dylib', 'cdylib', 'staticlib', 'proc-macro')
    if kind == 'Doc-tests':   # the header names the crate: it must be THIS package's library target, and no other package's
        owners = {pk.get('name') for pk in meta.get('packages', []) for t in pk.get('targets', [])
                  if any(k in libk for k in t.get('kind', [])) and t['name'].replace('-', '_') == rest.replace('-', '_')}
        return '--doc' if owners == {pkg} else None
    m = re.match(r'^(?:unittests\s+)?(\S+)$', rest)
    if not m: return None
    p = m.group(1); unit = rest.startswith('unittests'); es = exe_stem(exe)
    found = {}   # package -> set of selectors
    for pk in meta.get('packages', []):
        for t in pk.get('targets', []):
            sp = t.get('src_path', '')
            if not (sp == p or sp.endswith('/' + p)): continue
            if es is not None and es != t['name'].replace('-', '_'): continue   # the executable must be THIS target's
            kinds = t.get('kind', [])
            if unit:
                sel = '--lib' if any(k in libk for k in kinds) else ('--bin ' + t['name'] if 'bin' in kinds else None)
            else:
                sel = '--test ' + t['name'] if 'test' in kinds else None
            rf = t.get('required-features') or []
            if sel and rf: sel += ' --features ' + ','.join('%s/%s' % (pk.get('name'), x) for x in rf)   # a gated target only builds with them
            if sel: found.setdefault(pk.get('name'), set()).add(sel)
    if set(found) != {pkg} or len(found[pkg]) != 1: return None   # not ours, or ambiguous between packages / targets
    return next(iter(found[pkg]))

def resolve(pkg, lines, names, meta=None):
    want = set(names)
    found = {n: [] for n in names}
    cur, cur_hdr, in_fail = None, None, False
    def note(n):
        if cur_hdr is None: return
        sel = cur if cur is not None else '!UNSUPPORTED ' + cur_hdr
        if sel not in found[n]: found[n].append(sel)
    for ln in lines:
        ln = ln.rstrip('\n').rstrip('\r')
        m = HDR.match(ln)
        if m:
            cur_hdr = ln.strip(); in_fail = False
            cur = meta_selector(m.group(1), m.group(2), pkg, meta, m.group(3)) if meta is not None else selector(m.group(1), m.group(2), pkg, m.group(3))
            continue
        if ln == 'failures:': in_fail = True; continue
        if in_fail:
            if ln == '': in_fail = False
            elif ln.startswith('    ') and ln.strip() in want: note(ln.strip()); continue
        hit = None
        for n in want:   # `test <name> ... <status>`; the name may follow other (interleaved) output on the same line
            k = ln.find('test ' + n + ' ... ')
            if k >= 0 and (k == 0 or not re.match(r'[A-Za-z0-9_:]', ln[k - 1])): hit = n; break
        if hit is None:
            m = re.match(r'^---- (.+) stdout ----$', ln)
            if m and m.group(1) in want: hit = m.group(1)
        if hit is not None: note(hit)
    return found

def main(argv):
    import json
    args = argv[1:]; meta = None
    if args[:1] == ['--metadata']:
        if len(args) < 2:
            print(__doc__.strip().splitlines()[0], file=sys.stderr); return 2
        try:
            with open(args[1]) as f: meta = json.load(f)
        except (OSError, ValueError) as e:
            print('iso-resolve: cannot use metadata %s: %s' % (args[1], e), file=sys.stderr); return 2
        args = args[2:]
    if len(args) < 3:
        print(__doc__.strip().splitlines()[0], file=sys.stderr); return 2
    pkg, log, names = args[0], args[1], args[2:]
    try:
        with open(log, errors='replace') as f: lines = f.readlines()
    except OSError as e:
        print('iso-resolve: cannot read %s: %s' % (log, e), file=sys.stderr); return 2
    found = resolve(pkg, lines, names, meta)
    for n in names:
        sels = found[n]
        if not sels: print('%s\t!UNRESOLVED' % n)
        for s in sels: print('%s\t%s' % (n, s))
    return 0

if __name__ == '__main__': sys.exit(main(sys.argv))
