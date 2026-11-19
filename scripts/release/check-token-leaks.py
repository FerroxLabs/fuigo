#!/usr/bin/env python3
"""Leak guard: fail on an UNSPLIT vendor-shaped token (known prefix + token-length body) in tracked text files.

Fake fixtures must be split so secret scanners and push protection never see a token:
    concat!("sk_", "live_...")   "sk_" + "live_..."   printf '%s%s' sk_ live_...
A bare prefix (a regex, a redaction list, a comment) is not a token and is not flagged.

    check-token-leaks.py              scan the tracked files of the working tree (git ls-files)
    check-token-leaks.py <tree-ish>   scan that tree (public-squash.sh passes the release tree)
    check-token-leaks.py --files F..  scan the listed files (self-test)

Exit 0 clean, 1 found, 2 tool error. The matched text is never printed: only path:line.
Skipped: a line containing "leak-guard: allow", AWS's documented example key id, vendored third_party/,
historical docs/strike/audits/, and the lines in token-leak-baseline.txt (sha256 of the line text, written
when this guard was introduced for fixtures that predate it; editing such a line puts it back under the guard,
so split it then). Use `--print-baseline` to regenerate the baseline from the current tree.
"""
import hashlib, os, re, subprocess, sys

PATTERNS = [
    r"(?:sk|rk|pk)_live_[0-9A-Za-z]{16,}",
    r"shp(?:at|ss|ca|pa)_[0-9a-fA-F]{24,}",
    r"gh[pousr]_[0-9A-Za-z]{30,}",
    r"github_pat_[0-9A-Za-z_]{40,}",
    r"xox[abeoprs]-[0-9A-Za-z-]{20,}",
    r"(?:AKIA|ASIA)[0-9A-Z]{16}",
    r"AIza[0-9A-Za-z_-]{35}",
    r"glpat-[0-9A-Za-z_-]{20,}",
    r"npm_[0-9A-Za-z]{36}",
    r"sk-ant-[0-9A-Za-z_-]{30,}",
    r"sk-(?:proj-)?[0-9A-Za-z_]{40,}",
]
TOKEN = re.compile("|".join(PATTERNS))
ALLOW = re.compile(r"AKIAIOSFODNN7EXAMPLE|leak-guard: allow")
SKIP_DIRS = ("third_party/", "docs/strike/audits/")
HERE = os.path.dirname(os.path.abspath(__file__))
BASELINE = os.path.join(HERE, "token-leak-baseline.txt")


def git(*args, cwd=None):
    return subprocess.run(["git", *args], cwd=cwd, check=True, stdout=subprocess.PIPE).stdout


def load_baseline():
    try:
        with open(BASELINE) as f:
            return {l.split()[0] for l in f if l.strip() and not l.startswith("#")}
    except FileNotFoundError:
        return set()


def sources(spec):
    """Yield (path, bytes)."""
    if spec is None:
        for p in git("ls-files", "-z").decode().split("\0"):
            if p and os.path.isfile(p):
                with open(p, "rb") as f:
                    yield p, f.read()
    else:
        git("rev-parse", "--verify", spec + "^{tree}")
        for p in git("ls-tree", "-r", "-z", "--name-only", spec).decode().split("\0"):
            if p:
                yield p, git("show", f"{spec}:{p}")


def scan(items, baseline):
    hits = []
    for path, data in items:
        if path.startswith(SKIP_DIRS) or b"\0" in data[:8192] or not TOKEN.search(data.decode("latin-1")):
            continue
        for n, line in enumerate(data.decode("latin-1").splitlines(), 1):
            if TOKEN.search(line) and not ALLOW.search(line):
                h = hashlib.sha256(line.strip().encode("latin-1")).hexdigest()
                hits.append((path, n, h, h in baseline))
    return hits


def main(argv):
    mode, spec, items = "scan", None, None
    if argv[:1] == ["--files"]:
        if len(argv) < 2:
            print("usage: check-token-leaks.py --files FILE...", file=sys.stderr); return 2
        items = ((p, open(p, "rb").read()) for p in argv[1:])
    elif argv[:1] == ["--print-baseline"]:
        mode = "baseline"
    elif argv:
        spec = argv[0]
    try:
        hits = scan(items if items is not None else sources(spec), set() if mode == "baseline" else load_baseline())
    except (subprocess.CalledProcessError, OSError) as e:
        print(f"check-token-leaks: scan could not run: {e}", file=sys.stderr); return 2
    if mode == "baseline":
        print("# sha256 of grandfathered fixture lines that predate the leak guard (see check-token-leaks.py)")
        for h in sorted({h for _, _, h, _ in hits}):
            print(h)
        return 0
    bad = [(p, n) for p, n, _, known in hits if not known]
    if bad:
        print('FAIL: unsplit vendor token shape in source; split it, e.g. concat!("sk_", "live_..."):', file=sys.stderr)
        for p, n in bad:
            print(f"  {p}:{n}", file=sys.stderr)
        return 1
    print(f"leak guard: clean ({sum(1 for h in hits if h[3])} grandfathered)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
