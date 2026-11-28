"""TEMPORARY proof diagnostics: text-only report on two builds of the same exe (no binaries leave the runner).
usage: diag.py exe1 pdb1 exe2 pdb2 out.txt"""
import hashlib, re, struct, sys, collections

exe1, pdb1, exe2, pdb2, out = sys.argv[1:6]
o = open(out, "w")
def w(*a): print(*a, file=o)

def pe(d):
    p = struct.unpack_from("<I", d, 0x3C)[0]
    nsec, = struct.unpack_from("<H", d, p + 6); optsz, = struct.unpack_from("<H", d, p + 20)
    opt = p + 24
    secs = []
    for i in range(nsec):
        s = opt + optsz + 40 * i
        n = d[s:s + 8].rstrip(b"\0").decode(); vs, va, rs, rp = struct.unpack_from("<IIII", d, s + 8)
        secs.append((n, va, vs, rp, rs))
    dirs = [struct.unpack_from("<II", d, opt + 112 + 8 * i) for i in range(16)]
    return p, secs, dirs

def sec_of(secs, off):
    for n, va, vs, rp, rs in secs:
        if rp <= off < rp + rs: return "%s+0x%x" % (n, off - rp)
    return "header" if off < 0x400 else "?"

def r2o(secs, r):
    for n, va, vs, rp, rs in secs:
        if va <= r < va + max(vs, rs): return rp + r - va

def debugdir(tag, d):
    p, secs, dirs = pe(d)
    w("[%s] sha256 %s size %d TimeDateStamp %d" % (tag, hashlib.sha256(d).hexdigest(), len(d), struct.unpack_from("<I", d, p + 8)[0]))
    r, s = dirs[6]; base = r2o(secs, r)
    for k in range(s // 28):
        ch, ts, ma, mi, ty, sz, ra, pr = struct.unpack_from("<IIHHIIII", d, base + 28 * k)
        extra = ""
        if ty == 2 and d[pr:pr + 4] == b"RSDS":
            extra = "guid %s age %d path %r" % (d[pr + 4:pr + 20].hex(), struct.unpack_from("<I", d, pr + 20)[0], d[pr + 24:pr + sz].rstrip(b"\0"))
        w("[%s]   debug type %d ts %d size %d fileoff %d %s" % (tag, ty, ts, sz, pr, extra))
    return secs

def strings_at(d, a, b):
    return [m.group(0)[:100] for m in re.finditer(rb"[\x20-\x7e]{6,}", d[a:b])]

def paths(tag, d):
    c = collections.Counter()
    for m in re.finditer(rb"[A-Za-z]:\\[\x20-\x7e]{3,200}", d):
        c[b"\\".join(m.group(0).split(b"\\")[:7])] += 1
    for m in re.finditer(rb"(?:[A-Za-z]\x00:\x00\\\x00)(?:[\x20-\x7e]\x00){3,200}", d):
        c[("U16:" + "\\".join(m.group(0).decode("utf-16le").split("\\")[:7])).encode()] += 1
    w("[%s] distinct path prefixes (dir part), count:" % tag)
    for k, v in sorted(c.items()): w("[%s]   %5d %r" % (tag, v, k))
    tl = collections.Counter(m for m in re.findall(rb"[A-Za-z0-9_.-]{2,12}~\d+[A-Za-z0-9_.-]{0,4}", d) if not m[:1].isdigit())
    w("[%s] 8.3-looking tokens: %r" % (tag, [x for x in tl.most_common(30) if x[1] > 1]))

d1 = open(exe1, "rb").read(); d2 = open(exe2, "rb").read()
secs = debugdir("exe1", d1); debugdir("exe2", d2)
paths("exe1", d1)

# known cross-run (proof run a vs b) differing blocks: dump their strings and hex from exe1
KNOWN = [144048128, 144052224, 144056320, 144134144, 144142336, 144146432, 144166912, 144171008, 144441344, 144941056]
for b in KNOWN:
    w("[known-block %d %s] strings: %r" % (b, sec_of(secs, b), strings_at(d1, b, b + 4096)))
    w("[known-block %d] hex %s" % (b, d1[b:b + 4096].hex()))

# block hashes of exe1 for a cross-job comparison
w("[blocks-exe1] " + " ".join(hashlib.sha256(d1[i:i + 4096]).hexdigest()[:12] for i in range(0, len(d1), 4096)))

# in-job byte diff
if len(d1) != len(d2): w("[in-job] SIZE DIFFERS %d vs %d" % (len(d1), len(d2)))
n = min(len(d1), len(d2)); idx = []
for c in range(0, n, 4096):
    if d1[c:c + 4096] != d2[c:c + 4096]:
        idx += [k for k in range(c, min(c + 4096, n)) if d1[k] != d2[k]]
ranges = []
for k in idx:
    if ranges and k - ranges[-1][1] < 16: ranges[-1][1] = k + 1
    else: ranges.append([k, k + 1])
w("[in-job] differing byte ranges: %d (total bytes %d)" % (len(ranges), sum(b - a for a, b in ranges)))
for a, b in ranges[:200]:
    c0 = max(0, a - 16) // 16 * 16
    w("[in-job] off %d len %d %s\n   exe1 %s %r\n   exe2 %s %r" % (a, b - a, sec_of(secs, a), d1[c0:c0 + 48].hex(), d1[c0:c0 + 48], d2[c0:c0 + 48].hex(), d2[c0:c0 + 48]))

for tag, p in (("pdb1", pdb1), ("pdb2", pdb2)):
    try: pd = open(p, "rb").read()
    except OSError as e: w("[%s] missing %s" % (tag, e)); continue
    hits = collections.Counter(m[:120] for m in re.findall(rb"[\x20-\x7e]*(?:rustc[0-9A-Za-z]{4,}|\\Temp\\|\\TEMP\\|~1\\)[\x20-\x7e]*", pd))
    w("[%s] sha256 %s size %d; temp/short-name strings (%d distinct):" % (tag, hashlib.sha256(pd).hexdigest(), len(pd), len(hits)))
    for k, v in hits.most_common(40): w("[%s]   %4d %r" % (tag, v, k))
o.close()
print(open(out).read()[:6000])
