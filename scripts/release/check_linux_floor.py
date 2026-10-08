#!/usr/bin/env python3
"""Release floor check for the Linux binaries (P199 + P202). Direct ELF parser.

    check_linux_floor.py [--max-glibc 2.28] [--max-glibcxx 3.4.25]
                         [--max-cxxabi 1.3.11] [--no-sve auto|yes|no]
                         [--allow-no-version-requirements] BINARY
    check_linux_floor.py --self-test

Exit 0 = PASS, 1 = floor violated, 2 = could not inspect (usage error, not a
supported ELF, or ANYTHING the parser cannot fully account for). There is no
readelf, objdump or awk: the ELF structures are decoded from the bytes, every
offset and size is bounds-checked, and any inconsistency is exit 2.

What is checked
  1. ELF64, little endian, ET_EXEC/ET_DYN, machine x86-64 or AArch64.
  2. Version requirements, found through the dynamic segment (DT_VERNEED,
     DT_VERNEEDNUM, DT_STRTAB, DT_STRSZ; addresses translated with PT_LOAD) and
     cross-checked against the .gnu.version_r section header (address, offset,
     sh_info, and the decoded name list) when section headers exist.  The number
     of Verneed entries walked must equal DT_VERNEEDNUM and each entry's vn_cnt.
       GLIBC_<a>.<b>[.<c>]  canonical decimal (no leading zeros), compared as integer
                            tuples zero-padded (GLIBC_2.28.0 == 2.28), must be <= floor
       any other GLIBC_*    fails (GLIBC_ABI_DT_RELR, GLIBC_PRIVATE, ...)
       GLIBCXX_*, CXXABI_*  numeric and <= --max-glibcxx / --max-cxxabi
                            (defaults 3.4.25 and 1.3.11, GCC 8 era); non-numeric fails
                            (family names are matched case-insensitively: glibc_2.100 is
                            GLIBC, and fails because it is not the uppercase spelling)
       other names          listed, not judged
     A binary with no version requirements at all is exit 2 unless
     --allow-no-version-requirements (a static or musl binary is not what this
     release ships).
  3. DT_RELRSZ/DT_RELR/DT_RELRENT (tags 0x23/0x24/0x25) present = violation.
  4. AArch64 only: every 32-bit little-endian word of every SHF_EXECINSTR section
     (no section headers: every PT_LOAD with PF_X) that is CODE according to the
     $x/$d mapping symbols of .symtab (no .symtab: every word is treated as code)
       SVE/SVE2/streaming SVE : w[28:25] == 0b0010
       SME/SME2               : w[31] == 1 and w[28:25] == 0b0000
       SMSTART/SMSTOP         : w in d5034[2-7]7f  (the six allocated words)
     NOT covered: MRS/MSR accesses to SVE/SME system registers (SVCR, SMCR, ZCR_ELx),
     and code reached only at run time is still flagged (this is a static scan of
     the encodings, not a proof about which paths execute).  Zero code words = exit 2.
     A stripped binary has no mapping symbols, so a hit may be data: run the check
     before stripping.
"""
import argparse
import bisect
import os
import re
import struct
import sys

EM_X86_64, EM_AARCH64 = 62, 183
ET_EXEC, ET_DYN = 2, 3
PT_LOAD, PT_DYNAMIC = 1, 2
PF_X = 1
SHT_SYMTAB, SHT_NOBITS, SHT_NULL, SHT_GNU_VERNEED = 2, 8, 0, 0x6FFFFFFE
SHF_ALLOC, SHF_EXECINSTR = 2, 4
DT_NULL, DT_STRTAB, DT_STRSZ = 0, 5, 10
DT_VERNEED, DT_VERNEEDNUM = 0x6FFFFFFE, 0x6FFFFFFF
DT_RELRSZ, DT_RELR, DT_RELRENT = 0x23, 0x24, 0x25
RELR_TAGS = {DT_RELRSZ: "DT_RELRSZ", DT_RELR: "DT_RELR", DT_RELRENT: "DT_RELRENT"}
MAX_HITS_LISTED = 20

SVE_OP1 = 0b0010
SME_OP1 = 0b0000
SMSTATE_WORDS = frozenset(int("d5034%x7f" % n, 16) for n in range(2, 8))


class InspectError(Exception):
    """The file cannot be fully accounted for: exit 2."""


def classify(w):
    """Reason string if the A64 word w is SVE/SME/SMSTART/SMSTOP, else None."""
    op1 = (w >> 25) & 0xF
    if op1 == SVE_OP1:
        return "SVE-group"
    if (w >> 31) & 1 and op1 == SME_OP1:
        return "SME-group"
    if w in SMSTATE_WORDS:
        return "SMSTART/SMSTOP"
    return None


def _candidate_top_bytes():
    """Top bytes (bits 31:24) a hit can have: a superset filter for the fast scan."""
    out = set()
    for b in range(256):
        for low in (0x000000, 0xFFFFFF):
            if classify((b << 24) | low) is not None:
                out.add(b)
    out.add(0xD5)  # SMSTART/SMSTOP words
    return bytes(sorted(out))


CAND_RE = re.compile(b"[" + b"".join(b"\\x%02x" % b for b in _candidate_top_bytes()) + b"]")


def parse_ver(s, what):
    if not re.fullmatch(r"[0-9]+(\.[0-9]+)*", s):
        raise InspectError("bad %s '%s'" % (what, s))
    return tuple(int(x) for x in s.split("."))


def ver_gt(a, b):
    n = max(len(a), len(b))
    return (a + (0,) * (n - len(a))) > (b + (0,) * (n - len(b)))


class Elf:
    def __init__(self, data):
        self.d = data
        self.n = len(data)
        self.violations = []
        self.lines = []

    def say(self, s):
        self.lines.append(s)

    def fail(self, s):
        self.violations.append(s)
        self.lines.append("  FAIL: " + s)

    def rng(self, off, size, what):
        if off < 0 or size < 0 or off + size > self.n:
            raise InspectError("%s: range 0x%x+0x%x is outside the file (size 0x%x)" % (what, off, size, self.n))

    def u(self, fmt, off, what):
        sz = struct.calcsize(fmt)
        self.rng(off, sz, what)
        return struct.unpack_from("<" + fmt, self.d, off)

    # ---- header, program headers, section headers -------------------------
    def parse_header(self):
        if self.n < 64:
            raise InspectError("file is %d bytes: too short for an ELF64 header" % self.n)
        if self.d[:4] != b"\x7fELF":
            raise InspectError("not an ELF file")
        if self.d[4] != 2:
            raise InspectError("ELF class %d: only ELF64 is supported" % self.d[4])
        if self.d[5] != 1:
            raise InspectError("ELF data encoding %d: only little endian is supported" % self.d[5])
        if self.d[6] != 1:
            raise InspectError("ELF ident version %d" % self.d[6])
        (self.etype, self.machine, ver, self.entry, self.phoff, self.shoff, flags, ehsize,
         self.phentsize, self.phnum, self.shentsize, self.shnum, self.shstrndx) = struct.unpack_from(
            "<HHIQQQIHHHHHH", self.d, 16)
        if self.etype not in (ET_EXEC, ET_DYN):
            raise InspectError("ELF type %d: only ET_EXEC and ET_DYN are supported" % self.etype)
        if self.machine not in (EM_X86_64, EM_AARCH64):
            raise InspectError("ELF machine %d: only x86-64 (62) and AArch64 (183) are supported" % self.machine)
        self.arch = "x86_64" if self.machine == EM_X86_64 else "aarch64"
        if ver != 1:
            raise InspectError("ELF version %d" % ver)
        if ehsize != 64:
            raise InspectError("e_ehsize %d, expected 64" % ehsize)

    def parse_phdrs(self):
        self.phdrs = []
        if self.phnum == 0:
            return
        if self.phentsize != 56:
            raise InspectError("e_phentsize %d, expected 56" % self.phentsize)
        self.rng(self.phoff, self.phnum * 56, "program header table")
        for i in range(self.phnum):
            t, fl, off, va, pa, fsz, msz, al = struct.unpack_from("<IIQQQQQQ", self.d, self.phoff + 56 * i)
            if t in (PT_LOAD, PT_DYNAMIC):
                self.rng(off, fsz, "program header %d" % i)
                if t == PT_LOAD and msz < fsz:
                    raise InspectError("PT_LOAD %d: p_memsz < p_filesz" % i)
            self.phdrs.append((t, fl, off, va, fsz, msz))
        loads = [p for p in self.phdrs if p[0] == PT_LOAD]
        for i, a in enumerate(loads):
            for b in loads[i + 1:]:
                if a[4] and b[4] and a[2] < b[2] + b[4] and b[2] < a[2] + a[4]:
                    raise InspectError("PT_LOAD file images overlap (0x%x+0x%x and 0x%x+0x%x)" % (a[2], a[4], b[2], b[4]))
                if a[5] and b[5] and a[3] < b[3] + b[5] and b[3] < a[3] + a[5]:
                    raise InspectError("PT_LOAD virtual ranges overlap (0x%x+0x%x and 0x%x+0x%x)" % (a[3], a[5], b[3], b[5]))

    def parse_shdrs(self):
        self.sections = []
        if self.shoff == 0:
            if self.shnum != 0:
                raise InspectError("e_shnum %d but e_shoff 0" % self.shnum)
            return
        if self.shentsize != 64:
            raise InspectError("e_shentsize %d, expected 64" % self.shentsize)
        num = self.shnum
        self.rng(self.shoff, 64, "section header 0")
        if num == 0:  # extended count lives in sh_size of section 0
            num = struct.unpack_from("<Q", self.d, self.shoff + 32)[0]
            if num == 0:
                raise InspectError("e_shoff set but no section headers")
        self.rng(self.shoff, num * 64, "section header table")
        for i in range(num):
            (name, typ, flags, addr, off, size, link, info, align, entsize) = struct.unpack_from(
                "<IIQQQQIIQQ", self.d, self.shoff + 64 * i)
            if typ not in (SHT_NULL, SHT_NOBITS):
                self.rng(off, size, "section %d (offset)" % i)
            self.sections.append(dict(idx=i, name_off=name, type=typ, flags=flags, addr=addr, off=off,
                                      size=size, link=link, info=info, entsize=entsize, name="?"))
        shstr = self.shstrndx
        if shstr == 0xFFFF:
            shstr = struct.unpack_from("<I", self.d, self.shoff + 40)[0]
        if shstr >= num:
            raise InspectError("e_shstrndx %d out of range" % shstr)
        s = self.sections[shstr]
        if s["type"] == SHT_NOBITS:
            raise InspectError("section name table is NOBITS")
        for sec in self.sections:
            sec["name"] = self.cstr(s["off"], s["size"], sec["name_off"], "section name")

    def cstr(self, base, size, off, what):
        """NUL-terminated ASCII string at base+off, entirely inside [base, base+size)."""
        if off >= size:
            raise InspectError("%s: string offset %d outside string table of %d bytes" % (what, off, size))
        end = self.d.find(b"\0", base + off, base + size)
        if end < 0:
            raise InspectError("%s: unterminated string at offset %d" % (what, off))
        try:
            return self.d[base + off:end].decode("ascii")
        except UnicodeDecodeError:
            raise InspectError("%s: non-ASCII string at offset %d" % (what, off))

    def v2o(self, addr, size, what):
        """File offset of virtual range [addr, addr+size) inside one PT_LOAD's file image."""
        hits = [off + (addr - va) for t, fl, off, va, fsz, msz in self.phdrs
                if t == PT_LOAD and va <= addr and addr + size <= va + fsz]
        if not hits:
            raise InspectError("%s: address 0x%x+0x%x is not inside any PT_LOAD file image" % (what, addr, size))
        if len(hits) > 1:
            raise InspectError("%s: address 0x%x+0x%x is inside more than one PT_LOAD file image" % (what, addr, size))
        return hits[0]

    # ---- dynamic segment ---------------------------------------------------
    def parse_dynamic(self):
        dyns = [p for p in self.phdrs if p[0] == PT_DYNAMIC]
        if len(dyns) > 1:
            raise InspectError("more than one PT_DYNAMIC")
        self.dyn = None
        if not dyns:
            return
        _, _, off, va, fsz, _ = dyns[0]
        if self.v2o(va, fsz, "PT_DYNAMIC") != off:
            raise InspectError("PT_DYNAMIC p_vaddr does not map to its p_offset")
        tags = []
        pos, end = off, off + fsz
        while True:
            if pos + 16 > end:
                raise InspectError("dynamic section has no DT_NULL terminator")
            tag, val = struct.unpack_from("<QQ", self.d, pos)
            pos += 16
            if tag == DT_NULL:
                break
            tags.append((tag, val))
        self.dyn = tags

    def dget(self, tag):
        vals = [v for t, v in self.dyn if t == tag]
        if len(vals) > 1:
            raise InspectError("dynamic tag 0x%x appears %d times" % (tag, len(vals)))
        return vals[0] if vals else None

    # ---- version requirements ---------------------------------------------
    def walk_verneed(self, rd, start, num, strname, what):
        """rd(pos, size) -> bytes. Returns [(file, [aux names])]. Strict on counts."""
        out = []
        pos = start
        for i in range(num):
            ver, cnt, fname, aux, nxt = struct.unpack("<HHIII", rd(pos, 16))
            if ver != 1:
                raise InspectError("%s: Verneed %d has vn_version %d" % (what, i, ver))
            if cnt == 0:
                raise InspectError("%s: Verneed %d has vn_cnt 0" % (what, i))
            names = []
            apos = pos + aux
            for j in range(cnt):
                if j > 0 and anext == 0:
                    raise InspectError("%s: Verneed %d: vn_cnt %d but only %d Vernaux entries present" % (what, i, cnt, j))
                _h, _f, _o, nm, anext = struct.unpack("<IHHII", rd(apos, 16))
                names.append(strname(nm))
                apos += anext
            if anext != 0:
                raise InspectError("%s: Verneed %d: more Vernaux entries than vn_cnt %d" % (what, i, cnt))
            out.append((strname(fname), names))
            if i < num - 1:
                if nxt == 0:
                    raise InspectError("%s: only %d Verneed entries present, expected %d" % (what, i + 1, num))
                pos += nxt
            elif nxt != 0:
                raise InspectError("%s: more Verneed entries than the declared %d" % (what, num))
        return out

    def read_requirements(self):
        """List of (library, version name), or None when there are none. Cross-checks sections."""
        self.verneed_secs = [s for s in self.sections if s["type"] == SHT_GNU_VERNEED]
        if self.dyn is None:
            if self.verneed_secs:
                raise InspectError(".gnu.version_r section present but no dynamic segment")
            return None
        vn, vnum = self.dget(DT_VERNEED), self.dget(DT_VERNEEDNUM)
        if (vn is None) != (vnum is None):
            raise InspectError("DT_VERNEED and DT_VERNEEDNUM must appear together")
        if vn is None or vnum == 0:
            if self.verneed_secs and any(s["info"] for s in self.verneed_secs):
                raise InspectError(".gnu.version_r section exists but the dynamic section declares no requirements")
            return None
        strtab, strsz = self.dget(DT_STRTAB), self.dget(DT_STRSZ)
        if strtab is None or strsz is None:
            raise InspectError("DT_STRTAB/DT_STRSZ missing")
        stroff = self.v2o(strtab, strsz, "dynamic string table")

        def dstr(o):
            return self.cstr(stroff, strsz, o, "dynamic string table")

        def drd(pos, size):
            o = self.v2o(pos, size, "version requirements")
            return self.d[o:o + size]

        found = self.walk_verneed(drd, vn, vnum, dstr, "DT_VERNEED")
        if self.sections:
            if len(self.verneed_secs) != 1:
                raise InspectError("section headers present but %d .gnu.version_r sections (expected 1)" % len(self.verneed_secs))
            sec = self.verneed_secs[0]
            if sec["info"] != vnum:
                raise InspectError(".gnu.version_r sh_info %d != DT_VERNEEDNUM %d" % (sec["info"], vnum))
            if sec["addr"] != vn or sec["off"] != self.v2o(vn, 1, "DT_VERNEED"):
                raise InspectError(".gnu.version_r address/offset does not match DT_VERNEED")
            if sec["link"] >= len(self.sections):
                raise InspectError(".gnu.version_r sh_link out of range")
            ls = self.sections[sec["link"]]
            if ls["type"] == SHT_NOBITS:
                raise InspectError(".gnu.version_r string table is NOBITS")
            if ls["addr"] != strtab or ls["size"] != strsz:
                raise InspectError(".gnu.version_r string table differs from DT_STRTAB/DT_STRSZ")

            def srd(pos, size):
                if pos < sec["off"] or pos + size > sec["off"] + sec["size"]:
                    raise InspectError(".gnu.version_r: read outside the section")
                return self.d[pos:pos + size]

            def sstr(o):
                return self.cstr(ls["off"], ls["size"], o, ".gnu.version_r string table")

            other = self.walk_verneed(srd, sec["off"], sec["info"], sstr, ".gnu.version_r")
            if other != found:
                raise InspectError("DT_VERNEED and .gnu.version_r decode to different requirement lists")
        return [(lib, nm) for lib, names in found for nm in names]

    def check_versions(self, limits, allow_none):
        reqs = self.read_requirements()
        if reqs is None:
            if allow_none:
                self.say("  no version requirements (allowed by --allow-no-version-requirements)")
            else:
                raise InspectError("no version requirements at all (static or non-glibc binary?); "
                                   "pass --allow-no-version-requirements if that is intended")
        else:
            best = {"GLIBC": None, "GLIBCXX": None, "CXXABI": None}
            other = []
            num = r"(?:0|[1-9][0-9]*)"  # canonical decimal: no leading zeros
            for lib, name in reqs:
                fam = None
                up = name.upper()  # the family is recognised case-insensitively, the spelling is judged exactly
                if up.startswith("GLIBC_"):
                    fam, m = "GLIBC", re.fullmatch(r"GLIBC_(%s\.%s(\.%s)?)" % (num, num, num), name)
                elif up.startswith("GLIBCXX_"):
                    fam, m = "GLIBCXX", re.fullmatch(r"GLIBCXX_(%s(\.%s)+)" % (num, num), name)
                elif up.startswith("CXXABI_"):
                    fam, m = "CXXABI", re.fullmatch(r"CXXABI_(%s(\.%s)+)" % (num, num), name)
                if fam is None:
                    other.append(name)
                    continue
                if not m:
                    self.fail("%s (from %s) is not a plain numeric %s version" % (name, lib, fam))
                    continue
                v = parse_ver(m.group(1), name)
                if ver_gt(v, limits[fam]):
                    self.fail("%s (from %s) exceeds %s_%s" % (name, lib, fam, ".".join(map(str, limits[fam]))))
                if best[fam] is None or ver_gt(v, best[fam]):
                    best[fam] = v
            fmt = lambda v: ".".join(map(str, v)) if v else "none"
            self.say("  version requirements: %d (%s)" % (len(reqs), "; ".join("%s %s" % (l, n) for l, n in reqs) if len(reqs) <= 12 else "list truncated"))
            self.say("  highest GLIBC: %s (limit %s); GLIBCXX: %s (limit %s); CXXABI: %s (limit %s)" % (
                fmt(best["GLIBC"]), fmt(limits["GLIBC"]), fmt(best["GLIBCXX"]), fmt(limits["GLIBCXX"]),
                fmt(best["CXXABI"]), fmt(limits["CXXABI"])))
            if other:
                self.say("  other version tags (listed, not judged): " + " ".join(sorted(set(other))))
        relr = [] if self.dyn is None else [RELR_TAGS[t] for t, _ in self.dyn if t in RELR_TAGS]
        if relr:
            self.fail("dynamic section has %s (needs a loader newer than glibc 2.28)" % ", ".join(relr))
        else:
            self.say("  no DT_RELR/DT_RELRSZ/DT_RELRENT in the dynamic section")

    # ---- AArch64 instruction scan -----------------------------------------
    def mapping_regions(self, sec_list):
        """Per exec-section code/data regions from $x/$d symbols. Returns (dict idx -> sorted [(addr, 'x'|'d')], have_symtab)."""
        symtabs = [s for s in self.sections if s["type"] == SHT_SYMTAB]
        if len(symtabs) > 1:
            raise InspectError("more than one .symtab")
        if not symtabs:
            return {}, False
        st = symtabs[0]
        if st["entsize"] != 24 or st["size"] % 24:
            raise InspectError(".symtab entsize/size inconsistent")
        if st["link"] >= len(self.sections):
            raise InspectError(".symtab sh_link out of range")
        ss = self.sections[st["link"]]
        if ss["type"] == SHT_NOBITS:
            raise InspectError(".symtab string table is NOBITS")
        wanted = {s["idx"]: s for s in sec_list}
        res = {i: [] for i in wanted}
        d, base, strsz, sbase = self.d, st["off"], ss["size"], ss["off"]
        nsec = len(self.sections)
        for nm, info, other, shndx, val, sz in struct.iter_unpack("<IBBHQQ", d[base:base + st["size"]]):
            if nm >= strsz:
                raise InspectError(".symtab: symbol name offset %d outside string table" % nm)
            if d[sbase + nm:sbase + nm + 1] != b"$" or not 0 < shndx < nsec:
                continue
            name = self.cstr(sbase, strsz, nm, ".symtab")
            if name in ("$x", "$d") or name.startswith("$x.") or name.startswith("$d."):
                if shndx not in wanted:
                    # data mapping symbols in other sections (lld puts $d in .rodata, at any byte address) are no concern
                    if name[1] == "x":
                        raise InspectError("code mapping symbol %s at 0x%x is in section %s, which is not a scanned "
                                           "executable section" % (name, val, self.sections[shndx]["name"]))
                    continue
                if val % 4 and name[1] == "x":
                    # code must start on an instruction boundary.  An unaligned $d is legitimate (lld emits them
                    # inside .text between byte-sized literals) and only makes the scan more conservative.
                    raise InspectError("code mapping symbol %s at 0x%x is not 4-byte aligned" % (name, val))
                s = wanted[shndx]
                if not (s["addr"] <= val < s["addr"] + s["size"]):
                    raise InspectError("mapping symbol %s at 0x%x is outside its section %s" % (name, val, s["name"]))
                res[shndx].append((val, name[1]))
        for k in res:
            res[k].sort()
        return res, True

    def exec_plan(self):
        """With section headers: (exec sections, gaps). Every byte of every PF_X PT_LOAD file image must be exactly one of
        the ELF header, the program header table, a non-executable SHF_ALLOC section, a scanned executable section, or a
        gap.  Gaps (padding, or bytes no section header claims) are scanned as code; edge bytes that do not fill an
        aligned word must be zero.  Section headers that disagree with the loader's mapping are exit 2."""
        secs = []
        for s in self.sections:
            if not s["flags"] & SHF_EXECINSTR:
                continue
            if s["type"] == SHT_NOBITS:
                if s["size"]:
                    raise InspectError("section %s is SHT_NOBITS with SHF_EXECINSTR and size 0x%x" % (s["name"], s["size"]))
                continue
            if not s["flags"] & SHF_ALLOC:
                raise InspectError("section %s has SHF_EXECINSTR without SHF_ALLOC" % s["name"])
            if s["size"] == 0:
                continue
            if self.v2o(s["addr"], s["size"], "section %s" % s["name"]) != s["off"]:
                raise InspectError("section %s: sh_addr maps to a different file offset than sh_offset" % s["name"])
            c = dict(s)
            c["label"] = s["name"]
            secs.append(c)
        gaps = []
        xsegs = [(off, off + fsz, va) for t, fl, off, va, fsz, msz in self.phdrs if t == PT_LOAD and fl & PF_X and fsz]
        for k, (a, b, va) in enumerate(xsegs):
            iv = [(0, 64, "ELF header")]
            if self.phnum:
                iv.append((self.phoff, self.phoff + 56 * self.phnum, "program headers"))
            for s in self.sections:
                if s["type"] in (SHT_NULL, SHT_NOBITS) or not s["size"] or s["flags"] & SHF_EXECINSTR:
                    continue
                if s["flags"] & SHF_ALLOC and s["off"] < b and s["off"] + s["size"] > a:
                    if self.v2o(s["addr"], s["size"], "section %s" % s["name"]) != s["off"]:
                        raise InspectError("section %s: sh_addr maps to a different file offset than sh_offset" % s["name"])
                    iv.append((s["off"], s["off"] + s["size"], s["name"]))
            iv += [(s["off"], s["off"] + s["size"], s["name"]) for s in secs]
            iv = sorted((max(x, a), min(y, b), n) for x, y, n in iv if x < b and y > a)
            cur = a
            for x, y, n in iv:
                if x < cur:
                    raise InspectError("file ranges overlap inside an executable segment (%s)" % n)
                if x > cur:
                    gaps.append((cur, x, va + (cur - a)))
                cur = y
            if cur < b:
                gaps.append((cur, b, va + (cur - a)))
        units = []
        for k, (x, y, vx) in enumerate(gaps):
            ax = -(-vx // 4) * 4          # first aligned address
            ay = (vx + (y - x)) // 4 * 4  # end of the last whole aligned word
            if ay < ax:
                ax = ay = vx
            lo, hi = x + (ax - vx), x + (ax - vx) + (ay - ax)
            if any(self.d[x:lo]) or any(self.d[hi:y]):
                raise InspectError("non-zero bytes outside whole aligned words in a gap of an executable segment at 0x%x" % x)
            if ay > ax:
                units.append(dict(idx=-1000 - k, name="gap", label="gap@0x%x" % ax, addr=ax, off=lo, size=ay - ax))
        return secs, units

    def scan_unit(self, s, reg):
        """(words, code words, hits [(addr, word, why)], hit count) for one section or gap."""
        if s["addr"] % 4:
            raise InspectError("executable section %s is not 4-byte aligned (0x%x)" % (s["label"], s["addr"]))
        nwords = s["size"] // 4
        # default state is code at the start of the section (AAELF64)
        starts = [s["addr"]] + [a for a, _ in reg]
        states = ["x"] + [c for _, c in reg]
        # merge: a mapping symbol at the section start overrides the default
        if reg and reg[0][0] == s["addr"]:
            starts, states = starts[1:], states[1:]
        ends = starts[1:] + [s["addr"] + s["size"]]
        code = 0
        for a, e, c in zip(starts, ends, states):
            if c == "x":
                code += (-((s["addr"] - e) // 4)) - (-((s["addr"] - a) // 4))  # ceil((e-b)/4)-ceil((a-b)/4)
        # code words must lie wholly inside the section
        if s["size"] % 4:
            tail = s["addr"] + 4 * nwords
            if states[bisect.bisect_right(starts, tail) - 1] == "x":
                raise InspectError("section %s: %d trailing bytes after the last whole word are in a code region" % (s["label"], s["size"] % 4))
        code = min(code, nwords)
        top = self.d[s["off"] + 3:s["off"] + 4 * nwords:4]
        hits = []
        nhits = 0
        for m in CAND_RE.finditer(top):
            i = m.start()
            addr = s["addr"] + 4 * i
            if states[bisect.bisect_right(starts, addr) - 1] != "x":
                continue
            w = struct.unpack_from("<I", self.d, s["off"] + 4 * i)[0]
            why = classify(w)
            if why:
                nhits += 1
                if len(hits) < MAX_HITS_LISTED:
                    hits.append((addr, w, why))
        return nwords, code, hits, nhits

    def scan_aarch64(self):
        gaps = []
        if self.sections:
            secs, gaps = self.exec_plan()
        else:
            secs = []
            for k, (t, fl, off, va, fsz, msz) in enumerate(self.phdrs):
                if t == PT_LOAD and fl & PF_X:
                    secs.append(dict(idx=-1 - k, name="PT_LOAD#%d" % k, label="PT_LOAD#%d" % k, addr=va, off=off, size=fsz))
        regions, have_sym = self.mapping_regions(secs) if self.sections else ({}, False)
        if have_sym:
            self.say("  scan mode: .symtab mapping symbols ($x/$d) separate code from data")
        else:
            self.say("  scan mode: NO symbol table (stripped or no section headers): every word is treated as code, "
                     "so a hit may be data; run this check before stripping")
        tot_words = tot_code = tot_hits = 0
        for s in secs:
            nwords, code, hits, nhits = self.scan_unit(s, regions.get(s["idx"], []) if have_sym else [])
            self.say("  section %-10s addr 0x%x: words %d, code words %d, data words %d, hits %d" % (
                s["label"], s["addr"], nwords, code, nwords - code, nhits))
            for addr, w, why in hits:
                self.say("      hit 0x%x: %08x  %s" % (addr, w, why))
            if nhits > len(hits):
                self.say("      ... %d more hits not listed" % (nhits - len(hits)))
            tot_words += nwords
            tot_code += code
            tot_hits += nhits
        gwords = 0
        for s in gaps:
            nwords, code, hits, nhits = self.scan_unit(s, [])
            gwords += nwords
            tot_hits += nhits
            for addr, w, why in hits:
                self.say("      hit 0x%x: %08x  %s (in %s)" % (addr, w, why, s["label"]))
        if gaps:
            self.say("  gaps inside executable segments (padding, scanned as code): %d regions, %d words" % (len(gaps), gwords))
        self.say("  total: %d words, %d code words scanned, %d hits" % (tot_words, tot_code, tot_hits))
        if tot_code == 0:
            raise InspectError("no code words scanned in an AArch64 binary")
        if self.sections and self.entry and not any(s["addr"] <= self.entry < s["addr"] + s["size"] for s in secs):
            raise InspectError("entry point 0x%x is not inside a scanned executable section" % self.entry)
        if tot_hits:
            self.fail("%d SVE/SME instruction word(s) in AArch64 code%s" % (
                tot_hits, " (binary has no symbol table: hits may be data)" if not have_sym else ""))
        else:
            self.say("  no SVE/SVE2/SME/SMSTART/SMSTOP words in code")
        self.say("  NOT covered: MRS/MSR of SVE/SME system registers (SVCR, SMCR, ZCR_ELx); "
                 "run-time-detected paths are still flagged")


def check(path, limits, sve_mode, allow_none):
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        raise InspectError("cannot read %s: %s" % (path, e))
    e = Elf(data)
    e.parse_header()
    e.say("floor check: %s (ELF64 LE, %s)" % (path, e.arch))
    e.parse_phdrs()
    e.parse_shdrs()
    e.parse_dynamic()
    e.check_versions(limits, allow_none)
    do_scan = {"auto": e.arch == "aarch64", "yes": True, "no": False}[sve_mode]
    if do_scan and e.arch != "aarch64":
        raise InspectError("--no-sve yes requested but the binary is %s" % e.arch)
    if do_scan:
        e.scan_aarch64()
    else:
        e.say("  instruction scan skipped (--no-sve %s, arch %s)" % (sve_mode, e.arch))
    return e


def run_self_test():
    import unittest
    here = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, here)
    suite = unittest.defaultTestLoader.loadTestsFromName("test_check_linux_floor")
    res = unittest.TextTestRunner(verbosity=1).run(suite)
    print("self-test: %d tests, %d failures, %d errors" % (res.testsRun, len(res.failures), len(res.errors)))
    return 0 if res.wasSuccessful() and res.testsRun > 0 else 1


def main(argv=None):
    ap = argparse.ArgumentParser(prog="check-linux-floor.sh", add_help=True)
    ap.add_argument("--max-glibc", default="2.28")
    ap.add_argument("--max-glibcxx", default="3.4.25")
    ap.add_argument("--max-cxxabi", default="1.3.11")
    ap.add_argument("--no-sve", default="auto", choices=("auto", "yes", "no"))
    ap.add_argument("--allow-no-version-requirements", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("binary", nargs="?")
    try:
        args = ap.parse_args(argv)
    except SystemExit as e:
        return 2 if e.code not in (0, None) else 0
    if args.self_test:
        return run_self_test()
    if not args.binary:
        print("check-linux-floor: usage: check-linux-floor.sh [options] BINARY | --self-test", file=sys.stderr)
        return 2
    try:
        limits = {"GLIBC": parse_ver(args.max_glibc, "--max-glibc"),
                  "GLIBCXX": parse_ver(args.max_glibcxx, "--max-glibcxx"),
                  "CXXABI": parse_ver(args.max_cxxabi, "--max-cxxabi")}
        e = check(args.binary, limits, args.no_sve, args.allow_no_version_requirements)
    except InspectError as ex:
        print("floor check: FAIL(inspection): %s" % ex)
        return 2
    except Exception as ex:  # fail closed on anything unforeseen
        print("floor check: FAIL(inspection): internal error %s: %s" % (type(ex).__name__, ex))
        return 2
    print("\n".join(e.lines))
    if e.violations:
        print("floor check: FAIL (%d violation(s))" % len(e.violations))
        return 1
    print("floor check: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
