#!/usr/bin/env python3
"""Tests for check_linux_floor.py. Every case builds a small ELF64 byte by byte and runs the
real main() on it, asserting the exit code and the reason printed. No compiler, no binaries."""
import contextlib
import io
import os
import random
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import check_linux_floor as cl  # noqa: E402

BASE = 0x400000
NOP = 0xD503201F


def strtab(names):
    blob, offs = b"\0", {}
    for n in names:
        if n not in offs:
            offs[n] = len(blob)
            blob += n.encode() + b"\0"
    return blob, offs


def build_elf(machine=62, cls=2, data=1, etype=3, verneed=(("libc.so.6", ("GLIBC_2.28",)),),
              dyn_extra=(), text=None, text2=None, symbols=None, dynamic=True, shdrs=True,
              vnum_delta=0, vncnt_delta=0, bad_name_off=False, shoff_delta=0, shinfo_delta=0,
              sec_off_beyond=False, verneed_secinfo=None, extra_phdrs=()):
    """verneed: [(lib, (version names...)), ...] or None (no requirements).
    text/text2: lists of 32-bit words (None = no such section).
    symbols: None (no .symtab) or [(name, word_index_in_text)] mapping symbols in .text."""
    text = [NOP] if text is None and machine == 183 else (text or [])
    names = [lib for lib, _ in (verneed or [])] + [v for _, vs in (verneed or []) for v in vs]
    dynstr, off = strtab(names + ["x"])
    # verneed blob
    vblob = b""
    if verneed:
        for i, (lib, vs) in enumerate(verneed):
            last = i == len(verneed) - 1
            size = 16 + 16 * len(vs)
            vblob += struct.pack("<HHIII", 1, len(vs) + (vncnt_delta if i == 0 else 0),
                                 off[lib] + (10000 if bad_name_off and i == 0 else 0), 16, 0 if last else size)
            for j, v in enumerate(vs):
                vblob += struct.pack("<IHHII", 0x1234 + j, 0, 2 + j, off[v], 0 if j == len(vs) - 1 else 16)
    # layout
    nph = (2 if dynamic else 1) + len(extra_phdrs)
    pos = 64 + 56 * nph
    o_dynstr = pos; pos += len(dynstr)
    pos = (pos + 7) & ~7
    o_vn = pos; pos += len(vblob)
    pos = (pos + 15) & ~15
    dyn = []
    if dynamic:
        dyn = [(5, BASE + o_dynstr), (10, len(dynstr))]
        if verneed:
            dyn += [(0x6FFFFFFE, BASE + o_vn), (0x6FFFFFFF, len(verneed) + vnum_delta)]
        dyn += list(dyn_extra) + [(0, 0)]
    dynblob = b"".join(struct.pack("<QQ", t, v) for t, v in dyn)
    o_dyn = pos; pos += len(dynblob)
    pos = (pos + 15) & ~15
    tblob = b"".join(struct.pack("<I", w) for w in text)
    o_text = pos; pos += len(tblob)
    t2blob = b"".join(struct.pack("<I", w) for w in (text2 or []))
    o_text2 = pos; pos += len(t2blob)
    pos = (pos + 7) & ~7
    secs = [(b"", 0)]  # name, placeholder
    symblob = symstr = b""
    if symbols is not None:
        symstr, so = strtab([n for n, _ in symbols])
        symblob = struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0)
        for n, widx in symbols:
            symblob += struct.pack("<IBBHQQ", so[n], 0, 0, 3, BASE + o_text + 4 * widx, 0)
    o_sym = pos; pos += len(symblob)
    o_str = pos; pos += len(symstr)
    shnames = [".dynstr", ".gnu.version_r", ".dynamic", ".text", ".text2", ".symtab", ".strtab", ".shstrtab"]
    shstr, sn = strtab(shnames)
    o_shstr = pos; pos += len(shstr)
    pos = (pos + 7) & ~7
    o_sh = pos

    def sh(name, typ, flags, addr, off_, size, link=0, info=0, ent=0):
        return struct.pack("<IIQQQQIIQQ", sn[name] if name else 0, typ, flags, addr, off_, size, link, info, 8, ent)

    shs = [sh(None, 0, 0, 0, 0, 0)]
    shs.append(sh(".dynstr", 3, 2, BASE + o_dynstr, o_dynstr, len(dynstr)))                          # 1
    shs.append(sh(".gnu.version_r", 0x6FFFFFFE, 2, BASE + o_vn, o_vn + (10**9 if sec_off_beyond else 0), len(vblob), 1,
                  (len(verneed) if verneed_secinfo is None else verneed_secinfo) + shinfo_delta) if verneed
               else sh(".dynstr", 3, 2, BASE + o_dynstr, o_dynstr, 0))                                # 2 (dummy when none)
    shs.append(sh(".dynamic", 6, 3, BASE + o_dyn, o_dyn, len(dynblob), 1, 0, 16))                    # 3
    shs.append(sh(".text", 1, 6, BASE + o_text, o_text, len(tblob)))                                 # 4
    shs.append(sh(".text2", 1, 6, BASE + o_text2, o_text2, len(t2blob)))                             # 5
    shs.append(sh(".symtab", 2, 0, 0, o_sym, len(symblob), 7, 1, 24))                                # 6
    shs.append(sh(".strtab", 3, 0, 0, o_str, len(symstr)))                                           # 7
    shs.append(sh(".shstrtab", 3, 0, 0, o_shstr, len(shstr)))                                        # 8
    keep = [0, 1] + ([2] if verneed else []) + ([3] if dynamic else []) + [4] \
        + ([5] if text2 is not None else []) + ([6, 7] if symbols is not None else []) + [8]
    # section indexes shift when some are dropped; symbols' shndx and links are fixed up below
    newidx = {old: new for new, old in enumerate(keep)}
    sec_bytes = []
    for old in keep:
        b = bytearray(shs[old])
        if old == 2 and verneed:
            struct.pack_into("<I", b, 40, newidx[1])
        if old == 3:
            struct.pack_into("<I", b, 40, newidx[1])
        if old == 6:
            struct.pack_into("<I", b, 40, newidx[7])
        sec_bytes.append(bytes(b))
    if symbols is not None:
        sb = bytearray(symblob)
        for k in range(1, len(symbols) + 1):
            struct.pack_into("<H", sb, 24 * k + 6, newidx[4])
        symblob = bytes(sb)
    shblob = b"".join(sec_bytes)
    img = bytearray(o_sh + len(shblob))
    phs = struct.pack("<IIQQQQQQ", 1, 5, 0, BASE, 0, o_sym, o_sym, 0x1000)  # image up to the symbol table; symtab, strtab, shdrs are not mapped
    if dynamic:
        phs += struct.pack("<IIQQQQQQ", 2, 6, o_dyn, BASE + o_dyn, BASE + o_dyn, len(dynblob), len(dynblob), 8)
    for ph in extra_phdrs:
        phs += struct.pack("<IIQQQQQQ", *ph)
    img[64:64 + len(phs)] = phs
    for o_, blob in ((o_dynstr, dynstr), (o_vn, vblob), (o_dyn, dynblob), (o_text, tblob), (o_text2, t2blob),
                     (o_sym, symblob), (o_str, symstr), (o_shstr, shstr), (o_sh, shblob)):
        img[o_:o_ + len(blob)] = blob
    img[:16] = b"\x7fELF" + bytes([cls, data, 1, 0]) + b"\0" * 8
    struct.pack_into("<HHIQQQIHHHHHH", img, 16, etype, machine, 1, BASE + o_text, 64, o_sh if shdrs else 0, 0, 64,
                     56, nph, 64, len(keep) if shdrs else 0, newidx[8] if shdrs else 0)
    if shdrs and shoff_delta:
        struct.pack_into("<Q", img, 40, o_sh + shoff_delta)
    return bytes(img)


# ---- byte patching helpers for the round-4 fixtures --------------------------------------------
SH_FIELDS = dict(type=(4, "I"), flags=(8, "Q"), addr=(16, "Q"), off=(24, "Q"), size=(32, "Q"), link=(40, "I"),
                 info=(44, "I"), entsize=(56, "Q"))
PH_FIELDS = dict(type=(0, "I"), flags=(4, "I"), off=(8, "Q"), va=(16, "Q"), filesz=(32, "Q"), memsz=(40, "Q"),
                 align=(48, "Q"))
EH_FIELDS = dict(version=(20, "I"), entry=(24, "Q"), phoff=(32, "Q"), shoff=(40, "Q"), flags=(48, "I"),
                 ehsize=(52, "H"), phentsize=(54, "H"), phnum=(56, "H"), shentsize=(58, "H"), shnum=(60, "H"),
                 shstrndx=(62, "H"))


def put(img, off, fmt, val):
    b = bytearray(img)
    struct.pack_into("<" + fmt, b, off, val)
    return bytes(b)


def eh(img, field, val):
    o, f = EH_FIELDS[field]
    return put(img, o, f, val)


def sec(img, name):
    """(header offset, section dict) of the named section."""
    shoff = struct.unpack_from("<Q", img, 40)[0]
    n, sx = struct.unpack_from("<H", img, 60)[0], struct.unpack_from("<H", img, 62)[0]
    ho = [shoff + 64 * i for i in range(n)]
    stroff = struct.unpack_from("<Q", img, ho[sx] + 24)[0]
    for h in ho:
        nm = struct.unpack_from("<I", img, h)[0]
        end = img.index(b"\0", stroff + nm)
        if img[stroff + nm:end].decode() == name:
            f = struct.unpack_from("<IIQQQQ", img, h)
            return h, dict(type=f[1], flags=f[2], addr=f[3], off=f[4], size=f[5])
    raise KeyError(name)


def sh(img, name, field, val):
    h, _ = sec(img, name)
    o, f = SH_FIELDS[field]
    return put(img, h + o, f, val)


def ph(img, i, field, val):
    o, f = PH_FIELDS[field]
    return put(img, 64 + 56 * i + o, f, val)


class Base(unittest.TestCase):
    def run_check(self, img, *args, name="bin"):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, name)
            with open(p, "wb") as f:
                f.write(img)
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = cl.main(list(args) + [p])
        return rc, out.getvalue()

    def expect(self, img, rc, reason, *args):
        got, out = self.run_check(img, *args)
        self.assertEqual(got, rc, "wanted exit %d got %d; output:\n%s" % (rc, got, out))
        self.assertIn(reason, out)
        return out

    def x86(self, **kw):
        return build_elf(**kw)

    def arm(self, text, **kw):
        return build_elf(machine=183, text=text, **kw)


class Versions(Base):
    def v(self, *names, **kw):
        return build_elf(verneed=[("libc.so.6", tuple(names))], **kw)

    def test_pass_old_and_floor(self):
        self.expect(self.v("GLIBC_2.9", "GLIBC_2.28"), 0, "highest GLIBC: 2.28 (limit 2.28)")

    def test_multi_entry_pass(self):
        img = build_elf(verneed=[("libc.so.6", ("GLIBC_2.2.5", "GLIBC_2.28")), ("libgcc_s.so.1", ("GCC_3.0",))])
        out = self.expect(img, 0, "other version tags (listed, not judged): GCC_3.0")
        self.assertIn("PASS", out)

    def test_fail_229(self):
        self.expect(self.v("GLIBC_2.29"), 1, "GLIBC_2.29 (from libc.so.6) exceeds GLIBC_2.28")

    def test_fail_2100(self):
        self.expect(self.v("GLIBC_2.100"), 1, "GLIBC_2.100 (from libc.so.6) exceeds")

    def test_fail_patch(self):
        self.expect(self.v("GLIBC_2.28.1"), 1, "GLIBC_2.28.1 (from libc.so.6) exceeds")

    def test_fail_relr_version(self):
        self.expect(self.v("GLIBC_ABI_DT_RELR"), 1, "GLIBC_ABI_DT_RELR (from libc.so.6) is not a plain numeric")

    def test_fail_private(self):
        self.expect(self.v("GLIBC_PRIVATE"), 1, "GLIBC_PRIVATE (from libc.so.6) is not a plain numeric")

    def test_fail_glibcxx_cxxabi(self):
        self.expect(self.v("GLIBCXX_3.4.26"), 1, "exceeds GLIBCXX_3.4.25")
        self.expect(self.v("CXXABI_1.3.12"), 1, "exceeds CXXABI_1.3.11")
        self.expect(self.v("GLIBCXX_3.4.25", "CXXABI_1.3.11"), 0, "GLIBCXX: 3.4.25")
        self.expect(self.v("GLIBCXX_DEBUG_MESSAGE_LENGTH"), 1, "not a plain numeric GLIBCXX")

    def test_floor_flag(self):
        self.expect(self.v("GLIBC_2.28"), 1, "exceeds GLIBC_2.17", "--max-glibc", "2.17")

    def test_fail_dt_relr(self):
        for tag, nm in ((0x24, "DT_RELR"), (0x23, "DT_RELRSZ"), (0x25, "DT_RELRENT")):
            self.expect(self.v("GLIBC_2.28", dyn_extra=[(tag, 0)]), 1, nm)

    # ---- exit 2: cannot account for the file ----
    def test_text_file(self):
        self.expect(b"hello world, this is a text file, not an ELF binary at all..........\n" * 2, 2, "not an ELF")

    def test_truncated_header(self):
        self.expect(self.x86()[:40], 2, "too short")

    def test_empty(self):
        self.expect(b"", 2, "too short")

    def test_elf32(self):
        self.expect(self.x86(cls=1), 2, "only ELF64")

    def test_big_endian(self):
        self.expect(self.x86(data=2), 2, "only little endian")

    def test_wrong_machine(self):
        self.expect(self.x86(machine=8), 2, "ELF machine 8")

    def test_wrong_type(self):
        self.expect(self.x86(etype=1), 2, "ELF type 1")

    def test_vnum_too_large(self):
        self.expect(self.x86(vnum_delta=1), 2, "only 1 Verneed entries present, expected 2")

    def test_vnum_too_small(self):
        img = build_elf(verneed=[("libc.so.6", ("GLIBC_2.28",)), ("libm.so.6", ("GLIBC_2.2.5",))], vnum_delta=-1)
        self.expect(img, 2, "more Verneed entries than the declared 1")

    def test_vncnt_too_large(self):
        self.expect(self.x86(vncnt_delta=1), 2, "vn_cnt 2 but only 1 Vernaux")

    def test_vncnt_too_small(self):
        img = self.v("GLIBC_2.2.5", "GLIBC_2.28", vncnt_delta=-1)
        self.expect(img, 2, "more Vernaux entries than vn_cnt")

    def test_string_offset_outside(self):
        self.expect(self.x86(bad_name_off=True), 2, "outside string table")

    def test_section_offset_beyond_eof(self):
        self.expect(self.x86(sec_off_beyond=True), 2, "outside the file")

    def test_shoff_beyond_eof(self):
        self.expect(self.x86(shoff_delta=10**6), 2, "section header 0: range")

    def test_sh_info_mismatch(self):
        self.expect(self.x86(shinfo_delta=1), 2, "sh_info")

    def test_no_requirements(self):
        self.expect(self.x86(verneed=None), 2, "no version requirements at all")

    def test_no_requirements_allowed(self):
        self.expect(self.x86(verneed=None), 0, "allowed by --allow-no-version-requirements",
                    "--allow-no-version-requirements")

    def test_static_no_dynamic(self):
        self.expect(self.x86(dynamic=False, verneed=None), 2, "no version requirements at all")

    def test_no_section_headers_pass(self):
        self.expect(self.x86(shdrs=False), 0, "PASS")

    def test_missing_file(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = cl.main(["/nonexistent/definitely-not-here"])
        self.assertEqual(rc, 2)

    def test_bad_floor_arg(self):
        self.expect(self.x86(), 2, "bad --max-glibc", "--max-glibc", "two")


SVE = 0x04200000
SVE2 = 0x45DAE4E3
SME = 0xC00800FF
SMSTATE = [int("d5034%x7f" % n, 16) for n in range(2, 8)]


class AArch64(Base):
    def test_sve_sve2_sme_hits(self):
        for w in (SVE, SVE2, SME, 0xE1000000):
            out = self.expect(self.arm([NOP, w, NOP]), 1, "%08x" % w)
            self.assertIn("hits 1", out)

    def test_each_smstart_smstop(self):
        for w in SMSTATE:
            self.expect(self.arm([NOP, w]), 1, "SMSTART/SMSTOP")

    def test_hit_in_second_exec_section(self):
        for w in (SVE, SVE2, SME, SMSTATE[0]):
            out = self.expect(self.arm([NOP], text2=[NOP, w]), 1, "section .text2")
            self.assertIn("%08x" % w, out)
        for w in SMSTATE:
            self.expect(self.arm([NOP], text2=[w]), 1, "SMSTART/SMSTOP")

    def test_hit_in_stripped_binary(self):
        out = self.expect(self.arm([NOP, SVE]), 1, "no symbol table: hits may be data")
        self.assertIn("run this check before stripping", out)

    def test_pass_clean(self):
        out = self.expect(self.arm([NOP, NOP, 0xD65F03C0], symbols=[("$x", 0)]), 0, "code words 3, data words 0, hits 0")
        self.assertIn("NOT covered", out)

    def test_sve_word_in_data_region(self):
        out = self.expect(self.arm([NOP, NOP, SVE, SME, NOP], symbols=[("$x", 0), ("$d.1", 2), ("$x.2", 4)]), 0,
                          "code words 3, data words 2, hits 0")
        self.assertIn("mapping symbols", out)
        self.expect(self.arm([NOP, SVE, NOP], symbols=[("$x", 0)]), 1, "hits 1")

    def test_msr_tco_and_udf_are_code_not_hits(self):
        self.expect(self.arm([0xD503409F, 0x00000000, NOP], symbols=[("$x", 0)]), 0, "hits 0")
        self.expect(self.arm([0xD503409F, 0x00000000, NOP]), 0, "hits 0")

    def test_near_misses_pass(self):
        near = [0xD503407F, 0xD503487F, 0xD503427E, 0xD503419F, 0xD5034A7F, 0xD503201F]
        self.expect(self.arm(near, symbols=[("$x", 0)]), 0, "hits 0")

    def test_zero_code_words(self):
        self.expect(self.arm([]), 2, "no code words scanned")
        self.expect(self.arm([NOP, NOP], symbols=[("$d", 0)]), 2, "no code words scanned")

    def test_no_sve_no(self):
        self.expect(self.arm([SVE]), 0, "instruction scan skipped", "--no-sve", "no")

    def test_sve_yes_on_x86(self):
        self.expect(self.x86(), 2, "requested but the binary is x86_64", "--no-sve", "yes")

    def test_x86_not_scanned(self):
        self.expect(build_elf(text=[SVE]), 0, "instruction scan skipped")

    def test_no_section_headers_uses_load_segment(self):
        self.expect(self.arm([NOP, SVE], shdrs=False), 1, "PT_LOAD#0")

    def test_scan_matches_naive(self):
        rnd = random.Random(7)
        words = [rnd.getrandbits(32) for _ in range(20000)]
        words += [SVE, SME] + SMSTATE
        expect = sum(1 for w in words if cl.classify(w))
        out = self.expect(self.arm(words, symbols=[("$x", 0)]), 1, "hits %d" % expect)
        self.assertIn("code words %d" % len(words), out)

    def test_classify_masks(self):
        self.assertIsNone(cl.classify(0xD503409F))
        self.assertIsNone(cl.classify(0))
        self.assertEqual(cl.classify(0xD503477F), "SMSTART/SMSTOP")
        self.assertEqual(len(cl.SMSTATE_WORDS), 6)


class Mapping(Base):
    """Round 4, findings 1 and 7: the bytes the checker reads must be the bytes the loader maps."""

    def relr_trap(self, **kw):
        """PT_DYNAMIC p_offset points at a clean array; p_vaddr points at an appended one holding DT_RELR."""
        img = build_elf(**kw)
        extra = struct.pack("<QQ", 0x24, 1) + struct.pack("<QQ", 0, 0) * 4
        at = len(img)
        img += extra
        i = 1  # PT_DYNAMIC is program header 1
        img = ph(img, 0, "filesz", len(img))
        img = ph(img, 0, "memsz", len(img))
        img = ph(img, i, "va", BASE + at)
        return img

    def test_dynamic_vaddr_not_offset(self):
        self.expect(self.relr_trap(), 2, "PT_DYNAMIC p_vaddr does not map to its p_offset")
        self.expect(self.relr_trap(shdrs=False), 2, "PT_DYNAMIC p_vaddr does not map to its p_offset")

    def test_dynamic_vaddr_outside_load(self):
        img = ph(build_elf(), 1, "va", 0x900000)
        self.expect(img, 2, "PT_PT_DYNAMIC".replace("PT_PT", "PT") + ": address")

    def load_pair(self, off, filesz, va, memsz):
        dummy = (1, 4, 0, 0, 0, 0, 0, 0x1000)
        end = struct.unpack_from("<Q", build_elf(extra_phdrs=[dummy]), 64 + 32)[0]
        return build_elf(extra_phdrs=[(1, 4, off if off >= 0 else end, va, va, filesz, memsz, 0x1000)])

    def test_overlapping_load_file_images(self):
        self.expect(self.load_pair(0x10, 8, 0x900000, 8), 2, "PT_LOAD file images overlap")

    def test_overlapping_load_virtual_ranges(self):
        img = self.load_pair(-1, 16, BASE + 0x100, 16)
        self.expect(img, 2, "PT_LOAD virtual ranges overlap")

    def test_adjacent_loads_are_ambiguous_at_the_boundary(self):
        dummy = (1, 4, 0, 0, 0, 0, 0, 0x1000)
        end = struct.unpack_from("<Q", build_elf(extra_phdrs=[dummy]), 64 + 32)[0]
        img = build_elf(extra_phdrs=[(1, 4, end, BASE + end, BASE + end, 16, 16, 0x1000)])
        img = ph(img, 1, "va", BASE + end)
        img = ph(img, 1, "filesz", 0)
        img = ph(img, 1, "off", end)
        self.expect(img, 2, "inside more than one PT_LOAD")

    def test_second_pt_dynamic(self):
        img = build_elf()
        dyn = struct.unpack_from("<IIQQQQQQ", img, 64 + 56)
        self.expect(build_elf(extra_phdrs=[dyn]), 2, "more than one PT_DYNAMIC")

    def test_memsz_below_filesz(self):
        self.expect(ph(build_elf(), 0, "memsz", 8), 2, "p_memsz < p_filesz")

    def test_segment_beyond_eof(self):
        self.expect(ph(build_elf(), 0, "filesz", 10**7), 2, "program header 0: range")

    def test_phoff_beyond_eof(self):
        self.expect(eh(build_elf(), "phoff", 10**7), 2, "program header table")

    def test_ehsize(self):
        self.expect(eh(build_elf(), "ehsize", 63), 2, "e_ehsize 63")

    def test_phentsize(self):
        self.expect(eh(build_elf(), "phentsize", 48), 2, "e_phentsize 48")

    def test_ident_and_header_versions(self):
        b = bytearray(build_elf())
        b[6] = 2
        self.expect(bytes(b), 2, "ELF ident version 2")
        self.expect(eh(build_elf(), "version", 2), 2, "ELF version 2")

    def test_shentsize_and_shoff(self):
        self.expect(eh(build_elf(), "shentsize", 32), 2, "e_shentsize 32")
        self.expect(eh(build_elf(), "shoff", 0), 2, "e_shnum")

    def test_shstrndx_out_of_range(self):
        self.expect(eh(build_elf(), "shstrndx", 200), 2, "e_shstrndx 200 out of range")

    def test_extended_section_numbering(self):
        img = build_elf()
        n = struct.unpack_from("<H", img, 60)[0]
        shoff = struct.unpack_from("<Q", img, 40)[0]
        ext = put(eh(img, "shnum", 0), shoff + 32, "Q", n)
        self.expect(ext, 0, "PASS")
        self.expect(eh(img, "shnum", 0), 2, "no section headers")
        sx = struct.unpack_from("<H", img, 62)[0]
        ext = put(eh(img, "shstrndx", 0xFFFF), shoff + 40, "I", sx)
        self.expect(ext, 0, "PASS")

    def test_shstrtab_nobits(self):
        self.expect(sh(build_elf(), ".shstrtab", "type", 8), 2, "section name table is NOBITS")

    def test_version_r_without_dynamic(self):
        self.expect(build_elf(dynamic=False), 2, "no dynamic segment")

    def test_dynamic_without_terminator(self):
        self.expect(ph(build_elf(), 1, "filesz", 64), 2, "no DT_NULL terminator")

    def dyn_tag(self, img, k, tag):
        h, d = sec(img, ".dynamic")
        return put(img, d["off"] + 16 * k, "Q", tag)

    def test_verneed_without_verneednum_and_back(self):
        self.expect(self.dyn_tag(build_elf(), 3, 0x6FFFFFF0), 2, "must appear together")
        self.expect(self.dyn_tag(build_elf(), 2, 0x6FFFFFF0), 2, "must appear together")

    def test_strtab_missing(self):
        self.expect(self.dyn_tag(build_elf(), 0, 4), 2, "DT_STRTAB/DT_STRSZ missing")

    def test_duplicate_dynamic_tag(self):
        self.expect(build_elf(dyn_extra=[(5, 0)]), 2, "dynamic tag 0x5 appears 2 times")

    def test_verneed_declared_zero_but_section_has_info(self):
        img = build_elf()
        h, d = sec(img, ".dynamic")
        img = put(img, d["off"] + 16 * 3 + 8, "Q", 0)
        self.expect(img, 2, "declares no requirements")

    def test_two_version_r_sections(self):
        self.expect(sh(build_elf(), ".dynamic", "type", 0x6FFFFFFE), 2, "2 .gnu.version_r sections")

    def test_version_r_address_offset(self):
        self.expect(sh(build_elf(), ".gnu.version_r", "addr", BASE), 2, "address/offset does not match")

    def test_version_r_link_out_of_range(self):
        self.expect(sh(build_elf(), ".gnu.version_r", "link", 99), 2, "sh_link out of range")

    def test_version_r_string_table_nobits(self):
        self.expect(sh(build_elf(), ".dynstr", "type", 8), 2, "string table is NOBITS")

    def test_version_r_string_table_differs(self):
        img = build_elf()
        _, d = sec(img, ".dynstr")
        self.expect(sh(img, ".dynstr", "size", d["size"] - 1), 2, "differs from DT_STRTAB/DT_STRSZ")

    def test_version_r_string_table_address_differs(self):
        img = build_elf()
        _, d = sec(img, ".dynstr")
        self.expect(sh(img, ".dynstr", "addr", d["addr"] + 4), 2, "differs from DT_STRTAB/DT_STRSZ")

    def test_version_r_read_outside_section(self):
        self.expect(sh(build_elf(), ".gnu.version_r", "size", 8), 2, "read outside the section")

    def test_two_walks_decode_different_names(self):
        img = build_elf()
        _, d = sec(img, ".dynstr")
        copy = bytearray(img[d["off"]:d["off"] + d["size"]])
        k = copy.index(b"GLIBC_2.28")
        copy[k:k + 10] = b"GLIBC_2.27"
        at = len(img)
        img = sh(img + bytes(copy), ".dynstr", "off", at)
        self.expect(img, 2, "decode to different requirement lists")

    def vn(self, img, field_off, fmt, val):
        _, d = sec(img, ".gnu.version_r")
        return put(img, d["off"] + field_off, fmt, val)

    def test_vn_version(self):
        self.expect(self.vn(build_elf(), 0, "H", 2), 2, "vn_version 2")
        self.expect(self.vn(build_elf(), 0, "H", 0), 2, "vn_version 0")

    def test_vncnt_zero(self):
        self.expect(self.x86(vncnt_delta=-1), 2, "vn_cnt 0")

    def test_non_ascii_and_unterminated_names(self):
        img = build_elf()
        _, d = sec(img, ".dynstr")
        k = img.index(b"GLIBC_2.28", d["off"])
        b = bytearray(img)
        b[k] = 0xFF
        self.expect(bytes(b), 2, "non-ASCII")
        _, dyn = sec(img, ".dynamic")
        self.expect(put(img, dyn["off"] + 24, "Q", d["size"] - 3), 2, "unterminated")


class Spellings(Base):
    """Round 4, findings 3, 5 and the non-libc sonames."""

    def v(self, *names, lib="libc.so.6", **kw):
        return build_elf(verneed=[(lib, tuple(names))], **kw)

    def test_family_is_case_insensitive(self):
        for n in ("glibc_2.100", "Glibc_2.100", "glibc_2.28", "glibcxx_3.4.26", "cxxabi_1.3.12", "Cxxabi_1.3.11"):
            self.expect(self.v(n), 1, "%s (from libc.so.6) is not a plain numeric" % n)
            self.expect(self.v("GLIBC_2.28", n), 1, "%s (from libc.so.6) is not a plain numeric" % n)

    def test_non_canonical_decimals_fail(self):
        for n in ("GLIBC_2.028", "GLIBC_02.28", "GLIBC_2.28.00", "GLIBCXX_3.4.025", "CXXABI_1.03.11"):
            self.expect(self.v(n), 1, "%s (from libc.so.6) is not a plain numeric" % n)

    def test_trailing_zero_component_is_the_floor(self):
        # GLIBC_2.28.0 is the same version as 2.28 (zero-padded tuple compare): kept as is, passes at the floor
        self.expect(self.v("GLIBC_2.28.0"), 0, "highest GLIBC: 2.28.0 (limit 2.28)")
        self.expect(self.v("GLIBC_2.0", "GLIBC_2.2.5"), 0, "PASS")

    def test_too_new_tag_from_non_libc_soname(self):
        self.expect(self.v("GLIBC_2.29", lib="libm.so.6"), 1, "GLIBC_2.29 (from libm.so.6) exceeds")
        self.expect(self.v("GLIBC_2.34", lib="ld-linux-aarch64.so.1"), 1, "from ld-linux-aarch64.so.1) exceeds")
        self.expect(self.v("GLIBC_2.30", lib="libpthread.so.0"), 1, "from libpthread.so.0) exceeds")


class Round4Scan(Base):
    """Round 4, findings 2, 4 and 6 (AArch64 scan)."""

    def test_sh_addr_not_sh_offset(self):
        img = self.arm([NOP, SVE, NOP])
        at = len(img)
        img = sh(img + struct.pack("<3I", NOP, NOP, NOP), ".text", "off", at)
        self.expect(img, 2, "sh_addr maps to a different file offset than sh_offset")

    def test_exec_flag_cleared_hides_section(self):
        img = sh(self.arm([SVE, SVE], text2=[NOP, NOP]), ".text", "flags", 2)
        self.expect(img, 2, "entry point")

    def test_exec_flag_cleared_with_code_mapping_symbol(self):
        img = sh(self.arm([SVE, SVE], text2=[NOP, NOP], symbols=[("$x", 0)]), ".text", "flags", 2)
        self.expect(img, 2, "not a scanned executable section")

    def test_exec_nobits(self):
        img = sh(self.arm([SVE, SVE], text2=[NOP, NOP]), ".text", "type", 8)
        self.expect(img, 2, "SHT_NOBITS with SHF_EXECINSTR")

    def test_nobits_and_flag_cleared_bytes_become_gap_and_are_scanned(self):
        img = sh(sh(self.arm([SVE, SVE], text2=[NOP, NOP]), ".text", "type", 8), ".text", "flags", 2)
        img = eh(img, "entry", sec(img, ".text2")[1]["addr"])
        self.expect(img, 1, "in gap@")

    def test_exec_without_alloc(self):
        self.expect(sh(self.arm([NOP]), ".text", "flags", 4), 2, "SHF_EXECINSTR without SHF_ALLOC")

    def test_word_in_padding_is_scanned(self):
        img = self.arm([NOP])
        _, d = sec(img, ".text")
        self.expect(put(img, d["off"] + 4, "I", SVE), 1, "in gap@")

    def test_nonzero_partial_word_padding(self):
        img = build_elf(machine=183, verneed=None)
        _, d = sec(img, ".dynstr")
        b = bytearray(img)
        b[d["off"] + d["size"]] = 0xAA
        self.expect(bytes(b), 2, "non-zero bytes outside whole aligned words", "--allow-no-version-requirements")
        self.expect(img, 0, "gaps inside executable segments", "--allow-no-version-requirements")

    def test_overlapping_exec_sections(self):
        img = self.arm([NOP, NOP], text2=[NOP, NOP])
        _, t = sec(img, ".text")
        img = sh(sh(sh(img, ".text2", "addr", t["addr"] + 4), ".text2", "off", t["off"] + 4), ".text2", "size", 4)
        self.expect(img, 2, "file ranges overlap inside an executable segment")

    def test_non_exec_section_mapping_mismatch(self):
        img = self.arm([NOP])
        _, d = sec(img, ".dynamic")
        self.expect(sh(img, ".dynamic", "addr", d["addr"] - 16), 2, "sh_addr maps to a different file offset")

    def test_header_bytes_are_not_code(self):
        img = self.arm([NOP])
        img = ph(img, 0, "align", SVE)          # looks like an SVE word inside the program header table
        img = eh(img, "flags", SVE)             # and inside the ELF header
        self.expect(img, 0, "hits 0")

    def test_misaligned_code_mapping_symbol(self):
        for name in ("$x", "$x.1"):
            img = self.arm([NOP, NOP, NOP], symbols=[(name, 0)])
            _, s = sec(img, ".symtab")
            val = struct.unpack_from("<Q", img, s["off"] + 24 + 8)[0]
            self.expect(put(img, s["off"] + 24 + 8, "Q", val + 2), 2, "code mapping symbol %s at 0x%x is not 4-byte aligned" % (name, val + 2))

    def test_review_recipe_d_at_sve_word_x_two_bytes_later(self):
        # $d on the SVE word, $x two bytes later (not aligned): the word must not be silently skipped
        img = self.arm([NOP, SVE, NOP], symbols=[("$d", 1), ("$x", 1)])
        _, s = sec(img, ".symtab")
        val = struct.unpack_from("<Q", img, s["off"] + 48 + 8)[0]
        self.expect(put(img, s["off"] + 48 + 8, "Q", val + 2), 2, "not 4-byte aligned")

    def test_misaligned_data_symbol_inside_code_is_accepted(self):
        # real lld output (the delivered arm64 binary) has odd-address $d symbols inside .text
        img = self.arm([NOP, NOP, NOP], symbols=[("$d", 0)])
        _, s = sec(img, ".symtab")
        val = struct.unpack_from("<Q", img, s["off"] + 24 + 8)[0]
        out = self.expect(put(img, s["off"] + 24 + 8, "Q", val + 2), 0, "PASS")

    def test_misaligned_data_symbol_in_non_code_section_is_ignored(self):
        # real lld output has $d symbols at odd addresses inside .rodata (not a scanned section)
        img = self.arm([NOP, NOP], symbols=[("$d", 0)])
        _, s = sec(img, ".symtab")
        idx = 1  # .dynstr, a non-executable section
        img = put(put(img, s["off"] + 24 + 6, "H", idx), s["off"] + 24 + 8, "Q", BASE + 3)
        self.expect(img, 0, "PASS")

    def test_mapping_symbol_outside_section(self):
        img = self.arm([NOP], symbols=[("$x", 0)])
        _, s = sec(img, ".symtab")
        self.expect(put(img, s["off"] + 32, "Q", BASE), 2, "outside its section")

    def test_symtab_inconsistencies(self):
        img = self.arm([NOP], symbols=[("$x", 0)])
        self.expect(sh(img, ".symtab", "entsize", 16), 2, "entsize/size inconsistent")
        self.expect(sh(img, ".symtab", "link", 99), 2, ".symtab sh_link out of range")
        self.expect(sh(img, ".strtab", "type", 8), 2, ".symtab string table is NOBITS")
        self.expect(sh(img, ".strtab", "size", 1), 2, "symbol name offset")
        self.expect(sh(img, ".shstrtab", "type", 2), 2, "more than one .symtab")

    def test_entry_point_must_be_in_scanned_code(self):
        self.expect(eh(self.arm([NOP]), "entry", BASE), 2, "entry point")
        self.expect(eh(self.arm([NOP]), "entry", 0), 0, "PASS")


class Wrapper(unittest.TestCase):
    def test_shell_wrapper_exit_codes(self):
        import subprocess
        here = os.path.dirname(os.path.abspath(__file__))
        with tempfile.TemporaryDirectory() as d:
            ok, bad = os.path.join(d, "ok"), os.path.join(d, "bad")
            for p, img in ((ok, build_elf()), (bad, build_elf(verneed=[("libc.so.6", ("GLIBC_2.29",))]))):
                with open(p, "wb") as f:
                    f.write(img)
            run = lambda p: subprocess.run([os.path.join(here, "check-linux-floor.sh"), p],
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode
            self.assertEqual((run(ok), run(bad), run(os.path.join(d, "none"))), (0, 1, 2))


if __name__ == "__main__":
    unittest.main()
