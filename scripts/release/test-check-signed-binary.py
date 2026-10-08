#!/usr/bin/env python3
"""Unit tests for check-signed-binary.py using byte-built fixtures."""
import importlib.util
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("csb", os.path.join(HERE, "check-signed-binary.py"))
csb = importlib.util.module_from_spec(spec)
spec.loader.exec_module(csb)


def make_pe(cert=b"", pe32plus=True):
    opt_size = 240 if pe32plus else 224
    dos = bytearray(0x40)
    dos[:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    coff = b"PE\0\0" + struct.pack("<HHIIIHH", 0x8664, 0, 0, 0, 0, opt_size, 0x22)
    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0, 0x20B if pe32plus else 0x10B)
    dd = 112 if pe32plus else 96
    struct.pack_into("<I", opt, dd - 4, 16)
    body = bytes(dos) + coff + bytes(opt) + b"\0" * 64
    if cert:
        wc = struct.pack("<IHH", 8 + len(cert), 0x200, 2) + cert
        wc += b"\0" * (-len(wc) % 8)
        struct.pack_into("<II", opt, dd + 32, len(body), len(wc))
        body = bytes(dos) + coff + bytes(opt) + b"\0" * 64
        body += wc
    return body


def make_macho(flags=csb.CS_RUNTIME, team=b"PX6SP9GPWJ", sign=True, version=0x20400):
    ident = b"fuigo-pager\0"
    teamb = team + b"\0"
    cd_len = 0x58 + len(ident) + len(teamb)
    cd = bytearray(cd_len)
    struct.pack_into(">IIII", cd, 0, csb.CSMAGIC_CODEDIRECTORY, cd_len, version, flags)
    struct.pack_into(">I", cd, 20, 0x58)
    struct.pack_into(">I", cd, 0x30, 0x58 + len(ident))
    cd[0x58:0x58 + len(ident)] = ident
    cd[0x58 + len(ident):] = teamb
    sb = struct.pack(">III", csb.CSMAGIC_EMBEDDED_SIGNATURE, 12 + 8 + cd_len, 1)
    sb += struct.pack(">II", 0, 20) + bytes(cd)
    ncmds = 1 if sign else 0
    hdr = struct.pack("<IiiIIIII", csb.MH_MAGIC_64, 0x100000C, 0, 2, ncmds, 16 if sign else 0, 0, 0)
    off = 32 + (16 if sign else 0)
    lc = struct.pack("<IIII", csb.LC_CODE_SIGNATURE, 16, off, len(sb)) if sign else b""
    return hdr + lc + (sb if sign else b"")


class T(unittest.TestCase):
    def run_check(self, data, **kw):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(data)
        try:
            return csb.check_file(f.name, kw.get("subject", "Ferrox Labs"), kw.get("team", "PX6SP9GPWJ"))
        finally:
            os.unlink(f.name)

    def test_pe_unsigned(self):
        for p in (True, False):
            with self.assertRaisesRegex(csb.Fail, "empty"):
                self.run_check(make_pe(pe32plus=p))

    def test_pe_nonpkcs7_blob(self):
        # Not a real PKCS#7: either openssl finds no subject (Fail) or, without openssl, the
        # raw-search fallback reports the text. Both are acceptable; it must not crash.
        data = make_pe(cert=b"\x30\x80junk Ferrox Labs junk")
        try:
            self.assertIn("Ferrox Labs", self.run_check(data))
        except csb.Fail:
            pass

    def test_pe_nonempty_wrong_subject(self):
        with self.assertRaises(csb.Fail):
            self.run_check(make_pe(cert=b"\x30\x80other signer"))

    @unittest.skipUnless(shutil.which("openssl"), "needs openssl")
    def test_pe_real_pkcs7(self):
        d = tempfile.mkdtemp()
        try:
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout",
                            d + "/k", "-out", d + "/c", "-subj", "/CN=Ferrox Labs Test", "-days", "1"],
                           check=True, capture_output=True)
            der = subprocess.run(["openssl", "crl2pkcs7", "-nocrl", "-certfile", d + "/c", "-outform", "DER"],
                                 check=True, capture_output=True).stdout
            self.assertIn("Ferrox Labs Test", self.run_check(make_pe(cert=der)))
            with self.assertRaises(csb.Fail):
                self.run_check(make_pe(cert=der), subject="Someone Else")
        finally:
            shutil.rmtree(d)

    def test_macho_unsigned(self):
        with self.assertRaisesRegex(csb.Fail, "unsigned"):
            self.run_check(make_macho(sign=False))

    def test_macho_ok(self):
        self.assertIn("team=PX6SP9GPWJ", self.run_check(make_macho()))

    def test_macho_adhoc(self):
        with self.assertRaisesRegex(csb.Fail, "ad-hoc"):
            self.run_check(make_macho(flags=csb.CS_RUNTIME | csb.CS_ADHOC))

    def test_macho_no_runtime(self):
        with self.assertRaisesRegex(csb.Fail, "runtime"):
            self.run_check(make_macho(flags=0))

    def test_macho_wrong_team(self):
        with self.assertRaisesRegex(csb.Fail, "team"):
            self.run_check(make_macho(team=b"AAAAAAAAAA"))

    def test_macho_old_cd_no_team(self):
        with self.assertRaisesRegex(csb.Fail, "team"):
            self.run_check(make_macho(version=0x20100))

    def test_fat(self):
        thin = make_macho()
        fat = struct.pack(">III", csb.FAT_MAGIC, 0, 1)[:4] + struct.pack(">I", 1)
        fat += struct.pack(">IIIII", 0x100000C, 0, 64, len(thin), 14)
        fat += b"\0" * (64 - len(fat)) + thin
        self.assertIn("PX6SP9GPWJ", self.run_check(fat))

    def test_neither(self):
        with self.assertRaises(csb.Fail):
            self.run_check(b"\x7fELF" + b"\0" * 64)

    def test_real_system_files_are_rejected(self):
        for p in ("/bin/ls", sys.executable):
            self.assertEqual(csb.main([p]), 1)


if __name__ == "__main__":
    unittest.main()
