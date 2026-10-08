#!/usr/bin/env python3
"""Linux-side presence/identity check that release binaries carry the expected signature.

Runs on ubuntu with no network. For each file it auto-detects PE or Mach-O:

  PE      the Authenticode certificate table (security data directory) must exist and be
          non-empty, and a certificate in the embedded PKCS#7 must have a subject containing
          --windows-subject (default "Ferrox Labs"). Certificates are listed with
          `openssl pkcs7 -print_certs`; if openssl is absent, a raw DER substring search
          for the subject text is used (weaker, and said so in the output).
  Mach-O  (thin or fat) every slice must have an LC_CODE_SIGNATURE whose CodeDirectory has
          the hardened-runtime flag, is not ad-hoc, and has team id --team-id
          (default PX6SP9GPWJ).

WHAT THIS DOES NOT PROVE: it reads identity fields only. It does not validate the signature
cryptographically, the certificate chain, revocation, the timestamp, or that the signed
digest matches the file contents. That is what Get-AuthenticodeSignature / codesign / the
notary service did in the sign job. This is a tripwire that an unsigned or ad-hoc signed
binary cannot reach `publish`; it is not a substitute for those checks.
"""
import argparse
import struct
import subprocess
import sys

CS_ADHOC = 0x2
CS_RUNTIME = 0x10000
CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
CSMAGIC_CODEDIRECTORY = 0xFADE0C02
LC_CODE_SIGNATURE = 0x1D
MH_MAGIC_64 = 0xFEEDFACF
FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF


class Fail(Exception):
    pass


# ---------------------------------------------------------------- PE
def pe_certificate_blob(data):
    if data[:2] != b"MZ" or len(data) < 0x40:
        raise Fail("not a PE file (no MZ)")
    (e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
    if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        raise Fail("not a PE file (no PE signature)")
    opt = e_lfanew + 24
    (magic,) = struct.unpack_from("<H", data, opt)
    if magic == 0x10B:
        dd = opt + 96
    elif magic == 0x20B:
        dd = opt + 112
    else:
        raise Fail("unknown PE optional header magic 0x%x" % magic)
    (nrva,) = struct.unpack_from("<I", data, dd - 4)
    if nrva < 5:
        raise Fail("PE has no security data directory entry")
    off, size = struct.unpack_from("<II", data, dd + 4 * 8)  # entry 4: file offset, not RVA
    if off == 0 or size == 0:
        raise Fail("PE security directory is empty: file is not Authenticode signed")
    if off + size > len(data) or size < 8:
        raise Fail("PE security directory points outside the file")
    dwlen, _rev, ctype = struct.unpack_from("<IHH", data, off)
    if ctype != 2:
        raise Fail("WIN_CERTIFICATE type %d is not PKCS_SIGNED_DATA" % ctype)
    if dwlen < 8 or dwlen > size:
        raise Fail("bad WIN_CERTIFICATE length")
    return data[off + 8:off + dwlen]


def pe_subjects(blob):
    try:
        out = subprocess.run(
            ["openssl", "pkcs7", "-inform", "DER", "-print_certs"],
            input=blob, capture_output=True, check=True).stdout.decode("utf8", "replace")
    except (OSError, subprocess.CalledProcessError):
        return None
    return [l[len("subject="):].strip() for l in out.splitlines() if l.startswith("subject=")]


def check_pe(data, subject):
    blob = pe_certificate_blob(data)
    subs = pe_subjects(blob)
    if subs is None:
        # Fail closed: a raw byte search for the subject text would accept a forged certificate table.
        raise Fail("openssl could not read the PKCS#7 in the certificate table (openssl missing, or not a PKCS#7)")
    hit = [s for s in subs if subject in s]
    if not hit:
        raise Fail("no certificate subject contains %r; subjects: %s" % (subject, subs))
    return "certificate table %d bytes; signer subject: %s" % (len(blob), hit[0])


# ---------------------------------------------------------------- Mach-O
def code_directory(blob):
    magic, length, count = struct.unpack_from(">III", blob, 0)
    if magic != CSMAGIC_EMBEDDED_SIGNATURE:
        raise Fail("code signature blob has bad SuperBlob magic 0x%x" % magic)
    if length > len(blob) or count > 64:
        raise Fail("malformed SuperBlob")
    for i in range(count):
        _slot, off = struct.unpack_from(">II", blob, 12 + 8 * i)
        if off + 8 <= len(blob) and struct.unpack_from(">I", blob, off)[0] == CSMAGIC_CODEDIRECTORY:
            return blob[off:]
    raise Fail("no CodeDirectory in signature")


def cd_fields(cd):
    _m, _l, version, flags = struct.unpack_from(">IIII", cd, 0)
    (ident_off,) = struct.unpack_from(">I", cd, 20)
    team = None
    if version >= 0x20200:
        (team_off,) = struct.unpack_from(">I", cd, 0x30)
        if team_off:
            end = cd.index(b"\0", team_off)
            team = cd[team_off:end].decode("ascii", "replace")
    ident = cd[ident_off:cd.index(b"\0", ident_off)].decode("ascii", "replace")
    return flags, team, ident


def check_macho_slice(data, base, team_id):
    magic = struct.unpack_from("<I", data, base)[0]
    if magic != MH_MAGIC_64:
        raise Fail("slice is not a 64-bit little-endian Mach-O (magic 0x%x)" % magic)
    ncmds = struct.unpack_from("<I", data, base + 16)[0]
    pos = base + 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, pos)
        if cmd == LC_CODE_SIGNATURE:
            dataoff, datasize = struct.unpack_from("<II", data, pos + 8)
            if datasize == 0 or base + dataoff + datasize > len(data):
                raise Fail("LC_CODE_SIGNATURE is empty or out of range")
            cd = code_directory(data[base + dataoff:base + dataoff + datasize])
            flags, team, ident = cd_fields(cd)
            if flags & CS_ADHOC:
                raise Fail("signature is ad-hoc")
            if not flags & CS_RUNTIME:
                raise Fail("hardened runtime flag missing (flags 0x%x)" % flags)
            if team != team_id:
                raise Fail("team id %r != expected %r" % (team, team_id))
            return "identifier=%s team=%s flags=0x%x (runtime)" % (ident, team, flags)
        if cmdsize < 8:
            raise Fail("malformed load command")
        pos += cmdsize
    raise Fail("no LC_CODE_SIGNATURE: Mach-O is unsigned")


def check_macho(data, team_id):
    magic_be = struct.unpack_from(">I", data, 0)[0]
    if magic_be in (FAT_MAGIC, FAT_MAGIC_64):
        n = struct.unpack_from(">I", data, 4)[0]
        step, fmt = (20, ">IIIII") if magic_be == FAT_MAGIC else (32, ">IIQQII")
        res = []
        for i in range(n):
            f = struct.unpack_from(fmt, data, 8 + step * i)
            res.append(check_macho_slice(data, f[2], team_id))
        return "; ".join(res)
    return check_macho_slice(data, 0, team_id)


def check_file(path, subject, team_id):
    with open(path, "rb") as fh:
        data = fh.read()
    if data[:2] == b"MZ":
        return check_pe(data, subject)
    if len(data) >= 8 and (struct.unpack_from("<I", data, 0)[0] == MH_MAGIC_64
                           or struct.unpack_from(">I", data, 0)[0] in (FAT_MAGIC, FAT_MAGIC_64)):
        return check_macho(data, team_id)
    raise Fail("neither PE nor Mach-O")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--windows-subject", default="Ferrox Labs")
    ap.add_argument("--team-id", default="PX6SP9GPWJ")
    ap.add_argument("files", nargs="+")
    a = ap.parse_args(argv)
    bad = 0
    for p in a.files:
        try:
            print("OK   %s: %s" % (p, check_file(p, a.windows_subject, a.team_id)))
        except (Fail, OSError, struct.error, ValueError) as e:
            print("FAIL %s: %s" % (p, e))
            bad += 1
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
