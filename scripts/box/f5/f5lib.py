"""Shared helpers for the B-F5 harness."""
import os


def path_hash(path):
    """FNV-1a 64 over the path's bytes, 16 lowercase hex digits (fuigo_session_writer::trace::path_hash)."""
    h = 0xCBF29CE484222325
    for b in path.encode():
        h ^= b
        h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return "%016x" % h


def count_leaders(binary, proc="/proc"):
    """Pids of the `<binary> agent leader` processes under `proc`. A pid counts only when its argv is the leader's AND
    /proc/<pid>/exe resolves to the binary under test; a pid whose parent is itself a matched leader is excluded, because
    a fork child of the leader caught before its exec (a `git` spawn) still carries the leader's argv and exe."""
    want = os.path.realpath(binary)
    matched, ppid = [], {}
    for pid in os.listdir(proc):
        if not pid.isdigit():
            continue
        try:
            argv = open("%s/%s/cmdline" % (proc, pid), "rb").read().split(b"\0")
            exe = os.path.realpath(os.readlink("%s/%s/exe" % (proc, pid)).replace(" (deleted)", ""))
            ppid[int(pid)] = int(open("%s/%s/stat" % (proc, pid)).read().rsplit(")", 1)[1].split()[1])
        except (OSError, ValueError, IndexError):
            continue
        if (len(argv) > 2 and argv[0].decode(errors="replace") == binary and argv[1:3] == [b"agent", b"leader"]
                and exe == want):
            matched.append(int(pid))
    return sorted(p for p in matched if ppid.get(p) not in matched)
