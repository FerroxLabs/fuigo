#!/usr/bin/env python3
"""safe-kill.py marker <runid> <pid> <signal> [<starttime>]

Signal <pid> ONLY if it STILL carries the run marker, through a pidfd (so a pid that is recycled for an unrelated process
cannot be hit; an unrelated process can never carry a run id that is unique to this gate run):
  marker  <runid>  : the process environment carries FUIGO_GATE_RUN=<runid>
Order: pidfd_open FIRST (pins the process that held the pid at that moment), then read its /proc entry and verify, then
pidfd_send_signal. If the pid was recycled before the open, the verification reads the NEW process and rejects it; if it
was recycled after the open, the pidfd refers to the old (dead) process and the signal fails with ESRCH.
With <starttime> (field 22 of /proc/<pid>/stat) in marker mode the process must also have that exact start time.
Exit status: 0 signalled, 3 not signalled (gone, or no longer matches), 2 error (could not open / read / signal).
Environment: SAFE_KILL_VAR (default FUIGO_GATE_RUN) names the environment variable that carries the key; GATE_PROC_ROOT (default /proc) for the self-test only.
"""
import os, signal, sys

def main(argv):
    if len(argv) < 5 or argv[1] != "marker":
        print(__doc__.strip().splitlines()[0], file=sys.stderr); return 2
    mode, key, pid, sig = argv[1], argv[2], int(argv[3]), getattr(signal, argv[4].upper() if argv[4].upper().startswith("SIG") else "SIG" + argv[4].upper(), None)
    st = argv[5] if len(argv) > 5 else None
    if sig is None:
        print("safe-kill: unknown signal %s" % argv[4], file=sys.stderr); return 2
    root = os.environ.get("GATE_PROC_ROOT", "/proc")
    try:
        fd = os.pidfd_open(pid)
    except ProcessLookupError:
        return 3
    except OSError as e:
        print("safe-kill: pidfd_open(%d): %s" % (pid, e), file=sys.stderr); return 2
    try:
        try:
            stat = open("%s/%d/stat" % (root, pid)).read()
            fields = stat.rsplit(") ", 1)[-1].split()
            if st is not None and fields[19] != st: return 3
            env = open("%s/%d/environ" % (root, pid), "rb").read().split(b"\0")
            if (os.environ.get("SAFE_KILL_VAR", "FUIGO_GATE_RUN").encode() + b"=" + key.encode()) not in env: return 3
        except (FileNotFoundError, ProcessLookupError):
            return 3
        except OSError as e:
            print("safe-kill: cannot verify %d: %s" % (pid, e), file=sys.stderr); return 2
        try:
            signal.pidfd_send_signal(fd, sig)
        except ProcessLookupError:
            return 3
        except OSError as e:
            print("safe-kill: cannot signal %d: %s" % (pid, e), file=sys.stderr); return 2
        return 0
    finally:
        os.close(fd)

if __name__ == "__main__": sys.exit(main(sys.argv))
