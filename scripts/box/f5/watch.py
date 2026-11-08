"""Reads `inotifywait -m -r` lines (`<path>|<events>`), keeps the raw log, and acknowledges directory marks.

A `d.<gen>.<seq>.<hash>` mark is acknowledged by creating `<FUIGO_HOME>/f5-acks/d.<gen>.<seq>`. inotifywait adds its
watch on a new directory when it reads that directory's IN_CREATE, which the kernel queued before the mark's, so by the
time the mark's line arrives here the new directory is watched. Paused-writer control (`F5_PAUSE` set): on a
`p.<gen>.<seq>.<hash>` mark, append to the paused path without any mark, then acknowledge so the writer resumes.
Held writer (`F5_HOLD=<seconds>` set, B4): on a `p` mark, make no write and acknowledge only after the hold, from a timer
thread so the watch keeps reading; the release is recorded in acks.log and as `<f5-acks>/released.<gen>.<seq>`.
A second process (B6, B9, B10) has its own trace dir `<FUIGO_HOME>/p2/f5-marks`; its `d` marks are acknowledged in
`p2/f5-acks` (its writer waits there: the ack dir is the trace dir's sibling). Pause and hold apply to the leader only.
"""
import os
import sys
import threading
import time

from f5lib import path_hash

home, out = sys.argv[1], sys.argv[2]
pause = os.environ.get("F5_PAUSE") or ""
hold = float(os.environ.get("F5_HOLD") or 0)
marks, acks = home + "/f5-marks/", home + "/f5-acks/"
MARKDIRS = {marks: acks, home + "/p2/f5-marks/": home + "/p2/f5-acks/"}
log = open(os.path.join(out, "inotify.log"), "w", buffering=1)
acklog = open(os.path.join(out, "acks.log"), "w", buffering=1)
seen, dirs = set(), set()


def touch(path):
    open(path, "w").close()


for line in sys.stdin:
    line = line.rstrip("\n")
    log.write(line + "\n")
    path, _, events = line.rpartition("|")
    seen.add(path)
    if "CREATE" in events and "ISDIR" in events:
        dirs.add(path)
    mdir = next((m for m in MARKDIRS if path.startswith(m) and "/" not in path[len(m):]), None)
    if not (mdir and "CREATE" in events):
        continue
    name = path[len(mdir):]
    parts = name.split(".")
    if parts[0] == "d" and len(parts) == 4:
        touch(MARKDIRS[mdir] + "d.%s.%s" % (parts[1], parts[2]))
        acklog.write("ack %sd.%s.%s\n" % ("" if mdir == marks else "p2:", parts[1], parts[2]))
    elif mdir != marks:
        continue
    elif parts[0] == "p" and len(parts) == 4 and hold > 0:
        key = "%s.%s" % (parts[1], parts[2])
        acklog.write("hold p.%s for %.1fs at %.3f\n" % (key, hold, time.time()))

        def release(key=key):
            touch(acks + "released." + key)
            touch(acks + "p." + key)
            acklog.write("release p.%s at %.3f\n" % (key, time.time()))

        threading.Timer(hold, release).start()
    elif parts[0] == "p" and len(parts) == 4 and pause:
        # A directory made inside a just-created parent has no IN_CREATE of its own, so walk the tree as well.
        walked = {root for root, _, _ in os.walk(home + "/sessions")}
        candidates = seen | {d + "/" + pause for d in dirs | walked}
        target = next((c for c in candidates if path_hash(c) == parts[3]), None)
        if target:
            with open(target, "a") as f:
                f.write("F5 BYPASS WRITE (paused-writer control)\n")
        acklog.write("pause p.%s.%s target=%s\n" % (parts[1], parts[2], target))
        time.sleep(0.05)
        touch(acks + "p.%s.%s" % (parts[1], parts[2]))
