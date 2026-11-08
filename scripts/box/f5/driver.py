"""Scripted ACP clients for B-F5 (design F5 §4.1, §9.4). No model turn: initialize, authenticate, session/new, the
folder-trust grant, session/close, session/load. Every frame each client sends or receives is kept in
`<client>.frames.jsonl`; the case's assertions go to `case.json`.

usage: driver.py <case> <evidence dir> <workspace> <fuigo binary> <leader pid>
"""
import glob
import json
import os
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import f5lib  # noqa: E402

CASE, OUT, WS, BIN, LEADER = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5])
HOME = os.environ["FUIGO_HOME"]
MARKS, ACKS = HOME + "/f5-marks", HOME + "/f5-acks"
RELOAD_CAPS = {"fuigo/folderTrust": {"v2": True, "reload": True}}
# A 1.0.40 client without reload: v2 plus the P1 opt-in for the one reopen notice.
V2_CAPS = {"fuigo/folderTrust": {"v2": True, "reopenNotice": True}}
NOTICE = "Folder trust is on. Reopen this session to use it."
assertions = []
_phase = [0]


def check(name, ok, detail=""):
    assertions.append({"name": name, "ok": bool(ok), "detail": detail})
    print(("OK   " if ok else "FAIL ") + name + (" :: " + str(detail) if detail else ""), flush=True)


def phase(name):
    """Put the driver's step into the kernel-ordered event queue (a file under the watched FUIGO_HOME)."""
    _phase[0] += 1
    open("%s/phase.%02d.%s" % (ACKS, _phase[0], name), "w").close()
    print("-- phase", _phase[0], name, flush=True)


class Client:
    def __init__(self, name, caps, grant=True, hold_trust=False, argv=("agent", "--leader", "stdio"), env=None):
        self.name, self.caps, self.grant, self.hold = name, caps, grant, hold_trust
        self.p = subprocess.Popen([BIN, *argv], cwd=WS, stdin=subprocess.PIPE, env=env,
                                  stdout=subprocess.PIPE, stderr=open("%s/%s.stderr" % (OUT, name), "w"))
        self.frames = open("%s/%s.frames.jsonl" % (OUT, name), "w", buffering=1)
        self.cv = threading.Condition()
        self.resp, self.notes, self.trust, self.next_id, self.eof = {}, [], [], 0, False
        self.note_t, self.resp_t = [], {}
        # B8: act as the session's driver for a loop fire (`fuigo/scheduled_task_inject_prompt`): the pager enqueues the
        # task's prompt and runs it as a turn (acp_handler/background.rs handle_scheduled_task_inject_prompt). This
        # client sends it as a plain prompt, id `cron-<n>` (no fire ticket: the turn runs without scheduler authority).
        self.run_cron, self.cron_ids = False, []
        self.wlock = threading.Lock()
        threading.Thread(target=self._read, daemon=True).start()

    def _log(self, d, msg):
        self.frames.write(json.dumps({"t": round(time.time(), 3), "dir": d, "msg": msg}) + "\n")

    def send(self, msg):
        with self.wlock:
            self._log("out", msg)
            self.p.stdin.write((json.dumps(msg) + "\n").encode())
            self.p.stdin.flush()

    def _read(self):
        for raw in self.p.stdout:
            try:
                msg = json.loads(raw)
            except ValueError:
                self._log("junk", raw.decode(errors="replace"))
                continue
            self._log("in", msg)
            if "method" in msg and "id" in msg:
                self._on_request(msg)
            elif "method" in msg:
                with self.cv:
                    self.notes.append(msg)
                    self.note_t.append(time.time())
                    self.cv.notify_all()
                if self.run_cron and msg["method"].endswith("scheduled_task_inject_prompt"):
                    prm = msg.get("params") or {}
                    rid = "cron-%d" % (len(self.cron_ids) + 1)
                    self.cron_ids.append(rid)
                    self.send({"jsonrpc": "2.0", "id": rid, "method": "session/prompt",
                               "params": {"sessionId": prm.get("sessionId"),
                                          "prompt": [{"type": "text", "text": prm.get("prompt", "")}]}})
            else:
                with self.cv:
                    self.resp[msg.get("id")] = msg
                    self.resp_t[msg.get("id")] = time.time()
                    self.cv.notify_all()
        with self.cv:
            self.eof = True
            self.cv.notify_all()

    def _on_request(self, msg):
        method = msg["method"]
        if method == "session/request_permission":
            opts = msg.get("params", {}).get("options", [])
            pick = next((o for o in opts if str(o.get("kind", "")).startswith("allow")), opts[0] if opts else {})
            self.send({"jsonrpc": "2.0", "id": msg["id"],
                       "result": {"outcome": {"outcome": "selected", "optionId": pick.get("optionId")}}})
        elif method.endswith("fuigo/folder_trust/request"):
            with self.cv:
                self.trust.append(msg)
                self.cv.notify_all()
            if not self.hold:
                self.answer_trust(msg)
        else:
            self.send({"jsonrpc": "2.0", "id": msg["id"], "error": {"code": -32601, "message": "method not found"}})

    def answer_trust(self, msg):
        result = {"outcome": "trust", "scope": "configAndCommands"} if self.grant else {"outcome": "dismiss"}
        self.send({"jsonrpc": "2.0", "id": msg["id"], "result": result})

    def request(self, method, params, timeout=30.0):
        self.next_id += 1
        rid = self.next_id
        t0 = time.time()
        self.send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
        with self.cv:
            self.cv.wait_for(lambda: rid in self.resp or self.eof, timeout)
        return self.resp.get(rid), round(time.time() - t0, 3)

    def start(self, method, params):
        """Send a request without waiting; `await_resp` collects it."""
        self.next_id += 1
        rid = self.next_id
        self.send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
        return rid

    def await_resp(self, rid, timeout):
        with self.cv:
            self.cv.wait_for(lambda: rid in self.resp or self.eof, timeout)
        return self.resp.get(rid)

    def prompt(self, sid, text, timeout=90):
        return self.request("session/prompt", {"sessionId": sid, "prompt": [{"type": "text", "text": text}]}, timeout)

    def prompt_start(self, sid, text):
        return self.start("session/prompt", {"sessionId": sid, "prompt": [{"type": "text", "text": text}]})

    def wait(self, pred, timeout):
        with self.cv:
            return self.cv.wait_for(pred, timeout)

    def init(self):
        r, _ = self.request("initialize", {
            "protocolVersion": 1,
            "clientCapabilities": {"fs": {"readTextFile": False, "writeTextFile": False}, "terminal": False,
                                   "_meta": self.caps},
            "_meta": {"startupHints": {"nonInteractive": True, "skipGitStatus": True, "skipProjectLayout": True},
                      "clientType": "f5-box", "clientVersion": "0.0.0-box"}}, 60)
        assert r and "result" in r, "initialize failed: %s" % r
        a, _ = self.request("authenticate", {"methodId": "fuigo.api_key", "_meta": {"headless": True}})
        assert a and "result" in a, "authenticate failed: %s" % a

    def new(self):
        r, _ = self.request("session/new", {"cwd": WS, "mcpServers": []}, 60)
        assert r and "result" in r, "session/new failed: %s" % r
        return r["result"]["sessionId"]

    def close(self, sid, timeout=30):
        return self.request("session/close", {"sessionId": sid}, timeout)

    def load(self, sid, timeout=60):
        return self.request("session/load", {"sessionId": sid, "cwd": WS, "mcpServers": []}, timeout)

    def reloads(self):
        return [n for n in self.notes if "folder_trust_reload" in json.dumps(n)]

    def note_time(self, note):
        """When this client read `note` (a notification it received)."""
        return next((t for n, t in zip(self.notes, self.note_t) if n is note), None)

    def with_notice(self):
        return [n for n in self.notes if NOTICE in json.dumps(n)]

    def stop(self):
        try:
            self.p.stdin.close()
        except OSError:
            pass
        try:
            self.p.wait(10)
        except subprocess.TimeoutExpired:
            self.p.kill()
            self.p.wait(5)


def close_outcome(resp):
    meta = ((resp or {}).get("result") or {}).get("_meta") or {}
    return meta.get("fuigo/closeOutcome")


def mark_names():
    return sorted(os.listdir(MARKS))


def marks_of(prefix):
    return [m for m in os.listdir(MARKS) if m.startswith(prefix)]


def gens_of(sid):
    return sorted(int(m.rsplit(".", 1)[1]) for m in marks_of("claim.%s." % sid))


def wait_for(pred, timeout, step=0.05):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(step)
    return pred()


def session_dir(sid):
    hits = glob.glob(HOME + "/sessions/**/" + sid, recursive=True)
    return hits[0] if hits else None


ROOT = os.path.dirname(os.path.dirname(WS))
MARKERS = ROOT + "/markers"


def arm_pause():
    """Arm the held-writer pause (FUIGO_F5_PAUSE_ARM): the next chat_history.jsonl syscall is held for F5_HOLD s."""
    open(ACKS + "/pause-arm", "w").close()


def held_writer():
    """The writer paused at close (a `p` mark), and when the harness released it (`released.<gen>.<seq>`)."""
    return marks_of("p."), [a for a in os.listdir(ACKS) if a.startswith("released.")]


def session_end_hook(sid, gen1, wait):
    """Owner decision 3: the sleeping SessionEnd hook tries to write `f5-hook-late.txt` into the session folder after
    its sleep. Safe when it writes nothing there, or when its write lands inside a marked window. Returns the record."""
    done = wait_for(lambda: os.path.exists(MARKERS + "/session-end-done") or os.path.exists(MARKERS + "/hook-no-folder"),
                    wait) if wait else False
    started = [m for m in os.listdir(MARKERS) if m.startswith("hook-start.")]
    log = open(OUT + "/inotify.log").read().splitlines()
    names = [l.rpartition("|")[0] for l in log]
    late = [i for i, n in enumerate(names) if n.endswith("/" + sid + "/f5-hook-late.txt")]
    free_at = next((i for i, n in enumerate(names) if n.endswith("/free.%s.%d" % (sid, gen1))), None)
    ran = open(MARKERS + "/session-end-ran").read().strip() if os.path.exists(MARKERS + "/session-end-ran") else None
    rec = {"hook_started": bool(started), "hook_finished": done, "hook_ran_for": ran,
           "hook_wrote": open(MARKERS + "/hook-wrote").read().strip() if os.path.exists(MARKERS + "/hook-wrote") else None,
           "late_write_events": [log[i] for i in late], "first_late_event_index": late[0] if late else None,
           "free1_index": free_at,
           "after_free": bool(late and free_at is not None and late[0] > free_at)}
    open(OUT + "/session-end-hook.json", "w").write(json.dumps(rec, indent=1))
    return rec


def leader_proof(clients):
    """Exactly one `agent leader` process in this pid namespace, it is the one the harness started, and every client
    is a leader client (connected to the leader socket, not running its own agent)."""
    leaders = f5lib.count_leaders(BIN)
    check("one leader process", leaders == [LEADER], "leader pids %s (harness started %d)" % (leaders, LEADER))
    log = open(OUT + "/leader.log", errors="replace").read()
    for c in clients:
        ok = c.p.poll() is None
        socks = []
        try:
            for fd in os.listdir("/proc/%d/fd" % c.p.pid):
                socks.append(os.readlink("/proc/%d/fd/%s" % (c.p.pid, fd)))
        except OSError:
            pass
        check("client %s is a live leader client" % c.name, ok and any(s.startswith("socket:") for s in socks),
              "pid %d alive=%s" % (c.p.pid, ok))
    open(OUT + "/leader-proof.txt", "w").write("leaders=%s\nleader.log lines=%d\n" % (leaders, log.count("\n")))


def grant_session(owner, viewer=None):
    """session/new by `owner` (who holds the trust answer), optionally a second client attaches, then the grant."""
    phase("session-new")
    sid = owner.new()
    got = owner.wait(lambda: owner.trust, 30)
    check("the owner is asked for folder trust once", got and len(owner.trust) == 1, len(owner.trust))
    if viewer is not None:
        phase("viewer-attach")
        r, dt = viewer.load(sid)
        check("the second client attaches to the session", r and "result" in r, (r or {}).get("error"))
    phase("grant")
    if owner.trust:
        owner.answer_trust(owner.trust[0])
    return sid


def case_b1():
    a, b = Client("reload-client", RELOAD_CAPS, hold_trust=True), Client("viewer", RELOAD_CAPS)
    a.init(), b.init()
    sid = grant_session(a, b)
    check("one folder_trust_reload to the owner", a.wait(lambda: a.reloads(), 20) and len(a.reloads()) == 1,
          len(a.reloads()))
    time.sleep(1.0)
    check("still exactly one reload, none to the other client", len(a.reloads()) == 1 and not b.reloads(),
          "owner %d viewer %d" % (len(a.reloads()), len(b.reloads())))
    leader_proof([a, b])
    phase("close")
    r, dt = a.close(sid)
    check("close -> \"closed\"", close_outcome(r) == "closed", "%s in %ss" % (close_outcome(r) or r, dt))
    phase("load")
    r, dt = a.load(sid)
    check("one load, and it succeeds", r and "result" in r, (r or {}).get("error"))
    phase("loaded")
    gens = gens_of(sid)
    log = open(OUT + "/inotify.log").read().splitlines()
    idx = {l.rpartition("|")[0].rsplit("/", 1)[-1]: i for i, l in enumerate(log) if "/f5-marks/" in l}
    if len(gens) >= 2:
        f1, c2 = idx.get("free.%s.%d" % (sid, gens[0])), idx.get("claim.%s.%d" % (sid, gens[1]))
        check("free.1 precedes claim.2", f1 is not None and c2 is not None and f1 < c2, (gens[:2], f1, c2))
    else:
        check("free.1 precedes claim.2", False, "generations %s" % gens)
    check("exactly two generations (open, reload)", len(gens) == 2, gens)
    phase("viewer-sees-return")
    before = len(b.notes)
    r, dt = b.load(sid)
    check("the other client sees the returned session", r and "result" in r and len(b.notes) >= before,
          (r or {}).get("error"))
    leader_proof([a, b])
    check("one session/load request from the reload client",
          sum(1 for l in open(OUT + "/reload-client.frames.jsonl") if '"session/load"' in l and '"out"' in l) == 1)
    a.stop(), b.stop()
    return sid


def case_b4():
    a = Client("reload-client", RELOAD_CAPS)
    a.init()
    sid = grant_session(a)
    check("one folder_trust_reload", a.wait(lambda: a.reloads(), 20) and len(a.reloads()) == 1, len(a.reloads()))
    leader_proof([a])
    arm_pause()
    phase("close")
    r, dt = a.close(sid)
    gen1 = gens_of(sid)[0]
    check("stuck close -> \"timeout\" within 8.5 s", close_outcome(r) == "timeout" and dt <= 8.5,
          "%s in %ss" % (close_outcome(r) or r, dt))
    held, released = held_writer()
    check("the close-time writer is held (one p mark, not yet released)", len(held) == 1 and not released,
          (held, released))
    phase("load-while-closing")
    r, dt = a.load(sid, 30)
    err = json.dumps((r or {}).get("error"))
    check("immediate load waits, then 'still closing'", "still closing" in err and dt >= 5, "%s after %ss" % (err, dt))
    check("no gen-2 claim before free.1", len(gens_of(sid)) == 1, gens_of(sid))
    phase("wait-free")
    freed = wait_for(lambda: marks_of("free.%s.%d" % (sid, gen1)), 40)
    held, released = held_writer()
    check("generation 1 frees after the held writer is released", freed and len(released) == 1, (freed, released))
    phase("load-after-release")
    r, dt = a.load(sid)
    check("load succeeds after the pause is released", r and "result" in r, (r or {}).get("error"))
    # The free mark is in f5-marks before watch.py has logged it: wait for the log to catch up.
    wait_for(lambda: ("/free.%s.%d|" % (sid, gen1)) in open(OUT + "/inotify.log").read(), 10)
    log = open(OUT + "/inotify.log").read().splitlines()
    names = [l.rpartition("|")[0].rsplit("/", 1)[-1] for l in log]
    close_at = next((i for i, n in enumerate(names) if n.startswith("phase.") and n.endswith(".close")), None)
    free_at = next((i for i, n in enumerate(names) if n == "free.%s.%d" % (sid, gen1)), None)
    late = [n for n in names[close_at:free_at] if n.startswith(("b.%d." % gen1, "e.%d." % gen1))] if close_at and free_at else []
    check("the old generation's late writes carry gen-1 marks", len(late) > 0, "%d gen-1 b/e marks after close (the held syscall ends here)" % len(late))
    gens = gens_of(sid)
    g2 = [i for i, n in enumerate(names) if len(gens) > 1 and (n.startswith("b.%d." % gens[1])
                                                            or n == "claim.%s.%d" % (sid, gens[1]))]
    check("no gen-2 mark before free.1", free_at is not None and all(i > free_at for i in g2), (free_at, g2[:3]))
    phase("session-end-hook")
    rec = session_end_hook(sid, gen1, 40)
    # F13: the hook is dispatched in the shutdown path after the session's process scope closed; it now runs on its own
    # (1.0.40 killpg'd it at once: "session closed before the hook ran") and writes its marker outside the session
    # folder. Record the dispatch and its outcome from leader.log.
    runs = [l.split("hook_failure=")[-1].strip() if "hook_failure=" in l else "completed"
            for l in open(OUT + "/leader.log", errors="replace")
            if "hook_event=session_end" in l and "global/f5-session-end" in l and ("hook failed" in l or "hook completed" in l)]
    rec["leader_log_outcomes"] = runs
    open(OUT + "/session-end-hook.json", "w").write(json.dumps(rec, indent=1))
    check("the SessionEnd hook was dispatched at close without blocking it", len(runs) >= 1, runs)
    check("the SessionEnd hook ran and wrote its own marker outside the session folder",
          rec["hook_finished"] and rec["hook_ran_for"] == sid and "completed" in runs,
          {k: rec[k] for k in ("hook_started", "hook_finished", "hook_ran_for")} | {"runs": runs})
    check("the SessionEnd hook writes nothing into the session folder after free.1", not rec["after_free"],
          {k: rec[k] for k in ("hook_finished", "hook_wrote", "first_late_event_index", "free1_index")})
    leader_proof([a])
    a.stop()


def case_b4_noncap():
    n, v = Client("noncap-client", {}), Client("noncap-viewer", {})
    n.init(), v.init()
    phase("session-new")
    sid = n.new()
    # A fresh idle session closes with no writer syscall to hold once its startup writes settle. A second client
    # attached gives the session an updates.jsonl handle that the close itself releases (a marked syscall), which the
    # harness holds (run.sh: FUIGO_F5_PAUSE=updates.jsonl for this case).
    phase("viewer-attach")
    r, dt = v.load(sid)
    check("a second non-capable client attaches", r and "result" in r, (r or {}).get("error"))
    time.sleep(2.0)
    leader_proof([n, v])
    arm_pause()
    phase("close")
    r, dt = n.close(sid)
    check("stuck close -> \"closed\" to a non-capable client within 8.5 s", close_outcome(r) in ("closed", None)
          and r and "result" in r and dt <= 8.5, "%s in %ss" % (close_outcome(r) or r, dt))
    check("the close took the stuck path (waited for the shutdown deadline)", dt >= 7.0, dt)
    gen1 = gens_of(sid)[0]
    held, released = held_writer()
    check("the close-time writer is held (one p mark, not yet released)", len(held) == 1 and not released,
          (held, released))
    phase("wait-free")
    freed = wait_for(lambda: marks_of("free.%s.%d" % (sid, gen1)), 40)
    held, released = held_writer()
    check("generation 1 frees after the held writer is released", freed and len(released) == 1, (freed, released))
    # The free mark is in f5-marks before watch.py has logged it: wait for the log to catch up.
    wait_for(lambda: ("/free.%s.%d|" % (sid, gen1)) in open(OUT + "/inotify.log").read(), 10)
    log = open(OUT + "/inotify.log").read().splitlines()
    names = [l.rpartition("|")[0].rsplit("/", 1)[-1] for l in log]
    close_at = next((i for i, n_ in enumerate(names) if n_.startswith("phase.") and n_.endswith(".close")), None)
    free_at = next((i for i, n_ in enumerate(names) if n_ == "free.%s.%d" % (sid, gen1)), None)
    late = [n_ for n_ in names[close_at:free_at] if n_.startswith(("b.%d." % gen1, "e.%d." % gen1))] if close_at and free_at else []
    check("the old generation's late writes carry gen-1 marks", len(late) > 0, "%d gen-1 b/e marks after close (the held syscall ends here)" % len(late))
    phase("session-end-hook")
    # Untrusted folder: user hooks are skipped (leader.log "hooks skipped: folder not trusted"), so it never starts.
    rec = session_end_hook(sid, gen1, 0)
    check("the SessionEnd hook writes nothing into the session folder after free.1", not rec["after_free"],
          {k: rec[k] for k in ("hook_started", "hook_wrote", "first_late_event_index", "free1_index")})
    n.stop(), v.stop()


def case_b11():
    c = Client("noreload-client", V2_CAPS)
    c.init()
    sid = grant_session(c)
    c.wait(lambda: c.with_notice(), 20)
    time.sleep(2.0)
    check("one notice: '%s'" % NOTICE, len(c.with_notice()) == 1, len(c.with_notice()))
    check("no reload frame", not c.reloads(), len(c.reloads()))
    sent = [json.loads(l)["msg"].get("method") for l in open(OUT + "/noreload-client.frames.jsonl")
            if '"dir": "out"' in l]
    check("the client sent no close", "session/close" not in sent, sent)
    check("no generation was freed (nothing closed the session)", not marks_of("free.%s." % sid), marks_of("free."))
    r, dt = c.request("session/list", {}, 15)
    check("1.0.38 frames: the session stays open and listed", r is not None and sid in json.dumps(r), dt)
    leader_proof([c])
    c.stop()


def control(kind):
    c = Client("client", {})
    c.init()
    phase("session-new")
    sid = c.new()
    time.sleep(2.0)
    d = session_dir(sid)
    check("session folder exists", d is not None, d)
    phase("bypass-" + kind)
    if kind == "unmarked":
        with open(d + "/bypass.txt", "w") as f:
            f.write("raw write outside any window\n")
    elif kind == "rapid":
        os.mkdir(d + "/zz")
        with open(d + "/zz/f", "w") as f:
            f.write("x")
        os.remove(d + "/zz/f")
        os.rmdir(d + "/zz")
    elif kind == "image":
        # images/ as the pager leaves it (its creation is excepted), watched before the tool-style write lands.
        os.makedirs(d + "/images", exist_ok=True)
        time.sleep(0.5)
        with open(d + "/images/1.png", "wb") as f:
            f.write(b"\x89PNG\r\n\x1a\n")
    elif kind == "pause":
        check("the writer paused and the bypass ran", wait_for(lambda: marks_of("p."), 20), marks_of("p."))
    time.sleep(2.0)
    leader_proof([c])
    c.stop()


MODEL_SCRIPT = os.environ.get("F5_MODEL_SCRIPT")


def model_step(**step):
    """Queue the fake model's next agent-turn reply (fake_model.py): {"text"} or {"tool", "args"}, optional "gate"."""
    with open(MODEL_SCRIPT, "a") as f:
        f.write(json.dumps(step) + "\n")


def model_requests():
    try:
        return [json.loads(l) for l in open(OUT + "/model-requests.jsonl")]
    except OSError:
        return []


def case_probe():
    d = Client("client2", RELOAD_CAPS, grant=False)
    d.init()
    sid2 = d.new()
    d.wait(lambda: d.trust, 20)
    time.sleep(1)
    r, dt = d.prompt(sid2, "/hooks-trust", 20)
    print("HOOKS-TRUST", json.dumps(r)[:300], dt)
    print("RELOADS after /hooks-trust", d.wait(lambda: d.reloads(), 10), len(d.reloads()))
    print("NOTES", [json.dumps(n)[:200] for n in d.notes][-6:])
    for q in model_requests():
        print("REQ", json.dumps(q)[:1500])
    c.stop()


def events():
    """inotify.log as (index, full path, events)."""
    out = []
    for i, l in enumerate(open(OUT + "/inotify.log").read().splitlines()):
        p, _, e = l.rpartition("|")
        out.append((i, p, e))
    return out


def phase_at(name):
    wait_for(lambda: any(p.endswith("." + name) and "/phase." in p for _, p, _ in events()), 10)
    return next((i for i, p, _ in events() if "/phase." in p and p.endswith("." + name)), None)


def mark_at(name):
    wait_for(lambda: any(p.endswith("/" + name) for _, p, _ in events()), 10)
    return next((i for i, p, _ in events() if p.endswith("/f5-marks/" + name)), None)


def id_events(sid, lo, hi):
    """Session-folder events under <sid>/ in (lo, hi) of the kernel queue."""
    return [(i, p, e) for i, p, e in events() if lo < i < hi and ("/" + sid + "/") in p + "/" and "/f5-" not in p]


def err_text(r):
    return json.dumps((r or {}).get("error") or (r or {}).get("result"))


def held_elsewhere(r):
    return "open in another Fuigo window" in err_text(r)


def second_process(name="second-process"):
    """A second real fuigo process on the same FUIGO_HOME, standalone (not a leader client).

    Every process counts writer generations from 1, so the second process writes its marks to its own trace dir,
    `<FUIGO_HOME>/p2/f5-marks` (acks in `p2/f5-acks`, made by run.sh before the watch starts): passrule.py tags each
    mark with its process and judges generations per (process, id)."""
    env = dict(os.environ, FUIGO_F5_TRACE_DIR=HOME + "/p2/f5-marks")
    c = Client(name, RELOAD_CAPS, grant=False, argv=["agent", "--no-leader", "stdio"], env=env)
    c.init()
    return c


def reload_after_grant(a, sid, b=None):
    """B1's tail: one reload, close -> closed, one load, free.1 before claim.2, the viewer sees the return."""
    check("one folder_trust_reload to the owner", a.wait(lambda: a.reloads(), 20) and len(a.reloads()) == 1,
          len(a.reloads()))
    if b is not None:
        check("no reload to the other client", not b.reloads(), len(b.reloads()))
    phase("close")
    r, dt = a.close(sid)
    check("close -> \"closed\"", close_outcome(r) == "closed", "%s in %ss" % (close_outcome(r) or r, dt))
    phase("load")
    r, dt = a.load(sid)
    check("one load, and it succeeds", r and "result" in r, (r or {}).get("error"))
    phase("loaded")
    gens = gens_of(sid)
    f1 = mark_at("free.%s.%d" % (sid, gens[0])) if gens else None
    c2 = mark_at("claim.%s.%d" % (sid, gens[1])) if len(gens) > 1 else None
    check("free.1 precedes claim.2", f1 is not None and c2 is not None and f1 < c2, (gens, f1, c2))
    check("exactly two generations (open, reload)", len(gens) == 2, gens)
    if b is not None:
        r, dt = b.load(sid)
        check("the other client sees the returned session", r and "result" in r, (r or {}).get("error"))
    return gens


def case_b2():
    """Design §9.4 B2 (owner decision, rev 2.2): a `/hooks-trust` typed during a running turn waits in the prompt queue,
    as upstream, so its grant and the reload come after the reply: the reload arrives after the reply and before the
    close; the close comes only after the reply; then as B1."""
    a, b = Client("reload-client", RELOAD_CAPS, grant=False), Client("viewer", RELOAD_CAPS)
    a.init(), b.init()
    phase("session-new")
    sid = a.new()
    a.wait(lambda: a.trust, 20)
    r, _ = b.load(sid)
    check("the second client attaches to the session", r and "result" in r, (r or {}).get("error"))
    gate = MARKERS + "/b2-gate"
    model_step(text="B2 TURN REPLY", gate=gate)
    phase("turn")
    turn = a.prompt_start(sid, "B2 long turn")
    check("the turn reached the model (reply held mid-stream)",
          wait_for(lambda: any(q.get("step") for q in model_requests()), 20), len(model_requests()))
    phase("hooks-trust")
    trust_rid = a.prompt_start(sid, "/hooks-trust")
    early = a.wait(lambda: a.reloads(), 3)
    check("while the turn runs, /hooks-trust waits in the queue (no reload yet)", not early and turn not in a.resp,
          "reloads %d, turn done %s" % (len(a.reloads()), turn in a.resp))
    phase("release-reply")
    open(gate, "w").close()
    rt = a.await_resp(turn, 60)
    rh = a.await_resp(trust_rid, 60)
    check("the turn ends with its reply", rt and "result" in rt, err_text(rt))
    check("/hooks-trust answered", rh and "result" in rh, err_text(rh))
    t_reply = a.resp_t.get(turn)
    a.wait(lambda: a.reloads(), 20)
    t_reload = a.note_time(a.reloads()[0]) if a.reloads() else None
    # "The reply" is the turn's streamed reply text (its agent_message_chunk updates). The prompt's response frame and the
    # reload are both sent once the turn has ended and the queued /hooks-trust has run, so they race on the wire by
    # microseconds; order is judged by the client's receive order of the reply's last chunk and the reload.
    chunks = [k for k, n in enumerate(a.notes) if "agent_message_chunk" in json.dumps(n) and "REPLY" in json.dumps(n)]
    k_reload = next((k for k, n in enumerate(a.notes) if "folder_trust_reload" in json.dumps(n)), None)
    check("the reload arrives after the reply", chunks and k_reload is not None and k_reload > max(chunks),
          {"reply_last_chunk": max(chunks) if chunks else None, "reload": k_reload, "t_turn_response": t_reply,
           "t_reload": t_reload})
    leader_proof([a, b])
    t_close = time.time()
    if a.reloads():
        # The client closes only when idle and only once it has the reload: after the reply and /hooks-trust.
        reload_after_grant(a, sid, b)
    check("the reload arrives before the close; the close comes only after the reply",
          t_reload is not None and t_reply is not None and t_reload <= t_close and t_reply <= t_close,
          (t_reply, t_reload, t_close))
    hist = open(session_dir(sid) + "/chat_history.jsonl").read()
    check("the reply is in the history once", hist.count("B2 TURN REPLY") == 1, hist.count("B2 TURN REPLY"))
    leader_proof([a, b])
    a.stop(), b.stop()


def texts(req):
    return json.dumps(req.get("messages") or [])


def case_b3():
    a = Client("reload-client", RELOAD_CAPS, hold_trust=True)
    a.init()
    phase("session-new")
    sid = a.new()
    a.wait(lambda: a.trust, 20)
    model_step(text="B3 BEFORE REPLY")
    phase("before-turn")
    r, _ = a.prompt(sid, "B3 before the grant")
    check("a turn before the grant", r and "result" in r, err_text(r))
    starts_before = [m for m in os.listdir(MARKERS) if m.startswith("session-start.")]
    phase("grant")
    a.answer_trust(a.trust[0])
    reload_after_grant(a, sid)
    time.sleep(1.0)
    starts_after = [m for m in os.listdir(MARKERS) if m.startswith("session-start.")]
    check("SessionStart marker as a trusted load (none untrusted, one on the reload)",
          not starts_before and len(starts_after) >= 1, (starts_before, starts_after))
    n0 = len(model_requests())
    model_step(tool="f5echo__echo", args={"text": "b3"})
    model_step(tool="read_file", args={"target_file": "sub/notes.txt"})
    model_step(text="B3 AFTER REPLY")
    phase("after-turn")
    r, _ = a.prompt(sid, "B3 after the reload", 120)
    check("the prompt after the reload completes", r and "result" in r, err_text(r))
    reqs = [json.load(open(OUT + "/model-req.%03d.json" % q["n"])) for q in model_requests()[n0:]
            if q.get("method") == "POST" and q.get("tools")]
    pre = [json.load(open(OUT + "/model-req.%03d.json" % q["n"])) for q in model_requests()[:n0]
           if q.get("method") == "POST" and q.get("tools")]
    check("three agent requests after the reload (echo, read, reply)", len(reqs) >= 3, len(reqs))
    if len(reqs) < 3 or not pre:
        a.stop()
        return
    # MCP tools are deferred on every session (trusted cold loads too): the list offers search_tool/use_tool and a
    # reminder names the connected server; the tool itself is not in `tools` (session/acp_session_impl/mcp.rs).
    tools0 = [((t.get("function") or {}).get("name")) for t in reqs[0].get("tools", [])]
    pre_tools = [((t.get("function") or {}).get("name")) for t in pre[0].get("tools", [])]
    check("echo MCP server surfaced after the reload (deferred: search_tool/use_tool + connected reminder), not before",
          "use_tool" in tools0 and "f5echo (1 tool)" in texts(reqs[0])
          and "use_tool" not in pre_tools and "f5echo" not in json.dumps(pre[0]),
          ([t for t in tools0 if "tool" in t], "f5echo (1 tool)" in texts(reqs[0])))
    check("echo MCP callable (its result reaches the model)", "F5 ECHO b3" in texts(reqs[1]), texts(reqs[1])[-300:])
    full0 = json.dumps(reqs[0])
    check("skill listed after the reload (not before)", "f5-box-skill" in full0 and "f5-box-skill" not in json.dumps(pre[0]))
    check("project subagent available after the reload (not before)",
          "f5-box-agent" in full0 and "f5-box-agent" not in json.dumps(pre[0]))
    # A nested AGENTS.md is never injected on a read in any session (AgentsMdTracker::check_path has no product caller;
    # the top-level reminder tells the model to look for it): asserted against a fresh trusted load below (F7).
    reloaded_nested = "F5 MARKER NESTED AGENTS" in json.dumps(reqs[2])
    last = json.dumps(reqs[-1])
    check("top-level marker once", last.count("F5 MARKER TOP-LEVEL AGENTS") == 1, last.count("F5 MARKER TOP-LEVEL AGENTS"))
    check("no duplicated transcript", texts(reqs[-1]).count("B3 before the grant") == 1
          and texts(reqs[-1]).count("B3 after the reload") == 1,
          (texts(reqs[-1]).count("B3 before the grant"), texts(reqs[-1]).count("B3 after the reload")))
    check("history intact: the pre-reload turn and reply reach the model after the cold load",
          "B3 BEFORE REPLY" in texts(reqs[-1]) and texts(reqs[-1]).count("B3 BEFORE REPLY") == 1)
    # F7 reference (design F5 §8): a fresh session on the now-trusted folder, the same three steps; the reloaded session
    # must see what it sees.
    phase("fresh-trusted")
    sid2 = a.new()
    n1 = len(model_requests())
    model_step(tool="f5echo__echo", args={"text": "b3f"})
    model_step(tool="read_file", args={"target_file": "sub/notes.txt"})
    model_step(text="B3 FRESH REPLY")
    r, _ = a.prompt(sid2, "B3 fresh trusted load", 120)
    check("the fresh trusted load's prompt completes", r and "result" in r, err_text(r))
    fresh = [json.load(open(OUT + "/model-req.%03d.json" % q["n"])) for q in model_requests()[n1:]
             if q.get("method") == "POST" and q.get("tools")]
    if len(fresh) >= 3:
        names = lambda req: [((t.get("function") or {}).get("name")) for t in req.get("tools", [])]
        check("F7: tool list after the reload == fresh trusted load", names(reqs[2]) == names(fresh[2]),
              (sorted(set(names(reqs[2])) ^ set(names(fresh[2])))))
        same = lambda probe: ((probe in json.dumps(reqs[0]) or probe in json.dumps(reqs[1])),
                              (probe in json.dumps(fresh[0]) or probe in json.dumps(fresh[1])))
        for probe in ("f5echo (1 tool)", "f5-box-skill", "f5-box-agent", "F5 MARKER TOP-LEVEL AGENTS"):
            got = same(probe)
            check("F7: %s after the reload == fresh trusted load" % probe, got == (True, True), got)
        fresh_nested = "F5 MARKER NESTED AGENTS" in json.dumps(fresh[2])
        check("F7: nested AGENTS.md on reading sub/ after the reload == fresh trusted load",
              reloaded_nested == fresh_nested, (reloaded_nested, fresh_nested))
    else:
        check("three agent requests in the fresh trusted load", False, len(fresh))
    leader_proof([a])
    a.stop()


def held_close(a):
    sid = grant_session(a)
    check("one folder_trust_reload", a.wait(lambda: a.reloads(), 20) and len(a.reloads()) == 1, len(a.reloads()))
    arm_pause()
    phase("close")
    r, dt = a.close(sid)
    check("stuck close -> \"timeout\" within 8.5 s", close_outcome(r) == "timeout" and dt <= 8.5,
          "%s in %ss" % (close_outcome(r) or r, dt))
    held, released = held_writer()
    check("the close-time writer is held", len(held) == 1 and not released, (held, released))
    return sid, gens_of(sid)[0]


def case_b5():
    a = Client("reload-client", RELOAD_CAPS)
    a.init()
    sid, gen1 = held_close(a)
    d = session_dir(sid)
    before = sorted(os.listdir(d))
    phase("delete-while-held")
    r, dt = a.request("_fuigo/session/delete", {"sessionId": sid}, 30)
    check("delete during the hold -> 'still closing'", "still closing" in err_text(r), "%s after %ss" % (err_text(r), dt))
    check("folder intact", session_dir(sid) == d and sorted(os.listdir(d)) == before, sorted(os.listdir(d)))
    phase("wait-free")
    check("generation 1 frees", wait_for(lambda: marks_of("free.%s.%d" % (sid, gen1)), 40))
    phase("delete-after-free")
    r, dt = a.request("_fuigo/session/delete", {"sessionId": sid}, 30)
    check("after free, delete succeeds", r and "result" in r and session_dir(sid) is None, err_text(r))
    phase("deleted")
    time.sleep(3.0)
    phase("settled")
    lo, hi = phase_at("deleted"), phase_at("settled")
    later = [e for e in id_events(sid, lo, hi) if "CREATE" in e[2]]
    check("no later create under that path", lo is not None and not later, later[:3])
    leader_proof([a])
    a.stop()


def case_b6():
    a = Client("client", RELOAD_CAPS, grant=False)
    a.init()
    s1, s2 = a.new(), a.new()
    p2 = second_process()
    s3 = p2.new()
    time.sleep(2.0)
    summary = json.load(open(session_dir(s2) + "/summary.json"))
    other = os.path.dirname(WS) + "/other"
    os.makedirs(other, exist_ok=True)

    def probe(label, target, method, params, want, wantname):
        phase(label)
        r, dt = a.request(method, params, 30)
        phase(label + "-done")
        evs = id_events(target, phase_at(label), phase_at(label + "-done"))
        check("%s -> %s" % (label, wantname), want(r), err_text(r))
        check("%s: no event under the target id" % label, not evs, evs[:3])

    fork = lambda t: {"sourceSessionId": s2, "sourceCwd": WS, "newCwd": WS, "newSessionId": t}
    imp = lambda t: {"sessionId": t, "cwd": other, "state": {"summary": summary}, "updates": []}
    # Design §9.4 B6 amendment (rev 2.2): an import into an id whose summary.json exists answers 1.0.40's
    # {"imported": false}; a fork into another process's id with session files answers 1.0.40's "already exists ...
    # Nothing was written". HELD_ELSEWHERE stays the answer for a racing claim on an id with no files yet.
    open_here = lambda r: "This session is open. Close it first." in err_text(r)
    not_imported = lambda r: bool(r) and r.get("result") == {"imported": False}
    exists = lambda r: "a session with that id already exists" in err_text(r) and "Nothing was written" in err_text(r)
    probe("fork-to-open-id", s1, "_fuigo/session/fork", fork(s1), open_here, "This session is open...")
    probe("import-into-open-id", s1, "_fuigo/session/import", imp(s1), not_imported, '{"imported": false}')
    probe("fork-to-other-process-id", s3, "_fuigo/session/fork", fork(s3), exists, "already exists, nothing written")
    probe("import-into-other-process-id", s3, "_fuigo/session/import", imp(s3), not_imported, '{"imported": false}')
    phase("import-same-cwd")
    r, _ = a.request("_fuigo/session/import", {"sessionId": s1, "cwd": WS, "state": {"summary": summary}, "updates": []})
    phase("import-same-cwd-done")
    evs = id_events(s1, phase_at("import-same-cwd"), phase_at("import-same-cwd-done"))
    check("import of an open id at its own cwd changes nothing", not evs and "error" not in (r or {"error": 1}),
          (err_text(r), evs[:3]))
    leader_proof([a])
    a.stop(), p2.stop()


B7_SUMMARY_TOUCHED = {"num_messages", "last_active_at", "updated_at"}


def b7_summary_diff(before, after):
    """Problems (empty = fine) in the summary.json change across the resident load: num_messages must rise by exactly
    1, and no key except the record_activity timestamps may differ (added or removed keys count as differing)."""
    bad = [k for k in sorted(set(before) | set(after))
           if before.get(k, "<absent>") != after.get(k, "<absent>") and k not in B7_SUMMARY_TOUCHED]
    out = ["unexpected change: %s" % k for k in bad]
    if after.get("num_messages") != before.get("num_messages", 0) + 1:
        out.append("num_messages %r -> %r (want +1)" % (before.get("num_messages"), after.get("num_messages")))
    return out


def case_b7():
    a, b, c = Client("loader-a", RELOAD_CAPS, grant=False), Client("loader-b", RELOAD_CAPS), Client("resident", RELOAD_CAPS)
    a.init(), b.init(), c.init()
    sid = a.new()
    a.wait(lambda: a.trust, 20)
    time.sleep(1.0)
    r, _ = a.close(sid)
    check("close -> \"closed\"", close_outcome(r) == "closed", close_outcome(r) or r)
    wait_for(lambda: marks_of("free.%s." % sid), 10)
    phase("overlapping-loads")
    params = {"sessionId": sid, "cwd": WS, "mcpServers": []}
    ra, rb = a.start("session/load", params), b.start("session/load", params)
    xa, xb = a.await_resp(ra, 60), b.await_resp(rb, 60)
    check("both overlapping loads succeed", xa and "result" in xa and xb and "result" in xb, (err_text(xa), err_text(xb)))
    gens = gens_of(sid)
    check("one claim for the overlapping loads (one actor)", len(gens) == 2, gens)
    time.sleep(2.0)
    upd = session_dir(sid) + "/updates.jsonl"
    lines0 = open(upd).read().splitlines()
    summ = session_dir(sid) + "/summary.json"
    sum0 = json.load(open(summ))
    phase("resident-load")
    r, _ = c.load(sid)
    phase("resident-loaded")
    sum1 = json.load(open(summ))
    lo, hi = phase_at("resident-load"), phase_at("resident-loaded")
    bm = [p.rsplit("/", 1)[-1] for i, p, e in events() if lo < i < hi and "/f5-marks/b." in p]
    # Sanctioned (1.0.40 too): every session/load persists and broadcasts the live background_tasks snapshot
    # (session_setup.rs emit_background_tasks_snapshot_and_wait), one last-wins line in updates.jsonl through the
    # writer (its append and the append lock). That append goes through append_update_with_bookkeeping, which also
    # applies the summary bookkeeping patch (record_activity + messages Increment(1)): summary.json and its lock.
    # Before the 1.0.41 r1 H4 change that patch wrote summary.json outside the writer, so the marks never saw it; H4
    # routes it through the writer, so it is traced now. It is the same sanctioned write, not new behaviour, and the
    # oracle stays tight: the only summary.json differences allowed are num_messages up by exactly 1 and the
    # timestamps record_activity touches (last_active_at, and updated_at which apply_patch always sets).
    # Nothing else may be written by a resident load.
    allowed = {f5lib.path_hash(upd), f5lib.path_hash(upd + ".lock"),
               f5lib.path_hash(summ), f5lib.path_hash(summ + ".lock")}
    sdiff = b7_summary_diff(sum0, sum1)
    other = [m for m in bm if m.rsplit(".", 1)[-1] not in allowed]
    added = open(upd).read().splitlines()[len(lines0):]
    snapshot_only = len(added) == 1 and '"sessionUpdate":"background_tasks"' in added[0]
    check("the resident load succeeds and writes only its background_tasks snapshot (no other b mark)",
          r and "result" in r and not other and snapshot_only, (err_text(r), other[:4], [x[:120] for x in added]))
    check("the snapshot's summary bookkeeping changes only num_messages (+1) and the activity timestamps",
          not sdiff, sdiff)
    check("still one claim", len(gens_of(sid)) == 2, gens_of(sid))
    leader_proof([a, b, c])
    a.stop(), b.stop(), c.stop()


def fires(a):
    """One entry per fire: the loop's `fuigo/scheduled_task_inject_prompt` to the session's driver, with its arrival
    time. It is not persisted or replayed, so a load's replay of the transcript adds none."""
    return [{"t": t, "n": n} for n, t in zip(list(a.notes), list(a.note_t))
            if str(n.get("method", "")).endswith("scheduled_task_inject_prompt")]


B8_INTERVAL, B8_EARLY, B8_LATE = 60.0, 2.0, 15.0


def case_b8():
    """Design §9.4 B8 (owner decision, rev 2.2): the scheduler's floor is one minute (a 10 s loop is raised to
    "every 1 minute"), so the loop runs every minute. It fires once before the reload and once after it, each one
    interval after its anchor (creation, then the previous fire), within the scheduler's tick: at most B8_EARLY s early
    (clock rounding) and B8_LATE s late (the actor's wake plus the fire's turn)."""
    a = Client("reload-client", RELOAD_CAPS, hold_trust=True)
    a.run_cron = True
    a.init()
    sid = a.new()
    a.wait(lambda: a.trust, 20)
    model_step(tool="scheduler_create", args={"interval": "1m", "prompt": "F5 LOOP FIRE", "foreground": True,
                                               "fire_immediately": False})
    model_step(text="B8 loop created")
    t_create = time.time()
    r, _ = a.prompt(sid, "B8 set the loop")
    t_created = time.time()
    check("the loop task is created", r and "result" in r, err_text(r))
    bodies = "".join(open(f, errors="replace").read() for f in sorted(glob.glob(OUT + "/model-req.*.json")))
    check("the scheduler runs it every 1 minute", "every 1 minute" in bodies)
    lo, hi = B8_INTERVAL - B8_EARLY, B8_INTERVAL + B8_LATE
    wait_for(lambda: fires(a), hi + 10)
    f = fires(a)
    t1 = f[0]["t"] if f else None
    check("it fires once before the reload, on schedule",
          len(f) == 1 and t_create + lo <= t1 <= t_created + hi, [round(q["t"] - t_create, 1) for q in f])
    r1 = a.await_resp("cron-1", 30) if a.cron_ids else None
    check("the fire's turn runs and ends", r1 and "result" in r1, err_text(r1))
    phase("grant")
    a.answer_trust(a.trust[0])
    a.wait(lambda: a.reloads(), 20)
    reload_after_grant(a, sid)
    t_load = time.time()
    check("no fire during the reload", len(fires(a)) == len(f), [round(q["t"] - t_create, 1) for q in fires(a)])
    if t1 is not None:
        wait_for(lambda: len(fires(a)) > len(f), max(5.0, t1 + hi + 5 - time.time()))
    f2 = [q for q in fires(a) if t1 is not None and q["t"] > t1]
    check("it fires once after the reload, one interval after the first fire",
          len(f2) == 1 and f2[0]["t"] > t_load and lo <= f2[0]["t"] - t1 <= hi,
          {"after_first": [round(q["t"] - (t1 or 0), 1) for q in f2], "load_at": round(t_load - (t1 or 0), 1)})
    leader_proof([a])
    a.stop()


def case_b9():
    a = Client("reload-client", RELOAD_CAPS)
    a.init()
    sid, gen1 = held_close(a)
    p2 = second_process()
    phase("second-process-load")
    r, dt = p2.load(sid, 30)
    freed_then = bool(marks_of("free.%s.%d" % (sid, gen1)))
    check("second process: HELD_ELSEWHERE until free", held_elsewhere(r) and not freed_then, "%s after %ss" % (err_text(r), dt))
    phase("wait-free")
    check("generation 1 frees", wait_for(lambda: marks_of("free.%s.%d" % (sid, gen1)), 40))
    phase("second-process-load-after-free")
    r, dt = p2.load(sid, 60)
    check("then the second process opens it", r and "result" in r, err_text(r))
    leader_proof([a])
    a.stop(), p2.stop()


def case_b10():
    a = Client("client", RELOAD_CAPS, grant=False)
    a.init()
    p2 = second_process()
    known = set(glob.glob(HOME + "/sessions/*/*"))
    phase("session-new")
    t0 = time.time()
    rid = a.start("session/new", {"cwd": WS, "mcpServers": []})
    wait_for(lambda: set(glob.glob(HOME + "/sessions/*/*")) - known, 10, 0.005)
    new = sorted(set(glob.glob(HOME + "/sessions/*/*")) - known)
    sid = os.path.basename(new[0]) if new else None
    r1, dt1 = p2.load(sid, 30) if sid else (None, 0)
    t1 = time.time() - t0
    rn = a.await_resp(rid, 60)
    check("session/new succeeds", rn and "result" in rn and rn["result"]["sessionId"] == sid, err_text(rn))
    check("probe as the folder appears -> HELD_ELSEWHERE", held_elsewhere(r1), "%s at %.3fs" % (err_text(r1), t1))
    r2, dt2 = p2.load(sid, 30)
    check("probe within the first second -> HELD_ELSEWHERE", held_elsewhere(r2) and time.time() - t0 < 1.5 + dt2,
          "%s, %.3fs after session/new" % (err_text(r2), time.time() - t0))
    leader_proof([a])
    a.stop(), p2.stop()


def case_b12():
    a = Client("reload-client", RELOAD_CAPS, hold_trust=True)
    a.init()
    sid = a.new()
    a.wait(lambda: a.trust, 20)
    model_step(tool="run_terminal_command", args={"command": "for i in $(seq 1 60000); do echo f5bg $i; sleep 0.001; done",
                                                   "description": "F5 background job", "block_until_ms": 0})
    model_step(text="B12 job started")
    r, _ = a.prompt(sid, "B12 start the job")
    check("the background bash job starts", r and "result" in r, err_text(r))
    d = session_dir(sid)
    check("its terminal log is being written", wait_for(lambda: glob.glob(d + "/terminal/*.log"), 10),
          glob.glob(d + "/terminal/*"))
    n_spawn = open(OUT + "/leader.log", errors="replace").read().count("MCP server 'f5echo' spawned")
    phase("grant")
    a.answer_trust(a.trust[0])
    check("the MCP handshake is running (spawned, answer delayed)",
          wait_for(lambda: open(OUT + "/leader.log", errors="replace").read().count("MCP server 'f5echo' spawned") > n_spawn, 10))
    phase("close")
    r, dt = a.close(sid)
    phase("closed-received")
    check("close -> \"closed\"", close_outcome(r) == "closed", "%s in %ss" % (close_outcome(r) or r, dt))
    gen1 = gens_of(sid)[0]
    lo, hi = phase_at("close"), phase_at("closed-received")
    time.sleep(3.0)
    phase("after")
    end = phase_at("after")
    ev = events()
    names = {i: p.rsplit("/", 1)[-1] for i, p, _ in ev}
    tail = [(i, p, e) for i, p, e in id_events(sid, lo, end) if "/terminal/" in p or p.endswith("/events.jsonl")]
    g1 = [i for i in range(lo or 0, end or 0) if names.get(i, "").startswith(("b.%d." % gen1, "e.%d." % gen1))]
    free_at = mark_at("free.%s.%d" % (sid, gen1))
    check("terminal/*.log written during the close", any("/terminal/" in p for _, p, _ in tail),
          [p.rsplit("/", 2)[-2:] for _, p, _ in tail][:4])
    check("none of those writes lands after \"closed\" (their marked windows are judged by pass rule 1)",
          all(i < hi for i, _, _ in tail), [i for i, _, _ in tail if i > hi][:3])
    check("\"closed\" only after the last gen-1 mark and free.1", g1 and max(g1) < hi and free_at is not None
          and free_at < hi, (max(g1) if g1 else None, free_at, hi))
    leader_proof([a])
    a.stop()


try:
    {"probe": case_probe, "b1": case_b1, "b4": case_b4, "b4-noncap": case_b4_noncap, "b11": case_b11,
     "b2": case_b2, "b3": case_b3, "b5": case_b5, "b6": case_b6, "b7": case_b7, "b8": case_b8, "b9": case_b9,
     "b10": case_b10, "b12": case_b12,
     "c-unmarked": lambda: control("unmarked"), "c-rapid": lambda: control("rapid"),
     "c-image": lambda: control("image"), "c-pause": lambda: control("pause")}[CASE]()
except Exception as e:  # noqa: BLE001 - the harness records any driver failure as a failed assertion
    import traceback
    traceback.print_exc()
    check("driver ran to the end", False, repr(e))
json.dump({"case": CASE, "assertions": assertions}, open(OUT + "/case.json", "w"), indent=1)
sys.exit(0 if assertions and all(a["ok"] for a in assertions) else 1)
