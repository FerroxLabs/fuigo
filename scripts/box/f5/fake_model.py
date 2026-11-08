"""Scripted fake model server for B-F5 (loopback only, no key). OpenAI Chat Completions SSE, plus /models.

usage: fake_model.py <port> <script.jsonl> <evidence dir>
The driver appends one JSON step per line to <script.jsonl>; each agent request (a chat request that carries tools)
takes the next unserved step. A step is {"text": "..."} or {"tool": "<name>", "args": {...}}, optionally with
"gate": "<path>" (the final chunk waits until the file exists, at most 120 s: a turn held mid-stream). With no step
left the reply is plain text. Requests without tools (titles, summaries) get a short text. Every request is logged to
<evidence>/model-requests.jsonl (summary) and <evidence>/model-req.<n>.json (full body).
"""
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT, SCRIPT, OUT = int(sys.argv[1]), sys.argv[2], sys.argv[3]
lock = threading.Lock()
state = {"n": 0, "served": 0}
summary = open(os.path.join(OUT, "model-requests.jsonl"), "a", buffering=1)
MODELS = {"object": "list", "data": [{"id": "test-model", "object": "model", "created": 1234567890,
                                      "owned_by": "test"}]}


def steps():
    try:
        return [json.loads(l) for l in open(SCRIPT) if l.strip()]
    except OSError:
        return []


def chunk(delta, finish=None, usage=False):
    c = {"id": "chatcmpl-f5", "object": "chat.completion.chunk", "created": 1234567890, "model": "test-model",
         "choices": [{"index": 0, "delta": delta, "finish_reason": finish}]}
    if usage:
        c["usage"] = {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30}
    return c


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _json(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        with lock:
            state["n"] += 1
            summary.write(json.dumps({"t": round(time.time(), 3), "n": state["n"], "method": "GET",
                                      "path": self.path}) + "\n")
        if self.path.rstrip("/").endswith("/models"):
            return self._json(200, MODELS)
        self._json(404, {"error": {"message": "not served by the F5 fake model"}})

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("content-length") or 0))
        try:
            req = json.loads(body)
        except ValueError:
            req = {}
        tools = [((t.get("function") or {}).get("name") or t.get("name")) for t in req.get("tools") or []]
        with lock:
            state["n"] += 1
            n = state["n"]
            step = None
            if tools and "chat/completions" in self.path:
                s = steps()
                if state["served"] < len(s):
                    step = s[state["served"]]
                    state["served"] += 1
                    step = dict(step, index=state["served"])
            open(os.path.join(OUT, "model-req.%03d.json" % n), "w").write(json.dumps(req, indent=1))
            summary.write(json.dumps({"t": round(time.time(), 3), "n": n, "method": "POST", "path": self.path,
                                      "tools": tools, "messages": len(req.get("messages") or []),
                                      "step": step}) + "\n")
        if "chat/completions" not in self.path:
            return self._json(404, {"error": {"message": "only chat/completions is served"}})
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.send_header("connection", "close")
        self.end_headers()
        if step is None:
            step = {"text": "F5 FAKE MODEL REPLY" if tools else "F5 title"}
        events = [chunk({"role": "assistant", "content": ""})]
        if "tool" in step:
            events.append(chunk({"tool_calls": [{"index": 0, "id": "call_f5_%d" % n, "type": "function",
                                                 "function": {"name": step["tool"],
                                                              "arguments": json.dumps(step.get("args", {}))}}]}))
            final = chunk({}, "tool_calls", usage=True)
        else:
            for w in step["text"].split(" "):
                events.append(chunk({"content": w + " "}))
            final = chunk({}, "stop", usage=True)
        try:
            for e in events:
                self.wfile.write(("data: %s\n\n" % json.dumps(e)).encode())
                self.wfile.flush()
            gate = step.get("gate")
            if gate:
                end = time.time() + 120
                while not os.path.exists(gate) and time.time() < end:
                    time.sleep(0.05)
            self.wfile.write(("data: %s\n\ndata: [DONE]\n\n" % json.dumps(final)).encode())
            self.wfile.flush()
        except OSError:
            pass
        self.close_connection = True


ThreadingHTTPServer.daemon_threads = True
srv = ThreadingHTTPServer(("127.0.0.1", PORT), H)
open(os.path.join(OUT, "fake-model.ready"), "w").write(str(os.getpid()))
srv.serve_forever()
