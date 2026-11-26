#!/usr/bin/env python3
"""Scripted OpenAI-compatible stub for the L0 ACP probe and the extension integration test. No network egress, no keys.
POST /admin/queue  body: [turn,...]; turn = {"text": str} | {"tool_calls": [{"name": str, "args": {...}}]}
Inference requests pop one turn; empty queue -> text "ok". Every request body is appended to $MOCK_LOG."""
import json, os, sys, threading, time, http.server, socketserver
Q = []; LOCK = threading.Lock(); LOG = os.environ.get('MOCK_LOG', 'mock-requests.jsonl'); N = [0]

def log(path, body):
    with open(LOG, 'a') as f:
        f.write(json.dumps({'t': time.time(), 'path': path, 'body': body}) + '\n')

def chat_sse(turn, model):
    cid = f'chatcmpl-{N[0]}'
    def ch(delta, fin=None):
        return 'data: ' + json.dumps({'id': cid, 'object': 'chat.completion.chunk', 'created': int(time.time()), 'model': model,
                                      'choices': [{'index': 0, 'delta': delta, 'finish_reason': fin}]}) + '\n\n'
    out = [ch({'role': 'assistant', 'content': ''})]
    if 'tool_calls' in turn:
        for i, tc in enumerate(turn['tool_calls']):
            out.append(ch({'tool_calls': [{'index': i, 'id': f'call_{N[0]}_{i}', 'type': 'function',
                                           'function': {'name': tc['name'], 'arguments': json.dumps(tc['args'])}}]}))
        out.append(ch({}, 'tool_calls'))
    else:
        out.append(ch({'content': turn.get('text', 'ok')}))
        out.append(ch({}, 'stop'))
    out.append('data: ' + json.dumps({'id': cid, 'object': 'chat.completion.chunk', 'created': int(time.time()), 'model': model, 'choices': [],
                                      'usage': {'prompt_tokens': 10, 'completion_tokens': 5, 'total_tokens': 15}}) + '\n\n')
    out.append('data: [DONE]\n\n')
    return ''.join(out).encode()

class H(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def log_message(self, *a): pass
    def send(self, code, ctype, data):
        self.send_response(code); self.send_header('Content-Type', ctype); self.send_header('Content-Length', str(len(data))); self.end_headers(); self.wfile.write(data)
    def body(self):
        n = int(self.headers.get('Content-Length') or 0); raw = self.rfile.read(n) if n else b''
        try: return json.loads(raw) if raw else None
        except Exception: return raw.decode('utf-8', 'replace')
    def do_GET(self):
        p = self.path.split('?')[0]; log('GET ' + p, None)
        if p.endswith('/models'):
            return self.send(200, 'application/json', json.dumps({'object': 'list', 'data': [{'id': 'mock-model', 'object': 'model', 'created': 1, 'owned_by': 'test'}]}).encode())
        if p.endswith('/settings'):
            return self.send(200, 'application/json', b'{}')
        self.send(404, 'application/json', b'{}')
    def do_PUT(self):
        b = self.body(); log('PUT ' + self.path, b); self.send(200, 'application/json', b'{}')
    def do_POST(self):
        p = self.path.split('?')[0]; b = self.body()
        if p == '/admin/queue':
            with LOCK: Q[:] = b  # replace: a cancelled turn must not leak its leftover turns into the next prompt
            return self.send(200, 'application/json', b'{}')
        log('POST ' + p, b)
        if p.endswith('/chat/completions'):
            model = (b or {}).get('model', 'mock-model') if isinstance(b, dict) else 'mock-model'
            if isinstance(b, dict) and not b.get('stream'):
                # non-streaming side calls (titles, summaries)
                return self.send(200, 'application/json', json.dumps({'id': 'x', 'object': 'chat.completion', 'model': model,
                    'choices': [{'index': 0, 'message': {'role': 'assistant', 'content': 'title'}, 'finish_reason': 'stop'}],
                    'usage': {'prompt_tokens': 1, 'completion_tokens': 1, 'total_tokens': 2}}).encode())
            with LOCK:
                N[0] += 1; turn = Q.pop(0) if Q else {'text': 'ok'}
            return self.send(200, 'text/event-stream', chat_sse(turn, model))
        self.send(404, 'application/json', json.dumps({'error': {'message': 'mock: unsupported ' + p}}).encode())

class S(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True; allow_reuse_address = True

if __name__ == '__main__':
    s = S(('127.0.0.1', int(sys.argv[1])), H); print('mock up', flush=True); s.serve_forever()
