#!/usr/bin/env python3
# Mock-endpoint verification for docs/ptc-contract.md. Runs inside the hardbench image (needs /opt/bench/adapters.py):
#   docker run --rm --network none --entrypoint python3 -v $PWD/docs/ptc-mock-probe.py:/probe.py:ro fuigo-hardbench:<cand-tag> /probe.py
# Verified 2026-09-11 against fuigo-hardbench:cand-ptc (binary sha256 9ba0bc4098f4bfd4ff74e9c1f6d67009e01a5433b6f3fe3c6c9bd7f105260b8f): ALL PASS.
"""Offline PTC probe (no provider calls): does headless Fuigo on the Responses backend, with
FUIGO_PROGRAMMATIC_TOOL_CALLING=1, send the programmatic_tool_calling tool + allowed_callers, execute the two
client read_file calls a paused program requests, return their outputs as function_call_output items with the
program `caller`, replay the program item (with fingerprint) and finish after exactly ONE more model round trip?
A second run with the flag off asserts the request carries no PTC keys.

Mock Responses endpoint pattern: fuigo_reasoning_probe2.py."""
import json, os, subprocess, sys, threading, http.server, socketserver, time, shutil
sys.path.insert(0, '/opt/bench')
import adapters

PROGRAM_CODE = ("const [a, b] = await Promise.all([tools.read_file({file_path: WORK + '/a.txt'}), tools.read_file({file_path: WORK + '/b.txt'})]);"
                " text(`${a}|${b}`);")
WORK = {'dir': '/tmp/ptc-work-on'}
FINGERPRINT = 'fp-opaque-round-trip-0123456789'
REQS = []
MODE = {'ptc': True}


def sse(events):
    out = []
    for n, e in enumerate(events):
        e = {**e, 'sequence_number': n}
        out.append(f"event: {e['type']}\ndata: {json.dumps(e)}\n\n")
    return ''.join(out).encode()


def base_resp(model, output, usage):
    return {'id': f'resp_{len(REQS)}', 'object': 'response', 'created_at': int(time.time()), 'status': 'completed',
            'model': model, 'output': output, 'usage': usage, 'parallel_tool_calls': True, 'store': False}


def message(mid, text):
    return {'type': 'message', 'id': mid, 'role': 'assistant', 'status': 'completed',
            'content': [{'type': 'output_text', 'text': text, 'annotations': []}]}


def message_events(msg, idx):
    text = msg['content'][0]['text']
    return [{'type': 'response.output_item.added', 'output_index': idx, 'item': {**msg, 'status': 'in_progress', 'content': []}},
            {'type': 'response.content_part.added', 'item_id': msg['id'], 'output_index': idx, 'content_index': 0, 'part': {'type': 'output_text', 'text': '', 'annotations': []}},
            {'type': 'response.output_text.delta', 'item_id': msg['id'], 'output_index': idx, 'content_index': 0, 'delta': text},
            {'type': 'response.output_text.done', 'item_id': msg['id'], 'output_index': idx, 'content_index': 0, 'text': text},
            {'type': 'response.content_part.done', 'item_id': msg['id'], 'output_index': idx, 'content_index': 0, 'part': msg['content'][0]},
            {'type': 'response.output_item.done', 'output_index': idx, 'item': msg}]


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *a):
        pass

    def send(self, code, ctype, data):
        try:
            self.send_response(code); self.send_header('Content-Type', ctype); self.send_header('Content-Length', str(len(data))); self.end_headers(); self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self):
        self.send(404, 'text/plain', b'')

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get('Content-Length', '0')))
        body = json.loads(raw or b'{}'); REQS.append(body)
        n = len(REQS); model = body.get('model')
        usage = {'input_tokens': 100, 'output_tokens': 10, 'total_tokens': 110, 'input_tokens_details': {'cached_tokens': 0}, 'output_tokens_details': {'reasoning_tokens': 5}}
        tools = {t.get('name'): t for t in body.get('tools') or [] if t.get('type') == 'function'}
        inp = body.get('input') or []
        has_program_replay = any(isinstance(i, dict) and i.get('type') == 'program' for i in inp)
        if MODE['ptc'] and n == 1 and 'read_file' in tools:
            # Turn 1: the model writes a program that needs two client read_file calls; the program pauses on them.
            props = (tools['read_file'].get('parameters') or {}).get('properties') or {}
            key = 'file_path' if 'file_path' in props else next((k for k, v in props.items() if v.get('type') == 'string'), 'file_path')
            prog = {'type': 'program', 'id': 'prog_item_1', 'call_id': 'prog_1', 'code': PROGRAM_CODE, 'fingerprint': FINGERPRINT}
            caller = {'type': 'program', 'caller_id': 'prog_1'}
            fcs = [{'type': 'function_call', 'id': f'fc_{c}', 'call_id': f'call_{c}', 'name': 'read_file',
                    'arguments': json.dumps({key: f"{WORK['dir']}/{c}.txt"}), 'status': 'completed', 'caller': caller} for c in ('a', 'b')]
            r1 = {'type': 'reasoning', 'id': 'rs_1', 'summary': [], 'encrypted_content': 'gAAAAAenc_1'}
            out = [r1, prog, *fcs]
            resp = base_resp(model, out, usage)
            ev = [{'type': 'response.created', 'response': {**resp, 'status': 'in_progress', 'output': []}},
                  {'type': 'response.output_item.added', 'output_index': 0, 'item': {'type': 'reasoning', 'id': 'rs_1', 'summary': []}},
                  {'type': 'response.output_item.done', 'output_index': 0, 'item': r1},
                  {'type': 'response.output_item.added', 'output_index': 1, 'item': {**prog, 'code': ''}},
                  {'type': 'response.output_item.done', 'output_index': 1, 'item': prog}]
            for idx, fc in enumerate(fcs, start=2):
                ev += [{'type': 'response.output_item.added', 'output_index': idx, 'item': {**fc, 'arguments': '', 'status': 'in_progress'}},
                       {'type': 'response.function_call_arguments.delta', 'item_id': fc['id'], 'output_index': idx, 'delta': fc['arguments']},
                       {'type': 'response.function_call_arguments.done', 'item_id': fc['id'], 'output_index': idx, 'arguments': fc['arguments']},
                       {'type': 'response.output_item.done', 'output_index': idx, 'item': fc}]
            ev.append({'type': 'response.completed', 'response': resp})
        elif MODE['ptc'] and n == 2 and has_program_replay:
            # Resume: the runtime finished the program with the returned outputs; final message follows.
            outs = {i.get('call_id'): i.get('output') for i in inp if isinstance(i, dict) and i.get('type') == 'function_call_output'}
            result = f"{outs.get('call_a')}|{outs.get('call_b')}"
            po = {'type': 'program_output', 'id': 'po_item_1', 'call_id': 'prog_1', 'result': result, 'status': 'completed'}
            msg = message('msg_final', 'done: ' + result)
            resp = base_resp(model, [po, msg], usage)
            ev = [{'type': 'response.created', 'response': {**resp, 'status': 'in_progress', 'output': []}},
                  {'type': 'response.output_item.added', 'output_index': 0, 'item': po},
                  {'type': 'response.output_item.done', 'output_index': 0, 'item': po},
                  *message_events(msg, 1),
                  {'type': 'response.completed', 'response': resp}]
        else:
            msg = message(f'msg_{n}', 'done')
            resp = base_resp(model, [msg], usage)
            ev = [{'type': 'response.created', 'response': {**resp, 'status': 'in_progress', 'output': []}},
                  *message_events(msg, 0),
                  {'type': 'response.completed', 'response': resp}]
        self.send(200, 'text/event-stream', sse(ev))


class S(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


srv = S(('127.0.0.1', 8765), H); threading.Thread(target=srv.serve_forever, daemon=True).start()


def run(label, ptc_on):
    MODE['ptc'] = ptc_on
    REQS.clear()
    home = f'/tmp/ptc-home-{label}'; work = f'/tmp/ptc-work-{label}'; WORK['dir'] = work
    shutil.rmtree(home, ignore_errors=True); shutil.rmtree(work, ignore_errors=True)
    os.makedirs(home, exist_ok=True); os.makedirs(work, exist_ok=True)
    open(f'{work}/a.txt', 'w').write('hello-from-a\n'); open(f'{work}/b.txt', 'w').write('world-from-b\n')
    subprocess.run(['git', 'init', '-q', work])
    env = adapters.configure('fuigo', home, 'probe-token', profile='openai', presentation='adaptive')
    if ptc_on:
        env['FUIGO_PROGRAMMATIC_TOOL_CALLING'] = '1'
    cmd = adapters.command('fuigo', 'Read a.txt and b.txt, then say done.', profile='openai', max_turns=4)
    r = subprocess.run(cmd, env={**os.environ, **env}, cwd=work, capture_output=True, text=True, timeout=180)
    time.sleep(2)
    print(f'=== run {label} (ptc_on={ptc_on}) exit={r.returncode} end_event={"\"type\":\"end\"" in r.stdout} requests={len(REQS)}')
    print('   stderr_tail:', r.stderr[-300:].replace('\n', ' '))
    return r, list(REQS)


def tool_summary(b):
    return [(t.get('type'), t.get('name'), t.get('allowed_callers')) for t in b.get('tools') or []]


failures = []
def check(cond, msg):
    print(('   PASS ' if cond else '   FAIL ') + msg)
    if not cond:
        failures.append(msg)

# ---- run A: flag on ---------------------------------------------------------------------------
rA, reqsA = run('on', True)
stdoutA = rA.stdout
check(len(reqsA) == 2, f'exactly two model requests (one turn + one resume round trip), got {len(reqsA)}')
if reqsA:
    t1 = reqsA[0].get('tools') or []
    check(any(t.get('type') == 'programmatic_tool_calling' for t in t1), 'request 1 carries the programmatic_tool_calling tool')
    fn = [t for t in t1 if t.get('type') == 'function']
    check(fn and all(t.get('allowed_callers') == ['direct', 'programmatic'] for t in fn), f'every function tool has allowed_callers [direct, programmatic] ({len(fn)} tools)')
    check(not any(t.get('type') == 'custom_tool_call' for t in reqsA[0].get('input') or []), 'no carrier leaks into request 1')
if len(reqsA) >= 2:
    inp = reqsA[1].get('input') or []
    kinds = [(i.get('type') or 'message') for i in inp if isinstance(i, dict)]
    print('   request 2 input kinds:', kinds)
    progs = [i for i in inp if i.get('type') == 'program']
    check(len(progs) == 1 and progs[0].get('fingerprint') == FINGERPRINT and progs[0].get('call_id') == 'prog_1' and progs[0].get('code') == PROGRAM_CODE, 'program item replayed with its fingerprint, call_id and code')
    check(all(k not in ('custom_tool_call',) for k in kinds) and '__fuigo_ptc' not in json.dumps(inp), 'no carrier leaks into the replay')
    fcs = {i['call_id']: i for i in inp if i.get('type') == 'function_call'}
    outs = {i['call_id']: i for i in inp if i.get('type') == 'function_call_output'}
    caller = {'type': 'program', 'caller_id': 'prog_1'}
    check(set(fcs) >= {'call_a', 'call_b'} and all(fcs[c].get('caller') == caller for c in ('call_a', 'call_b')), 'both program function_calls replayed with caller=program')
    check(set(outs) >= {'call_a', 'call_b'} and all(outs[c].get('caller') == caller for c in ('call_a', 'call_b')), 'both function_call_outputs carry caller=program')
    oa = json.dumps(outs.get('call_a', {}).get('output', '')); ob = json.dumps(outs.get('call_b', {}).get('output', ''))
    print('   read_file schema:', json.dumps((next((t for t in reqsA[0].get('tools', []) if t.get('name') == 'read_file'), {}).get('parameters') or {}).get('properties'))[:400])
    print('   output call_a:', oa[:300]); print('   output call_b:', ob[:300])
    kinds_seen = {}
    for line in stdoutA.splitlines():
        try:
            ev = json.loads(line)
        except Exception:
            continue
        k = ev.get('type') or ev.get('event') or '?'
        sub = (ev.get('message') or {}).get('content') if isinstance(ev.get('message'), dict) else None
        if isinstance(sub, list):
            for c in sub:
                if isinstance(c, dict):
                    kinds_seen[f"{k}/{c.get('type')}:{c.get('name', '')}"] = kinds_seen.get(f"{k}/{c.get('type')}:{c.get('name', '')}", 0) + 1
        else:
            kinds_seen[k] = kinds_seen.get(k, 0) + 1
    print('   headless event kinds:', json.dumps(kinds_seen))
    check('hello-from-a' in oa and 'world-from-b' in ob, 'both read_file calls really executed (file contents returned)')
    order = [k for k in kinds if k in ('reasoning', 'program', 'function_call', 'function_call_output')]
    check(order[:4] == ['reasoning', 'program', 'function_call', 'function_call'] if 'reasoning' in order else order[:3] == ['program', 'function_call', 'function_call'], f'replay order keeps program before its calls: {order}')
check('done: L1: hello-from-a|L1: world-from-b' in stdoutA, 'final assistant message (built from the program result) reached the headless output')
check('programmatic_tool_calling' in stdoutA, 'program surfaced to the client (tool_use named programmatic_tool_calling)')
tool_calls = sum(1 for line in stdoutA.splitlines() if line.startswith('{') and '"tool_call"' in line and '"tool_call_update"' not in line)
check(tool_calls >= 4, f'headless output shows the program, both read_file calls and the program output as tool calls ({tool_calls} tool_call events)')

# ---- run B: flag off --------------------------------------------------------------------------
rB, reqsB = run('off', False)
if reqsB:
    check(all(t.get('type') != 'programmatic_tool_calling' for t in reqsB[0].get('tools') or []), 'flag off: no programmatic_tool_calling tool')
    check('allowed_callers' not in json.dumps(reqsB[0]), 'flag off: no allowed_callers anywhere in the request')
    check('caller' not in json.dumps(reqsB[0].get('input')), 'flag off: no caller on input items')
else:
    check(False, 'flag off: fuigo sent a request')

json.dump({'on': reqsA, 'off': reqsB}, open('/tmp/ptc-requests.json', 'w'))
print('=== RESULT:', 'ALL PASS' if not failures else f'{len(failures)} FAILED: {failures}')
sys.exit(1 if failures else 0)
