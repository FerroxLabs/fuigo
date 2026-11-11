#!/usr/bin/env python3
"""Full-path FA6/FA7/FA8/FA10/FA13/FA14: real ACP process, loopback refusal, no live service.
Run inside an isolated network namespace/container. Retain wire frames + request
metadata, never request headers. The corpus records source-rendered responses.
"""
from collections import Counter
import runpy
import argparse
import hashlib
import http.server
import json
import os
from pathlib import Path
import selectors
import subprocess
import threading
import time

parser = argparse.ArgumentParser()
parser.add_argument('--binary', required=True)
parser.add_argument('--evidence', required=True)
parser.add_argument('--cases', default='14,16,status-hold,final-matrix,table')
parser.add_argument('--resume', action='store_true')
args = parser.parse_args()
out = Path(args.evidence).resolve()
out.mkdir(parents=True, exist_ok=True)
corpus = Path(__file__).resolve().parents[2] / 'crates/codegen/fuigo-sampling-types/tests/fixtures/flux-fixtures'
binary = Path(args.binary).resolve()
(out / 'binary.sha256').write_text(hashlib.sha256(binary.read_bytes()).hexdigest() + '\n')
failures = []
results = []
final_codes = ["free_cap_reached", "free_tier_exhausted", "builder_auto_bump_eligible", "cap_reached", "key_revoked", "entitlement_missing", "subscription_account_mismatch", "key_not_found", "authorization_state_unknown", "key_budget_reached", "account_monthly_budget_exhausted", "key_lifetime_cap_exhausted", "credit_exhausted", "credit_hold", "credit_unresolved", "monthly_cap", "daily_cap", "hourly_burn_limit"]
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
import busyloop_data as bd
ref = bd.reference()
rows = bd.load_rows(str(corpus.parent / 'busyloop_expected.tsv'))
assert hashlib.sha256((corpus.parent / 'busyloop_expected.tsv').read_bytes()).hexdigest() == '691fb460e66023bd7c2dd4699ed6ba41d99a2b6b09ae3d8e03015e6930e6c035'
fx = bd.fixture_leaves(str(corpus))
specimens = {r['id']: fx[r['id']] if r['status']=='fixture' else {'status':int(r['status']),'headers':json.loads(r['headers']),'body':json.loads(r['body'])} for r in rows}
expected_rows = {r['id']: ref['upstream_by_row'][r['id']] for r in rows if r['endpoint']=='resp'}
def leaf(case):
    return specimens[case if case in specimens else case+'.resp']
cases = []
for selected in args.cases.split(','):
    if selected == 'final-matrix':
        for code in final_codes:
            for status, field in [(429, 'state'), (402, 'error'), (401, 'header')]:
                v = {'status':status, 'body':{'error':{'message':'terminal fixture refusal'}}, 'headers':{}}
                if field == 'header':
                    v['headers']['x-flux-hold-reason'] = code
                else:
                    v['body']['error'][field] = code
                want = {'http_status':status, 'hold_reason' if field == 'header' else 'code' if field == 'error' else 'state':code}
                want = ref['final_matrix_upstream'][f'{code}-{status}']
                cases.append((f'final-{code}-{status}', v, want, True))
    elif selected == 'table':
        for row, want in expected_rows.items():
            v = leaf(row)
            final = ref['terminal_by_row'][row]
            cases.append((row.replace('/', '-'), v, want, final))
    elif selected in ('p1-state', 'p1-type'):
        field = selected.split('-')[1]
        echo = 'xk3-9f2a7c1e0b4d6a8f3e5c7b9d1f0a2c4e6b8d'
        cases.append((selected, {'status':429,'headers':{},'body':{'error':{field:echo,'message':'refusal'}}},
                      {'http_status':429,field:'other','codes':['other']}, True))
    elif selected == 'status-hold':
        cases.append((selected, {'status':402,'headers':{'x-flux-hold-reason':'concurrency','retry-after':'2'},'body':{'error':{'message':'temporary hold'}}}, {'http_status':402,'hold_reason':'concurrency','retry_after_s':2}, True))
    else:
        cases.append((selected, leaf(selected), expected_rows[selected + '.resp'], selected != '05'))
for case, specimen, expected, final in cases:
    # A4 adds the allowlisted type for a Flux 401 whose envelope has no type.
    # Keep the frozen reference/fixtures intact and require this wire delta here.
    if specimen['status'] == 401:
        expected = {'type': 'authentication_error', **expected}
    body = json.dumps(specimen['body'], separators=(',', ':')).encode()
    requests = []
    class Stub(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            payload = self.rfile.read(int(self.headers.get('Content-Length', 0)))
            data = json.loads(payload)
            requests.append({'method': 'POST', 'path': self.path, 'time_ns': time.monotonic_ns(),
                             'model': data.get('model'), 'body_sha256': hashlib.sha256(payload).hexdigest()})
            self.send_response(specimen['status'])
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            for k, v in specimen.get('headers', {}).items():
                if k.lower() in ('retry-after', 'retry-after-ms', 'x-flux-hold-reason'):
                    self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)
        def do_GET(self):
            b = b'{"data":[]}'
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(b)))
            self.end_headers()
            self.wfile.write(b)
        def log_message(self, *_):
            pass
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Stub)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    home = out / ('scratch-' + case)
    home.mkdir(exist_ok=True)
    env = {'PATH': os.environ['PATH'], 'HOME': str(home), 'FUIGO_HOME': str(home / 'fuigo'),
           'FUIGO_API_KEY': 'fuigo-fixture-dummy-0000', 'FUIGO_MAX_RETRIES':'3' if final else '1', 'FUIGO_TURN_TRANSIENT_RETRY':'true' if final else 'false',
           'FUIGO_API_BASE_URL': f'http://127.0.0.1:{server.server_port}/v1', 'NO_COLOR': '1'}
    frames = []
    terminal = None
    session_id = None
    before_resume = None
    resume_complete = False
    command = [str(binary), '--permission-mode', 'default', '--no-memory', 'agent', '--no-leader', '-m', 'flux-auto', 'stdio']
    with (out / (case + '-stderr.log')).open('w') as err:
        p = subprocess.Popen(command, env=env, cwd=home, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=err, bufsize=0)
        def send(obj):
            frames.append({'direction': 'stdin', 'frame': obj})
            p.stdin.write((json.dumps(obj) + '\n').encode())
            p.stdin.flush()
        send({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {'protocolVersion': 1, 'clientCapabilities': {}, 'clientInfo': {'name': 'fuigo-refusal-test', 'version': '1'}}})
        sel = selectors.DefaultSelector()
        sel.register(p.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + 480
        try:
            while time.monotonic() < deadline:
                if not sel.select(1):
                    if p.poll() is not None:
                        raise RuntimeError('engine exited')
                    continue
                line = p.stdout.readline()
                if not line:
                    raise RuntimeError('engine EOF')
                m = json.loads(line)
                frames.append({'direction': 'stdout', 'time_ns':time.monotonic_ns(), 'frame': m})
                if m.get('id') == 1 and 'result' in m:
                    send({'jsonrpc': '2.0', 'id': 2, 'method': 'session/new', 'params': {'cwd': str(home), 'mcpServers': []}})
                elif m.get('id') == 2 and 'result' in m:
                    session_id = m['result']['sessionId']
                    send({'jsonrpc': '2.0', 'id': 3, 'method': 'session/prompt', 'params': {'sessionId': m['result']['sessionId'], 'prompt': [{'type': 'text', 'text': 'hi'}]}})
                elif m.get('id') == 3 and ('error' in m or 'result' in m):
                    terminal = m
                    if args.resume and final:
                        before_resume = len(requests)
                        send({'jsonrpc':'2.0', 'id':4, 'method':'session/load', 'params':{'sessionId':session_id, 'cwd':str(home), 'mcpServers':[]}})
                    else:
                        break
                elif m.get('id') == 4:
                    assert 'result' in m, m
                    resume_complete = True
                    # Observe actual idle after load, while the real process remains alive.
                    time.sleep(2)
                    break
                elif 'id' in m and 'method' in m:
                    send({'jsonrpc': '2.0', 'id': m['id'], 'result': {'outcome': {'outcome': 'cancelled'}}})
            if terminal is None:
                raise TimeoutError('prompt response deadline')
        except Exception as e:
            failures.append(f'{case}: {e}')
        finally:
            p.terminate()
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()
            server.shutdown()
            server.server_close()
            sel.close()
    (out / (case + '-frames.jsonl')).write_text(''.join(json.dumps(f) + '\n' for f in frames))
    (out / (case + '-requests.jsonl')).write_text(''.join(json.dumps(r) + '\n' for r in requests))
    def objects(v):
        if isinstance(v, dict):
            yield v
            for x in v.values():
                yield from objects(x)
        elif isinstance(v, list):
            for x in v:
                yield from objects(x)
    states = [v for f in frames if f['direction'] == 'stdout' for v in objects(f['frame'])
              if v.get('type') in ('retrying', 'failed', 'exhausted') and ('upstream' in v or 'attempt' in v or 'error_type' in v)]
    retrying = [s for s in states if s['type'] == 'retrying']
    try:
        assert terminal and 'error' in terminal, terminal
        upstream = terminal['error']['data']['upstream']
        assert upstream['http_status'] == specimen['status'], upstream
        assert upstream == expected, (upstream, expected)
        if final:
            assert len(requests) <= 2, requests
            assert sum(r['model'] == 'flux-fast' for r in requests) <= 1, requests
            terminal_time = next(f['time_ns'] for f in frames if f['direction']=='stdout' and f['frame'].get('id')==3 and ('error' in f['frame'] or 'result' in f['frame']))
            assert not any(r['time_ns'] > terminal_time for r in requests), requests
            assert sum(r['model'] == 'flux-auto' for r in requests) == 1, requests
            assert not retrying, states
            if args.resume:
                assert resume_complete and len(requests) == before_resume, requests
        if case.startswith('p1-'):
            field = case.split('-')[1]
            assert states, 'missing RetryState'
            for state in states:
                assert state['upstream'][field] == 'other', state
            persisted = []
            for file in (home / 'fuigo').rglob('*.jsonl'):
                for line in file.read_text().splitlines():
                    try: value = json.loads(line)
                    except ValueError: continue
                    for obj in objects(value):
                        if isinstance(obj.get('upstream'), dict) and field in obj['upstream']:
                            persisted.append(obj['upstream'])
            assert persisted, 'no persisted upstream facts in session'
            assert all(u[field] == 'other' for u in persisted), persisted
        if specimen['status'] == 401:
            # FA6: a Flux-routed static-key 401 is -32000 with typed upstream, and is never retried or refreshed.
            # (This harness always runs a Flux config; the non-Flux -32603 parent mapping is covered by the
            # r3_fa6_static_401_flux_minus_32000_non_flux_parent unit test.)
            assert terminal['error']['code'] == -32000, terminal
            assert terminal['error']['message'] == 'Internal error', terminal
            assert upstream['http_status'] == 401, upstream
            if case == '14':
                assert upstream['type'] == 'authentication_error', upstream
                # exactly one main-model POST (no retry, no refresh); the only other POST is the flux-fast side call
                assert sum(r['model'] == 'flux-auto' for r in requests) == 1, requests
        results.append({'case':case, 'final':final, 'max_attempts':int(env['FUIGO_MAX_RETRIES']),
                        'shell_transient_retry':env['FUIGO_TURN_TRANSIENT_RETRY']=='true',
                        'posts':len(requests), 'main_posts':sum(r['model']=='flux-auto' for r in requests),
                        'side_posts':sum(r['model']=='flux-fast' for r in requests),
                        'retrying':len(retrying), 'resumed':resume_complete, 'upstream':upstream})
        print(f'PASS case {case}: POSTs={len(requests)}, retrying={len(retrying)}', flush=True)
    except (AssertionError, KeyError) as e:
        failures.append(f'{case}: {e}')
        print(f'FAIL case {case}: {e}', flush=True)
(out / 'result.json').write_text(json.dumps({'command': command, 'cases': args.cases, 'failures': failures, 'results':results}, indent=2) + '\n')
raise SystemExit(bool(failures))
