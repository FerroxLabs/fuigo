#!/usr/bin/env python3
"""W1-W25: real ACP session actor + real sampler, loopback-only stub POST log.
The Rust parity test also executes the deliberate violation events in these exact
traces. Here those forbidden continuations must never reach the stub.
"""
import argparse,datetime,hashlib,http.server,json,os,runpy,selectors,socket,socketserver,ssl,subprocess,threading,time
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--binary',required=True);p.add_argument('--evidence',required=True);p.add_argument('--only',default='');a=p.parse_args()
root=Path(__file__).resolve().parents[2]/'crates/codegen/fuigo-sampling-types/tests/fixtures'
assert hashlib.sha256((root/'busyloop_expected.tsv').read_bytes()).hexdigest()=='691fb460e66023bd7c2dd4699ed6ba41d99a2b6b09ae3d8e03015e6930e6c035'
import sys;sys.path.insert(0,str(Path(__file__).resolve().parent));import busyloop_data as bd
ref=bd.reference()
fx=bd.fixture_leaves(str(root/'flux-fixtures'));rows=bd.load_rows(str(root/'busyloop_expected.tsv'))
inputs={r['id']:fx[r['id']] if r['status']=='fixture' else {'status':int(r['status']),'headers':json.loads(r['headers']),'body':json.loads(r['body'])} for r in rows}
out=Path(a.evidence).resolve();out.mkdir(parents=True,exist_ok=True);binary=Path(a.binary).resolve()
(out/'binary.sha256').write_text(hashlib.sha256(binary.read_bytes()).hexdigest()+'\n')
# Synthetic, test-only CA and external refresher; no live credential or service.
ca=out/'ca';ca.mkdir(exist_ok=True)
def openssl(*args):
 subprocess.run(['openssl',*args],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
openssl('req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(ca/'ca-key.pem'),'-out',str(ca/'cert.pem'),'-days','1','-subj','/CN=Busyloop Test CA','-addext','basicConstraints=critical,CA:TRUE')
openssl('req','-new','-newkey','rsa:2048','-nodes','-keyout',str(ca/'key.pem'),'-out',str(ca/'server.csr'),'-subj','/CN=api.fluxrouter.ai')
(ca/'server.ext').write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:api.fluxrouter.ai\n')
openssl('x509','-req','-in',str(ca/'server.csr'),'-CA',str(ca/'cert.pem'),'-CAkey',str(ca/'ca-key.pem'),'-set_serial','1','-out',str(ca/'server.pem'),'-days','1','-extfile',str(ca/'server.ext'))
ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(ca/'server.pem',ca/'key.pem')

def success():
 response={'id':'resp_test','object':'response','created_at':1234567890,'model':'flux-auto','status':'completed','output':[{'type':'message','id':'msg_test','role':'assistant','status':'completed','content':[{'type':'output_text','text':'done','annotations':[]}]}],'usage':{'input_tokens':10,'output_tokens':5,'total_tokens':15,'input_tokens_details':{'cached_tokens':0},'output_tokens_details':{'reasoning_tokens':0}}}
 events=[{'type':'response.created','sequence_number':0,'response':dict(response,status='in_progress',output=[])},{'type':'response.output_text.delta','sequence_number':1,'item_id':'msg_test','output_index':0,'content_index':0,'delta':'done'},{'type':'response.completed','sequence_number':2,'response':response}]
 return ''.join('data: '+json.dumps(e)+'\n\n' for e in events).encode()
failures=[]
for name,refreshable,events,expected in ref['witness_traces']:
 wid=name.split()[0]
 if a.only and wid not in a.only.split(','):continue
 home=out/wid;home.mkdir(exist_ok=True);fh=home/'fuigo';fh.mkdir(exist_ok=True)
 (fh/'config.toml').write_text('[session]\ntitle_policy = "'+('model' if wid=='W12' else 'local')+'"\n')
 refreshlog=home/'refreshes.log';refresher=home/'refresh.sh'
 refreshlog.write_text('')
 refresher.write_text('#!/bin/sh\necho refresh >> "'+str(refreshlog)+'"\nprintf fixture-refreshed-session-token\n');refresher.chmod(0o700)
 now=datetime.datetime.now(datetime.timezone.utc)
 if refreshable:
  (fh/'auth.json').write_text(json.dumps({'https://accounts.x.ai/sign-in':{'key':'fixture-session-token','auth_mode':'external','create_time':(now-datetime.timedelta(hours=1)).isoformat(),'user_id':'fixture-user','email':'fixture@example.invalid','expires_at':(now+datetime.timedelta(hours=1)).isoformat()}}))
 main_responses=[e[2] for e in events if e[0]=='r' and e[1]!='side']
 if wid=='W19':main_responses.append('01.resp')
 requests=[];frames=[];main_count=0;side_seen=threading.Event()
 class Stub(http.server.BaseHTTPRequestHandler):
  def do_POST(self):
   global main_count
   payload=self.rfile.read(int(self.headers.get('Content-Length',0)));data=json.loads(payload)
   requests.append({'path':self.path,'model':data.get('model'),'body_sha256':hashlib.sha256(payload).hexdigest(),'time_ns':time.monotonic_ns()})
   if data.get('model')=='flux-fast':
    side_seen.set();rid='16.resp'
   else:
    if wid=='W12':assert side_seen.wait(5), 'side request must precede W12 main refusal'
    rid=main_responses[min(main_count,len(main_responses)-1)];main_count+=1
   if rid=='ok':status=200;body=success();headers={'content-type':'text/event-stream'}
   else:
    v=inputs[rid];status=v['status'];body=json.dumps(v.get('body')).encode();headers={'content-type':'application/json',**(v.get('headers') or {})}
   self.send_response(status)
   for k,v in headers.items():
    if k.lower() not in ('content-length','transfer-encoding'):self.send_header(k,v)
   self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
  def do_GET(self):
   body=json.dumps({'data':[{'id':model,'object':'model','created':1234567890,'owned_by':'test','apiBackend':'responses'} for model in ['flux-auto','flux-fast']]}).encode()
   self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
  def log_message(self,*_):pass
 server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Stub);threading.Thread(target=server.serve_forever,daemon=True).start()
 class Front(socketserver.BaseRequestHandler):
  def handle(self):
   data=b''
   while not data.endswith(b'\r\n\r\n'):
    b=self.request.recv(1)
    if not b:return
    data+=b
   if not data.startswith(b'CONNECT api.fluxrouter.ai:443 '):return
   self.request.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
   try:client=ctx.wrap_socket(self.request,server_side=True)
   except ssl.SSLError:return
   upstream=socket.create_connection(server.server_address)
   def forward(src,dst):
    try:
     while chunk:=src.recv(65536):dst.sendall(chunk)
    except OSError:pass
    finally:
     try:dst.shutdown(socket.SHUT_WR)
     except OSError:pass
   t=threading.Thread(target=forward,args=(client,upstream),daemon=True);t.start();forward(upstream,client);t.join(timeout=2);upstream.close();client.close()
 class Proxy(socketserver.ThreadingTCPServer):allow_reuse_address=True;daemon_threads=True
 proxy=Proxy(('127.0.0.1',0),Front);threading.Thread(target=proxy.serve_forever,daemon=True).start()
 env={'PATH':os.environ['PATH'],'HOME':str(home),'FUIGO_HOME':str(fh),'NO_COLOR':'1','FUIGO_TELEMETRY_ENABLED':'false','FUIGO_FEEDBACK_ENABLED':'false','FUIGO_TURN_SUMMARY':'false','FUIGO_SESSION_RECAP':'false','FUIGO_MAX_RETRIES':'3' if wid=='W18' else '2','FUIGO_TURN_TRANSIENT_RETRY':'true'}
 if refreshable:
  env.update(FUIGO_API_BASE_URL='https://api.fluxrouter.ai/v1',FUIGO_CLI_CHAT_PROXY_BASE_URL='https://api.fluxrouter.ai/v1',FUIGO_MODELS_BASE_URL='https://api.fluxrouter.ai/v1',FUIGO_AUTH_PROVIDER_COMMAND=str(refresher),FUIGO_EXTRA_CA_BUNDLE=str(ca/'cert.pem'),HTTPS_PROXY=f'http://127.0.0.1:{proxy.server_address[1]}',HTTP_PROXY=f'http://127.0.0.1:{proxy.server_address[1]}',NO_PROXY='127.0.0.1,localhost')
 else:env.update(FUIGO_API_KEY='fixture-static-key',FUIGO_API_BASE_URL=f'http://127.0.0.1:{server.server_port}/v1')
 terminal=None;terminal_time=None;second=False;loaded=False
 with (home/'stderr.log').open('w') as err:
  process=subprocess.Popen([str(binary),'--permission-mode','default','--no-memory','agent','--no-leader','-m','flux-auto','stdio'],cwd=home,env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=err,bufsize=0)
  def send(method,params,rpcid):
   frame={'jsonrpc':'2.0','id':rpcid,'method':method,'params':params};frames.append({'direction':'stdin','frame':frame});process.stdin.write((json.dumps(frame)+'\n').encode());process.stdin.flush()
  send('initialize',{'protocolVersion':1,'clientCapabilities':{},'clientInfo':{'name':'busyloop-trace','version':'1'}},1)
  sel=selectors.DefaultSelector();sel.register(process.stdout,selectors.EVENT_READ);deadline=time.monotonic()+100
  try:
   while time.monotonic()<deadline:
    if not sel.select(1):
     if process.poll() is not None:raise RuntimeError('engine exited')
     continue
    line=process.stdout.readline()
    if not line:raise RuntimeError('engine EOF')
    m=json.loads(line);frames.append({'direction':'stdout','time_ns':time.monotonic_ns(),'frame':m})
    if m.get('id')==1 and 'result' in m:
     if refreshable:send('authenticate',{'methodId':'cached_token','_meta':{'headless':True}},10)
     else:send('session/new',{'cwd':str(home),'mcpServers':[]},2)
    elif m.get('id')==10:
     assert 'result'in m,m
     send('session/new',{'cwd':str(home),'mcpServers':[]},2)
    elif m.get('id')==2 and 'result'in m:
     sid=m['result']['sessionId'];send('session/prompt',{'sessionId':sid,'prompt':[{'type':'text','text':'hi'}]},3)
    elif m.get('id')==3 and ('error'in m or 'result'in m):
     terminal=m;terminal_time=time.monotonic_ns()
     if wid=='W19' and not second:
      second=True;send('session/prompt',{'sessionId':sid,'prompt':[{'type':'text','text':'hi again'}]},3)
     else:send('session/load',{'sessionId':sid,'cwd':str(home),'mcpServers':[]},4)
    elif m.get('id')==4:
     assert 'result'in m,m
     loaded=True;time.sleep(1);break
    elif 'method'in m and 'id'in m:
     process.stdin.write((json.dumps({'jsonrpc':'2.0','id':m['id'],'result':{'outcome':{'outcome':'cancelled'}}})+'\n').encode());process.stdin.flush()
   assert terminal is not None and loaded,'prompt/load deadline'
   wanted=2 if wid in ['W1','W2','W3','W4','W12','W18','W19','W21','W22','W23','W24','W25'] else 1
   assert len(requests)==wanted,(len(requests),wanted,requests)
   refreshes=len(refreshlog.read_text().splitlines()) if refreshlog.exists() else 0
   assert refreshes==(1 if wid in ['W1','W2','W3','W4','W21','W22','W23','W24','W25'] else 0),refreshes
   assert not any(r['time_ns']>terminal_time for r in requests),requests
   assert ('result'in terminal)==(wid in ['W1','W18']),terminal
   print(f'PASS {wid}: POSTs={len(requests)} refreshes={refreshes} load/idle=0',flush=True)
  except Exception as e:
   failures.append(f'{wid}: {e}');print(f'FAIL {wid}: {e}',flush=True)
  finally:
   process.terminate()
   try:process.wait(timeout=5)
   except subprocess.TimeoutExpired:process.kill();process.wait()
   sel.close()
 (home/'frames.jsonl').write_text(''.join(json.dumps(f)+'\n' for f in frames));(home/'requests.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in requests))
 server.shutdown();server.server_close();proxy.shutdown();proxy.server_close()
(out/'result.json').write_text(json.dumps({'failures':failures},indent=2)+'\n')
raise SystemExit(bool(failures))
