"""Real Fuigo process with a deterministic local model. Mechanics, not answer quality."""
import argparse, hashlib, json, subprocess, threading
from decimal import Decimal
from pathlib import Path
import deepseek_bench as b
from smoke_requests import is_recall_request, is_title_request

p=argparse.ArgumentParser();p.add_argument("--binary",type=Path,required=True);p.add_argument("--out",type=Path,required=True);p.add_argument("--force-recall-loop",action="store_true");p.add_argument("--hostile-final-tool",action="store_true");p.add_argument("--general-tools",action="store_true");a=p.parse_args()
a.out=a.out.resolve();a.out.mkdir(mode=0o700,parents=True,exist_ok=False)
seen=[]
def transport(key,raw):
    request=json.loads(raw);seen.append(request)
    message={"role":"assistant","content":"ACK"};finish="stop"
    last=request.get("messages",[])[-1]
    recalling=is_recall_request(request)
    if is_title_request(request):
        message={"role":"assistant","content":None,"tool_calls":[{"id":"fixture-title","type":"function","function":{"name":"session_title","arguments":json.dumps({"session_title":"Synthetic memory recall check"})}}]};finish="tool_calls"
    elif (a.force_recall_loop and recalling) or (last.get("role")=="user" and "CURRENT" in (last.get("content") or "")):
        tool=next((t["function"] for t in request.get("tools",[]) if t["function"]["name"]=="memory_search"),None)
        if tool:
            message={"role":"assistant","content":None,"tool_calls":[{"id":"recall-one","type":"function","function":{"name":"memory_search","arguments":json.dumps({"query":"cedar_route","max_results":5})}}]};finish="tool_calls"
        elif a.hostile_final_tool:
            message={"role":"assistant","content":None,"tool_calls":[{"id":"forbidden-final","type":"function","function":{"name":"memory_search","arguments":json.dumps({"query":"cedar_route"})}}]};finish="tool_calls"
    return {"id":"local-smoke","model":b.MODEL,"created":0,"choices":[{"message":message,"finish_reason":finish}],"usage":{"prompt_tokens":20,"completion_tokens":10,"total_tokens":30}}
ledger=b.Ledger(a.out/"ledger.json",Decimal("5"));proxy=b.Proxy(ledger,"synthetic-never-network",transport);thread=threading.Thread(target=proxy.serve_forever);thread.start()
results=[]
try:
    for enabled in (True,False):
        root=a.out/str(enabled);root.mkdir();home=root/"home";home.mkdir();work=root/"work";work.mkdir()
        subprocess.run(b.COMMAND_PREFIX+["git","init","-q",str(work)],check=True)
        # Deliberately enabled even for off arm: root CLI must win.
        (home/"config.toml").write_text(b.CONFIG.format(port=proxy.server_port,enabled="true"))
        sid=None;before=len(seen)
        for n,prompt in enumerate(("Fact: cedar_route = amber ferry\nAcknowledge only.","Correction: cedar_route = silver kite\nAcknowledge only.","Outcome: rehearsal = passed\nAcknowledge only.")):
            result=b.run_turn(a.binary.resolve(),home,work,proxy,prompt,root/f"{n}.jsonl",sid,enabled)
            assert result["completed"],result
            sid=result["session_id"]
        if enabled:
            result=b.run_turn(a.binary.resolve(),home,work,proxy,"What is the CURRENT cedar_route?",root/"recall.jsonl",enabled=True,tools_override="memory_search,memory_get,Read" if a.general_tools else None)
            if a.hostile_final_tool:
                assert not result["completed"],"Unadvertised final tool must fail closed"
                assert "Tool call rejected during recall finalization" in (root/"recall.jsonl").read_text()
            else:
                assert result["completed"] and result["session_id"]!=sid,result
            if a.force_recall_loop:
                recall_calls=[req for req in seen[before:] if is_recall_request(req)]
                assert len(recall_calls)==3,recall_calls
                if a.general_tools:
                    names=[tool["function"]["name"] for tool in recall_calls[-1].get("tools",[])]
                    assert names and "memory_search" not in names and "memory_get" not in names,names
                else:assert not recall_calls[-1].get("tools"),"Final answer slot must offer no action tools"
            tool_evidence=[m.get("content","") for req in seen[before:] for m in req["messages"] if m.get("role")=="tool"]
            assert any("silver kite" in str(text) for text in tool_evidence),"Actual memory tool did not return corrected source"
        memory_files=list((home/"memory").rglob("*.md")) if (home/"memory").exists() else []
        if not enabled:assert not memory_files,"CLI off captured persistent memory"
        results.append({"memory_enabled":enabled,"checks_passed":True,"expected_final_tool_rejection":bool(a.hostile_final_tool and enabled),"persistent_markdown_files":len(memory_files),"calls":len(seen)-before})
    b.save(a.out/"result.json",{"binary_sha256":hashlib.sha256(a.binary.read_bytes()).hexdigest(),"results":results,"scope":"Real Fuigo capture, native memory tool retrieval, restart and CLI override; scripted model, no task-quality claim"})
    print(json.dumps(results))
finally:proxy.shutdown();proxy.server_close();thread.join()
