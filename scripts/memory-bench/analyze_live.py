"""Post-run diagnostics; never changes the frozen strict rubric or its outcomes."""
import json, sys
from collections import Counter
from decimal import Decimal as D
from pathlib import Path
import deepseek_bench as b


def last_answer(text):
    decoder=json.JSONDecoder(); candidates=[]
    for i,c in enumerate(text):
        if c!="{":continue
        try:obj,end=decoder.raw_decode(text[i:])
        except ValueError:continue
        if isinstance(obj,dict) and {"answer","global_pin","foreign_code","authorized"}<=obj.keys():candidates.append(obj)
    return candidates[-1] if candidates else None


def analyze(root):
    report=json.loads((root/"results.json").read_text()); ledger=json.loads((root/"budget.json").read_text())
    cases={c["id"]:c for c in b.scenarios()};details=[]
    for row in report["results"]:
        turn=row["turns"][-1];answer=last_answer(turn["text"])
        # Supplementary diagnostic only: extra prose still fails original JSON-only contract.
        semantic=b.judge(cases[row["case"]],json.dumps(answer),row["memory"]) if answer else {"passed":False}
        finished=turn["completed"] and len(row["turns"])==4
        trace=root/(row["case"]+f"-{row['repeat']}-{row['memory']}")/"recall.jsonl"
        tool_text=[]; final_text=""
        if trace.exists():
            for line in trace.read_text().splitlines():
                try:event=json.loads(line)
                except ValueError:continue
                if event.get("type")=="tool_call":final_text=""
                if event.get("type")=="text":final_text+=event.get("data","")
                if event.get("type")=="tool_call_update" and event.get("status")=="completed":
                    output=event.get("rawOutput") or {}
                    if isinstance(output,dict) and isinstance(output.get("text"),str):tool_text.append(output["text"])
        evidence="\n".join(tool_text)
        case=cases[row["case"]]
        correction="Correction: "+case["key"]+" = "+case["new"]
        details.append({"corrected_fact_delivered":correction in evidence,
            "forbidden_canary_delivered":any(value in evidence for value in ("plum copper","ocean braid")),"case":row["case"],"memory":row["memory"],"repeat":row["repeat"],
            "task_pass":row["outcome"]["passed"],
            "strict_pass":finished and semantic["passed"] and b.judge(cases[row["case"]],final_text,row["memory"]).get("format_ok",False),"completed_recall":finished,
            "semantic_diagnostic_pass":finished and semantic["passed"],
            "stop_reason":turn.get("stop_reason"),"has_answer_object":answer is not None,
            "semantic_checks":semantic.get("checks"),"seconds":sum(t["seconds"] for t in row["turns"]),
            "tool_events":sum(t["tools"] for t in row["turns"])})
    arms={}
    for enabled in (True,False):
        rows=[r for r in details if r["memory"]==enabled]
        arms[str(enabled)]={"runs":len(rows),"strict_pass":sum(r["strict_pass"] for r in rows),
          "task_pass":sum(r["task_pass"] for r in rows),
          "corrected_fact_delivered":sum(r["corrected_fact_delivered"] for r in rows),
          "forbidden_canary_delivered":sum(r["forbidden_canary_delivered"] for r in rows),
          "completed_recall":sum(r["completed_recall"] for r in rows),
          "semantic_diagnostic_pass":sum(r["semantic_diagnostic_pass"] for r in rows),
          "stop_reasons":dict(Counter(r["stop_reason"] for r in rows))}
    peak=D(0);complete_usage=True;tokens=Counter()
    for call in ledger["calls"]:
        usage=call.get("usage")
        if not usage:complete_usage=False;continue
        for name in ("prompt_tokens","completion_tokens","prompt_cache_hit_tokens","prompt_cache_miss_tokens"):
            tokens[name]+=usage.get(name,0)
        hit=usage.get("prompt_cache_hit_tokens",0)
        miss=usage.get("prompt_cache_miss_tokens",usage.get("prompt_tokens",0)-hit)
        peak+=(D(hit)*D("0.014")+D(miss)*D("0.44")+D(usage.get("completion_tokens",0))*D("1.32"))/D(1000000)
    expected_runs=16 if report.get("focused") else 80
    return {"analysis_rubric_version":2,"source_rubric_version":report.get("rubric_version",1),"expected_runs":expected_runs,"recorded_runs":len(details),"matrix_complete":len(details)==expected_runs,
      "arms":arms,"requests":len(ledger["calls"]),"request_statuses":dict(Counter(c["status"] for c in ledger["calls"])),
      "reserved_usd":ledger["reserved_usd"],"tokens":dict(tokens),"all_calls_have_usage":complete_usage,
      "published_rate_estimate_usd":{"off_peak":str(peak/2),"peak":str(peak)},
      "billing_note":"Estimate from returned usage at published rate bands; no account balance or invoice reconciliation",
      "details":details,"limitations":report["limitations"]+["Supplementary JSON extraction does not turn a formatting failure into a strict pass"]}

if __name__=="__main__":
    root=Path(sys.argv[1]);result=analyze(root);b.save(root/"analysis-v2.json",result)
    print(json.dumps({k:v for k,v in result.items() if k!="details"},indent=2))
