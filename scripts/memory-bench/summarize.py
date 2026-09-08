"""Deterministic per-family retrieval scoring, without a language-model judge."""
import json, sys
from collections import Counter

def summarize(report):
    rows=report["cases"]
    if len(rows)!=240 or len({r["id"] for r in rows})!=240:raise ValueError("Expected 240 distinct evaluated queries")
    counts=Counter(r["family"] for r in rows)
    if len(counts)!=6 or any(n!=40 for n in counts.values()):raise ValueError("Expected six balanced families")
    def score(cases):
        answerable=[r for r in cases if r["expected"]];empty=[r for r in cases if not r["expected"]]
        emitted=sum(len(r["delivered"]) for r in cases)
        return {"cases":len(cases),"recall_at_10":sum(r["recall"] for r in answerable)/len(answerable) if answerable else None,
          "precision":sum(r["correct"] for r in cases)/emitted if emitted else None,
          "no_answer_abstention":sum(not r["delivered"] for r in empty)/len(empty) if empty else None,
          "forbidden_cases":sum(bool(r["forbidden"]) for r in cases),"unsupported_cases":sum(bool(r["unsupported"]) for r in cases)}
    return {"mode":report["mode"],"model":report["model"],"overall":score(rows),"families":{family:score([r for r in rows if r["family"]==family]) for family in sorted(counts)},"limitations":report["limitations"]}
if __name__=="__main__":
    for path in sys.argv[1:]:print(json.dumps(summarize(json.load(open(path))),indent=2))
