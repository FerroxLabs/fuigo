"""Select on development only, then evaluate frozen heldout exactly once."""
import argparse, hashlib, json, subprocess
from pathlib import Path


def metrics(report):
    rows=report["cases"]; positive=[r for r in rows if r["expected"]]; negative=[r for r in rows if not r["expected"]]
    if not positive or not negative or len({r["id"] for r in rows})!=len(rows):raise ValueError("Need distinct positive and negative controls")
    emitted=sum(len(r["delivered"]) for r in rows)
    return {"cases":len(rows),"recall":sum(r["recall"] for r in positive)/len(positive),
      "precision":sum(r["correct"] for r in rows)/emitted if emitted else 0,
      "abstention":sum(not r["delivered"] for r in negative)/len(negative),
      "forbidden":sum(bool(r["forbidden"]) for r in rows)}


def main():
    p=argparse.ArgumentParser();p.add_argument("--binary",type=Path,required=True);p.add_argument("--dev-vectors",required=True);p.add_argument("--held-vectors",required=True);p.add_argument("--out",type=Path,required=True);a=p.parse_args()
    a.out.mkdir(parents=True,exist_ok=False)
    base=Path(__file__).resolve().parent
    def run(name,corpus,vectors,threshold=None):
        path=a.out/(name+".json")
        argv=["rtk","proxy",str(a.binary.resolve()),str(base/corpus),str(path),vectors]
        if threshold is not None:argv.append(str(threshold))
        subprocess.run(argv,check=True,stdout=subprocess.DEVNULL)
        return metrics(json.loads(path.read_text()))
    development=[]
    for threshold in (0.35,0.45,0.55,0.65):
        score=run("dev-"+str(threshold),"development.json",a.dev_vectors,threshold)
        development.append({"threshold":threshold,**score})
    eligible=[r for r in development if r["precision"]>=0.9 and r["abstention"]>=0.9 and r["forbidden"]==0]
    report={"development":development,"heldout_sha256":hashlib.sha256((base/"heldout.json").read_bytes()).hexdigest(),"model":json.load(open(a.held_vectors))["identity"]}
    if not eligible:
        report["status"]="BLOCKED_DEVELOPMENT_PRECISION";(a.out/"result.json").write_text(json.dumps(report,indent=2));return
    chosen=max(eligible,key=lambda r:(r["recall"],r["threshold"]))["threshold"]
    report["selected_semantic_min_score"]=chosen
    # Durable selection before the first heldout result is observed.
    (a.out/"selection.json").write_text(json.dumps(report,indent=2))
    report["heldout_default"]=run("held-default","heldout.json",a.held_vectors)
    report["heldout_calibrated"]=run("held-calibrated","heldout.json",a.held_vectors,chosen)
    score=report["heldout_calibrated"]
    report["accepted"]=score["recall"]>report["heldout_default"]["recall"] and score["precision"]>=0.9 and score["abstention"]>=0.9 and score["forbidden"]==0
    report["status"]="ACCEPTED_LIMITED_PROFILE" if report["accepted"] else "BLOCKED_HELDOUT_QUALITY"
    (a.out/"result.json").write_text(json.dumps(report,indent=2));print(json.dumps(report,indent=2))
if __name__=="__main__":main()
