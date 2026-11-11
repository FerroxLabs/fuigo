"""Data loaders for the sanitized Flux refusal fixtures (shared by the strike scripts)."""
import glob
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2] / 'crates/codegen/fuigo-sampling-types/tests/fixtures'
EPS = {"/v1/chat/completions": "chat", "/v1/responses": "resp", "/v1/messages": "msg"}


def reference():
    return json.loads((ROOT / 'busyloop_reference.json').read_text())


def leaves(j):
    out = []
    if "body" in j or "headers" in j:
        out.append((EPS[j["endpoint"]], {k: v for k, v in j.items() if k != "per_endpoint"}))

    def walk(o, pre):
        for k, v in o.items():
            if not isinstance(v, dict):
                continue
            lab = EPS.get(k, k)
            if "status" in v and ("body" in v or "headers" in v):
                out.append((pre + lab, v))
            else:
                walk(v, pre + k.replace("_variant", "") + "/")
    walk(j.get("per_endpoint", {}), "")
    return out


def fixture_leaves(d):
    got = {}
    for sub, pat in (("", "[0-9]*.json"), ("siblings", "D*.json"), ("target-654", "*.json")):
        for f in sorted(glob.glob(os.path.join(d, sub, pat))):
            base = os.path.basename(f)
            if base.startswith("._"):
                continue
            j = json.load(open(f))
            if j.get("not_reachable_in_prod"):
                continue
            stem = base.split("-")[0]
            pre = "t654:" if sub == "target-654" else ""
            for leaf, r in leaves(j):
                got[f"{pre}{stem}.{leaf}"] = r
    return got


def load_rows(path):
    lines = open(path).read().splitlines()
    hdr = lines[0].split("\t")
    return [dict(zip(hdr, l.split("\t"))) for l in lines[1:] if l.strip()]
