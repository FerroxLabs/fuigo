"""Combine the case assertions (case.json) and the pass rule (rule.json) into one verdict line per case."""
import json
import sys

case, out = sys.argv[1], sys.argv[2]
try:
    rule = json.load(open(out + "/rule.json"))
except (OSError, ValueError):
    rule = {"pass": False, "rules_1_3_pass": False, "fail_reasons": ["no rule.json"]}
try:
    asserts = json.load(open(out + "/case.json"))["assertions"]
except (OSError, ValueError, KeyError):
    asserts = [{"name": "case.json present", "ok": False, "detail": ""}]
failed = [a["name"] for a in asserts if not a["ok"]]
if case.startswith("c-"):
    # A negative control passes when the pass rule FAILS; the paused-writer control must fail on the x-detector
    # while rules 1-3 themselves pass (the bypass sits inside the window).
    if case == "c-pause":
        ok = (not rule["pass"]) and rule.get("rules_1_3_pass") and bool(rule.get("x_marks")) and not failed
    else:
        ok = (not rule["pass"]) and not rule.get("rules_1_3_pass") and not failed
    print("%s: %s (pass rule %s: %s)%s" % (case, "EXPECTED FAILURE SEEN" if ok else "CONTROL DID NOT TRIP",
          "PASS" if rule["pass"] else "FAIL", "; ".join(rule.get("fail_reasons", [])),
          (" | assertion failures: %s" % failed) if failed else ""))
else:
    ok = rule["pass"] and not failed
    print("%s: %s (pass rule %s%s; %d/%d assertions)%s" % (case, "PASS" if ok else "FAIL",
          "PASS" if rule["pass"] else "FAIL", (": " + "; ".join(rule["fail_reasons"])) if rule["fail_reasons"] else "",
          len(asserts) - len(failed), len(asserts), (" | failed: %s" % failed) if failed else ""))
