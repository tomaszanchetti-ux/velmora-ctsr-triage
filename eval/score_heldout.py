"""Score the triage on an invented held-out set with expected_decision.
Usage: python3 eval/score_heldout.py eval/heldout_x.csv [--detail]
"""
import csv, sys
sys.path.insert(0, ".")
import triage
path = sys.argv[1]
text = open(path, encoding="utf-8-sig").read()
exp = {r["ticket_id"]: r["expected_decision"].strip() for r in csv.DictReader(open(path, encoding="utf-8-sig"))}
got = {r["ticket_id"]: r for r in triage.triage_text(text)[1]}
bad = [(k, exp[k], got[k]["decision"], got[k]["rule"]) for k in exp if got[k]["decision"] != exp[k]]
el = lambda d: triage.DECISIONS.get(d, "?")
bad_el = [k for k in exp if el(exp[k]) != got[k]["needs_elite_agent"]]
risky = [k for k in exp if el(exp[k]) == "yes" and got[k]["needs_elite_agent"] == "no"]
print(f"{path}: {len(exp)} tickets · decision errors {len(bad)} ({len(bad)/len(exp):.0%}) · "
      f"elite-flag errors {len(bad_el)} · elite cases sent to automation/no-elite: {len(risky)}")
if "--detail" in sys.argv:
    for b in bad: print("  ", *b)
