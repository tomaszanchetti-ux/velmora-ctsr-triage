"""Stability of the triage: same file twice, shuffled rows, and one batch per day (as it would run in production).
Usage: python3 eval/stability.py ../pm_builder_case_study_v2_tickets.csv output_v1.csv
"""
import csv, io, random, sys
from collections import defaultdict
sys.path.insert(0, ".")
import triage

src, ref = sys.argv[1], sys.argv[2]
text = open(src, encoding="utf-8-sig").read()
rows = list(csv.DictReader(io.StringIO(text)))
cols = list(rows[0].keys())
REF = {r["ticket_id"]: r["decision"] for r in csv.DictReader(open(ref))}

def to_csv(rs):
    b = io.StringIO(); w = csv.DictWriter(b, cols); w.writeheader(); w.writerows(rs); return b.getvalue()

def decisions(csv_text, history_text=None):
    try:
        res = triage.triage_text(csv_text, history_text)[1]
    except TypeError:  # v1 has no history parameter
        res = triage.triage_text(csv_text)[1]
    return {r["ticket_id"]: r["decision"] for r in res}

def changed(d):
    return sorted((k, REF[k], v) for k, v in d.items() if v != REF[k])

a, b = decisions(text), decisions(text)
print("run 1 vs run 2:", sum(a[k] != b[k] for k in a), "changes")
print("run 1 vs v1 file:", len(changed(a)), "changes")

sh = rows[:]; random.Random(7).shuffle(sh)
print("shuffled rows:", len(changed(decisions(to_csv(sh)))), "changes")

days = defaultdict(list)
for r in rows: days[r["created_at"][:10]].append(r)
daily = {}
for d in sorted(days): daily.update(decisions(to_csv(days[d])))
ch = changed(daily)
print(f"one batch per day, no history ({len(days)} days):", len(ch), "changes")
for c in ch: print("  ", *c)
daily_h, seen = {}, []
for d in sorted(days):
    daily_h.update(decisions(to_csv(days[d]), to_csv(seen) if seen else None))
    seen += days[d]
ch = changed(daily_h)
print(f"one batch per day, with earlier days as --history:", len(ch), "changes")
for c in ch: print("  ", *c)
