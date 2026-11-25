#!/usr/bin/env python3
"""CTSR triage for Velmora: the layers of the 2.1 design, as deterministic rules.

Usage:
    python3 triage.py tickets.csv > output.csv        (summary goes to stderr)

Python 3 standard library only. Same input, same output: no model, no randomness.

How it decides (one ticket at a time, in this order; the first rule that fires wins):
  0 GATE      no customer and no order: is it a CTSR case at all?
              lawyer/regulator -> risk (never dropped) · seller -> Seller Support ·
              phishing or text giving orders to an AI -> Security quarantine ·
              internal alert -> Tech on-call · auto-reply -> drop · IR/press -> owner · rest -> drop
  1 RISK      before anything automatic: legal (P4), text giving orders to an AI,
              account takeover / fraud signals / a bank dispute already open -> human, never automated
  2 ONE CASE  a follow-up on a case already open in the queue (same customer + order) -> merge
  3 RULES     the policy already answers it:
              P3 duplicate charge -> automatic refund once two captures are verified in the payments tool
              P1+P2 unopened, <= 14 days, <= ceiling -> automatic refund (the $100 limit was the only blocker)
  4 CAUSES    known patterns with an owner: broken tracking link (carrier) · counterfeit claims (seller)
              damaged item: the policy has no rule -> human
  5 ELITE     a refund the policy does not cover -> elite agent
  3 FRONTLINE chatbot dead end · simple request · escalation with no reason -> back to frontline
  - anything no rule decides -> unclassified_human (never a guess)

Text is only matched against patterns: nothing in a ticket can change the rules. Text that gives
orders to an AI is itself a risk signal.
"""
import csv
import io
import re
import sys
from collections import Counter, defaultdict

REFUND_CEILING = 500.0  # automatic refunds above this go to a human (parameter, not data)
RETURN_WINDOW_DAYS = 14  # P1

# Closed list of decisions -> needs_elite_agent. Nothing outside this list can be output.
DECISIONS = {
    "gate_drop_spam": "no",
    "gate_quarantine_phishing": "no",
    "gate_route_seller_support": "no",
    "gate_route_tech_oncall": "no",
    "gate_route_ir_press": "no",
    "risk_legal": "yes",
    "risk_fraud_account": "yes",
    "risk_injection": "yes",
    "merge_followup": "no",
    "auto_refund_duplicate_charge": "no",
    "auto_refund_in_policy": "no",
    "human_refund_above_ceiling": "yes",
    "cause_fix_tracking": "no",
    "cause_fix_counterfeit": "no",
    "policy_gap_damaged": "yes",
    "elite_edge_case": "yes",
    "frontline_chatbot_escape": "no",
    "frontline_simple_request": "no",
    "frontline_no_reason": "no",
    "unclassified_human": "yes",
}


def rx(*parts):
    return re.compile("|".join(parts), re.IGNORECASE)


# --- Signals (EN / ES / FR / DE) -------------------------------------------------------------
INJECTION = rx(r"ignore (all )?(your )?(previous|prior) (rules|instructions)",
               r"disregard (all )?(previous|prior|your) (rules|instructions)",
               r"note to the assistant", r"ai assistant", r"\[\[\s*assistant", r"\bassistant:",
               r"admin mode", r"you are now in", r"ignora (las|tus) instrucciones",
               r"ignorez (les|vos) instructions", r"ignoriere (alle|deine)")
LEGAL = rx(r"\blawyer", r"solicitor", r"attorney", r"legal action", r"legal claim", r"lawsuit",
           r"\bsue\b", r"consumer protection", r"regulator", r"\bi represent\b", r"\bombudsman",
           r"abogad", r"avocat", r"porter plainte", r"anwalt", r"verbraucherschutz")
TAKEOVER = rx(r"did not make", r"didn't make", r"did not buy", r"didn't buy", r"not made by",
              r"changed the password", r"email on the account was changed", r"hacked",
              r"someone (else )?(changed|accessed|logged)", r"account (was )?compromised")
DISPUTE_OPEN = rx(r"(opened|filed|raised|started) a (dispute|chargeback)",
                  r"chargeback (is )?(open|filed)", r"dispute (is )?open")
FRAUD = rx(r"(different|another|other) (card|account) than", r"refund .* to a (different|another) card",
           r"(third|3rd|fourth|4th) refund", r"signed for")

PHISHING = rx(r"verify your account", r"click here", r"bank details", r"billing details",
              r"invoice overdue", r"payment is due", r"business opportunity", r"\$\d+(\.\d+)?\s?m\b",
              r"wire transfer", r"gift card", r"confirm your (password|credentials)")
INTERNAL = rx(r"^\s*internal:", r"\brule t-\d+", r"monitoring alert")
AUTO_REPLY = rx(r"out of office", r"delivery failure", r"undeliverable", r"could not be delivered",
                r"unsubscribe", r"auto-?reply", r"fuera de la oficina", r"absent du bureau")
IR_PRESS = rx(r"shareholder", r"investor", r"earnings", r"journalist", r"reporter", r"\bpress\b",
              r"\bmedia\b", r"periodista", r"journaliste")

FOLLOWUP = rx(r"following (up|my message)", r"resending", r"second message", r"hello\?\?",
              r"anyone\?", r"got no reply", r"still nothing", r"same issue as before",
              r"confirm you received", r"sigo esperando", r"relance", r"nachfrage")

DUPLICATE = rx(r"charged (me )?twice", r"two (identical )?charges", r"double (charge|payment)",
               r"two captures", r"(cobraron|cobrado) dos veces", r"dos cargos", r"deux prélèvements",
               r"débité deux fois", r"doppelt (abgebucht|belastet)", r"zweimal (abgebucht|belastet)")
REFUND = rx(r"refund", r"\breturn", r"money back", r"back on my card", r"changed (their |his |her |my )?mind",
            r"reembolso", r"devoluci",
            r"rembourse", r"retour", r"erstatt", r"rückgabe", r"zurückgeben")
UNOPENED = rx(r"unopened", r"\bsealed\b", r"not opened", r"sin abrir", r"precintado",
              r"non ouvert", r"ungeöffnet", r"originalverpackt")
TRACKING = rx(r"tracking", r"\blink\b", r"seguimiento", r"enlace", r"\bsuivi\b", r"\blien\b",
              r"sendungsverfolgung")
BROKEN = rx(r"error", r"broken", r"\bdead\b", r"not found", r"does not open", r"doesn't open",
            r"says nothing", r"da error", r"no funciona", r"funktioniert nicht", r"ne marche pas",
            r"ne fonctionne pas")
COUNTERFEIT = rx(r"\bfake\b", r"knock-?off", r"counterfeit", r"is a copy", r"not the brand",
                 r"not as described", r"nothing like the original", r"\breplica\b", r"falsificad",
                 r"\bfalso\b", r"contrefa", r"fälschung", r"gefälscht")
DAMAGED = rx(r"damaged", r"arrived broken", r"\bcracked\b", r"\bbroken\b", r"shattered", r"dañado",
             r"roto\b", r"endommag", r"cassé", r"beschädigt", r"kaputt")
DEFECT = rx(r"stopped working", r"defective", r"faulty", r"no funciona", r"ne fonctionne plus",
            r"funktioniert nicht mehr")
CHATBOT = rx(r"chatbot", r"\bbot\b", r"talk to a (person|human)", r"\bhuman\b", r"humain",
             r"una persona", r"\bmensch\b")
SIMPLE = rx(r"invoice", r"factura", r"facture", r"rechnung", r"\bcancel", r"cancelar", r"annuler",
            r"stornieren", r"delivery address", r"change the address", r"password", r"log ?in",
            r"out for delivery", r"contraseña", r"mot de passe", r"passwort")
NO_REASON = rx(r"manager", r"supervisor", r"escalat", r"see previous notes")


# --- Reading the raw export --------------------------------------------------------------------
def norm_source(s):
    s = (s or "").strip().lower().replace(" ", "_")
    if s.startswith("frontline"):
        return "frontline"
    if s.startswith("direct"):
        return "direct"
    return {"exec_inbox": "exec", "routing_rule": "routing", "external_channel": "external"}.get(s, "blank")


def num(s, cast):
    s = (s or "").strip().replace("$", "").replace(",", "")
    try:
        return cast(s) if s else None
    except ValueError:
        return None


def normalize(row):
    return {
        "id": row["ticket_id"].strip(),
        "created": (row.get("created_at") or "").strip(),
        "source": norm_source(row.get("source")),
        "customer": (row.get("customer_id") or "").strip(),
        "order": (row.get("order_id") or "").strip(),
        "amount": num(row.get("order_amount_usd"), float),
        "payment": (row.get("payment_method") or "").strip(),
        "carrier": (row.get("carrier") or "").strip(),
        "seller": (row.get("seller_id") or "").strip(),
        "days": num(row.get("days_since_delivery"), int),
        "text": (row.get("text") or "").strip(),
    }


# --- The decision (pure function: ticket + what the queue already knows) ----------------------
def decide(t, open_cases=frozenset(), flagged_sellers=frozenset()):
    """Return (decision, rule) for one normalized ticket.

    open_cases: (customer, order) pairs already open earlier in the queue.
    flagged_sellers: sellers with repeated counterfeit claims in this batch.
    """
    x = t["text"]
    has_case = bool(t["customer"] or t["order"])

    # 0 GATE: only tickets with no customer and no order can leave here
    if not has_case:
        if LEGAL.search(x):
            return "risk_legal", "gate:legal_never_dropped"
        if t["seller"]:
            return "gate_route_seller_support", "gate:seller"
        if INJECTION.search(x) or PHISHING.search(x):
            return "gate_quarantine_phishing", "gate:phishing_or_injection"
        if INTERNAL.search(x):
            return "gate_route_tech_oncall", "gate:internal_alert"
        if AUTO_REPLY.search(x):
            return "gate_drop_spam", "gate:auto_reply"
        if IR_PRESS.search(x):
            return "gate_route_ir_press", "gate:ir_press"
        return "gate_drop_spam", "gate:no_customer_no_order"

    # 1 RISK: runs before anything that could act on its own
    if LEGAL.search(x):
        return "risk_legal", "risk:legal"
    if INJECTION.search(x):
        return "risk_injection", "risk:injection"
    if TAKEOVER.search(x):
        return "risk_fraud_account", "risk:account_takeover"
    if DISPUTE_OPEN.search(x):
        return "risk_fraud_account", "risk:dispute_open"
    if FRAUD.search(x):
        return "risk_fraud_account", "risk:fraud_signal"

    # 2 ONE CASE: follow-up on a case already open
    if t["order"] and (t["customer"], t["order"]) in open_cases and FOLLOWUP.search(x):
        return "merge_followup", "one_case:followup"

    # 3 RULES THAT ALREADY ANSWER IT
    if t["order"] and DUPLICATE.search(x):
        return "auto_refund_duplicate_charge", "rule:P3_duplicate"
    if t["order"] and REFUND.search(x) and UNOPENED.search(x):
        in_window = t["days"] is not None and t["days"] <= RETURN_WINDOW_DAYS
        if in_window and t["amount"] is not None:
            if t["amount"] <= REFUND_CEILING:
                return "auto_refund_in_policy", "rule:P1_P2_in_policy"
            return "human_refund_above_ceiling", "rule:P1_above_ceiling"

    # 4 CAUSES WITH AN OWNER
    if TRACKING.search(x) and BROKEN.search(x):
        return "cause_fix_tracking", "cause:broken_tracking"
    if t["order"] and (COUNTERFEIT.search(x) or t["seller"] in flagged_sellers):
        return "cause_fix_counterfeit", "cause:counterfeit"
    if t["order"] and DAMAGED.search(x):
        return "policy_gap_damaged", "cause:damaged_no_rule"

    # 3 FRONTLINE: the customer could not get a person, or frontline could close it
    if t["order"] and CHATBOT.search(x):
        return "frontline_chatbot_escape", "frontline:chatbot_dead_end"
    # 5 ELITE: a refund or a defect the policy does not cover
    if t["order"] and (REFUND.search(x) or DEFECT.search(x)):
        return "elite_edge_case", "elite:outside_policy"
    if t["order"] and SIMPLE.search(x):
        return "frontline_simple_request", "frontline:simple_request"
    if not t["order"] and (len(x.split()) <= 4 or NO_REASON.search(x)):
        return "frontline_no_reason", "frontline:no_reason"

    return "unclassified_human", "none"


# --- Context that needs the whole batch --------------------------------------------------------
def flag_sellers(tickets, min_claims=3):
    """Sellers with >= min_claims counterfeit claims in the batch: a cluster, not a one-off."""
    c = Counter(t["seller"] for t in tickets if t["seller"] and t["order"] and COUNTERFEIT.search(t["text"]))
    return frozenset(s for s, n in c.items() if n >= min_claims)


def run(tickets):
    flagged = flag_sellers(tickets)
    out, open_cases = {}, set()
    for t in sorted(tickets, key=lambda t: (t["created"], t["id"])):  # the queue order
        out[t["id"]] = decide(t, frozenset(open_cases), flagged)
        if t["customer"] and t["order"]:
            open_cases.add((t["customer"], t["order"]))
    return out, flagged


LAYER = {
    "gate_drop_spam": "0 Gate", "gate_quarantine_phishing": "0 Gate", "gate_route_seller_support": "0 Gate",
    "gate_route_tech_oncall": "0 Gate", "gate_route_ir_press": "0 Gate",
    "risk_legal": "1 Risk", "risk_fraud_account": "1 Risk", "risk_injection": "1 Risk",
    "merge_followup": "2 One case",
    "auto_refund_duplicate_charge": "3 Escalation rule", "auto_refund_in_policy": "3 Escalation rule",
    "human_refund_above_ceiling": "3 Escalation rule", "frontline_chatbot_escape": "3 Escalation rule",
    "frontline_simple_request": "3 Escalation rule", "frontline_no_reason": "3 Escalation rule",
    "cause_fix_tracking": "4 Fix the cause", "cause_fix_counterfeit": "4 Fix the cause",
    "policy_gap_damaged": "4 Fix the cause",
    "elite_edge_case": "5 Elite", "unclassified_human": "- Unclassified",
}


def triage_text(csv_text):
    """Whole run from CSV text (used by the command line and by the web page, so both are the same code).

    Returns (output_csv, results, summary_lines). results keep the input order.
    """
    rows = list(csv.DictReader(io.StringIO(csv_text.lstrip("\ufeff"))))
    tickets = [normalize(r) for r in rows]
    ids = [t["id"] for t in tickets]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate ticket_id in input")

    out, flagged = run(tickets)

    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["ticket_id", "decision", "needs_elite_agent"])
    results = []
    for t in tickets:  # same order as the input file
        d, rule = out[t["id"]]
        assert d in DECISIONS
        w.writerow([t["id"], d, DECISIONS[d]])
        results.append({"ticket_id": t["id"], "decision": d, "needs_elite_agent": DECISIONS[d],
                        "layer": LAYER[d], "rule": rule, "source": t["source"], "text": t["text"]})

    # Summary: counts are read, not assumed
    n = Counter(d for d, _ in out.values())
    assert sum(n.values()) == len(tickets) == len(out) == len(results)
    lines = [f"tickets in {len(tickets)} · out {len(out)}"]
    lines += [f"  {d:30} {n[d]:4}  elite={DECISIONS[d]}" for d in DECISIONS if n[d]]
    lines.append(f"needs_elite_agent=yes: {sum(n[d] for d in DECISIONS if DECISIONS[d] == 'yes')}")
    by = defaultdict(Counter)
    for t in tickets:
        d, _ = out[t["id"]]
        if d == "cause_fix_tracking":
            by["tracking by carrier"][t["carrier"] or "(none)"] += 1
        if d == "cause_fix_counterfeit":
            by["counterfeit by seller"][t["seller"] or "(none)"] += 1
        if d == "auto_refund_duplicate_charge":
            by["duplicate charge by payment method"][t["payment"] or "(none)"] += 1
    lines += [f"{k}: {dict(c)}" for k, c in by.items()]
    lines.append(f"sellers flagged as counterfeit cluster: {sorted(flagged)}")
    return buf.getvalue(), results, lines


def main(path):
    with open(path, encoding="utf-8-sig", newline="") as f:
        output, _, lines = triage_text(f.read())
    sys.stdout.write(output)
    print("\n".join(lines), file=sys.stderr)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: python3 triage.py tickets.csv > output.csv")
    main(sys.argv[1])
