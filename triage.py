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
import unicodedata
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


def fold(text):
    """Lowercase, strip accents and apostrophes, so 'doesn't', 'doesnt' and 'débité' match one pattern."""
    t = unicodedata.normalize("NFKD", text or "")
    t = "".join(c for c in t if not unicodedata.combining(c))
    return t.replace("’", "").replace("'", "").lower()


# --- Signals, on folded text (EN / ES / FR / DE / IT / PT) -----------------------------------
INJECTION = rx(r"ignore (all |any )?(your |the )?(previous|prior|above) (rules|instructions)",
               r"disregard (all |any )?(previous|prior|your|the above) (rules|instructions)",
               r"note to the (ai|assistant)", r"ai assistant", r"\[\[\s*assistant", r"\bassistant:",
               r"admin mode", r"maintenance mode", r"system override", r"you are now (in|operating)",
               r"no human review", r"do not route (it|this) to (any )?human", r"classify this ticket as",
               r"mark this ticket as", r"ignora (las|tus|todas|le) (instrucciones|istruzioni)",
               r"ignorez (les|vos|toutes)", r"ignoriere (alle|deine)", r"ignore as instrucoes")
LEGAL = rx(r"\blawyer", r"solicitor", r"attorney", r"legal action", r"legal claim", r"lawsuit", r"\bsue\b",
           r"small claims", r"consumer (protection|authority|ombudsman|rights office)", r"regulator", r"\bi represent\b",
           r"\bombudsman", r"abogad", r"autoridad de consumo", r"accion legal", r"demanda judicial", r"avocat",
           r"porter plainte", r"action en justice", r"anwalt", r"verbraucherschutz", r"rechtliche schritte",
           r"avvocat", r"azione legale", r"advogad", r"procon", r"acao judicial")
TAKEOVER = rx(r"did ?n.?t (make|place|order|buy)", r"did not (make|place|order|buy)", r"not (made|placed) by",
              r"unauthori[sz]ed (order|access|login|purchase)", r"hacked", r"hackead", r"pirate",
              r"someone (else )?(changed|accessed|logged|used)", r"account (was |has been )?compromised",
              r"changed the password", r"email on the account was changed",
              r"(cambiaron|cambio|modificaron) (el|mi|su) (correo|email|contrasena)", r"que no (hizo|hice|realice)",
              r"(commandes?|achats?) que je nai pas", r"die ich nicht (bestellt|gemacht)", r"che non ho (fatto|ordinato)",
              r"que (eu )?nao fiz")
DISPUTE_OPEN = rx(r"(opened|filed|raised|started|initiated) (a )?(dispute|chargeback)",
                  r"chargeback (is )?(open|filed)", r"dispute (is )?open", r"(abri|abrimos) (una )?disputa",
                  r"(jai )?(ouvert|fait) (un litige|opposition)", r"ruckbuchung (eingeleitet|veranlasst)",
                  r"(ho )?aperto (una )?contestazione", r"abri (uma )?contestacao")
FRAUD = rx(r"(different|another|other) (card|account)", r"refund .{0,40}to a (different|another) card",
           r"(third|3rd|fourth|4th) (refund|not.received|claim)", r"signed for", r"signed delivery",
           r"signature on file", r"otra tarjeta", r"autre carte", r"andere karte", r"altra carta", r"outro cartao")

PHISHING = rx(r"verify your (account|credentials|identity|password)", r"confirm your (password|credentials)",
              r"click here", r"bank details", r"billing details", r"invoice overdue", r"payment is due",
              r"access will be suspended", r"account will be (closed|suspended)", r"business opportunity",
              r"\$\d+(\.\d+)?\s?m\b", r"wire transfer", r"gift card", r"\binheritance\b")
INTERNAL = rx(r"^\s*internal:", r"\brule t-\d+", r"monitoring alert", r"^\s*\[alert\]", r"error rate",
              r"\brunbook\b", r"created by monitor", r"on-?call", r"\bp[0-4] incident\b")
AUTO_REPLY = rx(r"out of office", r"delivery failure", r"undeliverable", r"could not be delivered",
                r"unsubscribe", r"auto-?reply", r"automatic reply", r"fuera de la oficina", r"respuesta automatica",
                r"absent du bureau", r"reponse automatique", r"automatische antwort", r"nicht im buro",
                r"risposta automatica", r"fuori ufficio", r"resposta automatica", r"mailer-daemon")
IR_PRESS = rx(r"shareholder", r"\binvestor", r"earnings", r"journalist", r"reporter", r"press (inquiry|request)",
              r"for (an|a|our) (article|story|piece)", r"periodista", r"journaliste", r"giornalista",
              r"jornalista", r"accionista", r"actionnaire", r"aktionar")
SPAM = rx(r"partnership", r"webinar", r"\bseo\b", r"influencer", r"agency", r"media kit", r"\bdemo\b",
          r"quick call", r"\d+ ?min(utes)?\b.{0,20}(call|this week)", r"book (a|15|30)", r"% off", r"discount",
          r"offer\b", r"rates attached", r"promote", r"\bleads\b", r"grow your", r"\d+x your", r"crypto",
          r"financing", r"raise capital", r"\bdeck\b", r"retreat", r"register now", r"seats are limited",
          r"we help", r"our (team|services|agency)", r"manufacturer", r"best price", r"thesis", r"survey",
          r"questionnaire", r"opt out", r"newsletter", r"congratulations")

FOLLOWUP = rx(r"following (up|my message)", r"resending", r"second message", r"hello\?\?", r"anyone\?",
              r"got no reply", r"still nothing", r"still waiting", r"same issue as before", r"any update",
              r"confirm you received", r"no news", r"sigo esperando", r"alguna novedad", r"reenvio", r"de nuevo",
              r"des nouvelles", r"relance", r"toujours rien", r"noch keine antwort", r"nachfrage", r"erneut",
              r"novita", r"ancora nessuna", r"alguma novidade", r"de novo")

DUPLICATE = rx(r"(charged|billed|debited|taken) (me )?(twice|two times|2 times)", r"charged .{0,25}twice",
               r"two (identical )?(charges|payments|debits|captures)", r"double (charge|payment|debit|billing)",
               r"(cobraron|cobrado|cobro|cobrar) (dos veces|doble)", r"dos cargos", r"doble cargo", r"cargo duplicado",
               r"(debite|preleve|facture)e?s? deux fois", r"deux prelevements", r"double prelevement",
               r"(doppelt|zweimal) (abgebucht|belastet|berechnet)", r"addebitat[oa] due volte", r"doppio addebito",
               r"cobrad[oa] duas vezes", r"cobraram duas vezes", r"cobranca duplicada")
REFUND = rx(r"refund", r"\breturn", r"money back", r"back on my card", r"changed (their |his |her |my )?mind",
            r"reembols", r"devoluci", r"devolver", r"plata de vuelta", r"dinero de vuelta", r"rembourse", r"retour",
            r"erstatt", r"ruckgabe", r"zuruckgeben", r"zuruckschicken", r"restituire", r"rimborso", r"\breso\b",
            r"devolucao")
UNOPENED = rx(r"unopened", r"never (been )?opened", r"not (been )?opened", r"\bsealed\b", r"factory sealed",
              r"still (in|under) (its |the )?(plastic|shrink|wrap|film)", r"box not opened", r"sin abrir",
              r"no (la|lo|las|los) abri", r"precint", r"jamais ouvert", r"non ouvert", r"sous film", r"scelle",
              r"ungeoffnet", r"nicht geoffnet", r"verschwei", r"originalverpackt", r"mai aperta", r"non aperta",
              r"sigillat", r"nunca aberto", r"lacrad")
TRACKING = rx(r"tracking", r"\blink\b", r"seguimiento", r"enlace", r"\bsuivi\b", r"\blien\b",
              r"sendungsverfolgung", r"tracciamento", r"rastreamento", r"rastreio")
BROKEN = rx(r"error", r"broken", r"\bdead\b", r"not found", r"(does not|doesnt|wont|will not) (open|load|work)",
            r"says nothing", r"\b404\b", r"spins forever", r"no funciona", r"no disponible", r"no abre",
            r"funktioniert nicht", r"nicht gefunden", r"ne marche pas", r"ne fonctionne pas", r"introuvable",
            r"non funziona", r"nao (abre|funciona)")
COUNTERFEIT = rx(r"\bfake\b", r"knock-?off", r"counterfeit", r"is a copy", r"not (real|genuine|authentic|original)",
                 r"(arent|isnt) (real|genuine|authentic|original)", r"not the brand", r"not as described",
                 r"nothing like the original", r"\breplica\b", r"falsificad", r"\bfalso\b", r"no es original",
                 r"contrefa", r"pas authentique", r"\bfaux\b", r"falschung", r"gefalscht", r"nicht echt",
                 r"non (e )?original", r"contraffatt", r"imitazion", r"nao e (original|da marca)", r"\bfalsa\b")
QUALITY = rx(r"not what the (photos?|pictures?|listing) (showed|said)", r"(peeling|came apart|fell apart)",
             r"poor quality", r"cheap (material|plastic)", r"\bis plastic\b", r"wrong material")
DAMAGED = rx(r"damaged", r"arrived broken", r"\bbroken\b", r"cracked", r"shattered", r"smashed",
             r"in (\w+ ){0,2}pieces", r"\bdented\b", r"crushed", r"danad", r"\broto\b", r"\brota\b", r"endommag",
             r"\bcasse", r"beschadigt", r"kaputt", r"zerbrochen", r"danneggiat", r"\brott[oa]\b", r"quebrad",
             r"danificad", r"rachad", r"amassad")
DEFECT = rx(r"stopped working", r"(wont|doesnt|does not|will not) (charge|turn on|work|start)", r"not working",
            r"defective", r"faulty", r"no funciona", r"dejo de funcionar", r"ne fonctionne (plus|pas)",
            r"funktioniert nicht", r"non funziona", r"nao funciona")
CHATBOT = rx(r"chat-?bot", r"\bbot\b", r"virtual assistant", r"asistente virtual",
             r"talk to (a|an actual|a real) (person|human)", r"(real|actual) person", r"\bhuman\b", r"humano",
             r"humain", r"una persona", r"\bmensch\b", r"un umano", r"uma pessoa", r"main menu", r"hauptmenu")
SIMPLE = rx(r"invoice", r"factura", r"facture", r"rechnung", r"fattura", r"nota fiscal", r"\bcancel", r"cancelar",
            r"annuler", r"stornieren", r"annullare", r"delivery address", r"change the address", r"direccion",
            r"password", r"log ?in", r"out for delivery", r"en reparto", r"contrasena", r"mot de passe",
            r"passwort", r"senha")
NO_REASON = rx(r"manager", r"supervisor", r"escalat", r"see previous notes")
NEGATION = re.compile(r"\b(not|no|nothing|never|nada|ni|pas|rien|kein\w*|nicht|non|nao|sin|nunca)\b(\W+\w+){0,2}\W*$")


def hit(pattern, x):
    """True if the pattern appears at least once WITHOUT a negation in the three words before it."""
    for m in pattern.finditer(x):
        if not NEGATION.search(x[max(0, m.start() - 30):m.start()]):
            return True
    return False


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
        "norm": fold((row.get("text") or "").strip()),
    }


# --- The decision (pure function: ticket + what the queue already knows) ----------------------
def decide(t, open_cases=frozenset(), flagged_sellers=frozenset()):
    """Return (decision, rule) for one normalized ticket.

    open_cases: (customer, order) pairs already open earlier in the queue.
    flagged_sellers: sellers with repeated counterfeit claims in this batch.
    """
    x = t["norm"]
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
        if SPAM.search(x):
            return "gate_drop_spam", "gate:marketing"
        return "unclassified_human", "gate:no_evidence_to_drop"  # v2: never drop without a positive reason

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
    if t["order"] and (hit(COUNTERFEIT, x) or (t["seller"] in flagged_sellers
                                               and (hit(QUALITY, x) or hit(DEFECT, x) or hit(DAMAGED, x)))):
        return "cause_fix_counterfeit", "cause:counterfeit"
    if t["order"] and hit(DAMAGED, x):
        return "policy_gap_damaged", "cause:damaged_no_rule"

    # 3 FRONTLINE: the customer could not get a person, or frontline could close it
    if t["order"] and CHATBOT.search(x):
        return "frontline_chatbot_escape", "frontline:chatbot_dead_end"
    # 5 ELITE: a refund or a defect the policy does not cover
    if t["order"] and (REFUND.search(x) or hit(DEFECT, x)):
        return "elite_edge_case", "elite:outside_policy"
    if t["order"] and SIMPLE.search(x):
        return "frontline_simple_request", "frontline:simple_request"
    if not t["order"] and (len(x.split()) <= 4 or NO_REASON.search(x)):
        return "frontline_no_reason", "frontline:no_reason"

    return "unclassified_human", "none"


# --- Context that needs the whole batch --------------------------------------------------------
def flag_sellers(tickets, min_claims=3):
    """Sellers with >= min_claims counterfeit claims (batch + history): a cluster, not a one-off."""
    c = Counter(t["seller"] for t in tickets if t["seller"] and t["order"] and hit(COUNTERFEIT, t["norm"]))
    return frozenset(s for s, n in c.items() if n >= min_claims)


def run(tickets, history=()):
    """history: earlier tickets (e.g. the last 30 days). Used only as context: open cases and clusters."""
    flagged = flag_sellers(list(history) + list(tickets))
    out = {}
    open_cases = {(h["customer"], h["order"]) for h in history if h["customer"] and h["order"]}
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


REQUIRED = ["ticket_id", "created_at", "source", "customer_id", "order_id", "order_amount_usd", "payment_method",
            "carrier", "seller_id", "days_since_delivery", "text"]


def read_tickets(csv_text):
    """Fail loudly if a column is missing: a renamed 'text' column must not turn every ticket blank."""
    reader = csv.DictReader(io.StringIO((csv_text or "").lstrip("\ufeff")))
    missing = [c for c in REQUIRED if c not in (reader.fieldnames or [])]
    if missing:
        raise ValueError(f"missing columns: {', '.join(missing)}")
    return [normalize(r) for r in reader]


def triage_text(csv_text, history_text=None):
    """Whole run from CSV text (used by the command line and by the web page, so both are the same code).

    Returns (output_csv, results, summary_lines). results keep the input order.
    """
    tickets = read_tickets(csv_text)
    history = read_tickets(history_text) if history_text else []
    ids = [t["id"] for t in tickets]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate ticket_id in input")

    out, flagged = run(tickets, history)

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


def main(path, history_path=None):
    with open(path, encoding="utf-8-sig", newline="") as f:
        text = f.read()
    hist = open(history_path, encoding="utf-8-sig", newline="").read() if history_path else None
    output, _, lines = triage_text(text, hist)
    sys.stdout.write(output)
    print("\n".join(lines), file=sys.stderr)


if __name__ == "__main__":
    args = sys.argv[1:]
    if len(args) == 1:
        main(args[0])
    elif len(args) == 3 and args[1] == "--history":
        main(args[0], args[2])
    else:
        sys.exit("usage: python3 triage.py tickets.csv [--history earlier_tickets.csv] > output.csv")
