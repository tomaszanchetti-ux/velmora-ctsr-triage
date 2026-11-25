# Velmora CTSR triage

One decision per support ticket for the CTSR queue (level 2) of Velmora, a fictional marketplace from a
case study. The triage follows a layered design: **gate → risk → one case → escalation rule → fix the
cause → elite**. Rules decide; nothing written in a ticket can change them.

**Run it in the browser:** https://tomaszanchetti-ux.github.io/velmora-ctsr-triage/
Drop a CSV, get the decisions in a table, download `output.csv`. The file never leaves your browser.

**Run it locally** (Python 3, standard library only):

```bash
python3 triage.py tickets.csv > output.csv                          # counts per decision go to stderr
python3 triage.py today.csv --history last_30_days.csv > output.csv # daily runs: earlier tickets as context
python3 test_triage.py                                              # edge-case tests on synthetic tickets
```

The web page and the command line run the same `triage.py` (the page uses [Pyodide](https://pyodide.org)),
so both give the same output for the same file.

## Input and output

Input columns: `ticket_id, created_at, source, customer_id, order_id, order_amount_usd, payment_method,
carrier, seller_id, days_since_delivery, prior_contacts_30d, text`.
Output: `ticket_id,decision,needs_elite_agent`, one line per ticket, in the input order.

## How it decides

Each ticket goes through the layers in order. The first rule that fires wins.

| Layer | Question | Decisions | Elite agent |
|---|---|---|---|
| 0 Gate | No customer and no order: is it a CTSR case at all? | `gate_drop_spam`, `gate_quarantine_phishing`, `gate_route_seller_support`, `gate_route_tech_oncall`, `gate_route_ir_press` | no |
| 1 Risk | Could it hurt the customer, Velmora or the money? Runs before anything automatic. | `risk_legal` (P4: Legal informed within 24 h), `risk_fraud_account`, `risk_injection` | yes |
| 2 One case | Is this a follow-up on a case already open (same customer + order)? | `merge_followup` | no |
| 3 Escalation rule | Does the policy already answer it? | `auto_refund_duplicate_charge` (P3, once two captures are verified), `auto_refund_in_policy` (P1 + P2: unopened, ≤ 14 days, ≤ $500 ceiling), `human_refund_above_ceiling`, `frontline_chatbot_escape`, `frontline_simple_request`, `frontline_no_reason` | only above the ceiling |
| 4 Fix the cause | Is it part of a known pattern with an owner? | `cause_fix_tracking` (broken tracking link), `cause_fix_counterfeit` (a seller with ≥ 3 claims becomes a cluster), `policy_gap_damaged` (no rule in the policy) | damaged only |
| 5 Elite | A refund or defect the policy does not cover | `elite_edge_case` | yes |
| – | No rule decides | `unclassified_human`: never a guess | yes |

Design choices:
- **The gate never drops a ticket with a customer, an order or a legal signal.**
- **Risk runs before any automation.** A text that gives orders to an AI ("ignore previous instructions…") is
  treated as a risk signal, not an instruction. With no customer or order it is quarantined as phishing.
- **Clusters come from the data**, not from ids written in the code: a seller becomes a counterfeit cluster
  when the batch (plus `--history`) holds 3 or more claims against it, and it only pulls complaints about the item.
- **Signals in English, Spanish, French, German, Italian and Portuguese**, on text with accents and apostrophes folded, with a negation guard ("not damaged" is not damage).
- **Deterministic**: same file, same output. Two runs give zero changes.

## How wrong it is (measured)

| Test | v1 | v2 |
|---|---|---|
| Blind read of 63 of the case's 150 tickets (all elite + 3 per other decision) | 1 disagreement (T096, debatable) | same |
| 40 invented tickets it never saw (`eval/heldout_b.csv`) | 40% wrong decisions; a legal notice dropped as spam | 25% wrong; every error goes to a person |
| One batch per day instead of the whole week | 6 decisions change | 0 with `--history` |
| Same file twice / shuffled rows | 0 changes | 0 changes |

`eval/heldout_a.csv` was used to find the v1 errors (so v2 scores 0% on it, which proves nothing);
`eval/heldout_b.csv` was kept aside and only used to measure. Remaining errors are mostly paraphrases the
patterns do not know: the honest limit of keyword rules. Run `python3 eval/score_heldout.py eval/heldout_b.csv --detail`.

## Files

- `triage.py`: the rules and the command line (`decide()` is a pure function of one ticket)
- `test_triage.py`: edge cases on synthetic tickets (day 14 vs 15, $500 vs $500.01, injection vs refund…)
- `index.html`: the web page
- `sample_tickets.csv`: 16 invented tickets, one or more per layer
- `eval/`: held-out sets (invented tickets with the expected decision), scoring and stability scripts

The case's own ticket file is not included in this repository.
