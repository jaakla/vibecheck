---
name: vibecheck-report
description: >
  Turn vibecheck scan findings into a scored review — either a filled xlsx workbook or a
  client-ready markdown report. Use after vibecheck-scan when the user says "fill the scorecard",
  "generate the report", "give me the client version", "score this review", or wants the
  89-item checklist populated with findings. Supports English and Estonian, and two workbook
  profiles: reviewer (technical) and founder (plain-language client edition).
---

# Vibecheck Report

Convert findings from `vibecheck-scan` (and `vibecheck-supabase`) into a scored deliverable.

## Choose the profile first

- **reviewer** — for the technical reviewer doing the assessment. Technical control wording,
  statuses Pass / Partial / Fail / Not tested / N/A / Accepted risk, severity weights, full gate model.
- **founder** — plain-question client edition. Statuses Pass / Fail / N/A / Accepted risk, simplified
  verdict ladder, weights hidden. Use for the client leave-behind, never as the working sheet.

Do the review in the **reviewer** profile; hand over the **founder** profile only if the client
will re-run checks themselves.

## Mapping findings to the checklist

Each scanner finding carries `checklist_items` (numbers 1-89). Use
`${CLAUDE_PLUGIN_ROOT}/references/checklist-map.md` for item text, category, severity, and
scanner coverage — it is generated from `scripts/items.py`, the same source the workbook
builds from, so numbers always match.

The map's `scan` column says what the scanner's answer is worth for that item: **DECISIVE**
(a FAIL settles it), **EVIDENCE** (you decide from the evidence), **MANUAL** (no scanner
signal — it must be verified some other way or recorded as Not tested). A scanner PASS is
never sufficient grounds for a Pass on its own.

Collapse multiple findings hitting one item using the worst status:

- Any FAIL you confirm by reading the code → item = **Fail**
- Only WARN and your judgment clears it → **Pass** with a note; partially true → **Partial**
  (reviewer profile only); otherwise **Fail**
- MANUAL and not verified → **Not tested** (reviewer) / leave **blank** (founder) + to-do list
- Clean → **Pass** — but phrase automated passes as "no obvious issue detected", never "secure"

N/A on any Critical or High item **requires a written reason** in the Notes column, or the
workbook verdict drops to INCOMPLETE. **Accepted risk** requires a reason at every severity —
record who accepted, why, and a review-by date. It counts as reviewed but never as a Pass,
stays visible in the Summary counters, and clears a High-severity block; a **Critical item can
never be accepted** — the verdict stays BLOCK / DO NOT LAUNCH until it is fixed. If the client
believes a severity is overstated, put that argument in the acceptance reason; do not re-rate
the item. Items 60-63 (EU AI Act screening) take
Answered / Needs specialist — they are unscored in both profiles.

## Verdicts (computed by the workbook — do not restate your own)

Reviewer gates, in order: NOT REVIEWED → INCOMPLETE REVIEW (unreviewed Crit/High, N/A without
reason, open screening, or coverage < 100%) → BLOCK (Critical fail) → BLOCK — RISK ACCEPTANCE
REQUIRED (High fail) → FIX BEFORE RELEASE (weighted pass-rate < 90%) → RELEASE CANDIDATE.
Founder ladder: NOT REVIEWED → REVIEW INCOMPLETE → DO NOT LAUNCH → FIX BEFORE LAUNCH →
LOOKS READY FOR A LIMITED LAUNCH. A high percentage never overrides a failed gate, and there
is deliberately no "READY TO SHIP" — a checklist cannot prove an app safe.

## Output formats

**Markdown report (default, client-friendly):** verdict at top (copy the workbook's), findings
by category in severity order — each with evidence (file:line), one-sentence impact, and fix.
Then the Not-tested/MANUAL to-do list and any "Needs specialist" escalations. Redact secrets.

**Scored xlsx:** the builder needs `openpyxl`. Install it first if the import fails:

```bash
python3 -m pip install -r ${CLAUDE_PLUGIN_ROOT}/requirements.txt
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/build_workbook.py \
  --profile reviewer --lang en --out <path>.xlsx
```

Omit `--profile/--out` and pass `--outdir <dir>` to build all four (reviewer/founder × EN/ET) at once.

Then fill the Status (col F) and Notes (col G) columns on the Review tab — values must match the
sheet's language and profile — plus the metadata block on Summary. Always run the xlsx recalc
step afterwards so computed verdicts populate. Never hand over a workbook whose verdict cell
shows a stale or blank value.

## Language

Match the user's language. Estonian statuses: Korras / Osaline / Puudulik / Testimata /
Ei kohaldu (reviewer) or Korras / Puudulik / Ei kohaldu (founder); screening: Vastatud /
Vajab spetsialisti. Verdicts as rendered in the workbook (e.g. BLOKEERI, PARANDA ENNE
AVALDAMIST, VALJALASKEKANDIDAAT / ARA AVALDA, NAIB VALMIS PIIRATUD AVALDAMISEKS).
