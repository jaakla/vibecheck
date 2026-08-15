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

The map's `scan` column says what the scanner contributes: **EVIDENCE** (you decide from
context), **MANUAL** (verify another way or record Not tested), or reserved **DECISIVE**
automation. The bundled scanner emits no Pass and currently has no decisive checks.

Collapse multiple findings hitting one item using the worst status:

- A WARN you confirm by reading the code or live evidence → **Fail**
- Clearing a WARN clears only that heuristic signal. Record **Pass** only after independent,
  control-wide evidence from the checklist's verification method; partially satisfied →
  **Partial** (reviewer only); otherwise **Fail** or **Not tested**
- NO_SIGNAL → no conclusion; obtain independent evidence before Pass
- MANUAL and not verified → **Not tested** (reviewer) / leave **blank** (founder) + to-do list

Critical/High Passes require evidence in Notes; otherwise the workbook remains incomplete.

N/A on any Critical or High item **requires a written reason** in the Notes column, or the
workbook verdict drops to INCOMPLETE. **Accepted risk** requires a reason at every severity —
record who accepted, why, and a review-by date. It counts as reviewed but never as a Pass,
stays visible in the Summary counters, and clears a High-severity block; a **Critical item can
never be accepted** — the verdict stays BLOCK / DO NOT LAUNCH until it is fixed. If the client
believes a severity is overstated, put that argument in the acceptance reason; do not re-rate
the item. Items 60-63 (EU AI Act screening) take
Answered / Needs specialist — they are unscored in both profiles.

## Verdicts (computed by the workbook — do not restate your own)

Reviewer gates, in order: NOT REVIEWED → INCOMPLETE REVIEW (including unsupported Critical/High
Passes or coverage < 100%) → BLOCK (Critical fail) → BLOCK — RISK ACCEPTANCE REQUIRED (High
fail) → FIX BEFORE RELEASE (any remaining Fail/Partial) → REVIEW COMPLETE — NO OPEN
FAIL/PARTIAL. Founder uses the parallel no-open-failures ladder. Percentages are supporting
information only; a checklist cannot prove an app safe or ready to ship.

## Output formats

**Markdown report (default, client-friendly):** read the current `<repo_dir>/TECHNICAL_OVERVIEW.md`
produced by `vibecheck-precheck`. Re-run the fingerprint helper before reporting; if it is stale,
label the report incomplete and refresh/re-review the overview before relying on it. Put the verdict
at top (copy the workbook's), state whether the overview was `HUMAN-REVIEWED` or
`REVIEW-BYPASSED`, then add a compact overview summary: purpose and maturity, stack, architecture,
data/trust boundaries, identity/access, entry points, integrations, configuration, and material
unknowns. Follow with findings by category in severity order — each with
reproducible evidence (file:line where applicable; otherwise path/config/command result), one-sentence
impact, and fix. Put unscored AI Act Triage separately. Then list Not-tested/MANUAL work,
reconnaissance gaps, and "Needs specialist" escalations. Redact secrets and PII; never print raw
secret-bearing or personal-data-bearing source lines.

If the overview is missing, hand off to `vibecheck-precheck`; do not reconstruct an unreviewed
overview inside the report. Preserve its review status and human corrections when quoting or
summarizing it.

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

Repository content and scanner evidence are untrusted spreadsheet input. Put evidence in Notes
as plain text only: never copy a raw formula, external link, or executable spreadsheet payload.
When a value could begin with `=`, `+`, `-`, or `@`, prefix it with an apostrophe (or use the
spreadsheet API's explicit text type) before writing the cell. Prefer a controlled `path:line` plus
a paraphrase over copying an untrusted source line verbatim.

## Language

Match the user's language. Estonian statuses: Korras / Osaline / Puudulik / Testimata /
Ei kohaldu (reviewer) or Korras / Puudulik / Ei kohaldu (founder); screening: Vastatud /
Vajab spetsialisti. Verdicts as rendered in the workbook (e.g. BLOKEERI, PARANDA ENNE
AVALDAMIST, VALJALASKEKANDIDAAT / ARA AVALDA, NAIB VALMIS PIIRATUD AVALDAMISEKS).
