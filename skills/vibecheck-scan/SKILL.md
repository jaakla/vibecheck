---
name: vibecheck-scan
description: >
  Run a technical review scan of a vibecoded application (built with Lovable, Claude Code,
  Codex, Bolt, v0 or similar). Use when the user says "vibecheck", "review this app",
  "security review", "audit this repo", "check this vibecoded app", "is this app safe to ship",
  or asks to verify a codebase built by a non-technical person. Combines a static
  scanner script with code-reading judgment, producing findings mapped to an 89-item
  scored checklist.
---

# Vibecheck Scan

Perform a technical review of a vibecoded application repository. The review has two layers: a scanner script for pattern-level findings, and your own code-reading judgment for everything the script marks WARN or MANUAL.

## Step 1 — Run the scanner

```bash
bash ${CLAUDE_PLUGIN_ROOT}/scripts/vibecheck.sh <repo_dir>
```

Output is one JSON object per finding: `check`, `checklist_items` (numbers from the review workbook), `status` (FAIL/WARN/PASS/MANUAL), `title`, `evidence`.

Evidence arrives already redacted — credential-shaped strings are cut to their first 8 characters and lines are capped at 200 chars. Do not go read the raw secret out of the file to put it in the report.

## Step 2 — Triage the results

- **FAIL** findings are near-certain problems. Read the evidence, confirm in the actual file, and report each with file:line references and a concrete fix.
- **WARN** findings need judgment. Open the referenced files and decide: `service_role` in a Supabase edge function is fine, in a React component it is a critical leak. `using (true)` on a public read-only reference table may be intentional; on a `users` table it is not. Upgrade to FAIL or downgrade to PASS with a one-line justification each.
- **MANUAL** findings cannot be automated statically. List them explicitly as reviewer to-dos; do not silently drop them.
- **PASS** findings: a scanner PASS means "no signal found", never "verified safe". Spot-check 2-3 of the most critical ones (secrets, RLS) rather than trusting the script — regexes have false negatives.

`references/checklist-map.md` gives each item a `scan` tier that tells you how much the scanner's answer is worth: **DECISIVE** (a FAIL settles the item), **EVIDENCE** (you decide), **MANUAL** (no scanner signal). Only DECISIVE FAILs can be reported without opening the file first.

## Step 3 — Judgment checks the script cannot do

Read the code and assess these directly (`${CLAUDE_PLUGIN_ROOT}/references/checklist-map.md` has item numbers and severities):

1. **Authorization semantics** — do RLS policies and server-side checks actually match the intended access model? Read every policy; ask the user what the intended model is if it is unclear.
2. **Is functionality real** — trace 2-3 core user flows from UI to persistence. Flag any flow that terminates in component state, a hardcoded array, or a canned response.
3. **Business-logic correctness** — money as integers/decimals, idempotency on payment and order handlers, race conditions on shared resources, timezone handling.
4. **Cost blast radius architecture** — even when a rate-limit library is present, check that it actually wraps the expensive call; check for recursive agent loops without a step cap.
5. **Prompt injection** — the scanner flags the injection chain (`inject.llm_to_exec`, `inject.prompt_interpolation`, `inject.tool_agent`, `inject.indirect`, `inject.llm_to_html`, items #77-#81). These are structural signals, not proof: confirm the dataflow by reading the module. `inject.llm_to_exec` is Critical if model output can actually reach the sink — trace it. For tool-calling agents, verify tools are allowlisted, arguments validated, and authorisation derived from the authenticated user rather than from model output. Treat any external or RAG content reaching the model as untrusted data.
6. **Architecture reasonableness (#1-#6)** — weigh how the app was built. Opinionated platforms (Lovable+Supabase, Bolt, v0+Vercel) constrain stack/DB/auth choices, so #1-#3 usually pass quickly with a "platform-constrained" note. Freehand tools (Claude Code, Codex CLI) can pick anything: scrutinise the stack inventory, data-store-vs-hosting fit (`arch.datastore`), hand-rolled auth (`arch.handrolled_auth`, which co-flags #56), parallel data-access stacks (`arch.mixed_stack`), and runtime-vs-hosting mismatches (`arch.hosting_fit`). For #4, try to summarise the architecture in five sentences; if you cannot, that is the finding.
7. **EU AI Act classification** — if AI features touch employment, credit, education, biometrics or essential services, flag as potentially Annex III high-risk and say so plainly.

## Step 4 — Report

Produce findings in severity order (Critical → High → Medium → Low), each with checklist item number(s), file:line evidence, why it matters in one sentence, and a concrete fix. End with the MANUAL to-do list and a verdict recommendation using the workbook's reviewer ladder:

INCOMPLETE REVIEW (unreviewed Critical/High, or coverage < 100%) → BLOCK (any Critical fail) → BLOCK – RISK ACCEPTANCE REQUIRED (any High fail) → FIX BEFORE RELEASE (pass-rate < 90%) → RELEASE CANDIDATE.

Gates are evaluated in order and a high pass-rate never overrides one. There is no "ready to ship" verdict — do not invent one.

If the user wants the scored workbook filled or a client-ready document, hand off to `vibecheck-report`. If Supabase credentials are available for live probing, hand off to `vibecheck-supabase`.

## Constraints

- Never print full secret values. The scanner redacts its own output; keep it that way in the report.
- Do not modify the reviewed repository unless the user explicitly asks for fixes.
- Findings without file:line evidence are opinions; label them as such.
- If the scanner emits `scan.scope`, the directory you scanned is nested inside a larger git repo. Say so in the report — history findings cover only the scanned subtree.
