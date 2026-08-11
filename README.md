# vibecheck

A Claude Code / Cowork plugin for reviewing **vibecoded applications** — apps built by non-technical people using Lovable, Claude Code, Codex, Bolt, v0, and similar tools. It pairs a static scanner with Claude's code-reading judgment and produces a scored review against an 89-item checklist, rendered as two profiles (a technical reviewer edition and a plain-language founder edition, EN/ET) and covering GDPR and EU AI Act items.

## What the automation is worth

A static scan can prove a failure. It can never prove a pass. The checklist is tiered on exactly that asymmetry:

- **DECISIVE — 14 items.** When the check fires, the item is a Fail and needs no interpretation: a tracked `.env`, a `.env` in git history, `using (true)` policies, tables created without RLS, string-built SQL, provider key prefixes in source, `service_role` in a client component, an LLM endpoint called from the browser, a file-based DB on serverless hosting, hand-rolled auth primitives, a missing lockfile. A *clean* run of these checks still means only "no signal found".
- **EVIDENCE — 24 items.** The scanner surfaces material and a human decides either way: mock/stub markers, empty catch blocks, wildcard CORS, XSS sinks, webhook signature verification, prompt-injection chain signals, PII in logs, AI-disclosure strings.
- **MANUAL — 51 items.** No scanner signal at all: IDOR, tenant isolation, backups and restore, idempotency, budget caps, data residency, Annex III classification. These are emitted as explicit reviewer to-dos so they cannot be silently skipped.

**No item is ever marked Pass by the scanner alone.**

## Skills

| Skill | Use |
|-------|-----|
| `vibecheck-scan` | Run the full review on a repo. Runs the scanner, triages FAIL/WARN/MANUAL, adds judgment checks, reports with a verdict. |
| `vibecheck-supabase` | Live RLS / anon-exposure / IDOR probe of a Supabase project using the anon key only. Read-only by default. |
| `vibecheck-fix` | Propose and apply remediations, diff-first, on a branch — then re-scan to confirm each finding cleared. Separates mechanical fixes from ones needing a human decision, and keeps leaked-secret rotation and history purging advisory. |
| `vibecheck-report` | Fill the scored xlsx workbook or produce a client-ready markdown report. English or Estonian. |

### Architecture coverage

Architecture is category one (#1-#6) because the build tool determines how much of it to distrust. Opinionated platforms (Lovable+Supabase, Bolt, v0) inherit sane stack, DB and auth choices; freehand tools (Claude Code, Codex CLI) can pick anything. The scanner flags file-based DBs on serverless hosting, hand-rolled auth primitives, parallel data-access stacks accreted across sessions, and runtime-vs-hosting mismatches. Stack mainstream-ness (#1) and complexity proportionality (#4) stay judgment calls.

### Prompt-injection coverage

Because vibecoded apps almost always wrap an LLM, injection gets a dedicated block (items #77-#81). The scanner detects the injection *chain* structurally: LLM output reaching an exec/eval/shell sink (`inject.llm_to_exec`), raw variable interpolation into prompts (`inject.prompt_interpolation`), tool/function-calling agents (`inject.tool_agent`), external/RAG content flowing into a model (`inject.indirect`), and model output rendered as HTML (`inject.llm_to_html`). These are structural signals — Claude confirms the actual dataflow by reading the module. Passing a variable as message content is fine; interpolating it into a template-literal prompt is what flags.

## Usage

Just ask: *"vibecheck this repo"*, *"review this Lovable app"*, *"is this safe to ship?"*, *"check my RLS"*. Or run the pieces directly:

```bash
# Static scan — JSON lines, one finding per check
bash scripts/vibecheck.sh /path/to/repo

# Live Supabase probe (anon key only, no writes unless you opt in)
python3 scripts/supabase_probe.py --url "$SUPABASE_URL" --anon "$SUPABASE_ANON_KEY"

# Scored workbooks (needs openpyxl)
python3 -m pip install -r requirements.txt
python3 scripts/build_workbook.py --outdir ./out
```

Each finding is tagged with the checklist item numbers it maps to.

## Scoring & verdict

Weights Critical=5 / High=3 / Medium=2 / Low=1. Screening rows (#60-#63, EU AI Act) carry weight 0 and are unscored. Pass-rate = passed ÷ verified; coverage = verified ÷ applicable.

The workbook computes the verdict; gates are evaluated in order and a high percentage never overrides a failed gate:

**Reviewer profile:** NOT REVIEWED → INCOMPLETE REVIEW (unreviewed Critical/High, N/A without a reason, open screening, or coverage < 100%) → BLOCK (any Critical fail, or a Critical marked Accepted) → BLOCK – RISK ACCEPTANCE REQUIRED (any High fail) → FIX BEFORE RELEASE (pass-rate < 90%) → RELEASE CANDIDATE.

**Founder profile:** NOT REVIEWED → REVIEW INCOMPLETE → DO NOT LAUNCH → FIX BEFORE LAUNCH → LOOKS READY FOR A LIMITED LAUNCH.

There is deliberately no "READY TO SHIP" rung: a checklist cannot prove an app safe.

## Scope & limits

- The scanner is a **first pass**, not a proof. Regexes have false positives (WARN exists for this) and false negatives — spot-check the critical PASSes rather than trusting them.
- It never writes to the reviewed repo, and it redacts credential-shaped strings in its own output (first 8 characters plus a length marker) so findings can be pasted into a ticket. Evidence lines are capped at 200 characters.
- The Supabase probe sends **no writes by default**. PostgREST has no dry-run insert, so an anon-write test can create a real row; that probe is opt-in behind `--write-probe`, and the report states plainly when it was not run.
- The probe judges exposure on rows actually returned. A table with RLS enabled returns `200 []` to anon rather than a 401, so HTTP 200 alone is not a finding — and an empty table is indistinguishable from a protected one without a seeded row.
- Git history checks are pathspec-scoped to the directory you scan. If that directory sits inside a larger repo, the scanner says so rather than reporting a sibling project's leaks as yours.
- Legal items (GDPR, AI Act) are engineering-review flags, not legal advice.

## Development

```bash
python3 -m unittest discover -s tests -v   # scanner behaviour + consistency tests
python3 scripts/gen_map.py                 # regenerate references/checklist-map.md
```

`scripts/items.py` is the single source of truth: the 89-item bank in four wordings, the verification metadata, and `SCANNER_CHECKS` (which checklist items each scanner check covers, and at which tier). `references/checklist-map.md` is generated from it, and `tests/test_coverage_map.py` fails if the scanner, the item bank, the generated map, or the counts quoted in this README drift apart.

`tests/fixtures/` holds three miniature repos: a vulnerable one that must trip every FAIL check, a clean one that must trip none, and a docs-only one whose prose *mentions* `md5`, `Math.random` tokens and webhooks and must not be flagged for it. They contain fake credentials by design, so scanning this repo's own tree reports findings inside `tests/fixtures/`.

## Legal reference notes (as written, July 2026 — re-verify at review time)

- **EU AI Act**: Art. 50 transparency applies from Aug 2026; market surveillance/governance/sanctions from 2 Aug 2026; Annex III high-risk obligations deferred to 2 Dec 2027 by the May 2026 Digital Omnibus; prohibited practices enforceable since Feb 2025.
- **Estonian SaaS data residency**: no statute mandates in-country storage for private-sector SaaS; GDPR + IKS govern. EU-region hosting is compliant. Public sector / vital services (E-ITS, riigipilv), accounting retention, health, and NIS2 are the exceptions; enterprise-customer DPAs are the most common binding constraint in practice.

See `references/checklist-map.md` for the full item list, severities, EN/ET text, and scanner coverage.

## License

MIT — see [LICENSE](LICENSE).
