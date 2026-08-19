# vibecheck

## Install from GitHub

In Claude Code Desktop, go to Settings → Plugins → Add marketplace → Add from repository, then enter `jaakla/vibecheck`.

A Claude Code / Cowork plugin for organizing reviews of **vibecoded applications**. It combines lightweight static signals, guided code reading, live checks, and an 89-item workbook (technical and founder profiles, EN/ET). It is a review aid, not a security scanner replacement or certification.

## What the automation is worth

A regex/path scan usually proves neither a vulnerability nor its absence. The checklist therefore distinguishes:

- **DECISIVE — 0 items.** Reserved for conclusive automation. The bundled static scanner has none.
- **EVIDENCE — 38 items.** The scanner surfaces material and a reviewer decides after reading the relevant code or testing the deployment.
- **MANUAL — 51 items.** No scanner signal at all: IDOR, tenant isolation, backups and restore, idempotency, budget caps, data residency, Annex III classification. These are emitted as explicit reviewer to-dos so they cannot be silently skipped.

The scanner emits `WARN`, `NO_SIGNAL`, or `MANUAL`; `NO_SIGNAL` is never Pass.

## Skills

| Skill | Use |
|-------|-----|
| `vibecheck-precheck` | Discover and reconcile existing documentation, cross-check the codebase, and write a fingerprinted `TECHNICAL_OVERVIEW.md` for human review before scanning. |
| `vibecheck-scan` | After precheck review, triage WARN/NO_SIGNAL/MANUAL, add targeted code-reading and live evidence, then report. |
| `vibecheck-supabase` | Live RLS / anon-exposure / explicit-record IDOR probe using a public anon/publishable key. Read-only by default. |
| `vibecheck-fix` | Turn findings into outcome-based Actions with automated, guided, and specialist Procedures; authorize one exact attempt, apply it diff-first/branch-first, then independently verify and reassess before completion. |
| `vibecheck-report` | Fill the scored xlsx workbook or produce a client-ready markdown report. English or Estonian. |

### Architecture coverage

Architecture is category one (#1-#6). Platforms constrain some choices but do not prove secure configuration. The scanner flags candidate datastore/hosting mismatches, weak primitives, parallel data-access stacks, and runtime/hosting mismatches; every hit still needs context. Stack maintainability and proportional complexity remain judgment calls.

### Prompt-injection coverage

LLM applications get a dedicated prompt-injection block (items #77-#81). The scanner looks for co-located model and execution sinks, prompt interpolation, tool calling, retrieved content, and raw-HTML rendering. These are search signals, not dataflow proof; a reviewer must trace the path and authorization decisions.

### Project and confidentiality review

Every full review starts with `vibecheck-precheck`. It discovers existing READMEs, docs, ADRs,
specifications, API schemas, diagrams, and runbooks, then verifies material claims against code and
configuration. It writes a source-fingerprinted `TECHNICAL_OVERVIEW.md` covering purpose and maturity,
stack, architecture, data flows and trust boundaries, identity/access, entry points, integrations,
deployment, documentation discrepancies, and evidence gaps.

The overview starts as `DRAFT`; the default workflow pauses so a human can correct and approve it.
The full scan proceeds when the current fingerprint is `HUMAN-REVIEWED`, or after an explicit
`REVIEW-BYPASSED` choice that remains visible as an evidence gap. A raw scanner-only request can still
run without precheck, but it is not a completed Vibecheck review.

The guided confidentiality pass traces credentials, sessions, route/CSRF/CORS boundaries, sensitive
serialization and storage, TLS/proxies, outbound requests and SSRF, logs/prompts/analytics, third-party
disclosure, and admin bootstrap/recovery. Confirmed issues retain the existing 89-item mapping and
verdict model; ambiguous behavior remains Not tested/to-do rather than becoming a speculative finding.

## Prefer dedicated free tools for detection

Vibecheck's useful role is orchestration: it keeps technical, product, operational, and legal-review work from being silently skipped. It is a review aid and report/verdict framework, not a vulnerability-detection competitor to the specialist tools below or to an LLM security scanner run as a detection specialist. For detection depth, use maintained specialist tools alongside it.

The bundled scanner, the specialist adapters, and the LLM-driven judgment pass are all **detection**; the checklist, evidence model, coverage ledger, scoring, and verdict are **review orchestration**. Keep those two layers honest by treating every finding as refuting material a reviewer confirms, not as a proven vulnerability.

- **[Claude Security](https://github.com/anthropics/claude-plugins-official/tree/main/plugins/claude-security) (Anthropic, MIT)** — a deep multi-agent LLM scanner of your own code, run in-session, that maps architecture and threat models, hunts across components, and adversarially verifies every finding before it is reported. Its verification model (three independent lens verifiers defaulting to false-positive, vote-clamped confidence, code-computed tally) is the same trust discipline vibecheck applies to its own findings — vibecheck's three-lens panel (`vibecheck-scan`, `vibecheck-fix`) is the in-skill expression of that idea rather than code reused from it. Use Claude Security as an added detection specialist and feed what survives its panel into a Vibecheck review as normalized evidence; do not treat a scaffold of its ideas as an endorsement or as Anthropic's product.
- Secrets: Gitleaks or TruffleHog over the full git history.
- SAST: Semgrep Community; CodeQL for public GitHub repositories.
- Dependencies and containers: OSV-Scanner or Trivy.
- Dynamic web testing: OWASP ZAP against an authorized staging deployment.
- Functional and authorization flows: Playwright with two test accounts.

These tools also have false positives/negatives, but they are substantially more mature than the bundled grep-based scanner — so vibecheck ranks an installed one ahead of its own scanner and ahead of a person reading the code by hand, and imports what it produced as normalized evidence.

Two code-computed products keep a scan honest about coverage and machine-readable:

```bash
# Code coverage ledger: completeness = checked | partial | not-checkable,
# listing scanned, explicitly-skipped (with reasons) and unaccounted dirs.
bash scripts/vibecheck.sh <repo> > /tmp/vibecheck.jsonl
python3 scripts/coverage.py --repo <repo> < /tmp/vibecheck.jsonl

# SARIF 2.1.0 for GitHub code scanning / IDE viewers; --withhold-evidence
# never quotes a hard-coded credential line in a file that leaves the session.
python3 scripts/sarif.py --repo <repo> --withhold-evidence < /tmp/vibecheck.jsonl
```

The Python never installs or runs a tool. The scan skill may install the default pack after one user yes, then run and import:

```bash
# What the scan skill checks before asking. The Python never installs.
python3 scripts/external_adapters.py --availability

# What the skill uses after a run: import, never paste
python3 scripts/external_adapters.py --import gitleaks report.json \
  --command "gitleaks detect --source . --log-opts --all --report-format json --redact"
python3 scripts/external_adapters.py --import zap zap.json \
  --target-url https://staging.example.com --authorized-by "the deployment owner"
```

A finding becomes scoped refuting evidence; a clean run becomes neutral evidence that can never support a Pass; a missing tool, a crash, a timeout or a cancelled run becomes an open to-do naming the coverage nobody has. A DAST or browser run that cannot name its target and who authorized it is refused rather than imported.

## Usage

Just ask: *"vibecheck this repo"*, *"review this Lovable app"*, *"is this safe to ship?"*, *"check my RLS"*. Or run the pieces directly:

```bash
# Precheck source-state fingerprint (the skill writes TECHNICAL_OVERVIEW.md)
python3 scripts/precheck_fingerprint.py /path/to/repo

# Static scan — JSON lines, one finding per check
bash scripts/vibecheck.sh /path/to/repo

# What a bundled tool can and cannot claim, before you run it
bash scripts/vibecheck.sh --capability
python3 scripts/supabase_probe.py --capability

# Which verification method fits a control, and why the stronger ones are unavailable
python3 scripts/providers.py --list
python3 scripts/providers.py --select vibecheck.control.authz.object_level \
  --environment private_test --target source_tree --target supabase_project

# Optional: also ask the configured npm registry for advisory data
# (this sends dependency metadata over the network)
bash scripts/vibecheck.sh --online-audit /path/to/repo

# Live Supabase probe (legacy anon or modern publishable key; no writes by default)
python3 scripts/supabase_probe.py --url "$SUPABASE_URL" --anon "$SUPABASE_ANON_KEY"

# Opt-in anon write probe: may create a real row, so it must say where and on whose authority
python3 scripts/supabase_probe.py --url "$SUPABASE_URL" --anon "$SUPABASE_ANON_KEY" \
  --write-probe --environment private_test --authorized-by "founder:mari"

# Scored workbooks (needs openpyxl)
python3 -m pip install -r requirements.txt
python3 scripts/build_workbook.py --outdir ./out
```

Each finding is tagged with the checklist item numbers it maps to.

## Scoring & verdict

Weights Critical=5 / High=3 / Medium=2 / Low=1. Screening rows (#60-#63, EU AI Act) carry weight 0 and are unscored. Pass-rate = passed ÷ verified; coverage = verified ÷ applicable.

The workbook computes the verdict. Percentages are supporting metrics, never release gates:

**Reviewer profile:** NOT REVIEWED → INCOMPLETE REVIEW (including unsupported Critical/High Passes or incomplete coverage) → BLOCK (Critical fail/acceptance) → BLOCK – RISK ACCEPTANCE REQUIRED (High fail) → FIX BEFORE RELEASE (any remaining Fail/Partial) → REVIEW COMPLETE — NO OPEN FAIL/PARTIAL.

**Founder profile:** NOT REVIEWED → REVIEW INCOMPLETE → DO NOT LAUNCH → FIX BEFORE LAUNCH → REVIEW COMPLETE — NO OPEN FAILURES.

There is deliberately no "READY TO SHIP" rung: a checklist cannot prove an app safe.

## Scope & limits

- The scanner is a **first pass**, not a proof. Every WARN needs confirmation, and every `NO_SIGNAL` needs independent evidence before a checklist Pass.
- The scanner never writes to the reviewed repo. `vibecheck-precheck` is the bounded exception: it writes only `TECHNICAL_OVERVIEW.md` (or a non-destructive companion draft when that filename already belongs to the project). Credential/high-entropy shapes retain at most an 8-character prefix; low-entropy quoted secret literals retain at most 4. Evidence lines are capped at 200 characters and total evidence is bounded. This is credential redaction, not general PII or confidential-data anonymisation; treat scanner output as sensitive and review it before pasting elsewhere.
- Dependency auditing is offline by default. `--online-audit` opts into an npm registry request that can disclose the dependency inventory.
- The Supabase probe sends **no writes by default**. PostgREST has no dry-run insert, so an anon-write test can create a real row; that probe is opt-in behind `--write-probe`, and the report states plainly when it was not run.
- The probe uses `HEAD` plus a one-row range rather than downloading rows or forcing an exact full-table count. Visible anonymous rows need intent review; zero rows can mean either RLS or an empty table, unless a supplied test account sees rows in the same window, which is the one case where empty is ruled out by observation. IDOR testing requires two distinct test accounts and an explicit known A-owned private record.
- The scanner's `authz.backend_target` check locates the project URL, the publishable/anon key and the generated Supabase client so the live probe has a target. Those values are public by construction, so a hit is a to-do with an address, never a leak report; on platform builds the committed `.env` that carries them will also trip the tracked-`.env` and gitignore checks, which is expected rather than a credential to rotate.
- One probe result is one authorization cell: this object, this actor, this operation, this environment. It is never evidence about another table, another operation, another account type, or another environment, and cross-account update and delete are not automated at all — those cells close only through an authorized manual test whose result is recorded.
- Choosing a verification method never authorizes running it. A selected plan that reaches the network, uses a credential, writes, deploys, or acts in an external account is a request naming the provider, the effects and the destinations; the run starts after that exact request is granted, not before. That grant covers one environment: authorising a probe of the pilot project does not authorise the same probe against production.
- Git history checks are pathspec-scoped to the directory you scan. If that directory sits inside a larger repo, the scanner says so rather than reporting a sibling project's leaks as yours.
- Legal items (GDPR, AI Act) are engineering-review flags, not legal advice.

## Development

```bash
python3 -m unittest discover -s tests -v   # scanner behaviour + consistency tests
python3 scripts/gen_map.py                 # regenerate references/checklist-map.md
python3 scripts/gen_map.py --check         # verify without modifying files
python3 scripts/gen_canonical.py           # regenerate control registry + framework mappings (vibecheck_v1, founder_focus)
python3 scripts/gen_canonical.py --check   # verify without modifying files
python3 scripts/gen_goldens.py             # regenerate the golden context/risk/readiness cases
python3 scripts/gen_goldens.py --check     # verify without modifying files
python3 scripts/gen_report_goldens.py      # regenerate founder/reviewer markdown reports
python3 scripts/gen_report_goldens.py --check
python3 scripts/gen_authz_fixture.py       # regenerate the Supabase authorization lifecycle fixture
python3 scripts/gen_authz_fixture.py --check
python3 scripts/gen_provider_goldens.py    # regenerate the worked provider-selection plans
python3 scripts/gen_provider_goldens.py --check

python3 scripts/readiness.py ENVELOPE.json --summary   # derive risk + readiness for one envelope
python3 scripts/report.py ENVELOPE.json --profile founder --lang en
python3 scripts/report.py ENVELOPE.json --profile reviewer --lang et --out report.md
```

### Editing the checklist

`scripts/items.py` holds the 89-item bank in four wordings, the verification metadata,
and `SCANNER_CHECKS` (which checklist items each scanner check covers, at which tier).
It is **generator-only**: edit it, then regenerate.

```bash
$EDITOR scripts/items.py
python3 scripts/gen_canonical.py    # registry + framework mappings
python3 scripts/gen_map.py          # references/checklist-map.md
```

Everything at runtime — the workbook, the checklist map, the adapters, the provider
registry — reads the generated registry and `vibecheck_v1` mapping instead, through
`controls.build_framework_mapping()`. Nothing imports `items.py` but the generators,
and a test fails if that changes. `tests/test_coverage_map.py` and
`tests/test_framework_mappings.py` fail if the scanner, the item bank, the generated
map, or the counts quoted in this README drift apart.

### The assessment model

Beneath the checklist is a normalized, versioned model of what was observed and what
was decided. `rfcs/0001-assessment-schema-v1.md` is its design contract; the JSON
Schemas and validated examples live in `schema/`.

The pipeline is one direction, and each arrow is a place where something is *not*
allowed to be skipped:

```text
Application context  ──►  environment + intended use
                              │
Signal ──► Evidence ──► Assessment ──► control status
                              │              │
                       contextual risk ──► risk scenario
                                               │
                                            Action ──► Procedure
                                                          │
                                              authorized attempt ──► new evidence
                                                                          │
                                                                      reassess
```

The distinctions are the point. A signal is not evidence, evidence is not an
assessment, and an assessment is not a control status. Tools produce scoped
evidence; a human or an accountable process decides. `NO_SIGNAL` is never a Pass,
and an unknown is never a Low.

| Module | Responsibility |
|---|---|
| `controls.py` | Stable control IDs and the framework mappings generated from them |
| `canonical.py` | Validate, serialize and migrate `vibecheck.assessment` envelopes |
| `context.py` | Versioned application context; every fact carries state, source and freshness |
| `risk.py` | Derive contextual risk deterministically; unknown inputs yield unknown, not low |
| `readiness.py` | Readiness for one explicit environment + intended-use pair |
| `scenarios.py` / `report.py` | Founder-first failure stories and completeness-safe reports |
| `actions.py` | Action/Procedure registry, per-attempt authorization, deadlines, rollback |
| `authz.py` | Authorization coverage: one result covers one object/actor/operation/environment |
| `providers.py` | What each verification method can observe, what it costs, and safe selection |
| `adapters.py` / `external_adapters.py` | Import tool output as normalized evidence; never run a tool |

**Controls and frameworks.** A control has a stable ID that never moves when wording
changes or the workbook is renumbered. Framework views reference controls; they do
not own them. `vibecheck_v1` is the 89-item checklist as one such view, and
`founder_focus` is a short go/no-go view that reuses the same control records without
duplicating any. Items and controls are many-to-many, each mapping edge carries its
provenance, and historical envelopes keep the schema, registry and mapping versions
that were current at assessment time.

**Readiness, not clearance.** Readiness is derived for one environment and intended
use at a time (`incomplete`, `blocked`, `conditional`, `no_known_blocker`) and names
the more exposed scopes it does *not* cover. Context can change priority and
proportionality; it never turns a failed control into a Pass.

**Authorization is per run and per scope.** Choosing a verification method does not
authorize running it. Anything that reaches the network, uses a credential, writes,
deploys or acts in an external account becomes a request naming the provider, the
effects and the destinations — and a grant covers one environment, so permission to
probe the pilot is not permission to probe production. A refused stronger method is
reported as a coverage gap naming the exact grant that would have enabled it, never
silently skipped.

**Migrating a finished workbook.** `adapters.import_workbook_rows` imports legacy
workbook cells as canonical assessments — the one importer that creates assessments,
because a completed workbook is a human's decision. Rows the workbook's own gates
forbid (Critical marked Accepted, an acceptance or Pass with no reason, a screening
status on an ordinary control) are refused and reported rather than imported, so the
importer never reports success on an envelope the validator would reject.

Some anonymous writes are the product working: a contact form has to accept a submission from a browser with no account behind it. Vibecheck never decides that for you and never infers it. An observed write the review has not been told about becomes a `decide` Action for the owner, and only a confirmed entry (who decided, and why) turns it from a violation into an intended exposure. Confirming it is where the work starts rather than stops, because the same path is reachable by automation: the exception is only valid while the same caller cannot read the table back **and** the write path is bounded by something evidenced — a per-source throttle, a bot-defence challenge such as Turnstile or hCaptcha, or a queue a human releases. Unbounded, it stays an open control with an immediate remediation, a material readiness unknown, and a refused Pass, because the form that takes one enquiry takes ten thousand: the table fills, the mail goes out, the quota drains and the real submissions are buried. The scanner reports the static half as `cost.public_write_abuse`, and `schema/examples/intended-anon-write.json` walks the case end to end.

`tests/fixtures/` holds miniature repos for warning signals, quiet signals, and prose false-positive cases. They contain fake credential shapes by design, so scanning this repository itself reports warnings inside `tests/fixtures/`.

## Legal reference notes (reviewed August 2026 — re-verify at assessment time)

- **EU AI Act:** use the [European Commission's current implementation timeline](https://digital-strategy.ec.europa.eu/en/faqs/navigating-ai-act) and the [enacted regulation](https://eur-lex.europa.eu/eli/reg/2024/1689/oj); do not rely on the workbook for a legal deadline or classification.
- **Data location:** do not assume that “EU-hosted” alone establishes compliance. Check GDPR/IKS roles and transfers, subprocessors (including LLM routing), the DPA/controller instructions, sector rules, retention obligations, and public-sector/essential-service requirements for the actual use case.

See `references/checklist-map.md` for the full item list, severities, EN/ET text, and scanner coverage.

## License

MIT — see [LICENSE](LICENSE).
