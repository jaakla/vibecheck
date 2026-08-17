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

Vibecheck's useful role is orchestration: it keeps technical, product, operational, and legal-review work from being silently skipped. For detection depth, use maintained specialist tools alongside it:

- Secrets: Gitleaks or TruffleHog over the full git history.
- SAST: Semgrep Community; CodeQL for public GitHub repositories.
- Dependencies and containers: OSV-Scanner or Trivy.
- Dynamic web testing: OWASP ZAP against an authorized staging deployment.
- Functional and authorization flows: Playwright with two test accounts.

These tools also have false positives/negatives, but they are substantially more mature than the bundled grep-based scanner.

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
python3 scripts/gen_canonical.py           # regenerate the control registry + vibecheck_v1 mapping
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

`scripts/items.py` is the single source of truth: the 89-item bank in four wordings, the verification metadata, and `SCANNER_CHECKS` (which checklist items each scanner check covers, and at which tier). `references/checklist-map.md` is generated from it, and `tests/test_coverage_map.py` fails if the scanner, the item bank, the generated map, or the counts quoted in this README drift apart.

`rfcs/0001-assessment-schema-v1.md` is the design contract for the next-generation assessment model (stable control IDs, evidence, contextual risk, actions/procedures, environment-scoped readiness). Its JSON Schemas and validated examples live in `schema/`; `tests/test_rfc_schema.py` pins the schema invariants and the lossless `vibecheck_v1` mapping against `items.py`.

Increment 1 of that model is implemented: `scripts/controls.py` holds the hand-reviewed stable control-ID table (generated artifacts: `schema/vibecheck.controls.v1.json` and the full 89-entry mapping `schema/mappings/vibecheck_v1.json`), `scripts/canonical.py` validates, serializes and migrates `vibecheck.assessment` envelopes, and `scripts/adapters.py` imports scanner JSONL and Supabase probe JSON into canonical envelopes (and exports back, byte-compatibly, for the current report and workbook paths). `tests/test_canonical.py` covers all of it; `items.py` stays the authoring source until cutover.

Increment 2 adds the context and the two things derived from it (schema version 1.1.0, additive). `scripts/context.py` captures the application context as a separately versioned record where every fact carries its own state — confirmed, inferred, conflicting or unknown — with a source, a rationale, its own revision, expiry and reassessment triggers, all independent of the source-code fingerprint. `scripts/risk.py` derives contextual risk from it deterministically: impact from intrinsic severity plus context, exposure from the environment plus context, level from the shipped matrix, with an unknown or conflicting input producing an unknown level rather than a low one. `scripts/readiness.py` derives readiness for one explicit environment + intended-use pair (`incomplete`, `blocked`, `conditional`, `no_known_blocker` — never "secure" or "ready to ship"), lists the more exposed scopes it does *not* cover, and keeps the existing checklist verdict beside it with a written explanation whenever the two differ. The dimension list and the derivation rules are reviewable data (`schema/vibecheck.context.v1.json`, `schema/risk-derivation.v1.json`), and `tests/golden/` holds four fully derived cases — developer-only prototype, invite-only pilot, public product, and a sensitive/high-impact use with unknowns — regenerated by `scripts/gen_goldens.py` and pinned by `tests/test_context.py`.

Increment 3 adds the founder-first report (schema version 1.2.0, additive). `scripts/scenarios.py` groups unresolved assessments and their current/future contextual risks into deterministic failure stories without changing a control status, intrinsic severity, or accepted-risk record. `scripts/report.py` ranks at most five headlines, then separately proves complete placement of every unresolved Critical/High control, readiness-blocking unknown, incident response, specialist escalation, and blocking/overdue action. One object gets one visible disclosure slot even when it belongs to several mandatory categories. The report also partitions actions by who can act, renders founder/reviewer profiles in EN/ET, and retains all 89 checklist rows plus evidence, risks, scenario-to-assessment traceability, actions, and procedures in the technical appendix. The grouping, ranking, disclosure, and action-section rules are reviewable data in `schema/report-derivation.v1.json`; fixed bilingual wording is in `schema/report-wording.v1.json`; reviewable markdown goldens live in `tests/golden/reports/`.

Increment 4 replaces the fix workflow's canonical AUTO/PROPOSE/ADVISORY tiers with the versioned Action/Procedure registry (schema version 1.3.0, additive). `scripts/actions.py` enforces Action and Procedure lineages, lifecycle transitions, dependency safety, usable deadline triggers, exact per-attempt authorization, observed-effect scope, rollback records, and evidence-plus-reassessment completion. A single Action can offer automated, guided, and specialist Procedures without duplicating its outcome. The old three tiers survive only in a clearly lossy derived compatibility view; they never grant permission. The policy is reviewable data in `schema/action-policy.v1.json`, and the fully validated three-method example is `schema/examples/action-procedure-registry.json`.

Increment 5 runs the Supabase authorization workflow through the whole model (schema version 1.4.0, additive). `scripts/authz.py` counts what an observation is actually worth: one probe result covers one object, one actor, one operation, in one environment. The required matrix comes from the representative private objects the context declares (`context.authorization_objects`), so a single denied read can never close object-level authorization — with gaps, `partial` is the strongest available status, the gaps become material readiness unknowns and one open verify Action each, and observations made in the pilot do not count for the public scope. Invalid keys, expired tokens, network failures, empty tables and non-200 responses record `inconclusive`, which never counts as a denial; static migration analysis fills no cell at all. `scripts/actions.py` adds the remediation checkpoints — a diff-first, branch-first repository patch, a separately authorized deployment naming its target and revision, and a live verification that runs after the deploy and is independent of whoever deployed it — so a patch that was never deployed leaves the Action incomplete. Read-only stays the probe default; a data-writing probe is opt-in per run and records its consent, target environment, result and cleanup state (`--write-probe` now requires `--environment` and `--authorized-by`, and reports the exact row it created). The model is reviewable data in `schema/authz-coverage.v1.json`, the complete lifecycle — failed control, approved patch, deployment checkpoint, fresh verification, reassessment, and a write probe that reopens the control — is `schema/examples/supabase-authz-lifecycle.json`, regenerated by `scripts/gen_authz_fixture.py`.

Increment 6 adds the verification-provider registry and the selection policy that reads it (schema version 1.5.0, additive). A provider is a way of finding something out, never a way of deciding something, and `schema/provider-registry.v1.json` states per method what it can observe — which controls, subjects, evidence operations and authorization cells, at what strength, and what result would let an assessor close that aspect — alongside what it costs to run: the executor it needs, the tools, credentials and data fixtures, the environments it can speak about, monetary/compute/human cost, whether it reaches the network and what data leaves for where, and its read/write/destructive/deployment/external-account effects. `scripts/providers.py` matches those capabilities against a requirement and an offer, where the offer is what this review actually has and what its owner has actually authorized. The default offer grants nothing, so only reading what the review was already pointed at is selectable until somebody says otherwise.

Selection is deterministic — a live observation outranks a source reading, a decisive method outranks an indicative one, and the declared fallback order breaks the rest, ending in a provider ID so the same inputs always produce the same plan. The chain for authorization is the Supabase two-account probe, then a Playwright two-account flow, then a guided browser test, then code and policy review. What matters more than the ranking is that nothing disappears and nothing is overstated: a stronger method that was refused for a missing credential, an absent install, an unauthorized network call or an unauthorized write is reported as a coverage gap naming the exact grant that would have enabled it, while a method with nothing to observe here is reported as inapplicable rather than as work somebody forgot. Effects that need authorization turn a plan step into a request rather than an instruction, checked per cell as well as per provider: a read-only grant runs the probe's read and reports its insert as a gap. Authorization is also scoped to one environment — permission to probe the pilot is not permission to probe production, and a live method offered a mismatched scope is refused rather than quietly re-pointed. Covering every requested cell establishes the requirement, never the control — closure stays with the coverage model and the assessment rules. Rule R24 holds provider evidence to the capability it named, checked per claimed control rather than pooled across them, so a source reading is structurally unable to carry a coverage cell and one covered control cannot vouch for another. `vibecheck.sh`, `analyze_sql.py` and `supabase_probe.py` are registry providers now; their CLI output is unchanged, the first two answer `--capability` with their own record, and the adapters attach the capability *as exercised* to every envelope they build. Six worked plans are pinned in `tests/golden/providers/selection.md`.

Some anonymous writes are the product working: a contact form has to accept a submission from a browser with no account behind it. Vibecheck never decides that for you and never infers it. An observed write the review has not been told about becomes a `decide` Action for the owner, and only a confirmed entry (who decided, and why) turns it from a violation into an intended exposure. Confirming it is where the work starts rather than stops, because the same path is reachable by automation: the exception is only valid while the same caller cannot read the table back **and** the write path is bounded by something evidenced — a per-source throttle, a bot-defence challenge such as Turnstile or hCaptcha, or a queue a human releases. Unbounded, it stays an open control with an immediate remediation, a material readiness unknown, and a refused Pass, because the form that takes one enquiry takes ten thousand: the table fills, the mail goes out, the quota drains and the real submissions are buried. The scanner reports the static half as `cost.public_write_abuse`, and `schema/examples/intended-anon-write.json` walks the case end to end.

`tests/fixtures/` holds miniature repos for warning signals, quiet signals, and prose false-positive cases. They contain fake credential shapes by design, so scanning this repository itself reports warnings inside `tests/fixtures/`.

## Legal reference notes (reviewed August 2026 — re-verify at assessment time)

- **EU AI Act:** use the [European Commission's current implementation timeline](https://digital-strategy.ec.europa.eu/en/faqs/navigating-ai-act) and the [enacted regulation](https://eur-lex.europa.eu/eli/reg/2024/1689/oj); do not rely on the workbook for a legal deadline or classification.
- **Data location:** do not assume that “EU-hosted” alone establishes compliance. Check GDPR/IKS roles and transfers, subprocessors (including LLM routing), the DPA/controller instructions, sector rules, retention obligations, and public-sector/essential-service requirements for the actual use case.

See `references/checklist-map.md` for the full item list, severities, EN/ET text, and scanner coverage.

## License

MIT — see [LICENSE](LICENSE).
