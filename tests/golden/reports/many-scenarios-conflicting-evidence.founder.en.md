# Vibecheck review: what can go wrong, and what to do next

**Northstar Pilot**

> Vibecheck reports known blockers for a stated environment and intended use, on the evidence recorded here. It is not a certification, it does not state that an application is secure, and it never says an application is ready to ship.
>
> Everything below is scoped: a finding about one environment and intended use says nothing about a wider one, and an unreviewed control is not a passing one.
>
> Unknown never means low, and it never means permission to proceed. It means the evidence needed to answer is missing.

Envelope va-golden-many-scenarios, revision 1, derived 2026-08-16T12:00:00Z.

## What was assessed

| — | — |
|---|---|
| Application | Northstar Pilot |
| What it does | An invite-only order and support assistant intended to become a public product. |
| Platform | react+supabase+stripe+llm |
| Assessed environment and use | private test + invite-only pilot |
| Scopes under consideration | private test + invite-only pilot; public release + public product |
| Data involved | Names, email addresses, order history, support messages and hosted-checkout payment references for named pilot users. |
| Context confirmation | reviewed and confirmed by a human |
| Context revision | 1 |
| Context valid until | 2026-11-16T00:00:00Z |

### Recorded facts about the application

| Question | Answer | How we know | Source |
|---|---|---|---|
| Where is the application in its life right now? | piloted by a named group | confirmed by the owner | founder:liis |
| Who can use it today, and how many of them are there? | up to about 20 named people | confirmed by the owner | founder:liis |
| From where can the running application be reached? | the public internet at an unadvertised address | confirmed by the owner | founder:liis |
| What does someone need in order to get in? | accounts created by invitation only | confirmed by the owner | founder:liis |
| Whose data lives next to whose? | many customers in the same tables | confirmed by the owner | founder:liis |
| What is the most sensitive data it holds or touches? | personal data of identifiable people | confirmed by the owner | founder:liis |
| Does the application move money? | charges, payouts or metered spend | confirmed by the owner | founder:liis |
| What can it do beyond reading and writing its own data? | acts in external systems: email, payments, third-party APIs | confirmed by the owner | founder:liis |
| What happens if it stops working or misbehaves? | useful, but the work can go on without it | confirmed by the owner | founder:liis |

## Where this stands

### private test + invite-only pilot

**blocked** — There is a known blocker for this environment and intended use. It is listed below with what it rests on.

*Checklist verdict:* DO NOT LAUNCH (aligned). The vibecheck_v1 checklist verdict and the readiness state for this scope agree. The verdict is one judgement for the whole application; readiness is scoped to this environment and intended use.

*Blockers:*

- `rsk-authz.object_level-private_test.invite_only_pilot-current-r1` — Critical contextual security risk in this scope for unresolved control(s) vibecheck.control.authz.object_level (assessment status: fail)
- `rsk-cost.budget_caps-private_test.invite_only_pilot-current-r1` — High contextual financial risk in this scope for unresolved control(s) vibecheck.control.cost.budget_caps (assessment status: fail)
- `rsk-llm.untrusted_content_isolation-private_test.invite_only_pilot-current-r1` — Critical contextual security risk in this scope for unresolved control(s) vibecheck.control.llm.untrusted_content_isolation (assessment status: fail)
- `rsk-secrets.no_repo_history_leaks-private_test.invite_only_pilot-current-r1` — Critical contextual security risk in this scope for unresolved control(s) vibecheck.control.secrets.no_repo_history_leaks (assessment status: fail)

*Moving to a wider scope:*

- public release + public product: blocked. Moving to this scope is a separate question with its own answer: blocked (10 blocker(s), 0 material unknown(s)). Readiness here is not permission to go there.

*Valid until:* 2026-09-15T12:00:00Z

### public release + public product

**blocked** — There is a known blocker for this environment and intended use. It is listed below with what it rests on.

*Checklist verdict:* DO NOT LAUNCH (aligned). The vibecheck_v1 checklist verdict and the readiness state for this scope agree. The verdict is one judgement for the whole application; readiness is scoped to this environment and intended use.

*Blockers:*

- `act-contain-cross-account-incident` — Open incident_response action whose blocking scope covers this environment and intended use: Contain the cross-account order exposure and determine which records were accessed.
- `act-verify-error-paths` — Open verify action whose blocking scope covers this environment and intended use: Collect a bounded error-path inventory for the developer to instrument.
- `act-decide-support-data` — Open decide action whose blocking scope covers this environment and intended use: Decide and document which order fields the support assistant is allowed to receive.
- `rsk-authz.object_level-public_release.public_product-event_triggered-r1` — Critical contextual security risk in this scope for unresolved control(s) vibecheck.control.authz.object_level (assessment status: fail)
- `rsk-cost.budget_caps-public_release.public_product-event_triggered-r1` — Critical contextual financial risk in this scope for unresolved control(s) vibecheck.control.cost.budget_caps (assessment status: fail)
- `rsk-data.tested_backups-public_release.public_product-event_triggered-r1` — Critical contextual reliability risk in this scope for unresolved control(s) vibecheck.control.data.tested_backups (assessment status: fail)
- `rsk-llm.untrusted_content_isolation-public_release.public_product-event_triggered-r1` — Critical contextual security risk in this scope for unresolved control(s) vibecheck.control.llm.untrusted_content_isolation (assessment status: fail)
- `rsk-obs.error_tracking-public_release.public_product-event_triggered-r1` — High contextual reliability risk in this scope for unresolved control(s) vibecheck.control.obs.error_tracking (assessment status: fail)
- `rsk-privacy.data_minimisation-public_release.public_product-event_triggered-r1` — High contextual privacy risk in this scope for unresolved control(s) vibecheck.control.privacy.data_minimisation (assessment status: fail)
- `rsk-secrets.no_repo_history_leaks-public_release.public_product-event_triggered-r1` — Critical contextual security risk in this scope for unresolved control(s) vibecheck.control.secrets.no_repo_history_leaks (assessment status: fail)

*Valid until:* 2026-09-15T12:00:00Z

## What can go wrong

### 1. A key someone else can use

A credential that reached the browser bundle, the repository or a log is usable by whoever finds it, with everything it was issued for. No further defect is needed. At stake: personal data of identifiable people. Reachable by: up to about 20 named people. Risk today, for private test + invite-only pilot: critical. Risk if this moves to public release + public product: critical.

- **Risk today** (private test + invite-only pilot): critical — `rsk-secrets.no_repo_history_leaks-private_test.invite_only_pilot-current-r1`
- **Risk later** (public release + public product): critical — `rsk-secrets.no_repo_history_leaks-public_release.public_product-event_triggered-r1`

*This rests on:*

- #9 Have you checked that secrets were never committed to the code repository, even in the past? (Fail) — `asm-secrets.no_repo_history_leaks`

*Evidence:* `ev-no_repo_history_leaks-02`

### 2. Someone reaches data that is not theirs

Server-side authorization is the only thing standing between one user's records and everybody else. Where it is not enforced, reading or changing someone else's data needs no exploit at all. At stake: personal data of identifiable people. Reachable by: up to about 20 named people. Risk today, for private test + invite-only pilot: critical. Risk if this moves to public release + public product: critical.

- **Risk today** (private test + invite-only pilot): critical — `rsk-authz.object_level-private_test.invite_only_pilot-current-r1`
- **Risk later** (public release + public product): critical — `rsk-authz.object_level-public_release.public_product-event_triggered-r1`

*This rests on:*

- #13 Have you tested with two separate accounts that User A cannot view, edit or delete User B's data? (Fail) — `asm-authz.object_level`
  - *Evidence that disagrees* `ev-object-level-support` — *Resolution:* The code shape is only indicative; the scoped live cross-account result decides this assessment.

*Evidence:* `ev-object-level-support`, `ev-object_level-01`

*Next steps:*

- **Fix now** `act-contain-cross-account-incident` — Contain the cross-account order exposure and determine which records were accessed.

### 3. The AI feature is talked into working against you

Text the model reads is untrusted input. Where model output reaches a tool, a shell or a database, whoever writes that text is steering the application. At stake: personal data of identifiable people. Reachable by: up to about 20 named people. Risk today, for private test + invite-only pilot: critical. Risk if this moves to public release + public product: critical.

- **Risk today** (private test + invite-only pilot): critical — `rsk-llm.untrusted_content_isolation-private_test.invite_only_pilot-current-r1`
- **Risk later** (public release + public product): critical — `rsk-llm.untrusted_content_isolation-public_release.public_product-event_triggered-r1`

*This rests on:*

- #78 Can a user (or a web page the AI reads) trick the AI into ignoring its rules or leaking secrets? (Fail) — `asm-llm.untrusted_content_isolation`

*Evidence:* `ev-untrusted_content_isolation-07`

### 4. The bill runs away, or someone else runs it up

Unbounded work on a metered provider turns a careless user, a loop or a bot into a bill. Without caps and limits, nobody notices until the invoice or the outage arrives. At stake: personal data of identifiable people. Reachable by: up to about 20 named people. Risk today, for private test + invite-only pilot: high. Risk if this moves to public release + public product: critical.

- **Risk today** (private test + invite-only pilot): high — `rsk-cost.budget_caps-private_test.invite_only_pilot-current-r1`
- **Risk later** (public release + public product): critical — `rsk-cost.budget_caps-public_release.public_product-event_triggered-r1`

*This rests on:*

- #24 Have you set a hard spending cap and billing alerts on every paid service (AI, hosting, email)? (Fail) — `asm-cost.budget_caps`

*Evidence:* `ev-budget_caps-03`

### 5. Data disappears and cannot be brought back

Data that has never been restored from a backup is data the business only assumes it has. A destructive migration or a mistaken delete is where the assumption gets tested. At stake: personal data of identifiable people. Reachable by: up to about 20 named people. Risk today, for private test + invite-only pilot: moderate. Risk if this moves to public release + public product: critical.

- **Risk today** (private test + invite-only pilot): moderate — `rsk-data.tested_backups-private_test.invite_only_pilot-current-r1`
- **Risk later** (public release + public product): critical — `rsk-data.tested_backups-public_release.public_product-event_triggered-r1`

*This rests on:*

- #34 Do automatic backups exist, and has someone actually restored one to prove it works? (Fail) — `asm-data.tested_backups`

*Evidence:* `ev-tested_backups-04`

The summary above shows the highest-ranked failure stories only. Everything left below the cap keeps its controls, assessments, evidence, risks, actions and procedures in the appendix, and anything that must not be hidden is repeated in full in the section below.

## Blockers and escalations that may not be hidden

These items are shown regardless of the headline limit. Each appears exactly once here or in a headline scenario above, and every one of them is traceable in the appendix.

### Unresolved Critical and High controls

*A Critical or High control whose requirement is not met. Contextual risk can make it less urgent here; it does not make it met.*

In this category: 5. Told as a failure story above: 5. Listed here: 0. Cross-listed under another mandatory category: 0.

### Unknowns that block readiness

*Something that could hide a blocker is not established. Until it is, this scope cannot be called clear.*

Nothing in this category.

### Incident response

*Something has already happened and the response is not finished.*

In this category: 1. Told as a failure story above: 1. Listed here: 0. Cross-listed under another mandatory category: 0.

### Specialist escalations

*This needs a specialist. Vibecheck is explicitly not one, and neither is a checklist.*

In this category: 1. Told as a failure story above: 1. Listed here: 0. Cross-listed under another mandatory category: 0.

### Deadlines blocking the assessed use

*This work blocks the environment and intended use being assessed, or its deadline has already passed.*

In this category: 3. Told as a failure story above: 1. Listed here: 2. Cross-listed under another mandatory category: 0.

- `act-decide-support-data` **Before public launch** — Decide and document which order fields the support assistant is allowed to receive. (the owner)
- `act-verify-error-paths` **Before public launch** — Collect a bounded error-path inventory for the developer to instrument. (a developer)

### Screening rows needing a specialist

*A screening row a reviewer marked as needing specialist judgement. It has no scheduled action yet.*

Nothing in this category.

## What to do next

### Vibecheck can do now

- **Before public launch** — Collect a bounded error-path inventory for the developer to instrument. `act-verify-error-paths`
  - *Why:* The current scan shows no monitored error path.
  - *Owner:* a developer · *State:* open
  - *What closes it:* The inventory names every reviewed server error path and its current handling.
  - *Blocks:* public release + public product
  - *Candidate procedures:* `prc-inventory-error-paths`

### You need to do

- **Before public launch** — Decide and document which order fields the support assistant is allowed to receive. `act-decide-support-data`
  - *Why:* The owner must define the minimum necessary data before the code can enforce it.
  - *Owner:* the owner · *State:* open
  - *What closes it:* A reviewed field allowlist and retention statement are recorded.
  - *Blocks:* public release + public product

### Needs a developer or a specialist

- **Fix now** — Contain the cross-account order exposure and determine which records were accessed. `act-contain-cross-account-incident`
  - *Why:* The authorized test demonstrated access across account boundaries.
  - *Owner:* a specialist · *State:* open
  - *What closes it:* Access is denied in a repeated two-account test, affected access is reviewed, and the control is reassessed.
  - *Blocks:* public release + public product
  - *Candidate procedures:* `prc-contain-cross-account-incident`

### Can wait

- **Backlog** — Refactor the test-data helper when the next test suite cleanup is scheduled. `act-refactor-test-helper`
  - *Why:* The helper is awkward but does not block any assessed scope.
  - *Owner:* a developer · *State:* open
  - *What closes it:* The helper has focused tests and no duplicated setup.

## Confidence and assumptions

Confidence in the derived levels: high. Every context fact these levels depend on is confirmed by a human with authority over the application.

- Customers share one datastore, so a single authorization defect can cross tenants; context model v1 counts that blast radius through audience_scale only.
- This scope is not the one the application is in today, so this level is a floor for the move to public_release, not a measurement of it.
- Entering that scope implies audience_scale of at least 'open_small'; authentication of at least 'open_signup'; network_exposure of at least 'public_internet'; the captured values are lower and the higher reading was used.

Grouping findings into stories changes nothing about them: every control keeps its status, its severity and its accepted-risk record exactly as the reviewer left it.

## Technical appendix

The appendix is the reviewer record: every checklist row, every evidence item, every derived risk, every scenario, every action and every procedure, whether or not it reached the summary above.

### A. The full reviewer checklist

A blank status means the row was never reviewed. That is deliberately different from Not tested, which is a reviewer's recorded decision not to test it.

| # | Category | Control | Severity | Status | Assessment | Evidence |
|---|---|---|---|---|---|---|
| 1 | 1. Architecture reasonableness | Stack choices are mainstream and maintainable: widely-used language, framework and database with documentation, community and hireable developers | High | Pass | `asm-arch.mainstream_stack` | `ev-baseline-review` |
| 2 | 1. Architecture reasonableness | Primary data store fits the workload and hosting model: managed persistent DB for multi-user data; no SQLite/JSON-file/localStorage as system of record on serverless or ephemeral hosting | High | Pass | `asm-arch.datastore_fit` | `ev-baseline-review` |
| 3 | 1. Architecture reasonableness | Authentication is a proven provider or library (Supabase Auth, Firebase, Auth0, NextAuth, Clerk, etc.); no hand-rolled password hashing, session tokens or JWT schemes | High | Pass | `asm-arch.proven_auth_provider` | `ev-baseline-review` |
| 4 | 1. Architecture reasonableness | Complexity is proportional to the problem: no premature microservices/queues/orchestration for an MVP; no single god-module holding all logic | Medium | not reviewed | — | — |
| 5 | 1. Architecture reasonableness | One consistent pattern per concern: a single data-access layer, one state-management approach, one styling system - no parallel duplicated stacks accreted across sessions | Medium | not reviewed | — | — |
| 6 | 1. Architecture reasonableness | Hosting matches runtime needs: long-running jobs, websockets, cron and background work are supported by the platform's execution model (timeouts, persistent processes) | Medium | not reviewed | — | — |
| 7 | 2. Secrets & credentials | No secret-like literals in frontend source | Critical | Pass | `asm-secrets.no_frontend_literals` | `ev-baseline-review` |
| 8 | 2. Secrets & credentials | No provider key prefixes shipped to client (sk-, AKIA, service_role, etc.) | Critical | Pass | `asm-secrets.no_client_provider_keys` | `ev-baseline-review` |
| 9 | 2. Secrets & credentials | No secrets in current tree, git history, or public build bundle (.env excluded from VCS) | Critical | Fail | `asm-secrets.no_repo_history_leaks` | `ev-no_repo_history_leaks-02` |
| 10 | 2. Secrets & credentials | Secrets injected securely at runtime; not in code/images/logs; access restricted; rotation supported | High | Pass | `asm-secrets.secure_runtime_injection` | `ev-baseline-review` |
| 11 | 2. Secrets & credentials | Any exposed active credential treated as an incident: rotated, sessions revoked, logs inspected, removed from history | Critical | Pass | `asm-secrets.leak_incident_response` | `ev-baseline-review` |
| 12 | 3. Authorization & access control | Authorization enforced server-side, default-deny | Critical | Pass | `asm-authz.server_side_default_deny` | `ev-baseline-review` |
| 13 | 3. Authorization & access control | Object-level authorization: users cannot reach records they don't own (IDOR) | Critical | Fail | `asm-authz.object_level` | `ev-object_level-01` |
| 14 | 3. Authorization & access control | No data readable/writable by an unauthenticated/anon caller unless intended public | Critical | Pass | `asm-authz.anon_data_access` | `ev-baseline-review` |
| 15 | 3. Authorization & access control | Tenant isolation: no cross-tenant data access | Critical | Pass | `asm-authz.tenant_isolation` | `ev-baseline-review` |
| 16 | 3. Authorization & access control | Privileged/admin actions enforced server-side (Critical where admin functions are meaningful) | Critical | Pass | `asm-authz.admin_actions_server_side` | `ev-baseline-review` |
| 17 | 4. Product readiness - is it real? (not a security score) | Data truly persists (verified in the datastore) | High | Pass | `asm-product.data_persistence` | `ev-baseline-review` |
| 18 | 4. Product readiness - is it real? (not a security score) | Behaviour matches the documented product claim; mocks/fixtures/fallbacks not presented as live output | High | Pass | `asm-product.no_mocked_output` | `ev-baseline-review` |
| 19 | 4. Product readiness - is it real? (not a security score) | Emails/notifications actually deliver under production conditions | Medium | not reviewed | — | — |
| 20 | 4. Product readiness - is it real? (not a security score) | Payment account, keys, webhooks AND mode match the intended deployment environment | High | Pass | `asm-product.payment_mode_match` | `ev-baseline-review` |
| 21 | 4. Product readiness - is it real? (not a security score) | File uploads land in real storage and are retrievable | Medium | not reviewed | — | — |
| 22 | 4. Product readiness - is it real? (not a security score) | Search/filters query the backend, not a truncated client array | Medium | not reviewed | — | — |
| 23 | 5. Cost & abuse blast radius | Quotas, per-user budgets, per-operation maximums, timeouts and concurrency caps on paid/LLM work | High | Pass | `asm-cost.usage_quotas` | `ev-baseline-review` |
| 24 | 5. Cost & abuse blast radius | Hard budget caps + billing alerts on every paid provider | High | Fail | `asm-cost.budget_caps` | `ev-budget_caps-03` |
| 25 | 5. Cost & abuse blast radius | No unbounded loops / recursive agent steps; max-steps enforced | High | Pass | `asm-cost.bounded_agent_loops` | `ev-baseline-review` |
| 26 | 5. Cost & abuse blast radius | Expensive endpoints require auth; unauthenticated search/query bounded | High | Pass | `asm-cost.expensive_endpoints_auth` | `ev-baseline-review` |
| 27 | 5. Cost & abuse blast radius | Request-body/upload size limits; email/SMS abuse limits; webhook replay protection | Medium | not reviewed | — | — |
| 28 | 6. Input handling & injection | Server-side validation on all inputs | High | Pass | `asm-input.server_side_validation` | `ev-baseline-review` |
| 29 | 6. Input handling & injection | All DB queries use parameter binding / safe query API; raw fragments & dynamic identifiers allowlisted | High | Pass | `asm-input.sql_parameterized` | `ev-baseline-review` |
| 30 | 6. Input handling & injection | Output encoded per context (HTML/attr/JS/URL); HTML sanitized only when intentionally allowed; dangerous URL schemes blocked | High | Pass | `asm-input.output_encoding` | `ev-baseline-review` |
| 31 | 6. Input handling & injection | File uploads: content/MIME/magic-byte validation, path-traversal safe, isolated storage, randomised names | Medium | not reviewed | — | — |
| 32 | 6. Input handling & injection | Other injection classes considered where relevant: command, SSRF, template, path traversal, open redirect, deserialisation | Medium | not reviewed | — | — |
| 33 | 7. Data, migrations, backups | Schema changes via committed migrations; DB constraints, not only app validation | Medium | not reviewed | — | — |
| 34 | 7. Data, migrations, backups | Backups configured, encrypted, access-controlled - and a restore has actually been tested (RPO/RTO known) | High | Fail | `asm-data.tested_backups` | `ev-tested_backups-04` |
| 35 | 7. Data, migrations, backups | No silent destructive migrations on prod; rollback/forward-recovery plan exists | High | Pass | `asm-data.safe_prod_migrations` | `ev-baseline-review` |
| 36 | 7. Data, migrations, backups | Deletion semantics designed: recoverable where the business needs it, irreversible within the promised window where privacy/security requires erasure | Medium | not reviewed | — | — |
| 37 | 8. Errors, logging & observability | No swallowed errors; fail-closed on security-relevant paths | Medium | not reviewed | — | — |
| 38 | 8. Errors, logging & observability | Error tracking on client AND server; structured logs with correlation IDs; secrets/PII redacted | Medium | Fail | `asm-obs.error_tracking` | `ev-error_tracking-05` |
| 39 | 8. Errors, logging & observability | No stack traces / internal errors leaked to users | High | Pass | `asm-obs.no_leaked_internals` | `ev-baseline-review` |
| 40 | 8. Errors, logging & observability | Security & key business events logged; background jobs/webhooks observable (High for billing/payment/workflow apps) | Medium | not reviewed | — | — |
| 41 | 8. Errors, logging & observability | Health checks + alerting with an owner; monitoring tested, not merely wired up | Low | not reviewed | — | — |
| 42 | 9. Config & deployment pipeline | Debug off in prod; verbose error pages disabled; no source maps/debug endpoints in public build | High | Pass | `asm-deploy.debug_disabled` | `ev-baseline-review` |
| 43 | 9. Config & deployment pipeline | Prod vs dev/staging config & data separated; no prod secrets in preview builds | High | Pass | `asm-deploy.env_separation` | `ev-baseline-review` |
| 44 | 9. Config & deployment pipeline | CORS allows only intended origins/methods/headers; credentialed cross-origin narrowly restricted and tested | High | Pass | `asm-deploy.cors_restricted` | `ev-baseline-review` |
| 45 | 9. Config & deployment pipeline | Transport security: HTTPS + HSTS; security headers appropriate to the app (CSP, frame, nosniff, referrer, permissions) | Medium | not reviewed | — | — |
| 46 | 9. Config & deployment pipeline | Production change control: branch protection, reviewed changes, rollback procedure, reproducible artefacts | Medium | not reviewed | — | — |
| 47 | 10. Third-party integrations | Inbound webhooks verify signatures + timestamp; endpoint rejects unrelated event types | High | Pass | `asm-integ.webhook_signatures` | `ev-baseline-review` |
| 48 | 10. Third-party integrations | OAuth state/PKCE/nonce validated; redirect URIs locked; tokens stored encrypted | Medium | not reviewed | — | — |
| 49 | 10. Third-party integrations | Least-privilege scopes; secret lifecycle handled when an integration is disconnected | Medium | not reviewed | — | — |
| 50 | 10. Third-party integrations | Idempotency + retry/backoff + dead-letter handling on payment/order/webhook handlers | High | Pass | `asm-integ.idempotent_handlers` | `ev-baseline-review` |
| 51 | 11. Dependencies & supply chain | Runtime+build deps inventoried and continuously scanned; exploitable findings triaged, fixed or formally accepted | Medium | not reviewed | — | — |
| 52 | 11. Dependencies & supply chain | Dependency risk signals reviewed (compromise, ownership transfer, unreviewed install scripts, unjustified new deps) | Low | not reviewed | — | — |
| 53 | 11. Dependencies & supply chain | Lockfile committed; build reproducible; CI actions/containers pinned | Low | not reviewed | — | — |
| 54 | 11. Dependencies & supply chain | Licenses compatible with the intended business model | Low | not reviewed | — | — |
| 55 | 12. Privacy & GDPR | Data minimisation + data map: what PII, why (lawful basis), where it lives, transfers | Medium | Fail | `asm-privacy.data_minimisation` | `ev-data_minimisation-06` |
| 56 | 12. Privacy & GDPR | Passwords never stored plaintext; sensitive data encrypted; tokens hashed | Critical | Pass | `asm-privacy.password_hashing` | `ev-baseline-review` |
| 57 | 12. Privacy & GDPR | PII not leaking into logs, analytics, or LLM prompts; provider retention/training settings reviewed | High | Pass | `asm-privacy.no_pii_leakage` | `ev-baseline-review` |
| 58 | 12. Privacy & GDPR | International transfer mechanism + subprocessors + residency acceptable (DB region AND LLM routing) | Medium | not reviewed | — | — |
| 59 | 12. Privacy & GDPR | Data-subject rights operable: notice, lawful basis, access, deletion (incl. backups/third parties), retention, breach handling | Medium | not reviewed | — | — |
| 60 | 13. EU AI Act - plain screening (not scored) | High-risk domain screen (Annex III / product safety): important decisions about people | Screening | Answered | `asm-aiact.high_risk_screen` | — |
| 61 | 13. EU AI Act - plain screening (not scored) | Transparency duties (Art. 50): synthetic/mistakable-for-human content | Screening | Answered | `asm-aiact.transparency_screen` | — |
| 62 | 13. EU AI Act - plain screening (not scored) | Prohibited-practice screen (Art. 5): scoring, manipulation, exploitation | Screening | Answered | `asm-aiact.prohibited_practice_screen` | — |
| 63 | 13. EU AI Act - plain screening (not scored) | Escalation: specialist review where any answer is yes/uncertain; role (provider/deployer) & GPAI use documented | Screening | Answered | `asm-aiact.specialist_escalation` | — |
| 64 | 14. Correctness & business logic | Invariants + DB constraints enforce core rules; state-machine transitions validated | High | Pass | `asm-logic.invariant_enforcement` | `ev-baseline-review` |
| 65 | 14. Correctness & business logic | Concurrency safe: idempotency beyond payments, optimistic concurrency / stale-write handling, transactional boundaries | High | Pass | `asm-logic.concurrency_safety` | `ev-baseline-review` |
| 66 | 14. Correctness & business logic | Money/tax/currency: integer/decimal math, rounding rules, locale handling | High | Pass | `asm-logic.money_math` | `ev-baseline-review` |
| 67 | 14. Correctness & business logic | Dates/time zones/DST handled explicitly | Medium | not reviewed | — | — |
| 68 | 14. Correctness & business logic | Permission changes mid-session take effect; irreversible actions are auditable | Medium | not reviewed | — | — |
| 69 | 15. Product readiness - testing (not a security score) | Automated checks for the primary business transaction and destructive actions | High | Pass | `asm-testing.core_flow_tests` | `ev-baseline-review` |
| 70 | 15. Product readiness - testing (not a security score) | Automated checks for auth + authorization/tenant separation | High | Pass | `asm-testing.authz_tests` | `ev-baseline-review` |
| 71 | 15. Product readiness - testing (not a security score) | Automated checks for payment/webhook handling where present; deployment startup/health | Medium | not reviewed | — | — |
| 72 | 15. Product readiness - testing (not a security score) | Deterministic/property-based tests for complex critical calculations | Low | not reviewed | — | — |
| 73 | 16. Performance (not a security score) | Server-side pagination limits; max export/report size; query timeouts | Medium | not reviewed | — | — |
| 74 | 16. Performance (not a security score) | Representative production queries have acceptable plans/latency; necessary indexes exist and are used | Low | not reviewed | — | — |
| 75 | 16. Performance (not a security score) | Connection/pool limits; cache correctness & invalidation; graceful degradation on provider limits | Low | not reviewed | — | — |
| 76 | 16. Performance (not a security score) | Frontend bundle size / cold-start within target | Low | not reviewed | — | — |
| 77 | 17. AI security (prompt injection & agents) | LLM output never reaches an exec/eval/shell/SQL sink without validation/schema | Critical | Pass | `asm-llm.no_output_to_exec` | `ev-baseline-review` |
| 78 | 17. AI security (prompt injection & agents) | Untrusted content is separated and identified as data; it cannot modify trusted instructions/permissions/policy | High | Fail | `asm-llm.untrusted_content_isolation` | `ev-untrusted_content_isolation-07` |
| 79 | 17. AI security (prompt injection & agents) | Tool-call authorisation based on the authenticated user, not model output; tools allowlisted; args validated; high-impact actions need human confirmation | High | Pass | `asm-llm.tool_call_authorization` | `ev-baseline-review` |
| 80 | 17. AI security (prompt injection & agents) | Untrusted external/RAG content treated as data; retrieval ACLs propagated; RAG-source poisoning considered | Medium | not reviewed | — | — |
| 81 | 17. AI security (prompt injection & agents) | LLM output rendered as text or sanitized; sensitive-output filtering; memory isolated between users/tenants | Medium | not reviewed | — | — |
| 82 | 18. Ownership, continuity & usability | Continuity: someone other than the original builder can access, deploy, restore and maintain the app | High | Pass | `asm-continuity.bus_factor` | `ev-baseline-review` |
| 83 | 18. Ownership, continuity & usability | Account ownership: domain, hosting, DB, email, payment and AI-provider accounts owned by you/your company | High | Pass | `asm-continuity.account_ownership` | `ev-baseline-review` |
| 84 | 18. Ownership, continuity & usability | Data export: important business and user data can be exported in a usable format | Medium | not reviewed | — | — |
| 85 | 18. Ownership, continuity & usability | Failure & recovery behaviour: on external/network failure the app shows a clear message and avoids losing/duplicating data | Medium | not reviewed | — | — |
| 86 | 18. Ownership, continuity & usability | Support path: users have a working way to report a problem and someone receives it | Low | not reviewed | — | — |
| 87 | 18. Ownership, continuity & usability | Product analytics: you can tell whether the main journey succeeds / where users drop off, without unnecessary PII | Low | not reviewed | — | — |
| 88 | 18. Ownership, continuity & usability | Cross-device: main flow tested on a real phone and in at least two common browsers | Low | not reviewed | — | — |
| 89 | 18. Ownership, continuity & usability | Basic accessibility: main flow usable with keyboard, readable text sizes and clear labels | Low | not reviewed | — | — |

### B. Evidence

| Evidence | Provider | Subject | Direction | Strength | Observed | Valid until | What it covers, and what it does not |
|---|---|---|---|---|---|---|---|
| `ev-baseline-review` | vibecheck reviewer | repo . | supports | indicative | 2026-08-16T12:00:00Z | 2026-09-15T12:00:00Z | The current working tree and project settings visible during the 16 August review. |
| `ev-budget_caps-03` | vibecheck reviewer | config provider:billing | refutes | decisive within its scope | 2026-08-16T12:00:00Z | 2026-09-15T12:00:00Z | The production-bound provider account settings reviewed with the owner. |
| `ev-data_minimisation-06` | vibecheck reviewer | document support-assistant prompt | refutes | indicative | 2026-08-16T12:00:00Z | 2026-09-15T12:00:00Z | The server prompt builder and one redacted trace. |
| `ev-error_tracking-05` | vibecheck reviewer | repo . | refutes | indicative | 2026-08-16T12:00:00Z | 2026-09-15T12:00:00Z | Current working tree only. |
| `ev-no_repo_history_leaks-02` | vibecheck reviewer | repo . | refutes | indicative | 2026-08-16T12:00:00Z | 2026-09-15T12:00:00Z | Current branch and reachable history; the secret value is redacted. |
| `ev-object-level-support` | developer walkthrough | endpoint /api/orders/:id | supports | indicative | 2026-08-16T12:00:00Z | 2026-09-15T12:00:00Z | The handler calls an ownership helper, but the live two-account test below contradicts the helper's expected behavior. |
| `ev-object_level-01` | authorized two-account API test | endpoint /api/orders/:id | refutes | decisive within its scope | 2026-08-16T12:00:00Z | 2026-09-15T12:00:00Z | One known private order in the pilot environment; no writes were attempted. |
| `ev-tested_backups-04` | vibecheck reviewer | document operations/backups | refutes | indicative | 2026-08-16T12:00:00Z | 2026-09-15T12:00:00Z | Runbooks and provider activity available during the review. |
| `ev-untrusted_content_isolation-07` | vibecheck reviewer | file api/support-agent | refutes | indicative | 2026-08-16T12:00:00Z | 2026-09-15T12:00:00Z | Current support-agent request path only. |

### C. Contextual risks

| Risk | Control | Domain | Scope | Horizon | Impact | Exposure | Level | Confidence |
|---|---|---|---|---|---|---|---|---|
| `rsk-authz.object_level-private_test.invite_only_pilot-current-r1` | `vibecheck.control.authz.object_level` | security | private test + invite-only pilot | today | severe | plausible | critical | high |
| `rsk-authz.object_level-public_release.public_product-event_triggered-r1` | `vibecheck.control.authz.object_level` | security | public release + public product | on a future move | severe | expected | critical | high |
| `rsk-cost.budget_caps-private_test.invite_only_pilot-current-r1` | `vibecheck.control.cost.budget_caps` | money | private test + invite-only pilot | today | major | plausible | high | high |
| `rsk-cost.budget_caps-public_release.public_product-event_triggered-r1` | `vibecheck.control.cost.budget_caps` | money | public release + public product | on a future move | severe | expected | critical | high |
| `rsk-data.tested_backups-private_test.invite_only_pilot-current-r1` | `vibecheck.control.data.tested_backups` | reliability | private test + invite-only pilot | today | moderate | plausible | moderate | high |
| `rsk-data.tested_backups-public_release.public_product-event_triggered-r1` | `vibecheck.control.data.tested_backups` | reliability | public release + public product | on a future move | severe | expected | critical | high |
| `rsk-llm.untrusted_content_isolation-private_test.invite_only_pilot-current-r1` | `vibecheck.control.llm.untrusted_content_isolation` | security | private test + invite-only pilot | today | severe | plausible | critical | high |
| `rsk-llm.untrusted_content_isolation-public_release.public_product-event_triggered-r1` | `vibecheck.control.llm.untrusted_content_isolation` | security | public release + public product | on a future move | severe | expected | critical | high |
| `rsk-obs.error_tracking-private_test.invite_only_pilot-current-r1` | `vibecheck.control.obs.error_tracking` | reliability | private test + invite-only pilot | today | moderate | plausible | moderate | high |
| `rsk-obs.error_tracking-public_release.public_product-event_triggered-r1` | `vibecheck.control.obs.error_tracking` | reliability | public release + public product | on a future move | moderate | expected | high | high |
| `rsk-privacy.data_minimisation-private_test.invite_only_pilot-current-r1` | `vibecheck.control.privacy.data_minimisation` | privacy | private test + invite-only pilot | today | moderate | plausible | moderate | high |
| `rsk-privacy.data_minimisation-public_release.public_product-event_triggered-r1` | `vibecheck.control.privacy.data_minimisation` | privacy | public release + public product | on a future move | moderate | expected | high | high |
| `rsk-secrets.no_repo_history_leaks-private_test.invite_only_pilot-current-r1` | `vibecheck.control.secrets.no_repo_history_leaks` | security | private test + invite-only pilot | today | severe | plausible | critical | high |
| `rsk-secrets.no_repo_history_leaks-public_release.public_product-event_triggered-r1` | `vibecheck.control.secrets.no_repo_history_leaks` | security | public release + public product | on a future move | severe | expected | critical | high |

### D. Scenario traceability

| Rank | Scenario | Title | Headline | Risk today | Risk later | Control ID | Assessment | Risk | Evidence | Action | Procedure |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | `scn-credential_exposure` | A key someone else can use | yes | critical | critical | `vibecheck.control.secrets.no_repo_history_leaks` | `asm-secrets.no_repo_history_leaks` | `rsk-secrets.no_repo_history_leaks-private_test.invite_only_pilot-current-r1`, `rsk-secrets.no_repo_history_leaks-public_release.public_product-event_triggered-r1` | `ev-no_repo_history_leaks-02` | — | — |
| 2 | `scn-unauthorised_data_access` | Someone reaches data that is not theirs | yes | critical | critical | `vibecheck.control.authz.object_level` | `asm-authz.object_level` | `rsk-authz.object_level-private_test.invite_only_pilot-current-r1`, `rsk-authz.object_level-public_release.public_product-event_triggered-r1` | `ev-object-level-support`, `ev-object_level-01` | `act-contain-cross-account-incident` | `prc-contain-cross-account-incident` |
| 3 | `scn-ai_manipulation` | The AI feature is talked into working against you | yes | critical | critical | `vibecheck.control.llm.untrusted_content_isolation` | `asm-llm.untrusted_content_isolation` | `rsk-llm.untrusted_content_isolation-private_test.invite_only_pilot-current-r1`, `rsk-llm.untrusted_content_isolation-public_release.public_product-event_triggered-r1` | `ev-untrusted_content_isolation-07` | — | — |
| 4 | `scn-runaway_cost_or_abuse` | The bill runs away, or someone else runs it up | yes | high | critical | `vibecheck.control.cost.budget_caps` | `asm-cost.budget_caps` | `rsk-cost.budget_caps-private_test.invite_only_pilot-current-r1`, `rsk-cost.budget_caps-public_release.public_product-event_triggered-r1` | `ev-budget_caps-03` | — | — |
| 5 | `scn-data_loss` | Data disappears and cannot be brought back | yes | moderate | critical | `vibecheck.control.data.tested_backups` | `asm-data.tested_backups` | `rsk-data.tested_backups-private_test.invite_only_pilot-current-r1`, `rsk-data.tested_backups-public_release.public_product-event_triggered-r1` | `ev-tested_backups-04` | — | — |
| 6 | `scn-personal_data_misuse` | Personal data ends up where it must not be | no | moderate | high | `vibecheck.control.privacy.data_minimisation` | `asm-privacy.data_minimisation` | `rsk-privacy.data_minimisation-private_test.invite_only_pilot-current-r1`, `rsk-privacy.data_minimisation-public_release.public_product-event_triggered-r1` | `ev-data_minimisation-06` | `act-decide-support-data` | — |
| 7 | `scn-silent_failure` | It breaks and nobody finds out | no | moderate | high | `vibecheck.control.obs.error_tracking` | `asm-obs.error_tracking` | `rsk-obs.error_tracking-private_test.invite_only_pilot-current-r1`, `rsk-obs.error_tracking-public_release.public_product-event_triggered-r1` | `ev-error_tracking-05` | `act-verify-error-paths` | `prc-inventory-error-paths` |

### E. Actions

| Action | Kind | Required outcome | Owner | Priority | Urgency | When | State | Blocks | Control ID | Risk | Scenario | Procedure | What closes it |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `act-contain-cross-account-incident` | incident response | Contain the cross-account order exposure and determine which records were accessed. | a specialist | unknown | immediate | Fix now | open | public release + public product | `vibecheck.control.authz.object_level` | — | — | `prc-contain-cross-account-incident` | Access is denied in a repeated two-account test, affected access is reviewed, and the control is reassessed. |
| `act-decide-support-data` | decision | Decide and document which order fields the support assistant is allowed to receive. | the owner | unknown | next | Before public launch | open | public release + public product | `vibecheck.control.privacy.data_minimisation` | — | — | — | A reviewed field allowlist and retention statement are recorded. |
| `act-refactor-test-helper` | fix | Refactor the test-data helper when the next test suite cleanup is scheduled. | a developer | unknown | backlog | Backlog | open | — | — | — | — | — | The helper has focused tests and no duplicated setup. |
| `act-verify-error-paths` | verify | Collect a bounded error-path inventory for the developer to instrument. | a developer | unknown | next | Before public launch | open | public release + public product | `vibecheck.control.obs.error_tracking` | — | — | `prc-inventory-error-paths` | The inventory names every reviewed server error path and its current handling. |

### F. Procedures

| Procedure | Title | Executor | Execution mode | Mechanism | Consent | Network | Effects | Legacy view | What closes it |
|---|---|---|---|---|---|---|---|---|---|
| `prc-contain-cross-account-incident` | Disable the affected order endpoint and deploy an authorization fix | a developer | guided | code_change_and_deployment | explicit consent | no | write, deployment | PROPOSE | A repeated two-account test denies cross-account reads. |
| `prc-inventory-error-paths` | Scan and review server error paths | Vibecheck | automated | read_only_source_review | not required | no | none | AUTO | A bounded path-and-handler inventory with review notes. |

### G. Procedure attempts

| Attempt | Action | Procedure | Environment | Result | Consent | Effects | Rollback | Evidence | Reassessment |
|---|---|---|---|---|---|---|---|---|---|

### H. Method and versions

| Method | Version |
|---|---|
| vibecheck.assessment | 1.4.0 |
| vibecheck_v1 | 2026.08 |
| vibecheck.controls | 1.0.0 |
| vibecheck.action_registry | 1.0.0 |
| vibecheck.risk_derivation | 1.0.0 |
| vibecheck.readiness | 1.0.0 |
| vibecheck.report_derivation | 1.1.0 |
| vibecheck.report | 1.1.0 |
| vibecheck.action_policy | 1.1.0 |
| vibecheck.report_wording | 1.1.0 |
