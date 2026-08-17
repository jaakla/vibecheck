---
name: vibecheck-fix
description: >
  Turn Vibecheck findings into versioned Actions and candidate Procedures, execute only an
  explicitly selected and authorized Procedure, record the exact ProcedureAttempt, and
  independently verify the result before completing the Action. Use after vibecheck-scan
  when the user asks to fix, remediate, patch, or resolve review findings.
---

# Vibecheck Fix

Remediate findings from `vibecheck-scan`. Never silently change security-relevant behaviour, and never claim a fix without fresh success evidence and reassessment.

## Canonical remediation model

Do not classify work canonically as AUTO, PROPOSE, or ADVISORY. Create:

- an `Action` for the required, testable outcome, with its reason, priority, owner, dependencies, lifecycle state, urgency, deadline policy, blocking environment/use scopes, success evidence, and controls to reassess;
- one `Procedure` per possible method. Keep `executor_role`, `execution_mode`, mechanism, exact tool/steps, inputs, effect targets, reversibility, consent, cost, network/data egress, failure/rollback, and verification separate;
- one immutable `ProcedureAttempt` for an execution, including the exact consent record and scope, authorized effects, environment, input references, observed side effects, result, rollback state, produced evidence, and reassessments.

One Action may offer automated, guided, and specialist Procedures. Automation is not authorization. Approval is a consent policy, not a mechanism. Specialist is an executor role, not a mechanism. Destructiveness is an effect property, not an effect target.

## Remediation checkpoints

A fix that touches a running system is three decisions, not one. Set `required_stages` on the Action and `stage` on each Procedure:

- `repository_patch` — writes the source, never deploys. The attempt records the exact diff that was shown, the branch, and who approved it before it ran. An approval timestamped after the change is not diff-first.
- `deployment` — a separate consent, asked for per run. The attempt names the environment it changed and the exact revision now live, and it does not run from a plain local context.
- `live_verification` — an observation of the deployed behaviour, made after the deploy, by someone or something other than whoever wrote and deployed it.

The Action completes only when each checkpoint has its own succeeded attempt with produced evidence, in that order. **A committed migration that was never deployed does not fix anything**, and verification evidence observed before the deploy verifies the old state.

AUTO / PROPOSE / ADVISORY may be shown only through the derived `vibecheck.action_legacy_view` compatibility view. Never read that view to decide whether execution is allowed.

## Procedure patterns

Represent current fixes without overloading their meaning:

- Mechanical repository hygiene can use an automated `vibecheck_agent` Procedure, but any write remains `explicit_consent` and branch/diff scope must be exact.
- Project-specific code or policy changes usually offer a guided developer Procedure. Confirm inputs such as ownership columns, origin allowlists, provider secret names, and business rules before authorizing the attempt.
- Secret rotation, git-history purging, backups/restore, budget caps, data residency, DPA, and legal classification use founder/platform/specialist Procedures. Editing the tree does not complete them.
- A leaked secret in history requires separate Procedures for provider rotation and history cleanup. Never claim either happened without its own attempt evidence.

## Choosing the verification method

Verification methods are registry providers, not ad-hoc choices. `schema/provider-registry.v1.json` states per method what it can observe, at what strength, in which environments, and what running it needs and touches; `scripts/providers.py` ranks them and explains the result:

```bash
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/providers.py --list
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/providers.py \
  --select vibecheck.control.authz.object_level --environment private_test \
  --target source_tree --target supabase_project
```

Prefer the strongest applicable method the user has actually authorized, and walk the declared fallback chain when you cannot have it: Supabase two-account probe → Playwright two-account flow → guided browser test → code and policy review. Report the refusals, never hide them — "the probe would have settled this; it needs the anon key and permission to reach the project" is the useful sentence, and a weaker method silently substituted is the failure. Selecting a method authorizes nothing: a step that reaches the network, uses a credential, writes, deploys or acts in an external account is a request naming the provider, the effects and the destinations, and step 4 below is where it gets granted.

## Workflow

1. Use fresh scan/review evidence. Create or revise Actions for unresolved outcomes; do not duplicate the same outcome merely to offer another method.
2. Offer candidate Procedures. For each, state executor, execution mode, prerequisites/input references, exact method, network/egress, effect targets and booleans, reversibility, consent policy, failure/rollback, cost, expected evidence, and an independent verifier. Name the verifying provider by ID (`verification_provider_ref`) so what the verification is worth is recorded rather than assumed.
3. Show the proposed diff or exact non-code operation before authorization. Default code changes to a new branch. Keep secrets redacted and store inputs by reference only.
4. Get consent for one exact attempt. Bind consent to its attempt ID, authorized targets/effects, environment, grant time, expiry if any, and provenance. Consent for one attempt never authorizes a later run or a different side effect.
5. Execute only within that scope. For repository hygiene, preview the bounded helper first:

   ```bash
   bash ${CLAUDE_PLUGIN_ROOT}/scripts/apply_safe_fixes.sh <repo_dir> --dry-run
   bash ${CLAUDE_PLUGIN_ROOT}/scripts/apply_safe_fixes.sh <repo_dir>
   ```

   Lockfile generation also needs approved network access and `--allow-network-lockfile`; lifecycle scripts and implicit audit remain disabled. The helper never rotates secrets or rewrites history.
6. Record actual side effects, result, rollback state, and evidence. A failed, partial, or aborted attempt leaves the Action open/in progress/blocked.
7. Verify independently and create a superseding Assessment from fresh evidence. A cleared regex warning is not proof. Mark the Action `done` only when a succeeded attempt produced the defined evidence and a reassessment cites it.
   For authorization fixes, verification is per cell: object, actor, operation, environment. A denied read is not a denied write, and a fixed table is not a fixed database. Record what you observed and leave the rest as named gaps — `partial` with untested operations listed is the honest reassessment.
8. Report the Action state, every attempt result, remaining blockers, and which Procedures still need owner/developer/specialist action.

## Hard rules

- Diff-first and branch-first for code changes.
- Never execute from a legacy AUTO label or from execution mode alone.
- Never expand consent beyond the exact attempt, target, environment, inputs, or effects recorded.
- Never weaken a control to make a check pass.
- Never store secret input values in an attempt record.
- Never fabricate rotation, deployment, rollback, history purge, evidence, or reassessment.
- Never treat editing the repository as deploying it, or one denied request as a closed control.
- Never let a provider decide a control. It produces scoped evidence with a stated strength; the assessment is a separate, accountable step.
- Never substitute a weaker verification method without saying which stronger one was unavailable and what would have enabled it.
- Never decide on the owner's behalf that an anonymous write is intended, and never treat a confirmed one as finished: it needs the read path denied and an observed limit on the write path before the control can close.
- One failed or partial attempt never completes the Action; a disappeared warning is never success evidence.
