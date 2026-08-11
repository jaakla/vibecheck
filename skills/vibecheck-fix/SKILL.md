---
name: vibecheck-fix
description: >
  Propose and apply remediations for vibecheck findings. Use after vibecheck-scan when the
  user says "fix these", "remediate", "patch the issues", "apply the safe fixes", or asks to
  resolve findings from a review. Works diff-first: proposes changes, gets consent, applies on
  a branch, then re-scans to confirm each finding cleared. Distinguishes fixes that can be
  applied mechanically from ones needing a human decision.
---

# Vibecheck Fix

Remediate findings from `vibecheck-scan`. The guiding rule: **never silently change security-relevant behaviour, and never claim a fix you cannot verify.** Some findings (leaked secrets in history) cannot be "fixed" by editing files at all — they require rotation and history rewrite, which are advisory.

## Fix taxonomy

Classify every finding into one of three tiers before touching anything:

**AUTO — mechanical, deterministic, safe to apply after showing the diff:**
- `.env` tracked → `git rm --cached` + add to `.gitignore`
- Missing lockfile → generate it (`npm install --package-lock-only`)
- Wildcard CORS on a known endpoint → replace `*` with an allowlist constant
- Empty catch blocks → add error logging (never leave silent)
- `console.log` of secrets/PII → remove or redact
- Missing `.gitignore` entries for build/secret artifacts

**PROPOSE — needs a project-specific value; draft it and ask before applying:**
- `rls.missing` → generate `alter table X enable row level security;` plus a starter owner policy, but the owner column (`user_id`?) must be confirmed
- `rls.permissive` (`using(true)`) → propose `using (auth.uid() = <owner_col>)`; confirm the column and whether the table is meant to be public
- `inject.sql` → rewrite as parameterized query / ORM call
- `inject.llm_to_exec` (#77) → remove the exec sink or wrap model output in a strict validator/allowlist; propose the specific guard
- `inject.tool_agent` (#79) → add a tool allowlist + argument schema validation
- `cost.client_llm` → move the call to a server route/edge function and proxy it
- `integ.webhook_sig` → insert the provider's signature-verification snippet (needs the signing secret env var name)

**ADVISORY — cannot be fixed by editing code; state plainly as required human actions:**
- Any secret found in git **history** (`secrets.env_history`, `secrets.history_content`) → the key is compromised. Required: (1) rotate the key at the provider now, (2) purge history with `git filter-repo` or BFG, (3) force-push and have collaborators re-clone. Editing the current tree does **not** undo the leak.
- Backups/restore, budget caps, data residency, DPA, Annex III classification → dashboard or organisational actions.

## Workflow

1. Take the scan findings (re-run `vibecheck-scan` if you don't have them fresh).
2. Print the fix plan grouped by tier. For AUTO and PROPOSE, show the exact diff you intend to make. For ADVISORY, show the checklist of human actions.
3. Get explicit consent. Default to a new branch: `git checkout -b vibecheck-fixes`.
4. Apply AUTO fixes. Apply PROPOSE fixes only for items the user confirmed. Never touch ADVISORY items automatically.
5. For mechanical git-hygiene fixes you may use the helper. Preview first:
   ```bash
   bash ${CLAUDE_PLUGIN_ROOT}/scripts/apply_safe_fixes.sh <repo_dir> --dry-run
   bash ${CLAUDE_PLUGIN_ROOT}/scripts/apply_safe_fixes.sh <repo_dir>
   ```
   It only does the non-destructive, reversible actions (untrack `.env` while leaving it on disk, extend `.gitignore`, generate a lockfile) and prints what it changed. It never rewrites history or rotates keys.
6. **Re-run `vibecheck-scan` and confirm each targeted finding moved to PASS.** Report any that did not. A fix that doesn't clear the scanner isn't done.
7. Summarise: what was fixed, what still needs the user's decision, and the outstanding ADVISORY actions.

## Hard rules

- Diff-first. No edits before the user has seen them, except when they say "apply all safe fixes" — then AUTO tier only.
- Never weaken a control to make a check pass (e.g. do not delete a test, suppress a warning, or broaden a type to silence a validator).
- Never fabricate a rotation or a history purge. If you can't verify it, it stays ADVISORY.
- Keep secrets redacted in all output.
- One logical fix per commit, with a message naming the checklist item (e.g. `fix(#14): scope RLS policy on profiles to owner`).
