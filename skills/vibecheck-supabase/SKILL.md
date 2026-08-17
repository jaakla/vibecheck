---
name: vibecheck-supabase
description: >
  Live-probe a Supabase backend for access-control holes: anon-key read exposure, RLS
  effectiveness, and IDOR between two test accounts. Use when reviewing a Lovable or
  Supabase-backed vibecoded app and the user can provide the project URL and anon key,
  or says "check my RLS", "probe supabase", "can anyone read my tables",
  "test access control live". Read-only unless write probing is explicitly requested.
---

# Vibecheck Supabase Live Probe

Static scanning of migrations only produces signals; the live deployment is the ground truth. This skill probes a running Supabase project through its public REST API using a public **legacy anon** or modern **publishable** key — what a browser client has.

## Inputs required from the user

- `SUPABASE_URL` (e.g. `https://abcd.supabase.co`)
- `SUPABASE_ANON_KEY` or publishable key (public, but still redact it from reports)
- Optionally, a list of table names. If not given, the probe discovers them from the PostgREST OpenAPI root.

Never ask for a legacy `service_role` key or modern `sb_secret_...` key. If offered, decline. The script rejects both. A modern publishable key is sent only as `apikey`; a legacy anon JWT also gets the legacy bearer header.

Confirm the user owns or is authorised to review the project before running anything.

## Finding the URL and key yourself

Do not ask a founder for credentials they may not know how to find, and never ask a platform for a secret. The publishable/anon key is in the shipped client by construction, so it is discoverable from the source or the running app. `vibecheck.sh` reports where, as the `authz.backend_target` to-do; otherwise look in this order:

- **A committed `.env`.** Platform builders write one, holding only public values: `SUPABASE_URL`, `SUPABASE_PROJECT_ID`, `SUPABASE_PUBLISHABLE_KEY`, usually duplicated with a framework prefix (`VITE_`, `NEXT_PUBLIC_`, `PUBLIC_`, `EXPO_PUBLIC_`).
- **The generated client.** Lovable Cloud writes `src/integrations/supabase/client.ts` (plus `client.server.ts` for SSR); other stacks use `utils/supabase/client.ts` or `src/lib/supabase.ts`. It names the exact variables the app reads.
- **The project ref alone is enough.** `SUPABASE_PROJECT_ID=abcd…` means the API base is `https://abcd….supabase.co`.
- **The running app.** Open it, and read the `apikey` header off any request in the network tab.
- **`src/integrations/supabase/types.ts`**, when present, lists the tables and columns — the fastest way to draft the representative-object inventory before probing.

Two things to expect and interpret rather than escalate:

- A tracked `.env` trips `secrets.env_tracked`, and a `.gitignore` without a `.env` line trips `secrets.gitignore`. On a platform project both are normal — the file holds public values. What matters is whether anything *secret*-shaped sits in it today, and that the next variable someone adds there will also be committed. Say that, rather than telling a founder to rotate a public key.
- `SUPABASE_PUBLISHABLE_KEY` is often still a legacy anon JWT (`eyJ…`, `"role":"anon"`), despite the name. The probe checks the role claim and refuses anything but `anon`, so paste it as-is.

Test-account tokens for the two-account checks come from the app, not the platform: sign in as each test user and copy `sb-<project-ref>-auth-token` from `localStorage`, or lift the `Authorization` header off a request.

## Read-only probe (default)

```bash
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/supabase_probe.py \
  --url "$SUPABASE_URL" --anon "$SUPABASE_ANON_KEY" [--tables t1,t2,...]
```

For each table it reports `anon_select`:

- **`REVIEW_rows_readable_by_anon`** — the one-row response range shows at least one row visible to unauthenticated callers. Confirm whether that table is intentionally public before recording a failure.
- **`NO_ROWS_VISIBLE_UNCONFIRMED`** — the response range is empty. RLS is filtering **or the table is empty**; do not record a Pass without a seeded private row.
- **`PASS_no_anon_rows_on_non_empty_table`** — anon saw nothing while test account A saw rows in the same window, so the table is not empty. Only produced when `SUPABASE_JWT_A` is supplied.
- **`BLOCKED_OR_KEY_INVALID`** — `401/403`; validate the key/project before treating blocking as policy evidence. The finding carries `key_validated`, which is true when the same key was accepted elsewhere in the run — that is what separates a denying policy from a wrong key.
- **`UNKNOWN_*`** — network, server, discovery, or count failure. Resolve it; do not interpret it as blocked access.
- **`INFO_not_exposed`** — `404`, not published through PostgREST.

A `200` response on its own is **not** a finding. A table with RLS enabled and no matching policy returns `200 []` to anon rather than an error, so exposure is judged on rows returned (via `Content-Range`), not on the status code.

## Write probe (opt-in only)

PostgREST has no dry-run insert. An anon INSERT probe can **create a real row and fire triggers or other side effects**, so it is off by default and the output says `NOT_TESTED` when it did not run. Prefer an isolated test project or staging environment.

Only add `--write-probe` after telling the user it may write a row and getting explicit agreement, and only on a project they own. The run must also record where it wrote and on whose authority:

```bash
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/supabase_probe.py --url ... --anon ... \
  --write-probe --environment private_test --authorized-by "founder:mari"
```

Verdicts: `BLOCKED_OR_KEY_INVALID` (401/403; not automatically a Pass), `WARN_write_reached_validation` (400/409/422 — validation, not necessarily policy, stopped it), `FAIL_anon_write_succeeded` (a row was very likely created).

When a row is created the finding carries `created_row_hint` and a `cleanup` block naming the exact row. Deleting it is part of the probe, not an afterthought: report the identifier, get it removed, and record that it is gone. A failed insert reports `cleanup.state: not_needed` with the reason.

## IDOR probe (#13)

Needs two access tokens from distinct test accounts and a known private record created/owned by account A. Put tokens in environment variables so they do not land in shell history, and name the target explicitly:

```bash
SUPABASE_JWT_A="$TOKEN_A" SUPABASE_JWT_B="$TOKEN_B" \
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/supabase_probe.py --url ... --anon ... \
  --idor-target private_table:known-a-owned-id
```

The script first confirms A can see the supplied target, then asks whether B can see the same ID. Only `PASS_no_cross_account_read_of_known_private_record` is positive evidence for that one record and operation. A non-200 response, invalid token, unknown count, or target invisible to A is Unknown/Not tested — never a Pass.

## Coverage: what you may conclude

Every finding carries the cell it establishes — object, actor (`anonymous` / `other_account` / `other_tenant_member` / `unprivileged_account`), operation (`read` / `create` / `update` / `delete`), and `observed` (`denied` / `allowed` / `inconclusive`). The model, the required matrix per control and the closure rule are `schema/authz-coverage.v1.json`.

- List the representative private object types with the owner — a user-owned record, an organisation-scoped record, invitation or reset tokens, storage objects, anything admin-only — and record them as `context.authorization_objects`. Without that list there is no requirement to meet, and coverage reads `unestablished`.
- A table is left out only when the owner confirms it is meant to be public. "Probably fine" keeps it in.
- Closing #13 or #14 needs every required cell observed denied. One denied read is one cell. Cross-account update and delete are deliberately not automated, so those cells close only through an authorized manual test whose result you record.
- Cells do not transfer between environments: probing the pilot says nothing about production.
- Report the gaps as gaps. `partial` with named untested operations is the honest status; `pass` on one lucky request is not.

## When the write is supposed to be open

A visible anonymous INSERT is often the product: contact forms, booking requests and lead captures write from the browser by design. Do not record it as a failure, and do not assume it is fine either. Ask the owner, in their terms:

> Anyone on the internet can add a row to `public.bookings` without logging in. Is that your contact form working as intended?

If the answer is no, it is a finding. If it is yes, record the decision — actor, operation, who decided, and why — as an `intended_operations` entry on that object, and then check the two things that make the exception safe to keep:

1. **They cannot read it back.** Anonymous insert plus anonymous select is a full dump of every enquiry you have ever received. This is the same anon `read` cell the matrix already measures; it must be observed denied.
2. **Something bounds the path.** An open form is reachable by scripts as well as customers, and the founder-facing consequence is concrete: the table fills with junk, every submission emails you, any quota behind it drains, and the real enquiries are buried. One submission a minute from a source is plenty for a human. A per-source throttle, a challenge (Turnstile, hCaptcha, Altcha), or a queue someone releases all satisfy it — the owner picks. Having none does not.

The bound has to be observed, not described: send repeated submissions from one source and record the refusal. A dashboard setting or a screenshot is not evidence that the deployed path is limited. Until it is, the control stays open, the founder report carries it as an immediate fix, and no Pass is available for the anonymous-access control.

Also worth raising once the write is intended: body-size limits and mail-volume limits (#27), server-side validation of every field (#28), and a ceiling with an alert (#23). Those are recommendations, not gates.

## Interpretation

- Reference and lookup tables (countries, plan tiers) that are intentionally public are fine — confirm with the user which tables are meant to be readable before flagging.
- Discovery only sees tables PostgREST exposes. A table missing from the list is not proven safe; cross-check against the migrations.
- The read probe uses `HEAD` plus a one-row range, so it neither downloads row bodies nor requests an expensive exact full-table count. It refuses cross-origin redirects to avoid forwarding account tokens to another host.

## Platform-managed backends (Lovable Cloud and similar)

Nothing here needs credentials the platform withholds: the probe only ever uses public keys and user sessions. Two differences are worth handling explicitly.

- **Deployment is the platform's, not yours.** There is no `supabase db push` you drive. The agent applies an approved migration, so the remediation `deployment` checkpoint is a Procedure with `executor_role: platform`, `execution_context.kind: provider_dashboard`, `source_ref` = the platform version id, and the approval in the build chat as its consent record. The checkpoint still exists; only the executor changes.
- **Usually one database.** Editor preview and the published app typically share a backend. So approving a migration *is* deploying it to real users, an observation is about that one real environment whatever label the editor suggests, and a write probe writes production data. On a published platform app, treat `--write-probe` as a no unless the owner accepts a real row in real data, and prefer a seeded test table.

Also out of the probe's reach on these stacks: storage buckets (this probe speaks PostgREST only, so `file_or_storage_object` cells stay untested) and server-side functions, where a legitimately privileged key is used out of sight. Those are code-reading work under `authz.server_side_default_deny`, not probe work.

## Constraints

- Read-only by default; writes only with explicit consent, per run, and every write records its authorization, target environment, result and cleanup state.
- Only probe a project the user owns or is explicitly authorised to review.
- Treat all returned data as sensitive: summarise counts and shapes, never dump row contents into the report.
