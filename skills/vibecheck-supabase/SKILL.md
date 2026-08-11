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

Static scanning of migrations catches missing RLS, but the ground truth is the live database. This skill probes a running Supabase project through its public REST API using only the **anon** key — exactly what an attacker in a browser has.

## Inputs required from the user

- `SUPABASE_URL` (e.g. `https://abcd.supabase.co`)
- `SUPABASE_ANON_KEY` (the public/publishable key — safe to use; it already ships to browsers)
- Optionally, a list of table names. If not given, the probe discovers them from the PostgREST OpenAPI root.

Never ask for the `service_role` key. If the user offers it, decline — the probe must run with the anon key to reflect real attacker capability. The script refuses to run if it is handed a token whose `role` claim is `service_role`.

Confirm the user owns or is authorised to review the project before running anything.

## Read-only probe (default)

```bash
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/supabase_probe.py \
  --url "$SUPABASE_URL" --anon "$SUPABASE_ANON_KEY" [--tables t1,t2,...]
```

For each table it reports `anon_select`:

- **`FAIL_readable_by_anon`** — rows were actually returned to an unauthenticated caller. This is the single most common vibecoded-Lovable vulnerability. Map to #12/#14, Critical → BLOCK.
- **`PASS_no_rows_visible`** — `200` with zero rows. RLS is filtering **or the table is empty**. These look identical from outside: do not record a Pass until the user confirms the table has rows, or seeds one.
- **`PASS_blocked`** — `401/403`.
- **`INFO_not_exposed`** — `404`, not published through PostgREST.

A `200` response on its own is **not** a finding. A table with RLS enabled and no matching policy returns `200 []` to anon rather than an error, so exposure is judged on rows returned (via `Content-Range`), not on the status code.

## Write probe (opt-in only)

PostgREST has no dry-run insert. An anon INSERT probe can **create a real row** on a table whose columns are all nullable or defaulted, so it is off by default and the output says `NOT_TESTED` when it did not run.

Only add `--write-probe` after telling the user it may write a row and getting explicit agreement, and only on a project they own:

```bash
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/supabase_probe.py --url ... --anon ... --write-probe
```

Verdicts: `PASS_write_blocked_by_policy` (401/403), `WARN_write_reached_validation` (400/409/422 — the policy may allow anon writes and only validation stopped it), `FAIL_anon_write_succeeded` (a row was very likely created — tell the user to delete it).

## IDOR probe (#13)

Needs two access tokens from the user's own test accounts. The probe reads row ids as account A, then attempts to read those exact ids as account B — read-only:

```bash
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/supabase_probe.py --url ... --anon ... \
  --jwt-a "$TOKEN_A" --jwt-b "$TOKEN_B"
```

`FAIL_cross_account_read` means B could read A's rows. Without both tokens the check reports `NOT_TESTED` — never record #13 as passed on the strength of the anon probe alone.

## Interpretation

- Reference and lookup tables (countries, plan tiers) that are intentionally public are fine — confirm with the user which tables are meant to be readable before flagging.
- Discovery only sees tables PostgREST exposes. A table missing from the list is not proven safe; cross-check against the migrations.

## Constraints

- Read-only by default; writes only with explicit consent, per run.
- Only probe a project the user owns or is explicitly authorised to review.
- Treat all returned data as sensitive: summarise counts and shapes, never dump row contents into the report.
