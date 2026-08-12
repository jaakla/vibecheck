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

## Read-only probe (default)

```bash
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/supabase_probe.py \
  --url "$SUPABASE_URL" --anon "$SUPABASE_ANON_KEY" [--tables t1,t2,...]
```

For each table it reports `anon_select`:

- **`REVIEW_rows_readable_by_anon`** — the one-row response range shows at least one row visible to unauthenticated callers. Confirm whether that table is intentionally public before recording a failure.
- **`NO_ROWS_VISIBLE_UNCONFIRMED`** — the response range is empty. RLS is filtering **or the table is empty**; do not record a Pass without a seeded private row.
- **`BLOCKED_OR_KEY_INVALID`** — `401/403`; validate the key/project before treating blocking as policy evidence.
- **`UNKNOWN_*`** — network, server, discovery, or count failure. Resolve it; do not interpret it as blocked access.
- **`INFO_not_exposed`** — `404`, not published through PostgREST.

A `200` response on its own is **not** a finding. A table with RLS enabled and no matching policy returns `200 []` to anon rather than an error, so exposure is judged on rows returned (via `Content-Range`), not on the status code.

## Write probe (opt-in only)

PostgREST has no dry-run insert. An anon INSERT probe can **create a real row and fire triggers or other side effects**, so it is off by default and the output says `NOT_TESTED` when it did not run. Prefer an isolated test project or staging environment.

Only add `--write-probe` after telling the user it may write a row and getting explicit agreement, and only on a project they own:

```bash
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/supabase_probe.py --url ... --anon ... --write-probe
```

Verdicts: `BLOCKED_OR_KEY_INVALID` (401/403; not automatically a Pass), `WARN_write_reached_validation` (400/409/422 — validation, not necessarily policy, stopped it), `FAIL_anon_write_succeeded` (a row was very likely created — tell the user to locate and delete it).

## IDOR probe (#13)

Needs two access tokens from distinct test accounts and a known private record created/owned by account A. Put tokens in environment variables so they do not land in shell history, and name the target explicitly:

```bash
SUPABASE_JWT_A="$TOKEN_A" SUPABASE_JWT_B="$TOKEN_B" \
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/supabase_probe.py --url ... --anon ... \
  --idor-target private_table:known-a-owned-id
```

The script first confirms A can see the supplied target, then asks whether B can see the same ID. Only `PASS_no_cross_account_read_of_known_private_record` is positive evidence for that one record and operation. A non-200 response, invalid token, unknown count, or target invisible to A is Unknown/Not tested — never a Pass. Repeat for read/update/delete and representative object types before closing #13.

## Interpretation

- Reference and lookup tables (countries, plan tiers) that are intentionally public are fine — confirm with the user which tables are meant to be readable before flagging.
- Discovery only sees tables PostgREST exposes. A table missing from the list is not proven safe; cross-check against the migrations.
- The read probe uses `HEAD` plus a one-row range, so it neither downloads row bodies nor requests an expensive exact full-table count. It refuses cross-origin redirects to avoid forwarding account tokens to another host.

## Constraints

- Read-only by default; writes only with explicit consent, per run.
- Only probe a project the user owns or is explicitly authorised to review.
- Treat all returned data as sensitive: summarise counts and shapes, never dump row contents into the report.
