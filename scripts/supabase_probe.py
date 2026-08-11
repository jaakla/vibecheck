#!/usr/bin/env python3
"""Read-only Supabase access-control probe using the anon key only.

Reflects exactly what an attacker with a browser has. By default the probe
sends **no writes at all**: PostgREST offers no dry-run insert, so any write
probe risks creating a real row on a table whose columns are all nullable or
defaulted. Anon-write testing is therefore opt-in via --write-probe, and the
report says plainly when it was not tested.

Exposure is judged on rows actually returned, not on HTTP 200. A table with
RLS enabled and no matching policy returns `200 []` to anon, not 401 — so
"200" alone is not a finding.
"""
import argparse
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

TIMEOUT_DEFAULT = 15


def mask(key):
    """Anon keys are public, but reports get pasted around. Show the shape only."""
    if not key:
        return ""
    return key[:6] + "..." + key[-4:] if len(key) > 14 else "***"


def req(url, headers, method="GET", body=None, timeout=TIMEOUT_DEFAULT):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace"), dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), dict(e.headers or {})
    except Exception as e:  # network/DNS/TLS failure
        return -1, str(e), {}


def visible_count(headers, body):
    """Rows visible to this caller: Content-Range total if present, else len(body)."""
    cr = headers.get("Content-Range") or headers.get("content-range") or ""
    m = re.search(r"/(\d+)$", cr)
    if m:
        return int(m.group(1))
    try:
        arr = json.loads(body)
        return len(arr) if isinstance(arr, list) else None
    except Exception:
        return None


def discover_tables(base, H, timeout):
    """Enumerate tables PostgREST exposes, via its OpenAPI root."""
    status, body, _ = req(base + "/rest/v1/", H, timeout=timeout)
    tables = []
    if status == 200:
        try:
            spec = json.loads(body)
            tables = sorted(spec.get("definitions", {}).keys())
            if not tables:  # OpenAPI 3 shape
                tables = sorted(
                    spec.get("components", {}).get("schemas", {}).keys())
        except Exception:
            pass
    return status, tables


def probe_select(base, H, table, timeout):
    """Anon SELECT. Exposure = rows actually returned."""
    url = "%s/rest/v1/%s?select=*&limit=1" % (base, urllib.parse.quote(table))
    h = dict(H)
    h["Prefer"] = "count=exact"
    s, b, hdrs = req(url, h, timeout=timeout)

    n = visible_count(hdrs, b) if s == 200 else None
    if s == 200 and n:
        verdict = "FAIL_readable_by_anon"
        note = "%d row(s) visible to an unauthenticated caller" % n
    elif s == 200:
        verdict = "PASS_no_rows_visible"
        note = ("no rows returned to anon — RLS is filtering, OR the table is "
                "empty; confirm with a seeded row before recording a Pass")
    elif s in (401, 403):
        verdict = "PASS_blocked"
        note = b[:180]
    elif s == 404:
        verdict = "INFO_not_exposed"
        note = "not exposed through PostgREST"
    else:
        verdict = "UNKNOWN_%s" % s
        note = b[:180]

    return {"check": "anon_select", "table": table, "http": s,
            "verdict": verdict, "rows_visible_to_anon": n, "note": note}


def probe_insert(base, H, table, timeout):
    """Anon INSERT — only runs under --write-probe. MAY CREATE A ROW."""
    s, b, _ = req("%s/rest/v1/%s" % (base, urllib.parse.quote(table)),
                  H, method="POST", body={}, timeout=timeout)
    if s in (401, 403):
        verdict = "PASS_write_blocked_by_policy"
    elif s in (400, 409, 422):
        verdict = "WARN_write_reached_validation"  # policy may allow anon writes
    elif s in (200, 201, 204):
        verdict = "FAIL_anon_write_succeeded"      # a row was very likely created
    else:
        verdict = "UNKNOWN_%s" % s
    return {"check": "anon_insert_probe", "table": table, "http": s,
            "verdict": verdict, "note": b[:180]}


def probe_idor(base, anon, table, jwt_a, jwt_b, timeout):
    """Cross-account read: fetch row ids as A, then try to read them as B."""
    def auth(jwt):
        return {"apikey": anon, "Authorization": "Bearer " + jwt,
                "Content-Type": "application/json"}

    tq = urllib.parse.quote(table)
    s, b, _ = req("%s/rest/v1/%s?select=id&limit=5" % (base, tq),
                  auth(jwt_a), timeout=timeout)
    if s != 200:
        return {"check": "idor", "table": table, "verdict": "SKIP_no_rows_for_account_a",
                "http": s, "note": b[:180]}
    try:
        ids = [str(r["id"]) for r in json.loads(b) if isinstance(r, dict) and "id" in r]
    except Exception:
        ids = []
    if not ids:
        return {"check": "idor", "table": table, "verdict": "SKIP_no_id_column_or_no_rows",
                "http": s, "note": "account A sees no rows with an 'id' column"}

    q = "%s/rest/v1/%s?select=*&id=in.(%s)" % (base, tq, ",".join(ids))
    s2, b2, h2 = req(q, auth(jwt_b), timeout=timeout)
    leaked = visible_count(h2, b2) if s2 == 200 else 0
    return {"check": "idor", "table": table, "http": s2,
            "verdict": "FAIL_cross_account_read" if leaked else "PASS_no_cross_account_read",
            "rows_of_a_visible_to_b": leaked,
            "note": "account B could read %s of account A's %d probed row(s)"
                    % (leaked, len(ids))}


def main():
    ap = argparse.ArgumentParser(
        description="Read-only Supabase anon-key access-control probe.")
    ap.add_argument("--url", required=True, help="https://<project>.supabase.co")
    ap.add_argument("--anon", required=True, help="anon/publishable key (never service_role)")
    ap.add_argument("--tables", default="", help="comma-separated; discovered if omitted")
    ap.add_argument("--timeout", type=float, default=TIMEOUT_DEFAULT)
    ap.add_argument("--max-tables", type=int, default=50)
    ap.add_argument("--write-probe", action="store_true",
                    help="ALSO attempt an anon INSERT per table. This can CREATE A ROW "
                         "on permissive tables. Only use on a project you own, with consent.")
    ap.add_argument("--jwt-a", default="", help="access token for test account A (IDOR probe)")
    ap.add_argument("--jwt-b", default="", help="access token for test account B (IDOR probe)")
    args = ap.parse_args()

    if _jwt_role(args.anon) == "service_role":
        print(json.dumps({"error": "that looks like a service_role key — refusing to run. "
                                   "The probe must use the anon key to reflect attacker capability."}))
        return 2

    base = args.url.rstrip("/")
    H = {"apikey": args.anon, "Authorization": "Bearer " + args.anon,
         "Content-Type": "application/json"}

    tables = [t.strip() for t in args.tables.split(",") if t.strip()]
    findings = []

    if not tables:
        status, tables = discover_tables(base, H, args.timeout)
        findings.append({"check": "discovery", "status": "INFO",
                         "http": status,
                         "detail": "root status %s; discovered %d table definitions"
                                   % (status, len(tables))})
    tables = tables[:args.max_tables]

    for t in tables:
        findings.append(probe_select(base, H, t, args.timeout))
        if args.write_probe:
            findings.append(probe_insert(base, H, t, args.timeout))
        if args.jwt_a and args.jwt_b:
            findings.append(probe_idor(base, args.anon, t, args.jwt_a, args.jwt_b, args.timeout))

    if not args.write_probe:
        findings.append({
            "check": "anon_insert_probe", "verdict": "NOT_TESTED",
            "note": "anon write was not probed (default). PostgREST has no dry-run insert, "
                    "so a write probe can create a real row. Re-run with --write-probe on a "
                    "project you own if item #14 needs write coverage."})
    if not (args.jwt_a and args.jwt_b):
        findings.append({
            "check": "idor", "verdict": "NOT_TESTED",
            "note": "IDOR (#13) needs two authenticated test accounts. Re-run with "
                    "--jwt-a and --jwt-b access tokens from your own test users."})

    fails = [f for f in findings if str(f.get("verdict", "")).startswith("FAIL")]
    print(json.dumps({
        "supabase_probe": True,
        "url": base,
        "anon_key": mask(args.anon),
        "write_probe_enabled": args.write_probe,
        "tables_probed": tables,
        "critical_exposures": len(fails),
        "findings": findings,
    }, indent=2))
    return 0


def _jwt_role(token):
    """Best-effort read of the `role` claim; '' if the token isn't a readable JWT."""
    import base64
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload).decode("utf-8", "replace"))
        return str(claims.get("role", ""))
    except Exception:
        return ""


if __name__ == "__main__":
    sys.exit(main())
