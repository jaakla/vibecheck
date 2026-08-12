#!/usr/bin/env python3
"""Read-only Supabase access-control probe using a public API key only.

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
import base64
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

TIMEOUT_DEFAULT = 15


class SameOriginRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follow redirects only when scheme and authority stay unchanged.

    Authorization headers contain short-lived user access tokens during IDOR
    checks.  urllib otherwise forwards request headers while following redirects,
    which can disclose those tokens to a different host.
    """

    def redirect_request(self, req_, fp, code, msg, headers, newurl):
        old = urllib.parse.urlsplit(req_.full_url)
        new = urllib.parse.urlsplit(newurl)
        if (old.scheme.lower(), old.netloc.lower()) != (
                new.scheme.lower(), new.netloc.lower()):
            raise urllib.error.HTTPError(
                newurl, code, "cross-origin redirect refused", headers, fp)
        return super().redirect_request(req_, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(SameOriginRedirectHandler())


def mask(key):
    """Anon keys are public, but reports get pasted around. Show the shape only."""
    if not key:
        return ""
    return key[:6] + "..." + key[-4:] if len(key) > 14 else "***"


def req(url, headers, method="GET", body=None, timeout=TIMEOUT_DEFAULT):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with _OPENER.open(r, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace"), dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), dict(e.headers or {})
    except Exception as e:  # network/DNS/TLS failure
        return -1, str(e), {}


def visible_count(headers, body):
    """Rows visible in the response window, without requiring a full-table count."""
    cr = headers.get("Content-Range") or headers.get("content-range") or ""
    m = re.search(r"/(\d+)$", cr)
    if m:
        return int(m.group(1))
    m = re.match(r"^(\d+)-(\d+)/", cr)
    if m:
        return max(0, int(m.group(2)) - int(m.group(1)) + 1)
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
    # HEAD + a one-row range exercises SELECT/RLS without downloading a row or
    # forcing an exact full-table count on a potentially large relation.
    url = "%s/rest/v1/%s?select=*&limit=1" % (
        base, urllib.parse.quote(table, safe=""))
    h = dict(H)
    h["Range"] = "0-0"
    h["Range-Unit"] = "items"
    s, b, hdrs = req(url, h, method="HEAD", timeout=timeout)

    n = visible_count(hdrs, b) if s in (200, 206) else None
    if s in (200, 206) and n:
        verdict = "REVIEW_rows_readable_by_anon"
        note = ("%d row(s) visible to an unauthenticated caller; this is a "
                "failure only if the table is intended to be private") % n
    elif s in (200, 206) and n == 0:
        verdict = "NO_ROWS_VISIBLE_UNCONFIRMED"
        note = ("no rows returned to anon — RLS is filtering, OR the table is "
                "empty; confirm with a seeded row before recording a Pass")
    elif s in (200, 206):
        verdict = "UNKNOWN_count_unavailable"
        note = ("the server returned success without a usable row count; no data was "
                "downloaded, so repeat with a compatible PostgREST endpoint")
    elif s in (401, 403):
        verdict = "BLOCKED_OR_KEY_INVALID"
        note = ("request was blocked, but this does not prove RLS: verify that the "
                "public key is valid for this project")
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
    h = dict(H)
    h["Prefer"] = "return=minimal"
    s, b, _ = req("%s/rest/v1/%s" %
                  (base, urllib.parse.quote(table, safe="")),
                  h, method="POST", body={}, timeout=timeout)
    if s in (401, 403):
        verdict = "BLOCKED_OR_KEY_INVALID"
    elif s in (400, 409, 422):
        verdict = "WARN_write_reached_validation"  # policy may allow anon writes
    elif s in (200, 201, 204):
        verdict = "FAIL_anon_write_succeeded"      # a row was very likely created
    else:
        verdict = "UNKNOWN_%s" % s
    return {"check": "anon_insert_probe", "table": table, "http": s,
            "verdict": verdict, "note": b[:180]}


def probe_idor(base, anon, table, row_id, jwt_a, jwt_b, timeout):
    """Try one known A-owned, non-shared record as account A and then B."""
    def auth(jwt):
        return {"apikey": anon, "Authorization": "Bearer " + jwt,
                "Content-Type": "application/json"}

    tq = urllib.parse.quote(table, safe="")
    query = urllib.parse.urlencode({"select": "id", "id": "eq." + row_id,
                                    "limit": "1"})
    url = "%s/rest/v1/%s?%s" % (base, tq, query)

    s_a, b_a, h_a = req(url, auth(jwt_a), timeout=timeout)
    if s_a != 200:
        return {"check": "idor", "table": table, "record_id": row_id,
                "verdict": "UNKNOWN_account_a_request_failed", "http": s_a,
                "note": b_a[:180]}
    visible_a = visible_count(h_a, b_a)
    if visible_a is None:
        return {"check": "idor", "table": table, "record_id": row_id,
                "verdict": "UNKNOWN_account_a_response", "http": s_a,
                "note": "could not determine whether account A sees the target record"}
    if visible_a == 0:
        return {"check": "idor", "table": table, "record_id": row_id,
                "verdict": "NOT_TESTED_target_not_visible_to_a", "http": s_a,
                "note": "the supplied record is not visible to account A"}

    s_b, b_b, h_b = req(url, auth(jwt_b), timeout=timeout)
    if s_b != 200:
        return {"check": "idor", "table": table, "record_id": row_id,
                "verdict": "UNKNOWN_account_b_request_failed", "http": s_b,
                "note": ("B's request failed; this may be policy enforcement, an invalid "
                         "token, or a network/server error, so it is not a Pass: " + b_b[:120])}
    visible_b = visible_count(h_b, b_b)
    if visible_b is None:
        return {"check": "idor", "table": table, "record_id": row_id,
                "verdict": "UNKNOWN_account_b_response", "http": s_b,
                "note": "could not determine whether account B sees the target record"}
    return {"check": "idor", "table": table, "record_id": row_id,
            "http": s_b,
            "verdict": ("FAIL_cross_account_read" if visible_b
                        else "PASS_no_cross_account_read_of_known_private_record"),
            "rows_visible_to_b": visible_b,
            "note": ("account B could read the known A-owned record" if visible_b
                     else "account B could not read the known A-owned record")}


def jwt_claims(token):
    """Best-effort unverified JWT claim decoding for input validation only."""
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload).decode("utf-8", "replace"))
        return claims if isinstance(claims, dict) else {}
    except Exception:
        return {}


def public_headers(key):
    """Build anonymous headers for legacy anon JWTs and modern publishable keys."""
    headers = {"apikey": key, "Content-Type": "application/json"}
    if _jwt_role(key) == "anon":
        headers["Authorization"] = "Bearer " + key
    return headers


def validate_base_url(raw):
    """Accept HTTPS Supabase/custom domains and loopback HTTP development URLs."""
    parsed = urllib.parse.urlsplit(raw)
    if not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("URL must contain a hostname and no embedded credentials")
    if parsed.query or parsed.fragment:
        raise ValueError("URL must not contain a query string or fragment")
    loopback = parsed.hostname in ("localhost", "127.0.0.1", "::1")
    if parsed.scheme != "https" and not (parsed.scheme == "http" and loopback):
        raise ValueError("URL must use HTTPS (HTTP is allowed only for loopback development)")
    return raw.rstrip("/")


def parse_idor_target(value):
    """Parse TABLE:ID without imposing a UUID-only identifier policy."""
    if ":" not in value:
        raise argparse.ArgumentTypeError("IDOR target must be TABLE:ID")
    table, row_id = value.split(":", 1)
    if not table.strip() or not row_id.strip():
        raise argparse.ArgumentTypeError("IDOR target must contain both TABLE and ID")
    return table.strip(), row_id.strip()


def main():
    ap = argparse.ArgumentParser(
        description="Read-only Supabase anon-key access-control probe.")
    ap.add_argument("--url", required=True, help="https://<project>.supabase.co")
    ap.add_argument("--anon", required=True,
                    help="legacy anon or sb_publishable key (never service_role/sb_secret)")
    ap.add_argument("--tables", default="", help="comma-separated; discovered if omitted")
    ap.add_argument("--timeout", type=float, default=TIMEOUT_DEFAULT)
    ap.add_argument("--max-tables", type=int, default=50)
    ap.add_argument("--write-probe", action="store_true",
                    help="ALSO attempt an anon INSERT per table. This can CREATE A ROW "
                         "and trigger side effects. Use only on an authorized test project.")
    ap.add_argument("--jwt-a", default=os.environ.get("SUPABASE_JWT_A", ""),
                    help="test account A token; prefer SUPABASE_JWT_A to avoid shell history")
    ap.add_argument("--jwt-b", default=os.environ.get("SUPABASE_JWT_B", ""),
                    help="test account B token; prefer SUPABASE_JWT_B to avoid shell history")
    ap.add_argument("--idor-target", action="append", default=[],
                    type=parse_idor_target, metavar="TABLE:ID",
                    help="known private record owned by A; repeat for multiple records")
    args = ap.parse_args()

    role = _jwt_role(args.anon)
    if args.anon.startswith("sb_secret_") or role == "service_role":
        print(json.dumps({"error": "that is an elevated service_role/sb_secret key — "
                                   "refusing to run. Use anon or sb_publishable."}))
        return 2
    if role and role != "anon":
        print(json.dumps({"error": "the API key JWT role is %r, not anon — refusing to run" % role}))
        return 2

    try:
        base = validate_base_url(args.url)
    except ValueError as exc:
        print(json.dumps({"error": str(exc)}))
        return 2
    if args.timeout <= 0 or args.max_tables <= 0:
        print(json.dumps({"error": "timeout and max-tables must be positive"}))
        return 2

    if bool(args.jwt_a) != bool(args.jwt_b):
        print(json.dumps({"error": "IDOR testing requires both account tokens"}))
        return 2
    if args.idor_target and not (args.jwt_a and args.jwt_b):
        print(json.dumps({"error": "--idor-target requires both account tokens"}))
        return 2
    if args.jwt_a and args.jwt_b:
        claims_a, claims_b = jwt_claims(args.jwt_a), jwt_claims(args.jwt_b)
        if not claims_a.get("sub") or not claims_b.get("sub"):
            print(json.dumps({"error": "both account JWTs must contain a subject (sub) claim"}))
            return 2
        if claims_a["sub"] == claims_b["sub"]:
            print(json.dumps({"error": "account A and B tokens have the same subject"}))
            return 2
        if claims_a.get("iss") and claims_b.get("iss") and claims_a["iss"] != claims_b["iss"]:
            print(json.dumps({"error": "account tokens have different issuers/projects"}))
            return 2

    H = public_headers(args.anon)

    tables = [t.strip() for t in args.tables.split(",") if t.strip()]
    findings = []

    if not tables:
        status, tables = discover_tables(base, H, args.timeout)
        findings.append({"check": "discovery", "status": "INFO" if status == 200 else "UNKNOWN",
                         "http": status,
                         "detail": "root status %s; discovered %d table definitions"
                                   % (status, len(tables))})
    tables = tables[:args.max_tables]

    for t in tables:
        findings.append(probe_select(base, H, t, args.timeout))
        if args.write_probe:
            findings.append(probe_insert(base, H, t, args.timeout))
    for table, row_id in args.idor_target:
        findings.append(probe_idor(base, args.anon, table, row_id,
                                   args.jwt_a, args.jwt_b, args.timeout))

    if not args.write_probe:
        findings.append({
            "check": "anon_insert_probe", "verdict": "NOT_TESTED",
            "note": "anon write was not probed (default). PostgREST has no dry-run insert, "
                    "so a write probe can create a real row. Re-run with --write-probe on a "
                    "project you own if item #14 needs write coverage."})
    if not args.idor_target:
        findings.append({
            "check": "idor", "verdict": "NOT_TESTED",
            "note": "IDOR (#13) needs two authenticated test accounts plus at least one "
                    "known private record created by account A. Set SUPABASE_JWT_A/B and "
                    "pass --idor-target TABLE:ID."})

    fails = [f for f in findings if str(f.get("verdict", "")).startswith("FAIL")]
    unknown = [f for f in findings if (str(f.get("verdict", "")).startswith("UNKNOWN")
                                       or f.get("status") == "UNKNOWN")]
    exposures = [f for f in findings if str(f.get("verdict", "")).startswith("REVIEW")]
    not_tested = [f for f in findings
                  if str(f.get("verdict", "")).startswith("NOT_TESTED")]
    print(json.dumps({
        "supabase_probe": True,
        "url": base,
        "anon_key": mask(args.anon),
        "write_probe_enabled": args.write_probe,
        "tables_probed": tables,
        "confirmed_failures": len(fails),
        "exposures_needing_intent_review": len(exposures),
        "unknown_results": len(unknown),
        "not_tested": len(not_tested),
        "probe_complete": not unknown and not not_tested,
        "findings": findings,
    }, indent=2))
    return 0


def _jwt_role(token):
    """Best-effort read of the `role` claim; '' if the token isn't a readable JWT."""
    return str(jwt_claims(token).get("role", ""))


if __name__ == "__main__":
    sys.exit(main())
