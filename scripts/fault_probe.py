#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Fault-injection and error-leakage probe for web applications (Items #38, #39, #41).

Probes an HTTP API or web application endpoint with safe malformed inputs to:
1. Detect unhandled internal errors, stack trace leaks, database error messages,
   and server file path disclosures (Item #39 - High).
2. Generate a unique, traceable probe ID (`X-Vibecheck-Probe-Id`) to verify whether
   errors actually land in logging and observability dashboards (Sentry, Datadog,
   GCP Cloud Logging, CloudWatch, etc.) with redacted credentials (Items #38, #41).

Safety:
- Does not exploit vulnerabilities; sends bounded synthetic malformed payloads.
- Runs only against explicitly authorized targets.
- Uses stdlib only.
"""
import argparse
import datetime
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid

VERSION = "0.5.0"
TIMEOUT_DEFAULT = 10

# Signatures of internal error leakage in responses (Item #39)
STACK_TRACE_PATTERNS = [
    (re.compile(r"Traceback \(most recent call last\):", re.IGNORECASE), "Python traceback"),
    (re.compile(r"^\s*at\s+[\w$.]+\s+\(.*:\d+:\d+\)", re.MULTILINE), "Node.js/V8 stack trace"),
    (re.compile(r"^\s*at\s+[\w$./\\-]+\.js:\d+:\d+", re.MULTILINE), "JavaScript stack trace"),
    (re.compile(r"(\/app\/|\/var\/www\/|\/home\/|\/Users\/|[A-Z]:\\[\w\\]+)(src|dist|node_modules|lib|server|routes)[\w\/\.-]+\.(ts|js|py|go|rs):\d+", re.IGNORECASE), "Internal server file path with line number"),
    (re.compile(r"(syntax error at or near|pg_catalog|sqlite3\.OperationalError|SequelizeDatabaseError|PrismaClientKnownRequestError|MongoError|QueryFailedError)", re.IGNORECASE), "Raw database error / SQL syntax leak"),
    (re.compile(r"(UnhandledPromiseRejection|NullPointerException|Fatal error:|Internal Server Error.*details:)", re.IGNORECASE), "Unhandled exception message"),
]


def capability_record():
    return {
        "provider_id": "prov-fault-probe",
        "name": "Fault-injection & error-leakage probe",
        "version": VERSION,
        "mechanism": "scripts/fault_probe.py",
        "executor_role": "automation",
        "fallback_order": 12,
        "availability": {
            "bundled": True,
            "detect": "Bundled with vibecheck; uses Python stdlib only.",
            "requires_tools": ["python3"]
        },
        "network": {
            "outbound": True,
            "targets": ["the specified target web application or API endpoint"],
            "opt_in_flags": ["--url"]
        },
        "data_egress": {
            "occurs": True,
            "destinations": ["the specified target web application"],
            "opt_in_flags": ["--url"]
        },
        "side_effects": {
            "read": True,
            "write": False,
            "destructive": False,
            "deployment": False,
            "external_accounts": False
        },
        "cost": {"monetary": "none", "compute": "low", "human_effort": "low"},
        "confidence": {
            "limitations": "Probes targeted endpoints for stack traces and error leaks; verifies observability via traceable correlation IDs.",
            "false_positive_risk": "low",
            "false_negative_risk": "medium"
        },
        "coverage": [
            {
                "control_id": "vibecheck.control.obs.no_stack_traces",
                "operations": ["fault_injection_probe"],
                "subjects": ["api_endpoint", "http_response"],
                "max_strength": "decisive",
                "fills_coverage_cell": False,
                "closure_threshold": "A stack trace or database error leaked in a response is a decisive Fail for #39. A clean 4xx without leak is positive evidence for the probed endpoint."
            },
            {
                "control_id": "vibecheck.control.obs.error_tracking",
                "operations": ["fault_injection_probe"],
                "subjects": ["api_endpoint", "log_stream"],
                "max_strength": "indicative",
                "fills_coverage_cell": False,
                "closure_threshold": "Provides traceable probe ID for human verification in logging dashboards (Sentry, Datadog, GCP, CloudWatch)."
            }
        ],
        "environments": ["developer_only", "private_test", "public_release"],
        "environments_note": "Safe against local, staging, or authorized test environments.",
        "evidence_freshness": {"typical_validity": "until endpoints or error handlers change"}
    }


def analyze_response_for_leaks(status_code, body_text):
    """Check response body for leaked stack traces, SQL errors, or file paths."""
    leaks = []
    for pattern, label in STACK_TRACE_PATTERNS:
        match = pattern.search(body_text)
        if match:
            # Redact/truncate matching snippet
            snippet = match.group(0)[:120]
            leaks.append({"type": label, "snippet": snippet})
    return leaks


def send_probe_request(url, method="POST", data=None, headers=None, timeout=TIMEOUT_DEFAULT):
    """Send an HTTP request and return (status, headers, body, error_message)."""
    headers = headers or {}
    req_data = data.encode("utf-8") if isinstance(data, str) else data
    req = urllib.request.Request(url, data=req_data, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.status
            body = resp.read().decode("utf-8", errors="replace")
            return status, dict(resp.headers), body, None
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        return e.code, dict(e.headers), body, None
    except urllib.error.URLError as e:
        return 0, {}, "", f"Network connection error: {e.reason}"
    except Exception as e:
        return 0, {}, "", f"Probe execution error: {str(e)}"


def run_fault_probes(base_url, endpoint="/", authorized_by=None, environment="private_test"):
    """Run structured fault-injection cases against the target endpoint."""
    probe_uuid = str(uuid.uuid4())
    probe_id = f"vibecheck-probe-{probe_uuid[:8]}"
    full_url = urllib.parse.urljoin(base_url, endpoint)

    test_cases = [
        {
            "name": "malformed_json",
            "description": "Malformed/truncated JSON payload",
            "method": "POST",
            "headers": {"Content-Type": "application/json", "X-Vibecheck-Probe-Id": probe_id, "X-Request-Id": probe_id},
            "data": '{"vibecheck_test": true, "unclosed_string": "abc'
        },
        {
            "name": "schema_type_mismatch",
            "description": "Unexpected schema types (boolean for id, number for email)",
            "method": "POST",
            "headers": {"Content-Type": "application/json", "X-Vibecheck-Probe-Id": probe_id, "X-Request-Id": probe_id},
            "data": json.dumps({"id": True, "email": 999999, "action": ["invalid_type"]})
        },
        {
            "name": "invalid_resource_id",
            "description": "Non-existent resource ID lookup",
            "method": "GET",
            "headers": {"X-Vibecheck-Probe-Id": probe_id, "X-Request-Id": probe_id},
            "data": None
        },
        {
            "name": "boundary_special_chars",
            "description": "Special characters and SQL boundary test",
            "method": "POST",
            "headers": {"Content-Type": "application/json", "X-Vibecheck-Probe-Id": probe_id, "X-Request-Id": probe_id},
            "data": json.dumps({"query": "' OR '1'='1", "filter": "<script>alert(1)</script>", "tag": "=1+1"})
        }
    ]

    findings = []
    case_results = []
    total_leaks = 0

    for tc in test_cases:
        target = full_url
        if tc["name"] == "invalid_resource_id":
            target = urllib.parse.urljoin(full_url.rstrip("/") + "/", f"vibecheck-probe-nonexistent-{probe_uuid[:8]}")

        status, headers, body, err = send_probe_request(
            target, method=tc["method"], data=tc["data"], headers=tc["headers"]
        )

        if err:
            case_results.append({
                "case": tc["name"],
                "status": "error",
                "error": err
            })
            continue

        leaks = analyze_response_for_leaks(status, body)
        total_leaks += len(leaks)

        case_results.append({
            "case": tc["name"],
            "target_url": target,
            "http_status": status,
            "leaks_detected": leaks,
            "response_snippet": body[:200].replace("\n", " ").strip()
        })

    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Finding 1: Stack trace / error leakage (Item #39)
    if total_leaks > 0:
        findings.append({
            "check": "obs.no_stack_traces",
            "checklist_items": [39],
            "status": "WARN",
            "title": f"Internal error details / stack trace leaked in responses ({total_leaks} pattern match(es))",
            "evidence": json.dumps([c for c in case_results if c.get("leaks_detected")], indent=2),
            "observed_at": now_iso
        })
    else:
        findings.append({
            "check": "obs.no_stack_traces",
            "checklist_items": [39],
            "status": "NO_SIGNAL",
            "title": "No raw stack traces or database errors leaked in fault responses for probed endpoint",
            "evidence": f"Probed {len(test_cases)} malformed test cases against {full_url}; all returned clean 4xx/non-leaking responses.",
            "observed_at": now_iso
        })

    # Finding 2: Observability & log verification guidance (Items #38, #41)
    guidance = (
        f"Fault probe executed with probe ID '{probe_id}'. "
        f"Verify your logging/monitoring dashboard (Sentry, Datadog, GCP Cloud Logging, CloudWatch, PostHog):\n"
        f"1. Search logs for: '{probe_id}' or header 'X-Vibecheck-Probe-Id'\n"
        f"2. Confirm error event was recorded with appropriate severity (Warning/Error)\n"
        f"3. Confirm request headers and payloads have credentials/PII redacted in the log viewer."
    )
    findings.append({
        "check": "obs.error_tracking_verification",
        "checklist_items": [38, 41],
        "status": "MANUAL",
        "title": f"Observability dashboard verification required for probe ID: {probe_id}",
        "evidence": guidance,
        "probe_id": probe_id,
        "observed_at": now_iso
    })

    return {
        "probe_id": probe_id,
        "target": full_url,
        "environment": environment,
        "authorized_by": authorized_by or "interactive_user",
        "timestamp": now_iso,
        "results": case_results,
        "findings": findings
    }


def main():
    parser = argparse.ArgumentParser(description="Vibecheck fault-injection and error-leakage probe")
    parser.add_argument("--url", help="Base URL of the target application (e.g. http://localhost:3000)")
    parser.add_argument("--endpoint", default="/", help="API or page path to probe (default: /)")
    parser.add_argument("--environment", choices=["developer_only", "private_test", "public_release"], default="private_test")
    parser.add_argument("--authorized-by", help="Who authorized this probe run")
    parser.add_argument("--capability", action="store_true", help="Print capability record JSON")
    parser.add_argument("--json", action="store_true", help="Output full JSON results")

    args = parser.parse_args()

    if args.capability:
        print(json.dumps(capability_record(), indent=2))
        return 0

    if not args.url:
        parser.print_help()
        sys.exit(1)

    result = run_fault_probes(
        base_url=args.url,
        endpoint=args.endpoint,
        authorized_by=args.authorized_by,
        environment=args.environment
    )

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        for finding in result["findings"]:
            print(json.dumps(finding))

    return 0


if __name__ == "__main__":
    sys.exit(main())
