#!/usr/bin/env python3
"""Render `vibecheck.sh` JSON-lines output as a SARIF 2.1.0 log.

    bash scripts/vibecheck.sh <repo> | python3 scripts/sarif.py \
        --repo <repo> --out CLAUDE-SECURITY-RESULTS.sarif

Reads one finding object per line from stdin (the scanner's exact shape:
`check`, `checklist_items`, `status`, `title`, `evidence`), plus the opening
`{"scanner":"vibecheck","version":...}` line, and the closing
`{"scanner":"vibecheck","done":true,...}` line. Emits a SARIF log that
GitHub code scanning, IDE SARIF viewers and CI tooling can read.

Severity is resolved from the canonical control mapping (via controls.py), so
a check maps to a checklist item that is already a `Critical`/`High`/`Medium`/
`Low` control, and the SARIF `level` follows. Screening (Triage) items are
treated as `note`.

Credential handling (`--withhold-evidence`): by default machine products may
still carry an 8-char-redacted evidence line. With the flag, a check whose
item maps to the secrets category has its evidence withheld entirely (the line
is the credential; file/line/symbol still locate it). The flag mirrors
`_redact.py --withhold` and is what `vibecheck-scan` uses when it exports a
SARIF artifact, keeping raw secret values (or even useful prefixes) out of a
file that leaves the session (a code-scanning upload, a CI artifact).

Stdlib only.
"""
import argparse
import json
import os
import sys


def _load_controls():
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(0, os.path.join(repo, "scripts"))
    import controls  # noqa: E402
    return controls


def _item_severity(controls, item_number):
    """Worst control severity among the controls covering `item_number`."""
    worst_w = -1
    worst = "note"
    for entry in controls.build_framework_mapping()["entries"]:
        if entry["item_number"] == item_number:
            weight = entry["weight"]
            if weight > worst_w:
                worst_w = weight
                worst = entry["severity"]
    if worst_w <= 0:
        return "note", 0
    return worst, worst_w


def _is_screening(controls, item_number):
    for entry in controls.build_framework_mapping()["entries"]:
        if entry["item_number"] == item_number:
            return entry["kind"] == "screening"
    return False


def _level_for(severity):
    return {"Critical": "error", "High": "error",
            "Medium": "warning", "Low": "note"}.get(severity, "note")


def _item_is_secret(controls, item_numbers):
    """Whether any covered item is a secrets/credentials control (category 2)."""
    for entry in controls.build_framework_mapping()["entries"]:
        if entry["item_number"] in item_numbers and entry["category"]["number"] == 2:
            return True
    return False


def build(findings, meta, repo, version, withhold_evidence=False):
    controls = _load_controls()
    results = []
    rules = {}
    for finding in findings:
        check = finding.get("check", "?")
        items = finding.get("checklist_items") or []
        status = finding.get("status", "NO_SIGNAL")
        title = finding.get("title", "")
        evidence = finding.get("evidence", "")
        severity, weight = _item_severity(controls, int(items[0])) if items else ("note", 0)
        if status == "NO_SIGNAL":
            continue  # nothing to report as a result — absent signals aren't findings
        if status == "MANUAL":
            level = "note"
        else:
            level = _level_for(severity)
        rule_id = "vibecheck/" + check
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": check,
                "shortDescription": {"text": title[:200]},
                "properties": {
                    "tags": ["vibecheck"],
                    "checklist_items": items,
                    "status": status,
                },
            }
        message_text = title
        if status == "WARN" and evidence:
            message_text = title + "\n\nEvidence:\n" + evidence
        if withhold_evidence and _item_is_secret(controls, items):
            # The line is the credential; don't ship it (or a useful prefix).
            message_text = (title + "\n\n[A hard-coded credential line was "
                            "withheld — file/line/symbol locate it.]")
        locations = []
        first = _first_evidence_location(evidence)
        if first:
            locations.append({"physicalLocation": {
                "artifactLocation": {"uri": first["file"]},
                "region": {"startLine": first["line"]},
            }})
        results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {"text": message_text},
            "locations": locations,
            "properties": {"check": check, "status": status},
        })
    rules_metadata = [rules[k] for k in sorted(rules)]
    return {
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/"
                   "errata01/os/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Vibecheck static scanner",
                    "fullName": "Vibecheck — review of vibecoded applications",
                    "version": version or "unknown",
                    "informationUri": "https://github.com/jaakla/vibecheck",
                    "rules": rules_metadata,
                }
            },
            "results": results,
            "properties": {
                "status": meta.get("status"),
                "repo": repo,
                "scanner": "vibecheck",
            },
        }],
    }


def _first_evidence_location(evidence):
    """Best-effort parse of the first `<path>:<line>:` prefix in evidence."""
    import re
    m = re.search(r'([^\s:]+(?:\.[A-Za-z0-9]+)+):(\d+):', evidence)
    if not m:
        return None
    return {"file": m.group(1).lstrip("./"), "line": int(m.group(2))}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", default=".", help="repository path (for provenance)")
    ap.add_argument("--out", help="output .sarif path; default writes to stdout")
    ap.add_argument("--withhold-evidence", action="store_true",
                    help="withhold hard-coded credential evidence from machine output")
    ap.add_argument("--version", default=None, help="scanner version override")
    args = ap.parse_args(argv)

    findings = []
    meta = {}
    version = args.version
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if obj.get("scanner") == "vibecheck":
            if "version" in obj and "done" not in obj:
                version = version or obj.get("version")
            meta["status"] = obj.get("done", True)
            continue
        if "check" in obj:
            findings.append(obj)
    log = build(findings, meta, args.repo, version, args.withhold_evidence)
    text = json.dumps(log, indent=2, ensure_ascii=False)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    else:
        sys.stdout.write(text + "\n")


if __name__ == "__main__":
    main()
