# -*- coding: utf-8 -*-
"""Legacy import/export adapters for the canonical envelope (RFC 0001 §11).

Import (legacy tool output -> vibecheck.assessment envelope):

  import_scanner_jsonl(lines, ...)      vibecheck.sh JSONL stream  (§11.1)
  import_supabase_probe(probe, env, ..) supabase_probe.py JSON     (§11.2)

Both importers produce Signals (raw archive), Evidence and Actions only —
never Assessments: providers propose material, a human or accountable process
decides (§6.3). NO_SIGNAL becomes neutral evidence, which can never support a
pass (rule R3), and MANUAL/NOT_TESTED become open verify actions so nothing is
silently skipped. Raw values are redacted and bounded before they enter the
envelope; secret-bearing raw results are never copied in.

Export (envelope -> current output contracts):

  export_scanner_jsonl(env)    reconstructs the scanner JSONL stream
                               byte-for-byte from the archived signals
  export_workbook_rows(env)    per-item status/notes wording for the
                               reviewer/founder workbook paths
"""
import datetime
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import canonical
import items
from controls import (CONTROL_IDS, ITEM_NUMBERS, STATUS_MAP,
                      REGISTRY_NAME, REGISTRY_VERSION)

SCANNER_TOOL = "vibecheck.sh"
PROBE_TOOL = "supabase_probe.py"
EVIDENCE_VALIDITY_DAYS = 30

_TITLES = None


def _title_en(control_id):
    global _TITLES
    if _TITLES is None:
        _TITLES = {c["control_id"]: c["title"]["en"]
                   for c in canonical.load_registry()["controls"]}
    return _TITLES[control_id]


def _utcnow():
    return datetime.datetime.now(datetime.timezone.utc)


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_now(now):
    if now is None:
        return _utcnow()
    return datetime.datetime.fromisoformat(now.replace("Z", "+00:00"))


def _claim(item_numbers):
    control_ids = [CONTROL_IDS[n] for n in item_numbers if n in CONTROL_IDS]
    return {
        "control_ids": control_ids,
        "statement": "; ".join(_title_en(cid) for cid in control_ids),
    }


def _envelope(assessment_id, context_id, app_name, description,
              target_scopes, created_at):
    return {
        "schema": canonical.SCHEMA_NAME,
        "schema_version": canonical.SCHEMA_VERSION,
        "assessment_id": assessment_id,
        "revision": 1,
        "created_at": created_at,
        "context": {
            "context_id": context_id,
            "revision": 1,
            "application": {"name": app_name, "description": description},
            "target_scopes": target_scopes,
            # draft until a human confirms the context; a draft confirmation
            # caps readiness at incomplete (RFC §4.2), which is the honest
            # default for an unattended import
            "confirmation": {"state": "draft"},
        },
        "control_registry": {"name": REGISTRY_NAME, "version": REGISTRY_VERSION},
        "signals": [],
        "evidence": [],
        "actions": [],
    }


# ------------------------------------------------------------ scanner (§11.1)

def import_scanner_jsonl(lines, app_name="unknown application",
                         environment="developer_only", now=None,
                         assessment_id="va-scanner-import",
                         target_scopes=None):
    """Map a vibecheck.sh JSONL stream to a canonical envelope.

    Every line (header, findings, errors, footer) is archived as a Signal in
    stream order, which is what makes export_scanner_jsonl byte-compatible.
    WARN -> refuting indicative evidence; NO_SIGNAL -> neutral evidence;
    MANUAL -> an open verify action and no evidence; scanner errors -> a
    coverage-gap note. No assessments are produced and nothing maps to pass.
    """
    if isinstance(lines, str):
        lines = lines.splitlines()
    now_dt = _parse_now(now)
    observed_at = _iso(now_dt)
    valid_until = _iso(now_dt + datetime.timedelta(days=EVIDENCE_VALIDITY_DAYS))

    env = _envelope(
        assessment_id, "ctx-scanner-import", app_name,
        "Imported from the vibecheck.sh static scanner JSONL output.",
        target_scopes or [{"environment": "developer_only",
                           "intended_use": "prototype_demo"}],
        observed_at)
    tool_version = "unknown"
    seq = 0

    for lineno, line in enumerate(lines, 1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError as exc:
            raise ValueError("line %d is not valid JSON: %s" % (lineno, exc))
        seq += 1
        signal_id = "sig-scan-%04d" % seq
        signal = {
            "signal_id": signal_id,
            "source": {"tool": SCANNER_TOOL},
            "subject": {"kind": "repo", "locator": "."},
            "environment": environment,
            "observed_at": observed_at,
            "raw_ref": {"kind": "inline",
                        "value": canonical.bound_raw(line, canonical.MAX_RAW_SIGNAL)},
        }

        if "check" not in obj:
            # header / footer / error lines from the scanner itself
            if obj.get("version"):
                tool_version = str(obj["version"])
                signal["notes"] = "Scanner stream header."
            elif "error" in obj:
                signal["notes"] = (
                    "Scanner error: %s. Coverage gap: checks that would have "
                    "run may be missing from this artifact, and their controls "
                    "stay unassessed — absence of a finding here is not a pass."
                    % obj["error"])
            elif obj.get("done"):
                signal["notes"] = "Scanner stream footer (run completed)."
            env["signals"].append(signal)
            continue

        check = obj["check"]
        status = obj.get("status", "")
        signal["source"]["check_id"] = check
        env["signals"].append(signal)

        claim = _claim(obj.get("checklist_items") or [])
        tier = items.SCANNER_CHECKS.get(check, (None, "EVIDENCE"))[1]

        if status in ("WARN", "NO_SIGNAL") and claim["control_ids"]:
            if status == "WARN":
                direction = "refutes"
                scope = ("Current working tree only; ruleset = %s (tier %s). "
                         "A regex/path heuristic has both false positives and "
                         "false negatives — this is material for a human "
                         "decision, never a confirmed finding." % (check, tier))
            else:
                direction = "neutral"
                scope = ("Absence of matches for ruleset %s only. Absence of a "
                         "signal is not evidence of absence and can never "
                         "support a pass (rule R3)." % check)
            env["evidence"].append({
                "evidence_id": "ev-scan-%04d" % seq,
                "provider": {"name": "vibecheck.sh static scanner",
                             "version": tool_version},
                "subject": {"kind": "repo", "locator": "."},
                "environment": environment,
                "operation": "static_pattern_scan",
                "scope": scope,
                "claim": claim,
                "direction": direction,
                "strength": "indicative",
                "observed_at": observed_at,
                "valid_until": valid_until,
                "signal_refs": [signal_id],
                "raw_result_ref": {
                    "kind": "inline",
                    "value": canonical.bound_raw(obj.get("evidence") or
                                                 "no matches")},
                "redaction": ("scanner-side credential redaction plus import "
                              "bound of %d chars" % canonical.MAX_RAW_EVIDENCE),
                "side_effects": {"writes": False, "destructive": False,
                                 "external_accounts": False,
                                 "data_egress": False},
            })
        elif status == "MANUAL" and claim["control_ids"]:
            env["actions"].append({
                "action_id": "act-scan-%04d" % seq,
                "kind": "verify",
                "outcome": "Verified with recorded evidence: %s"
                           % (obj.get("title") or claim["statement"]),
                "reason": ("Scanner check %s is tier MANUAL: no static signal "
                           "exists for it. Emitted as an explicit to-do so it "
                           "cannot be silently skipped." % check),
                "urgency": "planned",
                "deadline": {
                    "kind": "unknown",
                    "rationale": ("The deadline depends on the confirmed "
                                  "target environment and intended use; set it "
                                  "during review."),
                },
                "blocking_scope": [],
                "owner": {"role": "unassigned"},
                "state": "open",
                "state_history": [{"state": "open", "at": observed_at,
                                   "by": "vibecheck scanner-jsonl import adapter"}],
                "control_refs": claim["control_ids"],
                "success_evidence": ("Recorded evidence for this control (a "
                                     "dashboard export, probe result, or "
                                     "reviewer walkthrough) — a disappeared "
                                     "warning is never sufficient."),
                "reassess_control_ids": claim["control_ids"],
            })
    return env


# -------------------------------------------------------------- probe (§11.2)

def _probe_evidence(finding, verdict):
    """(direction, strength, scope note) for one probe finding, or None when
    the finding maps to an action / signal only."""
    table = finding.get("table", "?")
    note = finding.get("note") or ""
    if verdict.startswith("REVIEW_rows_readable_by_anon"):
        return ("refutes", "decisive",
                "Observed behavior: %s row(s) in %r returned to an "
                "unauthenticated caller. Decisive that anon can read this "
                "table; whether that violates the control depends on whether "
                "the table is intended to be public, which is unestablished — "
                "see the linked decide action."
                % (finding.get("rows_visible_to_anon"), table))
    if verdict.startswith("NO_ROWS_VISIBLE_UNCONFIRMED"):
        return ("neutral", "indicative",
                "Zero rows returned to anon from %r. RLS may be filtering OR "
                "the table may be empty; only a seeded non-empty table turns "
                "this into supporting evidence." % table)
    if verdict.startswith("FAIL_anon_write_succeeded"):
        return ("refutes", "decisive",
                "Observed behavior: an unauthenticated INSERT into %r "
                "succeeded; a probe row was very likely created." % table)
    if verdict.startswith("WARN_write_reached_validation"):
        return ("refutes", "indicative",
                "An unauthenticated INSERT into %r was rejected by "
                "validation, not by authorization — policy may allow anon "
                "writes with well-formed input." % table)
    if verdict.startswith("FAIL_cross_account_read"):
        return ("refutes", "decisive",
                "Observed behavior: account B read a record owned by account "
                "A in %r (record %s)." % (table, finding.get("record_id")))
    if verdict.startswith("PASS_no_cross_account_read"):
        return ("supports", "decisive",
                "Account B could not read one known A-owned record in %r "
                "(record %s). Decisive for this record only; it is not proof "
                "for other tables, records, or operations."
                % (table, finding.get("record_id")))
    if verdict.startswith("BLOCKED_OR_KEY_INVALID"):
        return ("neutral", "indicative",
                "The request against %r was blocked, but that does not prove "
                "RLS: the key may be invalid for this project. %s"
                % (table, note))
    if verdict.startswith("UNKNOWN"):
        return ("neutral", "indicative",
                "Probe result %s for %r: the aspect stays unknown. %s"
                % (verdict, table, note))
    if verdict.startswith("INFO_not_exposed"):
        return ("neutral", "indicative",
                "%r is not exposed through PostgREST. This covers the REST "
                "vector only and may also mean the table name does not exist."
                % table)
    return None


_PROBE_CONTROL = {"anon_select": 14, "anon_insert_probe": 14, "idor": 13}
_PROBE_OPERATION = {"anon_select": "http_select_anon_head",
                    "anon_insert_probe": "http_insert_anon",
                    "idor": "http_select_authenticated_cross_account"}


def import_supabase_probe(probe, environment, now=None, app_name=None,
                          authorized_by=None,
                          assessment_id="va-supabase-probe-import"):
    """Map supabase_probe.py JSON to a canonical envelope.

    Every probe result becomes scoped evidence about one table (or one
    record), never a control-wide conclusion. NOT_TESTED becomes an open
    verify action; the derivable summary block (probe_complete, counters) is
    dropped, not stored. `environment` must be stated explicitly by the
    caller: the adapter cannot know whether the probed deployment is a
    sandbox or production.
    """
    now_dt = _parse_now(now)
    observed_at = _iso(now_dt)
    valid_until = _iso(now_dt + datetime.timedelta(days=EVIDENCE_VALIDITY_DAYS))
    url = probe.get("url", "unknown")

    env = _envelope(
        assessment_id, "ctx-supabase-probe-import",
        app_name or ("Supabase project %s" % url),
        "Imported from the vibecheck Supabase live probe output.",
        [{"environment": environment, "intended_use": "prototype_demo"}],
        observed_at)

    write_probe = bool(probe.get("write_probe_enabled"))
    authorization = {
        "authorized_by": authorized_by or
        "unrecorded — the probe runs only against a project the user "
        "supplied the URL and anon key for",
        "granted_at": observed_at,
        "scope": ("anon-key probe of %s%s" %
                  (url, " including opt-in write probe" if write_probe
                   else ", read-only (no write probe)")),
    }

    seq = 0
    for finding in probe.get("findings") or []:
        seq += 1
        check = finding.get("check", "")
        verdict = str(finding.get("verdict", ""))
        table = finding.get("table")
        subject = ({"kind": "table", "locator": str(table)} if table
                   else {"kind": "deployment", "locator": url})
        signal_id = "sig-probe-%04d" % seq
        env["signals"].append({
            "signal_id": signal_id,
            "source": {"tool": PROBE_TOOL, "check_id": check},
            "subject": subject,
            "environment": environment,
            "observed_at": observed_at,
            "raw_ref": {"kind": "inline",
                        "value": canonical.bound_raw(
                            json.dumps(finding, ensure_ascii=False,
                                       sort_keys=True),
                            canonical.MAX_RAW_EVIDENCE)},
        })

        item = _PROBE_CONTROL.get(check)
        if item is None:
            continue  # discovery and other informational entries: signal only
        claim = _claim([item])
        claim["aspect"] = {
            "anon_select": "anon read access to table %r" % table,
            "anon_insert_probe": "anon write access to table %r" % table,
            "idor": "cross-account read of one known record in %r" % table,
        }[check]

        if verdict.startswith("NOT_TESTED"):
            env["actions"].append({
                "action_id": "act-probe-%04d" % seq,
                "kind": "verify",
                "outcome": ("Probe the %s aspect with the required consent and "
                            "inputs, and record the resulting evidence."
                            % check),
                "reason": ("Probe check %s was NOT_TESTED: %s"
                           % (check, finding.get("note", ""))),
                "urgency": "planned",
                "deadline": {
                    "kind": "unknown",
                    "rationale": ("The deadline depends on the confirmed "
                                  "target environment and intended use; set it "
                                  "during review."),
                },
                "blocking_scope": [],
                "owner": {"role": "unassigned"},
                "state": "open",
                "state_history": [{"state": "open", "at": observed_at,
                                   "by": "vibecheck supabase-probe import adapter"}],
                "control_refs": claim["control_ids"],
                "success_evidence": ("Probe evidence for this aspect, or an "
                                     "equivalent authorized test with a "
                                     "recorded result."),
                "reassess_control_ids": claim["control_ids"],
            })
            continue

        mapped = _probe_evidence(finding, verdict)
        if mapped is None:
            continue
        direction, strength, scope = mapped
        wrote = verdict.startswith("FAIL_anon_write_succeeded")
        evidence_id = "ev-probe-%04d" % seq
        env["evidence"].append({
            "evidence_id": evidence_id,
            "provider": {"name": "vibecheck supabase probe"},
            "subject": subject,
            "environment": environment,
            "operation": _PROBE_OPERATION[check],
            "scope": scope,
            "claim": claim,
            "direction": direction,
            "strength": strength,
            "observed_at": observed_at,
            "valid_until": valid_until,
            "signal_refs": [signal_id],
            "raw_result_ref": {"kind": "inline",
                               "value": canonical.bound_raw(
                                   finding.get("note") or verdict)},
            "authorization": authorization,
            "side_effects": {
                "writes": wrote,
                "destructive": False,
                "external_accounts": False,
                "data_egress": False,
                **({"details": "the write probe very likely created a row in "
                               "%r; clean it up" % table} if wrote else {}),
            },
            "redaction": "probe masks the anon key; notes bounded at import",
        })

        if verdict.startswith("REVIEW_rows_readable_by_anon"):
            env["actions"].append({
                "action_id": "act-probe-%04d" % seq,
                "kind": "decide",
                "outcome": ("A recorded owner decision whether table %r is "
                            "intended to be publicly readable; if not, anon "
                            "read must be denied and re-probed." % table),
                "reason": ("Probe check anon_select found rows in %r readable "
                           "by an unauthenticated caller; this is a failure "
                           "only if the table is meant to be private, and "
                           "only the owner can decide that." % table),
                "urgency": "next",
                "deadline": {
                    "kind": "unknown",
                    "rationale": ("Until decided, this exposure blocks any "
                                  "claim that anon access is intended."),
                },
                "blocking_scope": [],
                "owner": {"role": "founder"},
                "state": "open",
                "state_history": [{"state": "open", "at": observed_at,
                                   "by": "vibecheck supabase-probe import adapter"}],
                "control_refs": claim["control_ids"],
                "risk_refs": [],
                "success_evidence": ("The recorded decision, plus a re-probe "
                                     "when access was tightened."),
                "reassess_control_ids": claim["control_ids"],
            })
    return env


# -------------------------------------------------------------------- exports

def export_scanner_jsonl(env):
    """Reconstruct the scanner JSONL stream from the archived signals.

    Byte-compatible with the imported stream: import_scanner_jsonl archives
    every line verbatim (the import bound sits above the scanner's own output
    cap, and scanner output is already credential-redacted, so bounding is a
    no-op on well-formed streams).
    """
    lines = [s["raw_ref"]["value"] for s in env.get("signals") or []
             if (s.get("source") or {}).get("tool") == SCANNER_TOOL
             and (s.get("raw_ref") or {}).get("kind") == "inline"]
    return "".join(line + "\n" for line in lines)


def export_workbook_rows(env, lang="en"):
    """Per-item {status, notes} wording for the workbook paths.

    The status cell carries the exact reviewer/founder wording from the
    bijective status map (§11.3). An item with no current assessment gets a
    blank status — deliberately distinct from an explicit 'Not tested'.
    """
    rows = {n: {"status": "", "notes": ""} for n in CONTROL_IDS}
    for asm in canonical.current_assessments(env):
        n = ITEM_NUMBERS.get(asm.get("control_id"))
        if n is None:
            continue
        wording = STATUS_MAP.get(asm.get("status"), {}).get(lang)
        if wording is None:
            continue
        notes = (asm.get("basis") or {}).get("rationale", "")
        acceptance = asm.get("acceptance")
        if acceptance:
            notes = ("%s [Accepted by %s: %s; review by %s]" % (
                notes, acceptance.get("accepted_by", "?"),
                acceptance.get("reason", "?"),
                acceptance.get("review_by", "?"))).strip()
        rows[n] = {"status": wording, "notes": notes}
    return rows
