# -*- coding: utf-8 -*-
"""Legacy import/export adapters for the canonical envelope (RFC 0001 §11).

Import (legacy tool output -> vibecheck.assessment envelope):

  import_scanner_jsonl(lines, ...)      vibecheck.sh JSONL stream  (§11.1)
  import_supabase_probe(probe, env, ..) supabase_probe.py JSON     (§11.2)
  import_rls_analysis(analysis, ...)    analyze_sql.py JSON        (§11.2)
  import_workbook_rows(rows, ...)      legacy review-workbook cells (§11.3)

All tool importers produce Signals (raw archive), Evidence and Actions only —
never Assessments: providers propose material, a human or accountable process
decides (§6.3). NO_SIGNAL emitted by a tool becomes neutral evidence, which can
never support a pass (rule R3), and MANUAL/NOT_TESTED become open verify actions
so nothing is silently skipped. Raw values are redacted and bounded before they
enter the envelope; secret-bearing raw results are never copied in.

`import_workbook_rows` is the one deliberate exception: a completed legacy
workbook *is* the human's decision, so its cells become canonical Assessments
(and the notes of pass/partial/fail cells become scoped Evidence, because the
schema requires an evidence-backed status).

Live probe results additionally carry the authorization coverage cell they
establish — one object, one actor, one operation, one environment (rule R20).
Probe output that predates those annotations is mapped from its check name and
verdict through schema/authz-coverage.v1.json, so an archived CLI result stays
importable without being re-run. Static migration analysis deliberately fills
no cell: it is a signal about the source tree, never an observation of the
deployed project.

Export (envelope -> current output contracts):

  export_scanner_jsonl(env)    reconstructs the scanner JSONL stream
                               byte-for-byte from the archived signals
  export_workbook_rows(env)    per-item status/notes wording for the
                               reviewer/founder workbook paths
  export_legacy_action_view(env) lossy AUTO/PROPOSE/ADVISORY display only;
                                 never an authorization input
"""
import datetime
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import canonical
import actions as actions_mod
import authz as authz_mod
import providers as providers_mod
from controls import (CONTROL_IDS, ITEM_NUMBERS, STATUS_MAP,
                      REGISTRY_NAME, REGISTRY_VERSION, scanner_tier)

SCANNER_TOOL = "vibecheck.sh"
PROBE_TOOL = "supabase_probe.py"
EVIDENCE_VALIDITY_DAYS = 30

#: The bundled tools are registry providers, so what each one is allowed to
#: claim comes from its capability record rather than from the adapter's own
#: idea of it. Nothing about the tools' own output changes: the CLI contracts
#: are unchanged and export_scanner_jsonl still reconstructs the stream
#: byte-for-byte from the archived signals.
SCANNER_PROVIDER = "prov-static-scanner"
PROBE_PROVIDER = "prov-supabase-probe"
RLS_PROVIDER = "prov-migration-analysis"

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
              target_scopes, created_at, authorization_objects=None):
    context = {
        "context_id": context_id,
        "revision": 1,
        "application": {"name": app_name, "description": description},
        "target_scopes": target_scopes,
        # draft until a human confirms the context; a draft confirmation
        # caps readiness at incomplete (RFC §4.2), which is the honest
        # default for an unattended import
        "confirmation": {"state": "draft"},
    }
    if authorization_objects:
        context["authorization_objects"] = [dict(obj) for obj
                                            in authorization_objects]
    return {
        "schema": canonical.SCHEMA_NAME,
        "schema_version": canonical.SCHEMA_VERSION,
        "assessment_id": assessment_id,
        "revision": 1,
        "created_at": created_at,
        "context": context,
        "control_registry": {"name": REGISTRY_NAME, "version": REGISTRY_VERSION},
        "action_registry": actions_mod.registry_ref(),
        "coverage_model": authz_mod.model_ref(),
        "provider_registry": providers_mod.registry_ref(),
        "signals": [],
        "evidence": [],
        "actions": [],
    }


def _attach_capability(env, provider_id, version=None, **instance):
    """Record what the tool that produced this envelope could do.

    An envelope is read long after the run, so the capability travels with the
    evidence instead of being looked up in whatever the registry says later.
    It is narrowed to the controls the run actually claimed: the capability as
    exercised, not a catalogue.
    """
    control_ids = sorted({control_id
                          for item in env.get("evidence") or []
                          if (item.get("provider") or {}).get("provider_ref")
                          == provider_id
                          for control_id in
                          ((item.get("claim") or {}).get("control_ids") or [])})
    if not control_ids:
        return
    record = providers_mod.instantiate(provider_id, control_ids=control_ids,
                                       version=version, **instance)
    env.setdefault("providers", []).append(record)


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
            "source": {"tool": SCANNER_TOOL, "provider_ref": SCANNER_PROVIDER},
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
        tier = scanner_tier(check) or "EVIDENCE"

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
                "provider": providers_mod.evidence_provider_block(
                    SCANNER_PROVIDER, tool_version),
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
                "action_key": "scan-%04d" % seq,
                "revision": 1,
                "created_at": observed_at,
                "kind": "verify",
                "outcome": "Verified with recorded evidence: %s"
                           % (obj.get("title") or claim["statement"]),
                "reason": ("Scanner check %s is tier MANUAL: no static signal "
                           "exists for it. Emitted as an explicit to-do so it "
                           "cannot be silently skipped." % check),
                "priority": "unknown",
                "urgency": "planned",
                "deadline": {
                    "kind": "unknown",
                    "rationale": ("The deadline depends on the confirmed "
                                  "target environment and intended use; set it "
                                  "during review."),
                    "reassess_trigger": {"kind": "context_change"},
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
    _attach_capability(env, SCANNER_PROVIDER, tool_version)
    return env


# -------------------------------------------------------------- probe (§11.2)

def _probe_evidence(finding, verdict):
    """(direction, strength, scope note) for one probe finding, or None when
    the finding maps to an action / signal only."""
    table = finding.get("table", "?")
    note = finding.get("note") or ""
    if verdict.startswith("PASS_no_anon_rows_on_non_empty_table"):
        return ("supports", "decisive",
                "Anon read of %r returned nothing while an authenticated test "
                "account saw %s row(s), so the table is not empty and the "
                "filtering is real. Covers reading this one table as an "
                "anonymous caller in this environment: not writing it, not "
                "another table, not another actor."
                % (table, finding.get("rows_visible_to_test_account")))
    if verdict.startswith("BLOCKED_OR_KEY_INVALID") and finding.get("key_validated"):
        return ("supports", "indicative",
                "The request against %r was refused while the same key was "
                "accepted elsewhere in this run, so the refusal is the "
                "project's policy rather than a wrong key. Indicative only: "
                "the response does not distinguish a denying policy from a "
                "missing grant, and it covers this one object and operation. %s"
                % (table, note))
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
                          assessment_id="va-supabase-probe-import",
                          authorization_objects=None):
    """Map supabase_probe.py JSON to a canonical envelope.

    Every probe result becomes scoped evidence about one table (or one
    record), never a control-wide conclusion. NOT_TESTED becomes an open
    verify action; the derivable summary block (probe_complete, counters) is
    dropped, not stored. `environment` must be stated explicitly by the
    caller: the adapter cannot know whether the probed deployment is a
    sandbox or production, and a probe that recorded its own environment must
    agree with it rather than being relabelled on import.

    Each mapped finding carries the coverage cell it establishes. Probe output
    from before those annotations is mapped through the shared coverage model,
    so archived CLI results import unchanged. Passing the application's
    representative objects (`authorization_objects`) additionally turns the
    still-untested cells into open verify Actions instead of silence.
    """
    now_dt = _parse_now(now)
    observed_at = _iso(now_dt)
    valid_until = _iso(now_dt + datetime.timedelta(days=EVIDENCE_VALIDITY_DAYS))
    url = probe.get("url", "unknown")

    recorded_environment = probe.get("environment")
    if recorded_environment and recorded_environment != environment:
        raise ValueError(
            "the probe recorded environment %r; importing it as %r would "
            "relabel where the observation was made"
            % (recorded_environment, environment))

    env = _envelope(
        assessment_id, "ctx-supabase-probe-import",
        app_name or ("Supabase project %s" % url),
        "Imported from the vibecheck Supabase live probe output.",
        [{"environment": environment, "intended_use": "prototype_demo"}],
        observed_at, authorization_objects)

    write_probe = bool(probe.get("write_probe_enabled"))
    recorded_authorization = probe.get("authorization") or {}
    authorization = {
        "authorized_by": (authorized_by
                          or recorded_authorization.get("authorized_by")
                          or "unrecorded — the probe runs only against a "
                             "project the user supplied the URL and anon key for"),
        "granted_at": recorded_authorization.get("granted_at") or observed_at,
        "scope": recorded_authorization.get("scope") or (
            "anon-key probe of %s%s" %
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
            "source": {"tool": PROBE_TOOL, "check_id": check,
                       "provider_ref": PROBE_PROVIDER},
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
                "action_key": "probe-%04d" % seq,
                "revision": 1,
                "created_at": observed_at,
                "kind": "verify",
                "outcome": ("Probe the %s aspect with the required consent and "
                            "inputs, and record the resulting evidence."
                            % check),
                "reason": ("Probe check %s was NOT_TESTED: %s"
                           % (check, finding.get("note", ""))),
                "priority": "unknown",
                "urgency": "planned",
                "deadline": {
                    "kind": "unknown",
                    "rationale": ("The deadline depends on the confirmed "
                                  "target environment and intended use; set it "
                                  "during review."),
                    "reassess_trigger": {"kind": "context_change"},
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
        cleanup = finding.get("cleanup") or {}
        known_object = authz_mod.inventory_object_for_locator(env, table)
        cells = authz_mod.cells_from_probe_finding(
            finding,
            object_class=(known_object or {}).get("object_class"),
            object_ref=(known_object or {}).get("locator"))
        for cell in cells:
            cell.setdefault("environment", environment)
            if known_object:
                cell.setdefault("object_id", known_object.get("object_id"))
                if cell.get("object_class") in (None, "unclassified"):
                    # The probe sees a table name; the review knows what kind of
                    # object it is. Classifying it here is what lets the cell
                    # count toward a requirement.
                    cell["object_class"] = known_object.get("object_class")
        evidence_id = "ev-probe-%04d" % seq
        env["evidence"].append({
            "evidence_id": evidence_id,
            "provider": providers_mod.evidence_provider_block(
                PROBE_PROVIDER, probe.get("version")),
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
                **({"details":
                    "the write probe very likely created a row in %r "
                    "(%s); cleanup state is %r"
                    % (table,
                       cleanup.get("target") or "row identifier not returned",
                       cleanup.get("state") or "unrecorded")} if wrote else {}),
            },
            "redaction": "probe masks the anon key; notes bounded at import",
            **({"coverage": cells} if cells else {}),
        })

        if wrote:
            env["actions"].append({
                "action_id": "act-probe-cleanup-%04d" % seq,
                "action_key": "probe-cleanup-%04d" % seq,
                "revision": 1,
                "created_at": observed_at,
                "kind": "remediate",
                "outcome": ("The row the anon write probe created in %r (%s) is "
                            "deleted, and its absence is recorded."
                            % (table,
                               cleanup.get("target") or "identifier not returned")),
                "reason": ("The opt-in write probe succeeded against %s, which "
                           "means real data was created in %s. A probe that "
                           "writes owns its cleanup." % (table, environment)),
                "priority": "high",
                "urgency": "immediate",
                "deadline": {
                    "kind": "immediate",
                    "rationale": ("Probe-created rows are indistinguishable "
                                  "from real ones once they age."),
                    "reassess_trigger": {"kind": "context_change"},
                },
                "blocking_scope": [],
                "owner": {"role": "founder"},
                "state": "open",
                "state_history": [{"state": "open", "at": observed_at,
                                   "by": "vibecheck supabase-probe import adapter"}],
                "control_refs": claim["control_ids"],
                "success_evidence": ("A recorded check that the created row is "
                                     "gone, by identifier."),
                "reassess_control_ids": claim["control_ids"],
            })

        if verdict.startswith("REVIEW_rows_readable_by_anon"):
            env["actions"].append({
                "action_id": "act-probe-%04d" % seq,
                "action_key": "probe-%04d" % seq,
                "revision": 1,
                "created_at": observed_at,
                "kind": "decide",
                "outcome": ("A recorded owner decision whether table %r is "
                            "intended to be publicly readable; if not, anon "
                            "read must be denied and re-probed." % table),
                "reason": ("Probe check anon_select found rows in %r readable "
                           "by an unauthenticated caller; this is a failure "
                           "only if the table is meant to be private, and "
                           "only the owner can decide that." % table),
                "priority": "high",
                "urgency": "next",
                "deadline": {
                    "kind": "unknown",
                    "rationale": ("Until decided, this exposure blocks any "
                                  "claim that anon access is intended."),
                    "reassess_trigger": {"kind": "context_change"},
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
    _attach_capability(env, PROBE_PROVIDER, probe.get("version"),
                       egress_destinations=[url], network_targets=[url])
    if authorization_objects:
        env = authz_mod.materialize_coverage_actions(env, observed_at,
                                                     environment)
    return env


# ------------------------------------------------------- static RLS (§11.2)

_RLS_ANALYSIS_TOOL = "analyze_sql.py"


def import_rls_analysis(analysis, now=None, app_name=None,
                        environment="developer_only",
                        assessment_id="va-rls-analysis-import"):
    """Map analyze_sql.py output (migration RLS signals) to an envelope.

    Migrations are the source of truth for what the project *intends*, not for
    what the deployed project does: a migration can be unapplied, superseded in
    the dashboard, or contradicted by a policy nobody committed. Everything
    here is therefore indicative, none of it fills an authorization coverage
    cell, and the import always emits the open verify Action that says the live
    behaviour still has to be observed.
    """
    now_dt = _parse_now(now)
    observed_at = _iso(now_dt)
    valid_until = _iso(now_dt + datetime.timedelta(days=EVIDENCE_VALIDITY_DAYS))

    env = _envelope(
        assessment_id, "ctx-rls-analysis-import",
        app_name or "unknown application",
        "Imported from the vibecheck SQL migration analysis.",
        [{"environment": environment, "intended_use": "prototype_demo"}],
        observed_at)

    scope_note = ("Recognized CREATE TABLE / RLS statements in the scanned "
                  "migration files only. It observes the source tree, never "
                  "the deployed project: an unapplied or overridden migration "
                  "looks identical here.")
    seq = 0

    def add(subject, items_found, item_numbers, aspect, direction, detail):
        nonlocal seq
        seq += 1
        signal_id = "sig-rls-%04d" % seq
        env["signals"].append({
            "signal_id": signal_id,
            "source": {"tool": _RLS_ANALYSIS_TOOL, "check_id": aspect,
                       "provider_ref": RLS_PROVIDER},
            "subject": subject,
            "environment": environment,
            "observed_at": observed_at,
            "raw_ref": {"kind": "inline",
                        "value": canonical.bound_raw(
                            json.dumps(items_found, ensure_ascii=False,
                                       sort_keys=True),
                            canonical.MAX_RAW_EVIDENCE)},
        })
        claim = _claim(item_numbers)
        claim["aspect"] = aspect
        env["evidence"].append({
            "evidence_id": "ev-rls-%04d" % seq,
            "provider": providers_mod.evidence_provider_block(RLS_PROVIDER),
            "subject": subject,
            "environment": environment,
            "operation": "migration_analysis",
            "scope": "%s %s" % (scope_note, detail),
            "claim": claim,
            "direction": direction,
            "strength": "indicative",
            "observed_at": observed_at,
            "valid_until": valid_until,
            "signal_refs": [signal_id],
            "raw_result_ref": {"kind": "inline",
                               "value": canonical.bound_raw(
                                   "; ".join(str(i) for i in items_found)
                                   or "no matches")},
            "side_effects": {"writes": False, "destructive": False,
                             "external_accounts": False, "data_egress": False},
        })

    repo_subject = {"kind": "repo", "locator": "supabase/migrations"}
    for table in analysis.get("missing_rls") or []:
        add({"kind": "table", "locator": str(table)}, [table], [12, 14],
            "row level security enabled in the creating migration", "refutes",
            "The migration creating %r has no matching ENABLE ROW LEVEL "
            "SECURITY statement." % table)
    if analysis.get("created") and not analysis.get("missing_rls"):
        add(repo_subject, sorted(analysis.get("rls_enabled") or []), [12, 14],
            "row level security enabled in the creating migration", "neutral",
            "Every recognized created table has an enable statement in the "
            "source. That is the absence of one signal, not evidence that the "
            "deployed project denies anonymous access.")
    if analysis.get("permissive"):
        add(repo_subject, analysis["permissive"][:20], [13, 14],
            "policy expressions that match every row", "refutes",
            "Unconditional using(true) / with check(true) expressions were "
            "found; whether that is intended is a decision, not a signal.")
    if analysis.get("anon_write"):
        add(repo_subject, analysis["anon_write"][:20], [14],
            "write access granted to the anon role", "refutes",
            "Policies or grants give the anon role write access in the source.")

    control_ids = _claim([12, 13, 14])["control_ids"]
    env["actions"].append({
        "action_id": "act-rls-live-verification",
        "action_key": "rls-live-verification",
        "revision": 1,
        "created_at": observed_at,
        "kind": "verify",
        "outcome": ("The deployed project's authorization behaviour is "
                    "observed directly — anonymous and cross-account access, "
                    "per object and per operation — and each observation is "
                    "recorded with the cell it covers."),
        "reason": ("Migration analysis reports what the source says. Only a "
                   "live observation says what the running project does, and "
                   "no static reading of a migration can fill a coverage "
                   "cell."),
        "priority": "high",
        "urgency": "next",
        "deadline": {
            "kind": "unknown",
            "rationale": ("The deadline depends on the confirmed target "
                          "environment and intended use; set it during review."),
            "reassess_trigger": {"kind": "context_change"},
        },
        "blocking_scope": [],
        "owner": {"role": "developer"},
        "state": "open",
        "state_history": [{"state": "open", "at": observed_at,
                           "by": "vibecheck rls-analysis import adapter"}],
        "control_refs": control_ids,
        "success_evidence": ("Live probe evidence per object, actor and "
                             "operation. A migration diff is never the "
                             "verification of a deployment."),
        "reassess_control_ids": control_ids,
    })
    _attach_capability(env, RLS_PROVIDER)
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


def export_legacy_action_view(env):
    """Derived migration display; canonical execution reads Procedure fields."""
    return actions_mod.legacy_view(env)


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
            review_by = acceptance.get("review_by", "?")
            if isinstance(review_by, str) and review_by.endswith("T00:00:00Z"):
                review_by = review_by[:10]
            notes = ("%s [Accepted by %s: %s; review by %s]" % (
                notes, acceptance.get("accepted_by", "?"),
                acceptance.get("reason", "?"), review_by)).strip()
        rows[n] = {"status": wording, "notes": notes}
    return rows


# --------------------------------------------------------- workbook rows (§11.3)

#: Reverse of STATUS_MAP: workbook display wording (per language) -> canonical
#: status. Built lazily because it depends on the per-language wording tables.
_WORKBOOK_WORDING_TO_STATUS = None


def _workbook_map():
    global _WORKBOOK_WORDING_TO_STATUS
    if _WORKBOOK_WORDING_TO_STATUS is None:
        _WORKBOOK_WORDING_TO_STATUS = {}
        for canonical_status, langs in STATUS_MAP.items():
            for lang, wording in langs.items():
                _WORKBOOK_WORDING_TO_STATUS[(lang, wording)] = canonical_status
    return _WORKBOOK_WORDING_TO_STATUS


_ACCEPTANCE_RE = None


def _acceptance_suffix(notes):
    """Split a notes cell into (rationale, acceptance_record). The workbook
    export composes acceptance as a trailing "[Accepted by ...]" block; this is
    the inverse, so a workbook row round-trips into an assessment without the
    acceptance being misread as plain rationale."""
    global _ACCEPTANCE_RE
    if _ACCEPTANCE_RE is None:
        _ACCEPTANCE_RE = re.compile(
            r"\s*\[Accepted by ([^:]+): ([^;]+); review by ([^\]]+)\]\s*$")
    m = _ACCEPTANCE_RE.search(notes)
    if not m:
        return notes, None
    rationale = notes[:m.start()].strip()
    accepted_by, reason, review_by = m.groups()
    reason = reason.strip()
    review_by = review_by.strip()
    if not review_by:
        review_by = None
    return rationale, {
        "accepted_by": accepted_by.strip(), "reason": reason,
        "review_by": review_by,
    }


def normalized_acceptance(acceptance):
    """Acceptance records demand a full timestamp in `review_by`; a legacy
    workbook cell usually carries a plain review-by date. Normalize a YYYY-MM-DD
    to the start of that day in UTC, and refuse anything unparseable so a typo
    is not silently kept."""
    record = dict(acceptance)
    review_by = record.get("review_by")
    if not review_by:
        return record
    try:
        datetime.datetime.strptime(review_by, "%Y-%m-%d")
        record["review_by"] = review_by + "T00:00:00Z"
    except ValueError:
        pass  # already a full timestamp, or malformed; let the schema decide
    return record


def import_workbook_rows(rows, lang="en", assessment_id="legacy-workbook",
                         context_id="ctx-legacy-workbook", app_name="legacy workbook",
                         now=None, env=None):
    """Migrate a legacy workbook into canonical Assessments (RFC §11.3).

    `rows` maps item numbers (1-89) to workbook cells:
        {item_number: {"status": <workbook wording>, "notes": <text>}}

    Semantic rules:
      * a blank status imports *no* assessment (deliberately distinct from an
        explicit "Not tested"),
      * a status wording that has no canonical counterpart in this language is
        refused (no silent guessing),
      * accepted-risk notes carry the [Accepted by ...] block, which is split
        back out into the structured acceptance record so the re-exported row
        is identical,
      * N/A is allowed only on non-Critical/non-High controls with the reason
        captured; Critical/High N/A is refused (matches the workbook gate),
      * Accepted risk is refused on Critical controls (rule R5) and refused
        without a parseable acceptance record,
      * pass/partial/fail is refused with an empty notes cell, because the
        note is the only evidence a legacy row carries.

    A refused row is reported in `problems` and produces no assessment, so a
    workbook cell the gates forbid can never enter the envelope as a valid-
    looking assessment. The rows the workbook itself counts as violations
    (Critical accepted, acceptance without a reason, Pass without evidence)
    are exactly the ones refused here.

    Returns a canonical envelope fragment (assessments) ready to be merged into
    an envelope, plus the created envelopes' evidence/accepted-risk view. The
    control's intrinsic severity and item mapping come from the canonical
    registry/mapping, so nothing is re-rated by this migration.
    """
    mapping = canonical.load_framework_mapping()
    by_number = {e["item_number"]: e for e in mapping["entries"]}
    w2s = _workbook_map()
    created_at = _iso(_parse_now(now))

    if env is None:
        env = _envelope("va-" + assessment_id, context_id, app_name,
                        "Legacy workbook assessment migrated on import",
                        [{"environment": "developer_only",
                          "intended_use": "prototype_demo"}],
                        created_at)
        env["signals"] = []
    env.setdefault("evidence", [])
    env.setdefault("signals", [])

    assessments = []
    problems = []
    for n in sorted(rows):
        cell = rows[n] or {}
        status_word = (cell.get("status") or "").strip()
        notes = (cell.get("notes") or "").strip()
        if not status_word:
            continue  # blank -> not reviewed -> no assessment object

        key = (lang, status_word)
        if key not in w2s:
            problems.append(
                "workbook status %r (lang %s) has no canonical counterpart"
                % (status_word, lang))
            continue
        status = w2s[key]
        entry = by_number.get(n)
        if entry is None:
            problems.append("item number %d is not in the vibecheck_v1 mapping" % n)
            continue
        severity = entry["severity"]
        entry_kind = entry.get("kind", "control")

        if status == "not_applicable" and severity in ("Critical", "High"):
            problems.append(
                "item %d: N/A on a Critical/High control requires a reason; "
                "the workbook gate forbids N/A on Critical/High without it"
                % n)
            continue

        # Rule R5: a Critical control can never be accepted, only fixed or
        # escalated. The workbook says so in its own instructions and counts
        # the violation (m_critacc), so a legacy file can carry the cell;
        # importing it would produce an envelope validate_envelope refuses.
        if status == "risk_accepted" and severity == "Critical":
            problems.append(
                "item %d: Critical controls cannot be marked Accepted risk "
                "(rule R5); fix or escalate the item instead" % n)
            continue

        rationale, acceptance = _acceptance_suffix(notes)
        if status == "not_applicable" and rationale:
            rationale = "N/A reason: %s" % rationale

        # An acceptance is a named decision with a review date; the schema
        # requires the record for risk_accepted. A cell whose notes carry no
        # parseable "[Accepted by ...]" block is an incomplete acceptance
        # (the workbook's m_narat counter), not one to invent a record for.
        if status == "risk_accepted" and acceptance is None:
            problems.append(
                "item %d: Accepted risk needs who accepted it, why, and a "
                "review-by date in the notes ('[Accepted by NAME: REASON; "
                "review by YYYY-MM-DD]')" % n)
            continue

        # Rule R5, other half: the screening statuses belong to the AI-Act
        # triage controls and mean nothing on an ordinary control.
        if status in ("answered", "needs_specialist") and entry_kind != "screening":
            problems.append(
                "item %d: %r is a screening status and is only valid on a "
                "screening control (rule R5)" % (n, status_word))
            continue

        # pass/partial/fail must rest on evidence, and the notes cell is the
        # only evidence a legacy row carries. With no notes there is nothing
        # to scope evidence to, so the status cannot be substantiated.
        if status in ("pass", "partial", "fail") and not rationale:
            problems.append(
                "item %d: %r needs a note to stand as evidence; an empty "
                "notes cell cannot support the status" % (n, status_word))
            continue

        # Every assessment states why (schema: basis.rationale minLength 1).
        # A status with an empty notes cell records a decision with no reason,
        # which the envelope cannot represent.
        if not rationale:
            problems.append(
                "item %d: %r needs a note saying why; an assessment cannot "
                "record a decision with no rationale" % (n, status_word))
            continue

        refs = []
        # A pass/partial/fail assessment must rest on evidence (schema rule);
        # the legacy notes cell becomes that scoped evidence, so the migration
        # does not drop the references the cell carries. The guard above has
        # already refused these statuses without a note.
        if status in ("pass", "partial", "fail"):
            evidence_id = "ev-wb-%s-%03d" % (assessment_id, n)
            env["evidence"].append({
                "evidence_id": evidence_id,
                "provider": providers_mod.evidence_provider_block(
                    "prov-code-policy-review"),
                "subject": {"kind": "repo", "locator": "."},
                "environment": "developer_only",
                "operation": "policy_source_review",
                "scope": rationale,
                "claim": {"control_ids": [entry["control_id"]],
                          "statement": rationale},
                "direction": ("supports" if status == "pass"
                              else "neutral" if status == "partial"
                              else "refutes"),
                "strength": "indicative",
                "observed_at": created_at,
            })
            refs = [evidence_id]

        asm = {
            "assessment_id": "asm-%s-%03d" % (assessment_id, n),
            "control_id": entry["control_id"],
            "status": status,
            "assessor": {"kind": "human", "id": "legacy-workbook-import"},
            "assessed_at": created_at,
            "basis": {"rationale": rationale, "evidence_refs": refs},
        }
        if acceptance:
            asm["acceptance"] = normalized_acceptance(acceptance)
        assessments.append(asm)
    env["assessments"] = assessments
    if env.get("evidence"):
        _attach_capability(env, "prov-code-policy-review")
    return env, problems
