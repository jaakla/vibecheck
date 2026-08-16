# -*- coding: utf-8 -*-
"""Completeness-safe founder and reviewer reports (RFC 0001 §9, gh issue #5).

Two jobs, deliberately separate:

  derive_report()  builds the report object: which failure stories lead, in
                   which order, what may never be hidden behind that cap, and
                   where each mandatory item is rendered;
  render()         turns the same object into markdown for a profile
                   (founder / reviewer) and a language (en / et).

The split is the point. The derivation is profile- and language-independent:
the same envelope produces the same headline scenarios, the same mandatory
disclosures and the same control identities in Estonian for a founder as in
English for a reviewer — only the words change (acceptance criterion
"reviewer/founder profiles and EN/ET output without changing control
identity").

The completeness invariant (rule R12) is what this module exists to protect.
The headline cap of 3-5 scenarios is a reading aid, and a reading aid may never
swallow:

  * an unresolved Critical or High control,
  * a material unknown that keeps a scope from being clear,
  * an open incident-response action,
  * a specialist escalation, including a legacy screening row that has not
    yet been materialized as an Increment-4 Action,
  * an action whose deadline blocks the assessed environment and intended use,
    or whose calendar deadline has already passed.

Every one of those is recomputed from the envelope, listed in
`mandatory_disclosures`, and placed exactly once — inside a headline scenario
that traces to it, or in the mandatory section below the headlines. The
placement is stored (`disclosure_placement`) so "it was shown" is checkable
rather than claimed; scripts/canonical.py fails validation when a matching
object is missing from its set.

Nothing here re-decides anything: no control status, intrinsic severity or
acceptance record is written, read back differently, or improved by being
summarized (rules R12, R14).

CLI: `python3 scripts/report.py ENVELOPE.json --profile founder --lang et`.
"""
import argparse
import copy
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import canonical
import actions as actions_mod
import context as ctx
import readiness as readiness_mod
import risk as risk_mod
import scenarios as scenarios_mod
import wording

POLICY_NAME = "vibecheck.report"
POLICY_VERSION = "1.1.0"

MANDATORY_CATEGORIES = (
    "unresolved_critical_high_refs",
    "readiness_blocking_unknown_refs",
    "incident_response_action_refs",
    "specialist_escalation_refs",
    "deadline_blocking_action_refs",
    "specialist_assessment_refs",
)

#: Headings for the mandatory categories, in the order they are rendered.
_CATEGORY_HEADINGS = {
    "unresolved_critical_high_refs": "h_unresolved_critical_high",
    "readiness_blocking_unknown_refs": "h_readiness_blocking_unknowns",
    "incident_response_action_refs": "h_incident_response",
    "specialist_escalation_refs": "h_specialist_escalations",
    "deadline_blocking_action_refs": "h_deadline_blocking",
    "specialist_assessment_refs": "h_specialist_assessments",
}


def load_policy():
    return scenarios_mod.load_policy()


def _registry():
    return {c["control_id"]: c for c in canonical.load_registry()["controls"]}


def _index(objects, key):
    return {o[key]: o for o in objects or [] if isinstance(o, dict) and key in o}


# -------------------------------------------------------- mandatory disclosures

def _open_actions(envelope):
    states = load_policy()["mandatory_disclosures"]["open_action_states"]
    return [a for a in actions_mod.current_actions(envelope)
            if a.get("state") in states]


def _target_scopes(envelope):
    return (envelope.get("context") or {}).get("target_scopes") or []


def _blocks_a_target_scope(action, envelope):
    return any(ctx.same_scope(blocked, target)
               for blocked in action.get("blocking_scope") or []
               for target in _target_scopes(envelope))


def is_overdue(action, now):
    """A calendar deadline that has already passed."""
    deadline = action.get("deadline") or {}
    rules = load_policy()["mandatory_disclosures"]
    if deadline.get("kind") not in rules["deadline_blocking_action_refs"][
            "overdue_deadline_kinds"]:
        return False
    return actions_mod.is_overdue(action, now)


def unresolved_critical_high(envelope):
    rule = load_policy()["mandatory_disclosures"]["unresolved_critical_high_refs"]
    registry = _registry()
    refs = []
    for assessment in canonical.current_assessments(envelope):
        entry = registry.get(assessment.get("control_id"))
        if (entry and entry["severity"] in rule["severities"]
                and assessment.get("status") in rule["statuses"]):
            refs.append(assessment["assessment_id"])
    return sorted(refs)


def readiness_blocking_unknowns(envelope):
    """Every material unknown on every readiness object, by stable id."""
    refs = []
    for readiness in envelope.get("readiness") or []:
        for unknown in readiness.get("unknowns") or []:
            if unknown.get("material") and unknown.get("unknown_id"):
                refs.append(unknown["unknown_id"])
    return sorted(set(refs))


def incident_response_actions(envelope):
    kinds = load_policy()["mandatory_disclosures"][
        "incident_response_action_refs"]["kinds"]
    return sorted(a["action_id"] for a in _open_actions(envelope)
                  if a.get("kind") in kinds)


def specialist_escalations(envelope):
    rule = load_policy()["mandatory_disclosures"]["specialist_escalation_refs"]
    return sorted(a["action_id"] for a in _open_actions(envelope)
                  if a.get("kind") in rule["kinds"]
                  or (a.get("owner") or {}).get("role") in rule["owner_roles"])


def deadline_blocking_actions(envelope, now=None):
    rule = load_policy()["mandatory_disclosures"]["deadline_blocking_action_refs"]
    now_dt = ctx.instant(now)
    refs = []
    for action in _open_actions(envelope):
        deadline = action.get("deadline") or {}
        if (_blocks_a_target_scope(action, envelope)
                or deadline.get("kind") in rule["deadline_kinds"]
                or is_overdue(action, now_dt)):
            refs.append(action["action_id"])
    return sorted(refs)


def specialist_assessments(envelope):
    statuses = load_policy()["mandatory_disclosures"][
        "specialist_assessment_refs"]["statuses"]
    # Only an *open* escalation covers the row. specialist_escalations() lists
    # open actions only, so treating a done or rejected one as coverage here
    # would drop the escalation out of both sets at once.
    covered = actions_mod.open_escalation_controls(envelope)
    return sorted(a["assessment_id"] for a in canonical.current_assessments(envelope)
                  if a.get("status") in statuses
                  and a.get("control_id") not in covered)


def mandatory_disclosures(envelope, now=None):
    """The five required sets of rule R12, plus legacy specialist rows that
    have not yet been materialized as Increment-4 Actions."""
    now_dt = ctx.instant(now)
    return {
        "unresolved_critical_high_refs": unresolved_critical_high(envelope),
        "readiness_blocking_unknown_refs": readiness_blocking_unknowns(envelope),
        "incident_response_action_refs": incident_response_actions(envelope),
        "specialist_escalation_refs": specialist_escalations(envelope),
        "deadline_blocking_action_refs": deadline_blocking_actions(envelope, now_dt),
        "specialist_assessment_refs": specialist_assessments(envelope),
    }


def mandatory_refs(disclosures):
    refs = set()
    for category in MANDATORY_CATEGORIES:
        refs.update(disclosures.get(category) or [])
    return refs


def mandatory_categories_by_ref(disclosures):
    """mandatory ref -> ordered categories it belongs to.

    One action can legitimately be an incident, a specialist escalation and a
    deadline blocker at the same time. It still gets one visible disclosure
    slot; the category list preserves every reason it was mandatory.
    """
    categories = {}
    for category in MANDATORY_CATEGORIES:
        for ref in disclosures.get(category) or []:
            categories.setdefault(ref, []).append(category)
    return categories


# ------------------------------------------------------------------ placement

def _unknown_index(envelope):
    """unknown_id -> (readiness, unknown)."""
    index = {}
    for readiness in envelope.get("readiness") or []:
        for unknown in readiness.get("unknowns") or []:
            if unknown.get("unknown_id"):
                index.setdefault(unknown["unknown_id"], (readiness, unknown))
    return index


def covering_scenario(envelope, ref, categories, headline_refs):
    """The first headline scenario that already tells this item's story."""
    scenarios = _index(envelope.get("scenarios"), "scenario_id")
    unknowns = _unknown_index(envelope)
    for scenario_ref in headline_refs:
        scenario = scenarios.get(scenario_ref)
        if scenario is None:
            continue
        trace = scenarios_mod.traceability(envelope, scenario)
        if any(category in (
                "unresolved_critical_high_refs", "specialist_assessment_refs")
               for category in categories):
            if ref in trace["assessment_refs"]:
                return scenario_ref
        if "readiness_blocking_unknown_refs" in categories:
            entry = unknowns.get(ref)
            if entry is not None:
                source = (entry[1].get("ref") or "")
                if source in trace["risk_refs"] or source in trace["assessment_refs"]:
                    return scenario_ref
        if ref in trace["action_refs"]:
            return scenario_ref
    return None


def disclosure_placement(envelope, disclosures, headline_refs):
    """Exactly one rendering slot per mandatory ref.

    A ref a headline scenario already tells the story of is rendered there; the
    rest are rendered in the mandatory section. Both are visible; neither is a
    substitute for the appendix, which keeps everything regardless.
    """
    placement = []
    for ref, categories in mandatory_categories_by_ref(disclosures).items():
        scenario_ref = covering_scenario(envelope, ref, categories, headline_refs)
        entry = {
            "ref": ref,
            "category": categories[0],
            "categories": categories,
            "rendered_in": "headline" if scenario_ref else "mandatory_section",
        }
        if scenario_ref:
            entry["scenario_ref"] = scenario_ref
        placement.append(entry)
    return placement


# -------------------------------------------------------------- action sections

def deadline_label_id(action, now=None):
    """Compatibility wrapper for the Increment-4 action policy."""
    return actions_mod.deadline_label_id(action, now)


def _executor_roles(envelope, action):
    procedures = _index(envelope.get("procedures"), "procedure_id")
    return {procedures[ref]["executor_role"]
            for ref in action.get("procedure_refs") or []
            if ref in procedures}


def derive_sections(envelope, disclosures=None, now=None):
    """The four founder sections, partitioned by who can act.

    A mandatory action never lands in "can wait", whatever its urgency field
    says: something that blocks the assessed use, or that is already an
    incident, is not deferred work.
    """
    now_dt = ctx.instant(now)
    policy = load_policy()["sections"]
    mandatory = mandatory_refs(disclosures if disclosures is not None
                               else mandatory_disclosures(envelope, now_dt))
    sections = {"vibecheck_can_do_now": [], "you_need_to_do": [],
                "needs_developer_or_specialist": [], "can_wait": []}

    for action in _open_actions(envelope):
        action_id = action["action_id"]
        deadline = action.get("deadline") or {}
        owner_role = (action.get("owner") or {}).get("role")
        can_wait = policy["can_wait"]
        if (action.get("urgency") in can_wait["urgencies"]
                and deadline.get("kind") in can_wait["deadline_kinds"]
                and not action.get("blocking_scope")
                and action_id not in mandatory):
            sections["can_wait"].append(action_id)
        elif _executor_roles(envelope, action) & set(
                policy["vibecheck_can_do_now"]["executor_roles"]):
            sections["vibecheck_can_do_now"].append(action_id)
        elif owner_role in policy["you_need_to_do"]["owner_roles"]:
            sections["you_need_to_do"].append(action_id)
        else:
            sections["needs_developer_or_specialist"].append(action_id)
    return {key: sorted(value) for key, value in sections.items()}


# ---------------------------------------------------------------- the report

def _context_summary(envelope, now):
    context = envelope.get("context") or {}
    summary = {
        "context_id": context.get("context_id"),
        "revision": int(context.get("revision", 1)),
        "confirmation_state": ctx.confirmation_state(context, now),
        "application": dict(context.get("application") or {}),
        "target_scopes": [dict(s) for s in context.get("target_scopes") or []],
    }
    current = ctx.current_scope(context)
    if current:
        summary["current_scope"] = current
    for key in ("context_fingerprint", "valid_until", "data_summary"):
        if context.get(key):
            summary[key] = context[key]
    fingerprint = (context.get("confirmation") or {}).get("source_fingerprint")
    if fingerprint:
        summary["source_fingerprint"] = fingerprint
    missing = ctx.missing_dimensions(context)
    if missing:
        summary["unestablished_dimensions"] = missing
    return summary


def _appendix(envelope):
    mapping = canonical.load_framework_mapping()
    return {
        "framework": mapping["framework"],
        "framework_version": mapping["framework_version"],
        "control_registry": dict(envelope.get("control_registry") or {}),
        "action_registry": dict(envelope.get("action_registry") or {}),
        "item_count": len(mapping["entries"]),
        "assessment_refs": sorted(a["assessment_id"]
                                  for a in envelope.get("assessments") or []),
        "evidence_refs": sorted(e["evidence_id"]
                                for e in envelope.get("evidence") or []),
        "risk_refs": sorted(r["risk_id"] for r in envelope.get("risks") or []),
        "scenario_refs": sorted(s["scenario_id"]
                                for s in envelope.get("scenarios") or []),
        "action_refs": sorted(a["action_id"] for a in envelope.get("actions") or []),
        "procedure_refs": sorted(p["procedure_id"]
                                 for p in envelope.get("procedures") or []),
        "attempt_refs": sorted(a["attempt_id"]
                               for a in envelope.get("attempts") or []),
        "legacy_action_view": actions_mod.legacy_view(envelope),
    }


def derive_report(envelope, audience="founder", language="en", now=None):
    """The report object: what leads, what may not be hidden, and where it goes.

    `audience` and `language` name the default rendering only. Everything else
    in the object is independent of both, which is what keeps a translation or
    a profile switch from changing which controls are reported.
    """
    now_dt = ctx.instant(now)
    ranking = scenarios_mod.rank_scenarios(envelope, now_dt)
    headline = scenarios_mod.headline_refs(ranking)
    disclosures = mandatory_disclosures(envelope, now_dt)
    context = envelope.get("context") or {}
    return {
        "audience": audience,
        "language": language,
        "generated_at": ctx.iso(now_dt),
        "headline_scenario_refs": headline,
        "scenario_ranking": ranking,
        "mandatory_disclosures": disclosures,
        "disclosure_placement": disclosure_placement(envelope, disclosures, headline),
        "sections": derive_sections(envelope, disclosures, now_dt),
        "context_summary": _context_summary(envelope, now_dt),
        "readiness_refs": [r["readiness_id"] for r in envelope.get("readiness") or []],
        "appendix": _appendix(envelope),
        "derivation": {
            "policy": {"name": POLICY_NAME, "version": POLICY_VERSION},
            "context_revision": int(context.get("revision", 1)),
            "rules_applied": sorted(
                {"report.headline_cap.%d" % load_policy()["ranking"]["headline_max"]}
                | {"report.mandatory.%s" % category
                   for category in MANDATORY_CATEGORIES
                   if disclosures.get(category)}),
        },
    }


def apply_report(envelope, audience="founder", language="en", now=None):
    updated = copy.deepcopy(envelope)
    updated["report"] = derive_report(updated, audience, language, now)
    return updated


def derive_into(envelope, audience="founder", language="en", now=None):
    """Risks, then readiness over those risks, then scenarios, then the report.

    Each stage reads the stage before it, so a single call re-derives the whole
    presentation from the assessments and evidence without any of them being
    able to write back.
    """
    source = actions_mod.materialize_specialist_actions(envelope, now)
    derived = readiness_mod.derive_into(source, now)
    derived = scenarios_mod.apply_scenarios(derived, now)
    return apply_report(derived, audience, language, now)


# ------------------------------------------------------------------ rendering

def _cell(value):
    text = "" if value is None else str(value)
    text = text.replace("|", "\\|").replace("\n", " ").strip()
    return text or "—"


def _table(headers, rows):
    lines = ["| %s |" % " | ".join(_cell(h) for h in headers),
             "|%s|" % "|".join("---" for _ in headers)]
    for row in rows:
        lines.append("| %s |" % " | ".join(_cell(c) for c in row))
    return lines


def _refs(refs):
    return ", ".join("`%s`" % ref for ref in refs) if refs else "—"


def _profile_wording(control_id, lang, profile):
    return wording.control_wording(control_id, lang, profile)


def _render_header(envelope, report, profile, lang):
    context_summary = report["context_summary"]
    application = context_summary.get("application") or {}
    lines = ["# %s" % wording.text(
        "title_reviewer" if profile == "reviewer" else "title_founder", lang), ""]
    if application.get("name"):
        lines.append("**%s**" % application["name"])
        lines.append("")
    for disclaimer in wording.disclaimers(lang):
        lines.append("> %s" % disclaimer)
        lines.append(">")
    lines[-1] = ""
    lines.append(wording.template(
        "generated", lang,
        assessment_id=envelope.get("assessment_id", "—"),
        revision=envelope.get("revision", 1),
        generated_at=report["generated_at"]))
    lines.append("")
    return lines


def _render_context(envelope, report, profile, lang):
    summary = report["context_summary"]
    context = envelope.get("context") or {}
    application = summary.get("application") or {}
    lines = ["## %s" % wording.text("h_context", lang), ""]

    rows = [(wording.text("f_application", lang), application.get("name")),
            (wording.text("f_description", lang), application.get("description")),
            (wording.text("f_platform", lang), application.get("platform"))]
    if summary.get("current_scope"):
        rows.append((wording.text("f_current_scope", lang),
                     wording.scope_label(summary["current_scope"], lang)))
    rows.append((wording.text("f_target_scopes", lang),
                 "; ".join(wording.scope_label(s, lang)
                           for s in summary.get("target_scopes") or [])))
    if summary.get("data_summary"):
        rows.append((wording.text("f_data_summary", lang), summary["data_summary"]))
    rows.append((wording.text("f_confirmation", lang),
                 wording.label("confirmation_states",
                               summary["confirmation_state"], lang)))
    rows.append((wording.text("f_context_revision", lang), summary["revision"]))
    if summary.get("valid_until"):
        rows.append((wording.text("f_context_valid_until", lang),
                     summary["valid_until"]))
    if profile == "reviewer":
        for key, label_key in (("context_fingerprint", "f_context_fingerprint"),
                               ("source_fingerprint", "f_source_fingerprint")):
            if summary.get(key):
                rows.append((wording.text(label_key, lang), "`%s`" % summary[key]))
    lines.extend(_table(["", ""], rows))
    lines.append("")

    lines.append("### %s" % wording.text("h_context_profile", lang))
    lines.append("")
    profile_rows = []
    for dimension_id in ctx.dimensions():
        state = ctx.field_state(context, dimension_id)
        value = ctx.field_value(context, dimension_id)
        entry = (context.get("profile") or {}).get(dimension_id) or {}
        profile_rows.append((
            wording.dimension_question(dimension_id, lang),
            wording.dimension_value(dimension_id, value, lang) if value is not None
            else wording.text("v_not_established", lang),
            wording.label("field_states", state, lang),
            entry.get("source") or ", ".join(entry.get("candidates") or [])
            or wording.text("v_not_recorded", lang)))
    lines.extend(_table([wording.text("f_dimension", lang),
                         wording.text("f_value", lang),
                         wording.text("f_field_state", lang),
                         wording.text("f_source", lang)], profile_rows))
    lines.append("")
    for assumption in context.get("assumptions") or []:
        lines.append("- %s" % assumption)
    if context.get("assumptions"):
        lines.append("")
    return lines


def _verdict_text(envelope, profile, lang):
    key, _counts = readiness_mod.framework_verdict(envelope)
    string_key = load_policy()["framework_verdict_profiles"][profile][key]
    return wording.label("framework_verdicts", string_key, lang)


def _render_readiness(envelope, report, profile, lang):
    lines = ["## %s" % wording.text("h_readiness", lang), ""]
    for readiness in envelope.get("readiness") or []:
        scope = readiness["scope"]
        state = readiness["state"]
        lines.append("### %s" % wording.scope_label(scope, lang))
        lines.append("")
        lines.append("**%s** — %s" % (
            wording.label("readiness_states", state, lang),
            wording.label("readiness_sentences", state, lang)))
        lines.append("")
        verdict = readiness.get("framework_verdict") or {}
        lines.append("*%s:* %s" % (
            wording.text("f_framework_verdict", lang),
            wording.template("verdict_line", lang,
                             verdict=_verdict_text(envelope, profile, lang),
                             agreement=verdict.get("agreement", "—"),
                             explanation=verdict.get("explanation", ""))))
        lines.append("")
        if readiness.get("blockers"):
            lines.append("*%s:*" % wording.text("f_blockers", lang))
            lines.append("")
            for blocker in readiness["blockers"]:
                lines.append("- `%s` — %s" % (blocker.get("ref", "—"),
                                              blocker.get("reason", "")))
            lines.append("")
        material = [u for u in readiness.get("unknowns") or [] if u.get("material")]
        if material:
            # The full records are rendered exactly once through the report's
            # disclosure placement (headline or mandatory section). Readiness
            # states the count so it remains intelligible without duplicating
            # a mandatory item in a second visible slot.
            lines.append(wording.template(
                "unknown_count", lang, count=len(material)))
            lines.append("")
        for condition in readiness.get("conditions") or []:
            lines.append("- *%s* %s (%s: %s%s)" % (
                wording.text("f_conditions", lang), condition["requirement"],
                wording.text("f_enforced_by", lang), condition["enforced_by"],
                ", %s %s" % (wording.text("f_expires", lang),
                             condition["expires_at"])
                if condition.get("expires_at") else ""))
        if readiness.get("conditions"):
            lines.append("")
        if readiness.get("blocked_transitions"):
            lines.append("*%s:*" % wording.text("f_blocked_transitions", lang))
            lines.append("")
            for transition in readiness["blocked_transitions"]:
                lines.append("- %s" % wording.template(
                    "transition", lang,
                    scope=wording.scope_label(transition["scope"], lang),
                    state=wording.label("readiness_states", transition["state"], lang),
                    reason=transition.get("reason", "")))
            lines.append("")
        if readiness.get("valid_until"):
            lines.append("*%s:* %s" % (wording.text("f_valid_until", lang),
                                       readiness["valid_until"]))
            lines.append("")
    return lines


def _scenario_rank(report, scenario_ref):
    for entry in report["scenario_ranking"]:
        if entry["scenario_ref"] == scenario_ref:
            return entry["rank"]
    return None


def _render_scenarios(envelope, report, profile, lang):
    """The headline failure stories, with what each one rests on."""
    scenarios = _index(envelope.get("scenarios"), "scenario_id")
    assessments = _index(envelope.get("assessments"), "assessment_id")
    current_by_control = {assessment.get("control_id"): assessment
                          for assessment in canonical.current_assessments(envelope)}
    actions = _index(envelope.get("actions"), "action_id")
    lines = ["## %s" % wording.text("h_scenarios", lang), ""]
    if not report["headline_scenario_refs"]:
        lines.extend([wording.text("note_no_scenarios", lang), ""])
        return lines

    for scenario_ref in report["headline_scenario_refs"]:
        scenario = scenarios.get(scenario_ref)
        if scenario is None:
            continue
        trace = scenarios_mod.traceability(envelope, scenario)
        rank = _scenario_rank(report, scenario_ref)
        lines.append("### %s" % wording.template(
            "scenario_heading", lang, rank=rank,
            title=(scenario.get("wording") or {}).get("title", {}).get(
                lang, scenario["title"])))
        lines.append("")
        lines.append((scenario.get("wording") or {}).get("narrative", {}).get(
            lang, scenario["narrative"]))
        lines.append("")
        for reading in scenario.get("risk_by_scope") or []:
            key = ("f_risk_today" if reading["horizon"]["kind"] == "current"
                   else "f_risk_later")
            lines.append("- **%s** (%s): %s — %s" % (
                wording.text(key, lang),
                wording.scope_label(reading["scope"], lang),
                wording.label("levels", reading["level"], lang),
                _refs(reading["risk_refs"])))
        lines.append("")
        lines.append("*%s:*" % wording.text("f_rests_on", lang))
        lines.append("")
        for control_id in trace["control_refs"]:
            assessment = current_by_control.get(control_id) or next(
                (assessments[a] for a in trace["assessment_refs"]
                 if a in assessments
                 and assessments[a].get("control_id") == control_id), None)
            status = assessment.get("status") if assessment else None
            item = wording.item_number(control_id)
            lines.append("- %s%s — %s%s" % (
                "#%d " % item if item else "",
                wording.template(
                    "control_with_status", lang,
                    control=_profile_wording(control_id, lang, profile),
                    status=wording.status_label(status, lang) if status else "—"),
                _refs([assessment["assessment_id"]] if assessment else []),
                " `%s`" % control_id if profile == "reviewer" else ""))
            if assessment and assessment.get("basis", {}).get("rationale") \
                    and profile == "reviewer":
                lines.append("  - %s" % assessment["basis"]["rationale"])
            for conflict in (assessment or {}).get("conflicts") or []:
                lines.append("  - *%s* `%s` — *%s:* %s" % (
                    wording.text("f_conflicting_evidence", lang),
                    conflict.get("evidence_ref", "—"),
                    wording.text("f_resolution", lang),
                    conflict.get("resolution", "")))
        lines.append("")
        if trace["evidence_refs"]:
            lines.append("*%s:* %s" % (wording.text("f_evidence", lang),
                                       _refs(trace["evidence_refs"])))
            lines.append("")
        if trace["action_refs"]:
            lines.append("*%s:*" % wording.text("f_next_steps", lang))
            lines.append("")
            for action_ref in trace["action_refs"]:
                action = actions.get(action_ref)
                if action is None:
                    continue
                lines.append("- **%s** `%s` — %s" % (
                    wording.label("deadline_labels",
                                  deadline_label_id(action, report["generated_at"]),
                                  lang),
                    action_ref, action.get("outcome", "")))
            lines.append("")
        covered_unknowns = [
            entry["ref"] for entry in report.get("disclosure_placement") or []
            if entry.get("scenario_ref") == scenario_ref
            and "readiness_blocking_unknown_refs" in (
                entry.get("categories") or [entry.get("category")])]
        if covered_unknowns:
            lines.append("*%s:*" % wording.text("f_unknowns", lang))
            lines.append("")
            for ref in covered_unknowns:
                lines.append(_mandatory_line(
                    envelope, report, ref, "readiness_blocking_unknown_refs",
                    profile, lang))
            lines.append("")
    if len(report["scenario_ranking"]) > len(report["headline_scenario_refs"]):
        lines.extend([wording.text("note_headline_cap", lang), ""])
    return lines


def _mandatory_line(envelope, report, ref, category, profile, lang):
    assessments = _index(envelope.get("assessments"), "assessment_id")
    actions = _index(envelope.get("actions"), "action_id")
    unknowns = _unknown_index(envelope)
    if ref in assessments:
        assessment = assessments[ref]
        control_id = assessment.get("control_id")
        registry = _registry().get(control_id) or {}
        item = wording.item_number(control_id)
        return "- `%s` %s%s — %s (%s)%s" % (
            ref, "#%d " % item if item else "",
            _profile_wording(control_id, lang, profile),
            wording.status_label(assessment.get("status"), lang),
            wording.label("severities", registry.get("severity"), lang),
            " `%s`" % control_id if profile == "reviewer" else "")
    if ref in actions:
        action = actions[ref]
        return "- `%s` **%s** — %s (%s)" % (
            ref,
            wording.label("deadline_labels",
                          deadline_label_id(action, report["generated_at"]), lang),
            action.get("outcome", ""),
            wording.label("owner_roles",
                          (action.get("owner") or {}).get("role"), lang))
    if ref in unknowns:
        readiness, unknown = unknowns[ref]
        return "- `%s` (%s) — %s" % (
            ref, wording.scope_label(readiness["scope"], lang),
            unknown.get("description", ""))
    return "- `%s`" % ref


def _render_mandatory(envelope, report, profile, lang):
    """Everything that may not be hidden, minus what a headline already told.

    Each item is rendered exactly once across this section and the headline
    scenarios; the counts say how the category was split, so folding an item
    into a story above never reads as dropping it.
    """
    placement = {entry["ref"]: entry
                 for entry in report.get("disclosure_placement") or []}
    lines = ["## %s" % wording.text("h_mandatory", lang), "",
             wording.text("note_mandatory", lang), ""]
    for category in MANDATORY_CATEGORIES:
        refs = report["mandatory_disclosures"].get(category) or []
        here = [r for r in refs if placement.get(r, {}).get("rendered_in")
                == "mandatory_section"
                and placement.get(r, {}).get("category") == category]
        above = [r for r in refs if placement.get(r, {}).get("rendered_in")
                 == "headline"]
        elsewhere = [r for r in refs if r not in here and r not in above]
        lines.append("### %s" % wording.text(_CATEGORY_HEADINGS[category], lang))
        lines.append("")
        lines.append("*%s*" % wording.label("mandatory_categories", category, lang))
        lines.append("")
        if not refs:
            lines.extend([wording.text("note_nothing_here", lang), ""])
            continue
        lines.append(wording.template("mandatory_counts", lang, total=len(refs),
                                      above=len(above), here=len(here),
                                      elsewhere=len(elsewhere)))
        lines.append("")
        for ref in here:
            lines.append(_mandatory_line(envelope, report, ref, category,
                                         profile, lang))
        if here:
            lines.append("")
    return lines


def _render_actions(envelope, report, profile, lang):
    actions = _index(envelope.get("actions"), "action_id")
    headings = {"vibecheck_can_do_now": "h_can_do_now",
                "you_need_to_do": "h_you_need_to_do",
                "needs_developer_or_specialist": "h_needs_developer_or_specialist",
                "can_wait": "h_can_wait"}
    lines = ["## %s" % wording.text("h_actions", lang), ""]
    for section in ("vibecheck_can_do_now", "you_need_to_do",
                    "needs_developer_or_specialist", "can_wait"):
        lines.append("### %s" % wording.text(headings[section], lang))
        lines.append("")
        refs = report["sections"].get(section) or []
        if not refs:
            lines.extend([wording.text("note_nothing_here", lang), ""])
            continue
        for ref in refs:
            action = actions.get(ref)
            if action is None:
                continue
            lines.append("- **%s** — %s `%s`" % (
                wording.label("deadline_labels",
                              deadline_label_id(action, report["generated_at"]), lang),
                action.get("outcome", ""), ref))
            lines.append("  - *%s:* %s" % (wording.text("f_reason", lang),
                                           action.get("reason", "")))
            lines.append("  - *%s:* %s · *%s:* %s" % (
                wording.text("f_owner", lang),
                wording.label("owner_roles",
                              (action.get("owner") or {}).get("role"), lang),
                wording.text("f_state", lang),
                wording.label("action_states", action.get("state"), lang)))
            if action.get("success_evidence"):
                lines.append("  - *%s:* %s" % (
                    wording.text("f_success_evidence", lang),
                    action["success_evidence"]))
            if action.get("blocking_scope"):
                lines.append("  - *%s:* %s" % (
                    wording.text("f_blocking_scope", lang),
                    "; ".join(wording.scope_label(s, lang)
                              for s in action["blocking_scope"])))
            if action.get("procedure_refs"):
                lines.append("  - *%s:* %s" % (
                    wording.text("f_procedures", lang),
                    _refs(action["procedure_refs"])))
        lines.append("")
    return lines


def _render_confidence(envelope, report, profile, lang):
    scenarios = envelope.get("scenarios") or []
    lines = ["## %s" % wording.text("h_confidence", lang), ""]
    confidences = [s["confidence"] for s in scenarios if s.get("confidence")]
    worst = None
    for value in ("low", "medium", "high"):
        if value in confidences:
            worst = value
            break
    if worst:
        lines.append(wording.template(
            "confidence_line", lang,
            confidence=wording.label("confidence", worst, lang),
            rationale=wording.label("confidence_rationale", worst, lang)))
        lines.append("")
    assumptions, seen = [], set()
    for scenario in scenarios:
        for assumption in scenario.get("assumptions") or []:
            if assumption not in seen:
                seen.add(assumption)
                assumptions.append(assumption)
    for assumption in assumptions:
        lines.append("- %s" % assumption)
    if assumptions:
        lines.append("")
    lines.extend([wording.text("note_aggregation", lang), ""])
    return lines


def _render_appendix(envelope, report, profile, lang):
    mapping = canonical.load_framework_mapping()
    by_control = {}
    for assessment in canonical.current_assessments(envelope):
        by_control[assessment.get("control_id")] = assessment
    registry = _registry()

    lines = ["## %s" % wording.text("h_appendix", lang), "",
             wording.text("note_appendix", lang), "",
             "### %s" % wording.text("h_appendix_items", lang), "",
             wording.text("note_blank_status", lang), ""]
    rows = []
    for entry in sorted(mapping["entries"], key=lambda e: e["item_number"]):
        control_id = entry["control_id"]
        assessment = by_control.get(control_id)
        rows.append((
            entry["item_number"],
            entry["category"][lang],
            # The founder-facing summary changes register, not the record. The
            # appendix is always the technical reviewer view of all 89 rows.
            _profile_wording(control_id, lang, "reviewer"),
            wording.label("severities", registry[control_id]["severity"], lang),
            wording.status_label(assessment["status"], lang) if assessment
            else wording.text("v_not_reviewed", lang),
            "`%s`" % assessment["assessment_id"] if assessment else "—",
            _refs((assessment.get("basis") or {}).get("evidence_refs") or [])
            if assessment else "—",
        ))
    lines.extend(_table([wording.text("t_item", lang),
                         wording.text("t_category", lang),
                         wording.text("t_control", lang),
                         wording.text("t_severity", lang),
                         wording.text("t_status", lang),
                         wording.text("t_assessment", lang),
                         wording.text("t_evidence", lang)], rows))
    lines.append("")

    lines.extend(["### %s" % wording.text("h_appendix_evidence", lang), ""])
    evidence_rows = []
    for evidence in sorted(envelope.get("evidence") or [],
                           key=lambda e: e["evidence_id"]):
        subject = evidence.get("subject") or {}
        evidence_rows.append((
            "`%s`" % evidence["evidence_id"],
            (evidence.get("provider") or {}).get("name"),
            "%s %s" % (subject.get("kind", ""), subject.get("locator", "")),
            wording.label("evidence_directions", evidence.get("direction"), lang),
            wording.label("evidence_strengths", evidence.get("strength"), lang),
            evidence.get("observed_at"),
            evidence.get("valid_until"),
            evidence.get("scope"),
        ))
    lines.extend(_table([wording.text("t_evidence", lang),
                         wording.text("t_provider", lang),
                         wording.text("t_subject", lang),
                         wording.text("t_direction", lang),
                         wording.text("t_strength", lang),
                         wording.text("t_observed_at", lang),
                         wording.text("t_valid_until", lang),
                         wording.text("t_scope_text", lang)], evidence_rows))
    lines.append("")

    lines.extend(["### %s" % wording.text("h_appendix_risks", lang), ""])
    risk_rows = []
    for risk in sorted(envelope.get("risks") or [], key=lambda r: r["risk_id"]):
        inputs = risk.get("inputs") or {}
        risk_rows.append((
            "`%s`" % risk["risk_id"],
            _refs(risk.get("control_refs") or []),
            wording.label("domains", risk.get("domain"), lang),
            wording.scope_label(risk.get("scope") or {}, lang),
            wording.label("horizons", (risk.get("horizon") or {}).get("kind"), lang),
            inputs.get("impact"),
            inputs.get("exposure"),
            wording.label("levels", risk.get("level"), lang),
            wording.label("confidence", risk.get("confidence"), lang),
        ))
    lines.extend(_table([wording.text("t_risk", lang),
                         wording.text("t_control", lang),
                         wording.text("t_domain", lang),
                         wording.text("t_scope", lang),
                         wording.text("t_horizon", lang),
                         wording.text("t_impact", lang),
                         wording.text("t_exposure", lang),
                         wording.text("t_level", lang),
                         wording.text("f_confidence", lang)], risk_rows))
    lines.append("")

    lines.extend(["### %s" % wording.text("h_appendix_scenarios", lang), ""])
    scenario_rows = []
    scenarios = _index(envelope.get("scenarios"), "scenario_id")
    for entry in report["scenario_ranking"]:
        scenario = scenarios.get(entry["scenario_ref"]) or {}
        trace = scenarios_mod.traceability(envelope, scenario)
        scenario_rows.append((
            entry["rank"],
            "`%s`" % entry["scenario_ref"],
            (scenario.get("wording") or {}).get("title", {}).get(
                lang, scenario.get("title", "")),
            wording.text("v_yes" if entry["headline"] else "v_no", lang),
            wording.label("levels", scenario.get("current_level"), lang),
            wording.label("levels", scenario.get("future_level"), lang),
            _refs(trace["control_refs"]),
            _refs(trace["assessment_refs"]),
            _refs(trace["risk_refs"]),
            _refs(trace["evidence_refs"]),
            _refs(trace["action_refs"]),
            _refs(trace["procedure_refs"]),
        ))
    lines.extend(_table([wording.text("t_rank", lang),
                         wording.text("t_scenario", lang),
                         wording.text("t_title", lang),
                         wording.text("t_headline", lang),
                         wording.text("f_risk_today", lang),
                         wording.text("f_risk_later", lang),
                         wording.text("t_control_id", lang),
                         wording.text("t_assessment", lang),
                         wording.text("t_risk", lang),
                         wording.text("t_evidence", lang),
                         wording.text("t_action", lang),
                         wording.text("t_procedure", lang)], scenario_rows))
    lines.append("")

    lines.extend(["### %s" % wording.text("h_appendix_actions", lang), ""])
    action_rows = []
    for action in sorted(envelope.get("actions") or [], key=lambda a: a["action_id"]):
        action_rows.append((
            "`%s`" % action["action_id"],
            wording.label("action_kinds", action.get("kind"), lang),
            action.get("outcome"),
            wording.label("owner_roles", (action.get("owner") or {}).get("role"), lang),
            wording.label("priorities", action.get("priority"), lang),
            wording.label("urgencies", action.get("urgency"), lang),
            wording.label("deadline_labels",
                          deadline_label_id(action, report["generated_at"]), lang),
            wording.label("action_states", action.get("state"), lang),
            "; ".join(wording.scope_label(s, lang)
                      for s in action.get("blocking_scope") or []),
            _refs(action.get("control_refs") or []),
            _refs(action.get("risk_refs") or []),
            _refs(action.get("scenario_refs") or []),
            _refs(action.get("procedure_refs") or []),
            action.get("success_evidence"),
        ))
    lines.extend(_table([wording.text("t_action", lang),
                         wording.text("t_kind", lang),
                         wording.text("f_outcome", lang),
                         wording.text("f_owner", lang),
                         wording.text("t_priority", lang),
                         wording.text("t_urgency", lang),
                         wording.text("f_deadline", lang),
                         wording.text("f_state", lang),
                         wording.text("f_blocking_scope", lang),
                         wording.text("t_control_id", lang),
                         wording.text("t_risk", lang),
                         wording.text("t_scenario", lang),
                         wording.text("t_procedure", lang),
                         wording.text("f_success_evidence", lang)], action_rows))
    lines.append("")

    lines.extend(["### %s" % wording.text("h_appendix_procedures", lang), ""])
    procedure_rows = []
    legacy_rows = {
        row["procedure_ref"]: row
        for action_row in actions_mod.legacy_view(envelope)["actions"]
        for row in action_row["procedure_views"]
    }
    for procedure in sorted(envelope.get("procedures") or [],
                            key=lambda p: p["procedure_id"]):
        effects = procedure.get("effects") or {}
        enabled_effects = [key for key in (
            "write", "destructive", "deployment", "data", "external_accounts")
                           if effects.get(key)]
        if (procedure.get("data_egress") or {}).get("occurs"):
            enabled_effects.append("data_egress")
        procedure_rows.append((
            "`%s`" % procedure["procedure_id"],
            procedure.get("title"),
            wording.label("executor_roles", procedure.get("executor_role"), lang),
            wording.label("execution_modes", procedure.get("execution_mode"), lang),
            procedure.get("mechanism"),
            wording.label("consent", (procedure.get("authorization") or {}).get(
                "consent"), lang),
            wording.text("v_yes" if (procedure.get("network") or {}).get("required")
                         else "v_no", lang),
            ", ".join(enabled_effects) or wording.text("v_none", lang),
            (legacy_rows.get(procedure["procedure_id"]) or {}).get(
                "classification"),
            procedure.get("success_evidence"),
        ))
    lines.extend(_table([wording.text("t_procedure", lang),
                         wording.text("t_title", lang),
                         wording.text("t_executor", lang),
                         wording.text("t_execution_mode", lang),
                         wording.text("t_mechanism", lang),
                         wording.text("t_consent", lang),
                         wording.text("t_network", lang),
                         wording.text("t_effects", lang),
                         wording.text("t_legacy_view", lang),
                         wording.text("f_success_evidence", lang)], procedure_rows))
    lines.append("")

    lines.extend(["### %s" % wording.text("h_appendix_attempts", lang), ""])
    attempt_rows = []
    for attempt in sorted(envelope.get("attempts") or [],
                          key=lambda item: item["attempt_id"]):
        observed = attempt.get("side_effects_observed") or {}
        enabled_effects = [key for key in actions_mod.load_policy()["effect_flags"]
                           if observed.get(key)]
        attempt_rows.append((
            "`%s`" % attempt["attempt_id"],
            "`%s`" % attempt.get("action_ref"),
            "`%s`" % attempt.get("procedure_ref"),
            attempt.get("execution_environment"),
            attempt.get("result"),
            (attempt.get("authorization") or {}).get("mode"),
            ", ".join(enabled_effects) or wording.text("v_none", lang),
            (attempt.get("rollback") or {}).get("state"),
            _refs(attempt.get("evidence_refs") or []),
            _refs(attempt.get("reassessment_refs") or []),
        ))
    lines.extend(_table([wording.text("t_attempt", lang),
                         wording.text("t_action", lang),
                         wording.text("t_procedure", lang),
                         wording.text("t_environment", lang),
                         wording.text("t_result", lang),
                         wording.text("t_consent", lang),
                         wording.text("t_effects", lang),
                         wording.text("t_rollback", lang),
                         wording.text("t_evidence", lang),
                         wording.text("t_reassessment", lang)], attempt_rows))
    lines.append("")

    lines.extend(["### %s" % wording.text("h_appendix_method", lang), ""])
    appendix = report["appendix"]
    method_rows = [
        ("vibecheck.assessment", envelope.get("schema_version")),
        (appendix["framework"], appendix["framework_version"]),
        ((appendix.get("control_registry") or {}).get("name"),
         (appendix.get("control_registry") or {}).get("version")),
        ((appendix.get("action_registry") or {}).get("name"),
         (appendix.get("action_registry") or {}).get("version")),
        (risk_mod.POLICY_NAME, risk_mod.load_policy()["schema_version"]),
        (readiness_mod.POLICY_NAME, readiness_mod.POLICY_VERSION),
        (scenarios_mod.POLICY_NAME, load_policy()["schema_version"]),
        (POLICY_NAME, POLICY_VERSION),
        (actions_mod.POLICY_NAME, actions_mod.load_policy()["schema_version"]),
        (wording.WORDING_NAME, wording.load_wording()["schema_version"]),
    ]
    lines.extend(_table([wording.text("t_method", lang),
                         wording.text("t_version", lang)], method_rows))
    lines.append("")
    return lines


def render(envelope, profile="founder", language="en", now=None):
    """The whole report as markdown, for one profile and one language."""
    if profile not in wording.PROFILES:
        raise ValueError("unknown report profile %r" % (profile,))
    if language not in wording.LANGUAGES:
        raise ValueError("unknown report language %r" % (language,))
    report = envelope.get("report") or derive_report(envelope, profile, language, now)
    lines = []
    for builder in (_render_header, _render_context, _render_readiness,
                    _render_scenarios, _render_mandatory, _render_actions,
                    _render_confidence, _render_appendix):
        lines.extend(builder(envelope, report, profile, language))
    return "\n".join(lines).rstrip() + "\n"


# ------------------------------------------------------------------------ CLI

def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Derive and render a founder or reviewer report from a "
                    "vibecheck.assessment envelope")
    parser.add_argument("envelope", help="path to a vibecheck.assessment JSON file")
    parser.add_argument("--profile", default="founder", choices=list(wording.PROFILES))
    parser.add_argument("--lang", default="en", choices=list(wording.LANGUAGES))
    parser.add_argument("--now", help="derivation timestamp (default: now, UTC)")
    parser.add_argument("--json", action="store_true",
                        help="print the derived envelope instead of the markdown")
    parser.add_argument("--out", help="write the output here")
    args = parser.parse_args(argv)

    with open(args.envelope, encoding="utf-8") as fh:
        envelope = json.load(fh)
    derived = derive_into(envelope, args.profile, args.lang, args.now)
    problems = canonical.validate_envelope(derived)
    for problem in problems:
        print("problem: %s" % problem, file=sys.stderr)

    output = (canonical.dumps(derived) if args.json
              else render(derived, args.profile, args.lang, args.now))
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(output)
    else:
        sys.stdout.write(output)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
