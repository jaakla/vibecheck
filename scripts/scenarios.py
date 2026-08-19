# -*- coding: utf-8 -*-
"""Founder-facing risk scenarios (RFC 0001 §9).

A reviewer reads "control 14 is failed". An owner needs to hear "anyone with
the address of your app can read every order, and it gets worse the day you
launch". This module turns the second sentence out of the first one, without
inventing anything:

    unresolved assessments -> derived contextual risks -> one scenario per
    failure story, carrying every control, assessment, evidence record, risk
    and action it was built from

What it refuses to do, in the same spirit as risk.py:

  * change anything it aggregates — no scenario writes a control status, an
    intrinsic severity or an accepted-risk record (rules R12, R14). A scenario
    is a way of reading assessments, never a re-assessment of them;
  * hide a level it does not know — a stale or unknown member risk makes the
    scenario's level unknown, and unknown sorts above every measured level
    that is not itself blocking, never as low (rule R8);
  * average today and later — the current-horizon reading and the
    event-triggered readings stay side by side, which is how "fine in the
    pilot, critical at launch" survives into the summary.

Which controls tell which story, and how stories are ranked and capped, are
data: schema/report-derivation.v1.json. The words are data too, in both
languages: schema/report-wording.v1.json.
"""
import copy
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import canonical
import actions as actions_mod
import context as ctx
import risk as risk_mod
import wording

POLICY_PATH = os.path.join(canonical.REPO_ROOT, "schema", "report-derivation.v1.json")
POLICY_NAME = "vibecheck.report_derivation"

_cache = {}


def load_policy():
    if "policy" not in _cache:
        with open(POLICY_PATH, encoding="utf-8") as fh:
            _cache["policy"] = json.load(fh)
    return _cache["policy"]


def _registry():
    if "registry" not in _cache:
        _cache["registry"] = {c["control_id"]: c
                              for c in canonical.load_registry()["controls"]}
    return _cache["registry"]


def _group_by_namespace():
    if "by_namespace" not in _cache:
        table = {}
        for group in load_policy()["scenario_groups"]:
            for namespace in group["namespaces"]:
                table[namespace] = group["group_id"]
        _cache["by_namespace"] = table
    return _cache["by_namespace"]


def group_of(control_id):
    """The failure story this control belongs to.

    Per-control overrides first, then the namespace. Returns None when neither
    knows the control, which tests/test_report.py turns into a failure: a
    control that cannot be told as a story would silently vanish from every
    founder report.
    """
    policy = load_policy()
    override = (policy.get("group_by_control") or {}).get(control_id)
    if override:
        return override
    namespace = control_id.split(".")[2] if control_id.count(".") >= 3 else ""
    return _group_by_namespace().get(namespace)


def unresolved_assessments(envelope):
    """control_id -> current assessment, for controls whose requirement is not
    met (fail, partial, or an accepted risk — an acceptance is a decision about
    a gap, not a closed gap)."""
    statuses = load_policy()["unresolved_statuses"]
    out = {}
    for assessment in canonical.current_assessments(envelope):
        if assessment.get("status") in statuses and assessment.get("control_id"):
            out[assessment["control_id"]] = assessment
    return out


# ------------------------------------------------------------------- levels

def level_rank(level):
    ranks = load_policy()["ranking"]["level_rank"]
    return ranks.get(level or "none", 0)


def worst_level(levels):
    """The level a reader must act on. Unknown never collapses into low."""
    worst = "none"
    for level in levels:
        if level_rank(level) > level_rank(worst):
            worst = level
    return worst


def _scope_slug(scope):
    return "%s.%s" % (scope.get("environment"), scope.get("intended_use"))


# --------------------------------------------------------------- narratives

def _describe_value(context, dimension_id, lang):
    """One context answer in reader-facing words, or an explicit 'not
    established' — an unknown dimension is never described as the benign
    value."""
    value = ctx.field_value(context, dimension_id)
    if value is None:
        return wording.text("v_not_established", lang)
    return wording.dimension_value(dimension_id, value, lang)


def _narrative(context, group_id, current, futures, lang):
    """The founder-facing story, in one language.

    Deliberately short: what can happen, what is at stake, what it is worth
    today and what it becomes later. The controls, evidence and actions it
    rests on are structural (control_refs, evidence_refs, action_refs) and the
    report renders them beside the narrative rather than inside it.
    """
    parts = [wording.group_wording(group_id, "opener", lang),
             wording.template(
                 "scenario_stake", lang,
                 data=_describe_value(context, "data_sensitivity", lang),
                 audience=_describe_value(context, "audience_scale", lang))]
    if current is not None:
        parts.append(wording.template(
            "scenario_current", lang,
            scope=wording.scope_label(current["scope"], lang),
            level=wording.label("levels", current["level"], lang)))
    else:
        parts.append(wording.text("scenario_no_current", lang))
    for entry in futures:
        parts.append(wording.template(
            "scenario_future", lang,
            scope=wording.scope_label(entry["scope"], lang),
            level=wording.label("levels", entry["level"], lang)))
    if any(entry["level"] == "unknown"
           for entry in ([current] if current else []) + list(futures)):
        parts.append(wording.text("disclaimer_unknown", lang))
    return " ".join(parts)


# ---------------------------------------------------------------- derivation

_CONFIDENCE_ORDER = ("low", "medium", "high")


def _worst_confidence(risks, envelope=None, now=None):
    # A stale risk is read as unknown by readiness and by the scenario. Calling
    # that same reading "high confidence" because its context was once well
    # confirmed would be internally contradictory.
    if envelope is not None and any(
            risk_mod.is_stale(risk, envelope, now) for risk in risks):
        return "low"
    worst = None
    for risk in risks:
        value = risk.get("confidence")
        if value not in _CONFIDENCE_ORDER:
            continue
        if worst is None or _CONFIDENCE_ORDER.index(value) < _CONFIDENCE_ORDER.index(worst):
            worst = value
    return worst


def _linked_actions(envelope, scenario_id, control_ids, risk_ids):
    """Actions that already point at this story, by control, risk or scenario.

    Actions are never rewritten from a presentation layer: editing
    its own inputs is how traceability rots.
    """
    linked = []
    for action in actions_mod.current_actions(envelope):
        refs = set(action.get("control_refs") or [])
        risks = set(action.get("risk_refs") or [])
        scenes = set(action.get("scenario_refs") or [])
        if (refs & control_ids) or (risks & risk_ids) or scenario_id in scenes:
            linked.append(action["action_id"])
    return sorted(linked)


def _risk_evidence_refs(risk):
    """Every evidence record that can substantively affect a risk reading."""
    refs = set(risk.get("evidence_refs") or [])
    for measure in (risk.get("inputs") or {}).get("compensating_controls") or []:
        refs.update(measure.get("evidence_refs") or [])
    refs.update((risk.get("downgrade") or {}).get("evidence_refs") or [])
    return refs


def traceability(envelope, scenario):
    """Resolve the complete scenario -> assessment/evidence/action path.

    New derived scenarios store these links directly. This resolver also makes
    an older or hand-authored scenario reviewable without rewriting it: risks
    contribute their controls and evidence, current assessments contribute
    their basis and conflicts, and actions may link through any of the three.
    """
    risks = {
        risk["risk_id"]: risk for risk in envelope.get("risks") or []
        if risk.get("risk_id")
    }
    risk_ids = set(scenario.get("risk_refs") or [])
    control_ids = set(scenario.get("control_refs") or [])
    evidence_ids = set(scenario.get("evidence_refs") or [])
    assessment_ids = set(scenario.get("assessment_refs") or [])

    for risk_id in risk_ids:
        risk = risks.get(risk_id)
        if risk is None:
            continue
        control_ids.update(risk.get("control_refs") or [])
        evidence_ids.update(_risk_evidence_refs(risk))

    for assessment in canonical.current_assessments(envelope):
        if assessment.get("control_id") not in control_ids:
            continue
        assessment_ids.add(assessment["assessment_id"])
        evidence_ids.update((assessment.get("basis") or {}).get("evidence_refs") or [])
        evidence_ids.update(
            conflict["evidence_ref"] for conflict in assessment.get("conflicts") or []
            if conflict.get("evidence_ref"))

    action_ids = set(scenario.get("action_refs") or [])
    action_ids.update(_linked_actions(
        envelope, scenario.get("scenario_id"), control_ids, risk_ids))
    actions = {action["action_id"]: action for action in actions_mod.current_actions(envelope)
               if action.get("action_id")}
    procedure_ids = set()
    for action_id in action_ids:
        procedure_ids.update((actions.get(action_id) or {}).get("procedure_refs") or [])

    return {
        "risk_refs": sorted(risk_ids),
        "control_refs": sorted(control_ids),
        "assessment_refs": sorted(assessment_ids),
        "evidence_refs": sorted(evidence_ids),
        "action_refs": sorted(action_ids),
        "procedure_refs": sorted(procedure_ids),
    }


def derive_scenarios(envelope, now=None):
    """One scenario per failure story with at least one derived risk.

    Sorted by scenario id, so the same envelope always serializes identically.
    """
    now_dt = ctx.instant(now)
    context = envelope.get("context") or {}
    unresolved = unresolved_assessments(envelope)
    current_scope = ctx.current_scope(context) or {}

    grouped = {}
    for risk in sorted(risk_mod.current_risks(envelope), key=lambda r: r["risk_id"]):
        for control_id in risk.get("control_refs") or []:
            if control_id not in unresolved:
                continue
            group_id = group_of(control_id)
            if group_id is None:
                continue
            grouped.setdefault(group_id, {"controls": set(), "risks": []})
            grouped[group_id]["controls"].add(control_id)
            if risk not in grouped[group_id]["risks"]:
                grouped[group_id]["risks"].append(risk)

    scenarios = []
    for group_id, members in sorted(grouped.items()):
        risks = members["risks"]
        control_ids = sorted(members["controls"])
        assessments = [unresolved[c] for c in control_ids]

        by_scope = {}
        for risk in risks:
            key = (_scope_slug(risk["scope"]), risk["horizon"]["kind"])
            entry = by_scope.setdefault(key, {
                "scope": dict(risk["scope"]),
                "horizon": copy.deepcopy(risk["horizon"]),
                "levels": [],
                "risk_refs": [],
            })
            entry["levels"].append(risk_mod.effective_level(risk, envelope, now_dt))
            entry["risk_refs"].append(risk["risk_id"])

        readings = []
        for key in sorted(by_scope):
            entry = by_scope[key]
            readings.append({
                "scope": entry["scope"],
                "horizon": entry["horizon"],
                "level": worst_level(entry["levels"]),
                "risk_refs": sorted(entry["risk_refs"]),
            })
        current = next((r for r in readings
                        if r["horizon"]["kind"] == "current"
                        and ctx.same_scope(r["scope"], current_scope)), None)
        futures = [r for r in readings if r["horizon"]["kind"] == "event_triggered"]

        assumptions, seen = [], set()
        for risk in risks:
            for assumption in risk.get("assumptions") or []:
                if assumption not in seen:
                    seen.add(assumption)
                    assumptions.append(assumption)

        scenario_id = "scn-%s" % group_id
        scenario = {
            "scenario_id": scenario_id,
            "group_id": group_id,
            "title": wording.group_wording(group_id, "title", "en"),
            "narrative": _narrative(context, group_id, current, futures, "en"),
            "wording": {
                "title": {lang: wording.group_wording(group_id, "title", lang)
                          for lang in wording.LANGUAGES},
                "narrative": {lang: _narrative(context, group_id, current, futures, lang)
                              for lang in wording.LANGUAGES},
            },
            "domains": sorted({r["domain"] for r in risks if r.get("domain")}),
            "risk_refs": sorted(r["risk_id"] for r in risks),
            "control_refs": control_ids,
            "assessment_refs": sorted(a["assessment_id"] for a in assessments),
            "risk_by_scope": readings,
            "current_level": current["level"] if current else "none",
            "future_level": worst_level([r["level"] for r in futures]),
            "assessed_at": ctx.iso(now_dt),
            "derivation": {
                "policy": {"name": POLICY_NAME,
                           "version": load_policy()["schema_version"]},
                "context_revision": int(context.get("revision", 1)),
                "rules_applied": sorted(
                    {"scenario.group.%s" % group_id}
                    | {"scenario.control.%s" % c for c in control_ids}),
            },
        }
        scenario.update(traceability(envelope, scenario))
        confidence = _worst_confidence(risks, envelope, now_dt)
        if confidence:
            scenario["confidence"] = confidence
        if assumptions:
            scenario["assumptions"] = assumptions
        scenarios.append(scenario)
    return sorted(scenarios, key=lambda s: s["scenario_id"])


def apply_scenarios(envelope, now=None):
    """Replace the derived scenarios; leave hand-authored ones alone.

    Scenarios are a derived view of assessments and risks, like readiness:
    recomputing them after new evidence is the point, and keeping a superseded
    copy of a view would only make two answers where there is one.
    """
    updated = copy.deepcopy(envelope)
    derived = derive_scenarios(updated, now)
    kept = [s for s in updated.get("scenarios") or []
            if not s.get("derivation")]
    derived_ids = {s["scenario_id"] for s in derived}
    kept = [s for s in kept if s.get("scenario_id") not in derived_ids]
    updated["scenarios"] = sorted(kept + derived, key=lambda s: s["scenario_id"])
    return updated


# ------------------------------------------------------------------ ranking

def _max_severity_rank(scenario):
    policy = load_policy()["ranking"]
    registry = _registry()
    ranks = [policy["severity_rank"].get(
        (registry.get(c) or {}).get("severity"), 0)
        for c in scenario.get("control_refs") or []]
    return max(ranks) if ranks else 0


def _domain_rank(scenario):
    order = load_policy()["ranking"]["domain_order"]
    positions = [order.index(d) for d in scenario.get("domains") or [] if d in order]
    return min(positions) if positions else len(order)


def rank_scenarios(envelope, now=None):
    """Scenarios in reading order, with the reason each one sits where it does.

    The key is fixed in schema/report-derivation.v1.json (level today, level
    later, worst intrinsic severity, how many controls, domain, id) and every
    component is read from the envelope, so the order is reproducible and
    explainable rather than a judgement call at render time.
    """
    scenarios = list(envelope.get("scenarios") or [])
    policy = load_policy()["ranking"]

    def sort_key(scenario):
        return (
            -level_rank(scenario.get("current_level")),
            -level_rank(scenario.get("future_level")),
            -_max_severity_rank(scenario),
            -len(scenario.get("control_refs") or []),
            _domain_rank(scenario),
            scenario["scenario_id"],
        )

    # Only scenarios produced by this deterministic aggregation policy compete
    # for headline slots. Older/custom scenarios remain in the appendix, but
    # cannot displace or duplicate the normalized failure stories.
    derived = [s for s in scenarios
               if ((s.get("derivation") or {}).get("policy") or {}).get("name")
               == POLICY_NAME]
    derived_ids = {s["scenario_id"] for s in derived}
    retained = [s for s in scenarios if s.get("scenario_id") not in derived_ids]
    ordered = sorted(derived, key=sort_key) + sorted(retained, key=sort_key)
    headline_levels = policy["headline_levels"]
    at_headline_level = sum(
        1 for s in derived
        if s.get("current_level") in headline_levels
        or s.get("future_level") in headline_levels)
    count = min(policy["headline_max"],
                max(policy["headline_min"], at_headline_level),
                len(derived))

    ranking = []
    for position, scenario in enumerate(ordered, 1):
        ranking.append({
            "scenario_ref": scenario["scenario_id"],
            "rank": position,
            "headline": scenario.get("scenario_id") in derived_ids and position <= count,
            "inputs": {
                "derived_by_policy": scenario.get("scenario_id") in derived_ids,
                "current_level": scenario.get("current_level", "none"),
                "future_level": scenario.get("future_level", "none"),
                "max_control_severity_rank": _max_severity_rank(scenario),
                "unresolved_control_count": len(scenario.get("control_refs") or []),
                "domain_rank": _domain_rank(scenario),
            },
        })
    return ranking


def headline_refs(ranking):
    return [entry["scenario_ref"] for entry in ranking if entry["headline"]]
