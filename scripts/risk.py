# -*- coding: utf-8 -*-
"""Deterministic contextual risk (RFC 0001 §5).

Turns "this control is not met" into "and here is what that means for *this*
application, in *this* environment, for *this* intended use" — reproducibly:

    impact   = base(intrinsic severity) + context adjustments, capped
    exposure = base(environment) + context adjustments, capped, minus at most
               one evidenced compensating control
    level    = risk-matrix[impact][exposure]

The numbers, caps and per-rule rationales are data
(schema/risk-derivation.v1.json), the matrix is data
(schema/risk-matrix.v1.json), and every derived risk records the exact rule ids
it applied, so the same normalized inputs always produce the same level and the
reasoning can be read back without re-running anything.

What this module refuses to do:

  * turn a failed control into a passing one — it never touches assessment
    status, and no derived object carries a control status (rule R14);
  * change intrinsic severity — severity is read from the registry and only
    ever selects the impact base and ceiling;
  * answer with "low" when it does not know — an unknown or conflicting
    dimension that could move an input makes that input, and therefore the
    level, unknown (rules R6/R8);
  * average today and later into one number — the scope the application is in
    now gets a `current` risk, every other target scope gets an
    `event_triggered` one, so "fine today, critical at launch" stays two facts.

A derived level is a defensible default, not a verdict. A reviewer may raise it
freely; lowering it needs the downgrade record the matrix method demands.
"""
import copy
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import canonical
import context as ctx

POLICY_PATH = os.path.join(canonical.REPO_ROOT, "schema", "risk-derivation.v1.json")
POLICY_NAME = "vibecheck.risk_derivation"

#: Statuses that derive no risk here, for reasons the policy file states: an
#: untested Critical control is a material unknown for readiness, which is
#: stronger than any low risk, not weaker.
_NO_RISK_STATUSES = ("pass", "not_tested", "not_applicable", "answered",
                     "needs_specialist")

_cache = {}


def load_policy():
    if "policy" not in _cache:
        with open(POLICY_PATH, encoding="utf-8") as fh:
            _cache["policy"] = json.load(fh)
    return _cache["policy"]


def _registry_index():
    if "registry" not in _cache:
        _cache["registry"] = {c["control_id"]: c
                              for c in canonical.load_registry()["controls"]}
    return _cache["registry"]


def severity_of(control_id):
    entry = _registry_index().get(control_id)
    return entry["severity"] if entry else None


def title_of(control_id):
    entry = _registry_index().get(control_id)
    return entry["title"]["en"] if entry else control_id


def domain_of(control_id):
    """The primary risk domain of a control: the per-control override first,
    then the namespace default."""
    policy = load_policy()
    override = (policy.get("domain_by_control") or {}).get(control_id)
    if override:
        return override
    namespace = control_id.split(".")[2] if control_id.count(".") >= 3 else ""
    return (policy.get("domain_by_namespace") or {}).get(namespace, "security")


# ------------------------------------------------------------------ the scale

def _index(scale, value):
    return scale.index(value) + 1 if value in scale else None


def _value(scale, index):
    return scale[max(1, min(len(scale), index)) - 1]


def level_for(impact, exposure):
    """matrix[impact][exposure]; unknown in, unknown out (rule R6)."""
    if impact == "unknown" or exposure == "unknown":
        return "unknown"
    matrix = canonical.load_matrix()["matrix"]
    return (matrix.get(impact) or {}).get(exposure, "unknown")


def _rule_applies(rule, context, scope, domain):
    domains = rule.get("domains")
    if domains != load_policy()["domains_wildcard"] and domain not in (domains or []):
        return False
    when = rule.get("when") or {}
    if "dimension" in when:
        return ctx.field_value(context, when["dimension"]) == when["value"]
    if "scope_field" in when:
        field = when["scope_field"]
        value = scope.get(field)
        resolved = (ctx.resolve_environment(context, value) if field == "environment"
                    else ctx.resolve_intended_use(context, value))
        return resolved == when["value"]
    return False


def _relevant_dimensions(section, domain):
    """Required dimensions that could actually move this domain's input.

    A dimension whose every rule is scoped to other domains cannot change this
    result, so not knowing it cannot hide anything here either. Every dimension
    that *can* move the input and is not established makes the input unknown.
    """
    wildcard = load_policy()["domains_wildcard"]
    movable = set()
    for rule in section.get("adjustments") or []:
        when = rule.get("when") or {}
        if "dimension" not in when:
            continue
        domains = rule.get("domains")
        if domains == wildcard or domain in (domains or []):
            movable.add(when["dimension"])
    return [d for d in section.get("required_dimensions") or [] if d in movable]


def projected_profile(context, scope):
    """Dimension values a future scope implies, where they exceed today's.

    Returns {dimension: value} for the dimensions the transition necessarily
    changes. A dimension that is unknown or conflicting today is left alone: a
    projection is a floor for a scope the application has not entered, not an
    answer to an open question.
    """
    projection = load_policy().get("scope_projection") or {}
    environment = ctx.resolve_environment(context, scope.get("environment"))
    intended_use = ctx.resolve_intended_use(context, scope.get("intended_use"))
    wanted = {}
    wanted.update((projection.get("by_environment") or {}).get(environment) or {})
    wanted.update((projection.get("by_intended_use") or {}).get(intended_use) or {})

    bands = {d: {v["id"]: v["band"] for v in spec["values"]}
             for d, spec in ctx.dimensions().items()}
    out = {}
    for dimension_id, value in wanted.items():
        captured = ctx.field_value(context, dimension_id)
        if captured is None:
            continue  # unknown stays unknown
        if bands[dimension_id][value] > bands[dimension_id][captured]:
            out[dimension_id] = value
    return out


def _with_projection(context, projection):
    """A context view whose projected dimensions read as confirmed values.

    Only the profile is swapped, and only in memory: the recorded context keeps
    saying what is true today.
    """
    if not projection:
        return context
    view = dict(context)
    profile = dict(context.get("profile") or {})
    for dimension_id, value in projection.items():
        profile[dimension_id] = {"state": "confirmed", "value": value,
                                 "source": "scope projection"}
    view["profile"] = profile
    return view


def _derive_input(section, prefix, context, scope, domain, base_index,
                  ceiling_index=None):
    """(value, rules applied, unknown dimensions) for one matrix input."""
    scale = section["scale"]
    rules = []
    unknown = []
    for dimension_id in _relevant_dimensions(section, domain):
        if ctx.field_value(context, dimension_id) is None:
            unknown.append("%s (%s)" % (dimension_id,
                                        ctx.field_state(context, dimension_id)))
    if unknown:
        return "unknown", rules, unknown

    delta = 0
    for rule in section.get("adjustments") or []:
        if _rule_applies(rule, context, scope, domain):
            delta += rule["delta"]
            rules.append(rule["rule_id"])
    if delta > section["max_increase"]:
        delta = section["max_increase"]
        rules.append("%s.cap.max_increase" % prefix)
    elif delta < -section["max_decrease"]:
        delta = -section["max_decrease"]
        rules.append("%s.cap.max_decrease" % prefix)

    index = base_index + delta
    if ceiling_index is not None and index > ceiling_index:
        index = ceiling_index
        rules.append("%s.cap.severity_ceiling" % prefix)
    if index < 1:
        index = 1
        rules.append("%s.cap.floor" % prefix)
    return _value(scale, index), rules, unknown


# ------------------------------------------------------- compensating controls

def _evidence_index(envelope):
    return {e.get("evidence_id"): e for e in envelope.get("evidence") or []}


def current_supporting_evidence(envelope, evidence_refs, now):
    """Supporting evidence records that hold at `now` (rule R15).

    Current means observed already and not yet expired. Evidence dated after
    the derivation instant has not happened yet from this derivation's point of
    view, and support that has not happened cannot lower anything — the same
    reading the assessment rules apply to a `pass` (rule R3).
    """
    evidence = _evidence_index(envelope)
    now_dt = ctx.instant(now)
    fresh = []
    for ref in evidence_refs or []:
        item = evidence.get(ref)
        if item is None or item.get("direction") != "supports":
            continue
        observed = ctx.parse_instant(item.get("observed_at"))
        if observed is None or observed > now_dt:
            continue
        valid_until = ctx.parse_instant(item.get("valid_until"))
        if "valid_until" in item and (
                valid_until is None or valid_until < now_dt):
            continue
        fresh.append(ref)
    return fresh


def _applicable_measures(envelope, control_id, domain, scope, now):
    """Compensating controls that may reduce exposure for this risk.

    Scope is stated, never assumed: a measure applies only to the controls,
    domains and scopes it names, and only while at least one supporting
    evidence record is current.
    """
    out = []
    for measure in (envelope.get("context") or {}).get("compensating_controls") or []:
        applies = measure.get("applies_to") or {}
        if control_id not in (applies.get("control_ids") or []) and \
                domain not in (applies.get("domains") or []):
            continue
        scopes = applies.get("scopes")
        if scopes and not any(ctx.same_scope(scope, s) for s in scopes):
            continue
        valid_until = ctx.parse_instant(measure.get("valid_until"))
        if "valid_until" in measure and (
                valid_until is None or valid_until < now):
            continue
        fresh = current_supporting_evidence(envelope, measure.get("evidence_refs"), now)
        if not fresh:
            continue
        out.append((measure, fresh))
    return out


def _input_with_projection(section, prefix, context, projection, scope, domain,
                           base_index, ceiling_index=None):
    """One matrix input, read at the higher of today's and the target scope's
    implied values. Unknown stays unknown either way."""
    value, rules, unknown = _derive_input(section, prefix, context, scope, domain,
                                          base_index, ceiling_index)
    relevant = {d: v for d, v in (projection or {}).items()
                if d in _relevant_dimensions(section, domain)}
    if not relevant or value == "unknown":
        return value, rules, unknown
    view = _with_projection(context, relevant)
    raised, raised_rules, _ = _derive_input(section, prefix, view, scope, domain,
                                            base_index, ceiling_index)
    if _index(section["scale"], raised) > _index(section["scale"], value):
        return raised, raised_rules + [
            "%s.scope_projection.%s=%s" % (prefix, dimension_id, projected)
            for dimension_id, projected in sorted(relevant.items())], unknown
    return value, rules, unknown


# --------------------------------------------------------------- derived prose

def _describe(context, dimension_id):
    value = ctx.field_value(context, dimension_id)
    if value is None:
        return "not established (%s)" % ctx.field_state(context, dimension_id)
    for entry in ctx.dimensions()[dimension_id]["values"]:
        if entry["id"] == value:
            return "%s (%s)" % (value, entry["description"].rstrip("."))
    return value


def _rule_rationales(section, rule_ids):
    by_id = {r["rule_id"]: r for r in section.get("adjustments") or []}
    return [by_id[rid]["rationale"] for rid in rule_ids if rid in by_id]


def _plausibility(context, scope, exposure_rules, measures):
    policy = load_policy()["exposure"]
    environment = ctx.resolve_environment(context, scope.get("environment"))
    parts = ["Exposure starts at %r for environment %r: %s"
             % (policy["base_by_environment"].get(environment, "unknown"),
                scope.get("environment"), policy["base_rationale"])]
    parts.extend(_rule_rationales(policy, exposure_rules))
    for measure, applied in measures:
        parts.append(
            "Compensating control %s (enforced by %s) %s"
            % (measure["compensating_control_id"], measure["enforced_by"],
               "lowers exposure by one step."
               if applied else
               "is in place but changes nothing here: exposure is already at "
               "the bottom of the scale, or another measure already took the "
               "one step a compensating control may take."))
    if any(rule.endswith(".cap.max_increase") or rule.endswith(".cap.max_decrease")
           for rule in exposure_rules):
        parts.append(policy["cap_rationale"])
    return " ".join(parts)


def _affected(context, control_id, domain):
    return ("%s. Data at stake: %s. Business criticality: %s. Risk domain: %s."
            % (title_of(control_id), _describe(context, "data_sensitivity"),
               _describe(context, "business_criticality"), domain))


def _blast_radius(context):
    return ("Audience reached: %s. Tenancy: %s. Privileged operations "
            "available: %s. Money movement: %s."
            % (_describe(context, "audience_scale"),
               _describe(context, "tenancy"),
               _describe(context, "privileged_operations"),
               _describe(context, "financial_operations")))


def _actor(context, domain, scope):
    if domain in ("security", "privacy"):
        return ("Anyone who can reach the application in this scope: %s, "
                "authentication %s."
                % (_describe(context, "network_exposure"),
                   _describe(context, "authentication")))
    if domain == "reliability":
        return "Normal operation and load in this scope; no attacker required."
    if domain == "financial":
        return ("Whoever can exercise the cost or payment path: %s."
                % _describe(context, "authentication"))
    return None


def _confidence(context, contributing, now):
    policy = load_policy()["confidence"]
    inferred = [d for d in contributing if ctx.field_state(context, d) == "inferred"]
    if ctx.is_expired(context, now) or len(inferred) >= policy["inferred_threshold_for_low"]:
        return "low"
    if inferred:
        return "medium"
    if ctx.confirmation_state(context, now) != "human_reviewed":
        # facts may each look solid, but nobody with authority has confirmed
        # the picture they add up to
        return policy["draft_context_cap"]
    return "high"


def _assumptions(context, assessment, contributing, now, horizon, projection):
    assumptions = []
    if horizon.get("kind") == "event_triggered":
        assumptions.append(
            "This scope is not the one the application is in today, so this "
            "level is a floor for the move to %s, not a measurement of it."
            % horizon.get("trigger", {}).get("value", "the new scope"))
        if projection:
            assumptions.append(
                "Entering that scope implies %s; the captured values are lower "
                "and the higher reading was used."
                % "; ".join("%s of at least %r" % (dimension_id, value)
                            for dimension_id, value in sorted(projection.items())))
    for dimension_id in contributing:
        if ctx.field_state(context, dimension_id) == "inferred":
            entry = (context.get("profile") or {})[dimension_id]
            assumptions.append(
                "%s = %s is inferred from %s, not confirmed by the owner."
                % (dimension_id, entry.get("value"), entry.get("source")))
    if ctx.field_value(context, "tenancy") == "multi_tenant_shared_store":
        assumptions.append(
            "Customers share one datastore, so a single authorization defect "
            "can cross tenants; context model v1 counts that blast radius "
            "through audience_scale only.")
    status = assessment.get("status")
    if status == "partial":
        assumptions.append(
            "Assessment %s is partial: the unmet aspect is treated as not met, "
            "which is what 'partial' says." % assessment.get("assessment_id"))
    if status == "risk_accepted":
        acceptance = assessment.get("acceptance") or {}
        assumptions.append(
            "The control is marked accepted risk by %s (review by %s). "
            "Acceptance records a decision; it does not remove the exposure."
            % (acceptance.get("accepted_by", "?"), acceptance.get("review_by", "?")))
    state = ctx.confirmation_state(context, now)
    if state != "human_reviewed":
        assumptions.append(
            "Context confirmation state is %r: these inputs have not been "
            "confirmed by a human with authority over the application." % state)
    return assumptions


# ---------------------------------------------------------------- derived risk

def _horizon(context, scope):
    if ctx.same_scope(scope, ctx.current_scope(context)):
        return {"kind": "current"}
    return {"kind": "event_triggered",
            "trigger": {"kind": "before_environment",
                        "value": scope.get("environment")}}


def _scope_slug(scope):
    return "%s.%s" % (scope.get("environment"), scope.get("intended_use"))


def risk_id(control_id, scope, horizon_kind, revision):
    return "rsk-%s-%s-%s-r%d" % (control_id.split("vibecheck.control.")[-1],
                                 _scope_slug(scope), horizon_kind, revision)


def _applied_compensating_controls(risk):
    return [measure for measure in
            ((risk.get("inputs") or {}).get("compensating_controls") or [])
            if measure.get("exposure_reduction_applied")]


def _freshness_evidence_refs(risk):
    """Every evidence record whose validity can change this stored level."""
    references = list(risk.get("evidence_refs") or [])
    for measure in _applied_compensating_controls(risk):
        references.extend(measure.get("evidence_refs") or [])
    references.extend((risk.get("downgrade") or {}).get("evidence_refs") or [])
    seen = set()
    return [ref for ref in references
            if not (ref in seen or seen.add(ref))]


def _reassess_by(envelope, context, risk):
    """Earliest expiry among everything this risk's level rests on.

    That includes the compensating controls that actually lowered the exposure:
    when the measure or its supporting evidence lapses, the level this risk
    records stops being the level the inputs would produce, so the deadline has
    to move with the earliest of them.
    """
    evidence = _evidence_index(envelope)
    instants = []
    for measure in _applied_compensating_controls(risk):
        measure_expiry = ctx.parse_instant(measure.get("valid_until"))
        if measure_expiry is not None:
            instants.append(measure_expiry)
    for ref in _freshness_evidence_refs(risk):
        instant = ctx.parse_instant((evidence.get(ref) or {}).get("valid_until"))
        if instant is not None:
            instants.append(instant)
    context_expiry = ctx.parse_instant(context.get("valid_until"))
    if context_expiry is not None:
        instants.append(context_expiry)
    return ctx.iso(min(instants)) if instants else None


def derive_risk(envelope, assessment, scope, now=None):
    """One derived contextual risk for one assessment in one scope."""
    now_dt = ctx.instant(now)
    context = envelope.get("context") or {}
    control_id = assessment.get("control_id")
    severity = severity_of(control_id)
    if severity is None:
        return None
    domain = domain_of(control_id)
    policy = load_policy()
    impact_policy, exposure_policy = policy["impact"], policy["exposure"]

    horizon = _horizon(context, scope)
    projection = (projected_profile(context, scope)
                  if horizon["kind"] == "event_triggered" else {})

    base_impact = _index(impact_policy["scale"],
                         impact_policy["base_by_severity"][severity])
    ceiling = _index(impact_policy["scale"],
                     impact_policy["ceiling_by_severity"][severity])
    impact, impact_rules, impact_unknown = _input_with_projection(
        impact_policy, "impact", context, projection, scope, domain,
        base_impact, ceiling)
    impact_rules = ["impact.base.severity.%s" % severity] + impact_rules

    environment = ctx.resolve_environment(context, scope.get("environment"))
    base_exposure = _index(exposure_policy["scale"],
                           exposure_policy["base_by_environment"].get(environment, ""))
    if base_exposure is None:
        exposure, exposure_rules, exposure_unknown = "unknown", [], [
            "environment (%s is not a resolvable standard environment)"
            % scope.get("environment")]
        measures = []
    else:
        exposure, exposure_rules, exposure_unknown = _input_with_projection(
            exposure_policy, "exposure", context, projection, scope, domain,
            base_exposure)
        exposure_rules = ["exposure.base.environment.%s" % environment] + exposure_rules
        measures = _applicable_measures(envelope, control_id, domain, scope, now_dt)

    compensating, applied_measures = [], []
    for measure, fresh_refs in measures:
        reduced = False
        if exposure != "unknown" and not any(
                c["exposure_reduction_applied"] for c in compensating):
            index = _index(exposure_policy["scale"], exposure)
            if index > 1:
                exposure = _value(exposure_policy["scale"],
                                  index - exposure_policy["compensating_control_reduction"])
                exposure_rules.append("exposure.compensating_control.%s"
                                      % measure["compensating_control_id"])
                reduced = True
        applied = {
            "compensating_control_id": measure["compensating_control_id"],
            "description": "%s (enforced by %s)" % (measure["description"],
                                                    measure["enforced_by"]),
            "evidence_refs": fresh_refs,
            "exposure_reduction_applied": reduced,
        }
        if measure.get("valid_until"):
            applied["valid_until"] = measure["valid_until"]
        compensating.append(applied)
        applied_measures.append((measure, reduced))

    contributing = sorted(set(_relevant_dimensions(impact_policy, domain))
                          | set(_relevant_dimensions(exposure_policy, domain)))
    evidence_refs = list((assessment.get("basis") or {}).get("evidence_refs") or [])
    revision = int(context.get("revision", 1))
    # the prose describes the same reading the numbers came from: for a scope
    # the application has not entered, that is the projected one
    view = _with_projection(context, projection)

    risk = {
        "risk_id": risk_id(control_id, scope, horizon["kind"], revision),
        "control_refs": [control_id],
        "domain": domain,
        "scope": {"environment": scope.get("environment"),
                  "intended_use": scope.get("intended_use")},
        "horizon": horizon,
        "method": {"name": "vibecheck.risk_matrix",
                   "version": canonical.load_matrix()["schema_version"]},
        "inputs": {
            "impact": impact,
            "exposure": exposure,
            "affected": _affected(view, control_id, domain),
            "plausibility_rationale": _plausibility(view, scope, exposure_rules,
                                                    applied_measures),
            "blast_radius": _blast_radius(view),
            "compensating_controls": compensating,
        },
        "level": level_for(impact, exposure),
        "confidence": _confidence(context, contributing, now_dt),
        "assumptions": _assumptions(context, assessment, contributing, now_dt,
                                    horizon, projection),
        "evidence_refs": evidence_refs,
        "assessed_at": ctx.iso(now_dt),
        "derivation": {
            "policy": {"name": POLICY_NAME, "version": policy["schema_version"]},
            "context_revision": revision,
            "rules_applied": impact_rules + exposure_rules,
        },
    }
    actor = _actor(view, domain, scope)
    if actor:
        risk["inputs"]["actor"] = actor
    unknown_inputs = (["impact:%s" % u for u in impact_unknown]
                      + ["exposure:%s" % u for u in exposure_unknown])
    if unknown_inputs:
        risk["derivation"]["unknown_inputs"] = unknown_inputs
    reassess_by = _reassess_by(envelope, context, risk)
    if reassess_by:
        risk["reassess_by"] = reassess_by
    triggers = [{"kind": "context_change"}]
    for target in ctx.more_exposed_scopes(context, scope):
        triggers.append({"kind": "before_environment",
                         "value": target.get("environment")})
    seen, unique = set(), []
    for trigger in triggers:
        key = (trigger["kind"], trigger.get("value"))
        if key not in seen:
            seen.add(key)
            unique.append(trigger)
    risk["reassess_triggers"] = unique
    return risk


def derive_risks(envelope, now=None):
    """Derived risks for every current fail/partial/accepted assessment, in
    every target scope, sorted by risk id for byte-stable output."""
    context = envelope.get("context") or {}
    scopes = context.get("target_scopes") or []
    derived = []
    for assessment in canonical.current_assessments(envelope):
        if assessment.get("status") in _NO_RISK_STATUSES:
            continue
        for scope in scopes:
            risk = derive_risk(envelope, assessment, scope, now)
            if risk is not None:
                derived.append(risk)
    return sorted(derived, key=lambda r: r["risk_id"])


#: Fields compared when deciding whether a re-derivation actually changed
#: anything. `assessed_at` is excluded on purpose: re-running the derivation at
#: a later clock time is not a change of substance. `reassess_by` is included,
#: because a renewed context or refreshed evidence moves the deadline and the
#: stored head would otherwise keep going stale on the old one. The context
#: revision is deliberately not part of substance: a revision that changes
#: nothing this risk reads should not churn its history.
_SUBSTANCE = ("control_refs", "domain", "scope", "horizon", "level",
              "inputs", "confidence", "assumptions", "evidence_refs",
              "reassess_by", "reassess_triggers")


def _substance(risk):
    body = {k: risk[k] for k in _SUBSTANCE if k in risk}
    body["rules_applied"] = (risk.get("derivation") or {}).get("rules_applied")
    body["unknown_inputs"] = (risk.get("derivation") or {}).get("unknown_inputs")
    return canonical.dumps(body)


def _derived_key(risk):
    return (tuple(risk.get("control_refs") or []),
            risk["scope"]["environment"], risk["scope"]["intended_use"],
            risk["horizon"]["kind"], risk["domain"])


def apply_risks(envelope, now=None):
    """Return a copy of the envelope with derived risks brought up to date.

    Hand-authored risks (no derivation record) are left alone. A derived risk
    whose substance is unchanged is kept as it is, so re-running the derivation
    is idempotent; a changed one is appended as a new object superseding the
    previous head, because risks are immutable and their history is the
    supersedes chain (RFC §3.2).
    """
    updated = copy.deepcopy(envelope)
    existing = list(updated.get("risks") or [])
    superseded = {r["supersedes"] for r in existing if r.get("supersedes")}
    heads = {}
    for risk in existing:
        if risk.get("derivation") and risk.get("risk_id") not in superseded:
            heads[_derived_key(risk)] = risk

    taken = {r.get("risk_id") for r in existing}
    for risk in derive_risks(updated, now):
        head = heads.get(_derived_key(risk))
        if head is None:
            existing.append(risk)
        elif _substance(head) != _substance(risk):
            if risk["risk_id"] in taken:
                # new evidence at the same context revision: the id would
                # collide, so it gets a suffix and the superseded record stays
                # readable next to it
                base, suffix = risk["risk_id"], 2
                while "%s.%d" % (base, suffix) in taken:
                    suffix += 1
                risk["risk_id"] = "%s.%d" % (base, suffix)
            risk["supersedes"] = head["risk_id"]
            taken.add(risk["risk_id"])
            existing.append(risk)
    updated["risks"] = existing
    return updated


# ------------------------------------------------------------------ freshness

def is_stale(risk, envelope, now=None):
    """True when a risk is past its own reassess_by, or rests on evidence that
    has expired (rule R15). Stale risks count as unknown for readiness.

    The evidence a risk rests on is not only the assessment's: a compensating
    control that lowered the exposure is holding the level down, so its support
    expiring makes the recorded level stale too, even when the assessment
    evidence is still good.
    """
    now_dt = ctx.instant(now)
    reassess_by = ctx.parse_instant(risk.get("reassess_by"))
    if reassess_by is not None and reassess_by < now_dt:
        return True
    evidence = _evidence_index(envelope)
    assessed_at = ctx.parse_instant(risk.get("assessed_at"))
    for ref in _freshness_evidence_refs(risk):
        item = evidence.get(ref)
        if item is None:
            return True
        observed_at = ctx.parse_instant(item.get("observed_at"))
        if (observed_at is None or assessed_at is None
                or observed_at > assessed_at):
            return True
        valid_until = ctx.parse_instant(item.get("valid_until"))
        if "valid_until" in item and (
                valid_until is None or valid_until < now_dt):
            return True
    for measure in _applied_compensating_controls(risk):
        valid_until = ctx.parse_instant(measure.get("valid_until"))
        if "valid_until" in measure and (
                valid_until is None or valid_until < now_dt):
            return True
    return False


def effective_level(risk, envelope, now=None):
    """The level readiness must use: the recorded one, or unknown when the risk
    has gone stale. Never low by default."""
    if is_stale(risk, envelope, now):
        return "unknown"
    return risk.get("level", "unknown")


def current_risks(envelope):
    """Risks not superseded by another one (heads of the chains)."""
    superseded = {r["supersedes"] for r in envelope.get("risks") or []
                  if r.get("supersedes")}
    return [r for r in envelope.get("risks") or []
            if r.get("risk_id") not in superseded]
