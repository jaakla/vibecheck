# -*- coding: utf-8 -*-
"""Verification provider registry, capability matching and safe selection
(RFC 0001 section 8).

A provider is a way of finding something out. It is never a way of deciding
something: it produces scoped Evidence, and an assessor reads it. That single
constraint is what the rest of this module protects.

  capability(provider_id)              what one provider can observe and costs
  requirement(control_id, environment) what this review needs observed
  offer(...)                           what the user has made available and
                                       actually authorized for this run
  select(requirement, offer)           a ranked, explainable plan
  explain(plan)                        the plan as prose, including refusals
  validate_providers(envelope)         rule R24

Selection prefers the strongest applicable method whose requirements the user
has accepted, and walks down the declared fallback order when it cannot have
it:

    Supabase two-account probe
      -> Playwright two-account flow
        -> guided browser test
          -> code / policy review

Two properties matter more than the ranking itself. The first is that nothing
disappears: a provider excluded because it needed a credential, a network
grant, a write, or money that was not offered is reported as a coverage gap
naming the exact grant that would have enabled it, never skipped in silence.
The second is that a plan is not a closure. Covering every requested cell means
the requirement was met; whether the control closes is decided by the coverage
model and the assessment rules against evidence that actually exists.

The registry itself — providers, ranking keys, constraint vocabulary, and the
prose that says why each rule exists — is reviewable data in
schema/provider-registry.v1.json. Stdlib only; imports authz for the coverage
vocabulary and controls for the static scanner's control list, and nothing from
canonical.py, because canonical imports this module.
"""
import copy
import json
import os

import authz as authz_mod
import controls as controls_mod

REGISTRY_NAME = "vibecheck.provider_registry"
REGISTRY_VERSION = "1.0.0"

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REGISTRY_PATH = os.path.join(REPO_ROOT, "schema", "provider-registry.v1.json")

#: Effects a provider may exercise. Each one requires an explicit grant in the
#: offer before a provider that exercises it can be selected; reading a local
#: working tree is deliberately not among them.
EFFECTS = ("network", "data_egress", "credentials", "write", "destructive",
           "deployment", "external_accounts", "metered_cost")

#: Side-effect booleans on a capability that map to a grant of the same name.
_SIDE_EFFECT_GRANTS = ("write", "destructive", "deployment", "external_accounts")

_REGISTRY = None


def load_registry():
    global _REGISTRY
    if _REGISTRY is None:
        with open(REGISTRY_PATH, encoding="utf-8") as fh:
            _REGISTRY = json.load(fh)
    return _REGISTRY


def registry_ref():
    return {"name": REGISTRY_NAME, "version": REGISTRY_VERSION}


def selection_policy():
    return load_registry()["selection"]


def constraint_kinds():
    return load_registry()["constraint_kinds"]


def effect_policy():
    return {key: value for key, value in load_registry()["effects"].items()
            if isinstance(value, dict)}


def operation_kinds():
    return {key: value["kind"]
            for key, value in load_registry()["operations"].items()
            if isinstance(value, dict)}


def live_operations():
    return tuple(sorted(op for op, kind in operation_kinds().items()
                        if kind == "live"))


def source_operations():
    return tuple(sorted(op for op, kind in operation_kinds().items()
                        if kind == "source"))


# ----------------------------------------------------------------- capabilities

def _expand_controls(controls_from):
    """Control IDs a coverage rule stands for, in registry order."""
    if controls_from == "all":
        return list(controls_mod.CONTROL_IDS[number]
                    for number in sorted(controls_mod.CONTROL_IDS))
    if controls_from == "scanner_checks":
        return controls_mod.scanner_covered_control_ids()
    if controls_from == "coverage_tracked":
        return sorted(authz_mod.requirements())
    raise ValueError("unknown coverage rule source %r" % (controls_from,))


def _expanded_coverage(record, control_ids=None):
    """coverage entries of a capability, with coverage_rules expanded.

    A rule such as ``controls_from: scanner_checks`` is how a bundled tool
    declares "every control I have a check for" without restating identical
    prose forty-three times, and it stays in step with the check map instead
    of drifting from it.
    """
    wanted = set(control_ids) if control_ids else None
    coverage = []
    for entry in record.get("coverage") or []:
        if wanted is None or entry.get("control_id") in wanted:
            coverage.append(copy.deepcopy(entry))
    for rule in record.get("coverage_rules") or []:
        expanded = _expand_controls(rule["controls_from"])
        for control_id in expanded:
            if wanted is not None and control_id not in wanted:
                continue
            entry = {key: copy.deepcopy(value) for key, value in rule.items()
                     if key != "controls_from"}
            entry["control_id"] = control_id
            entry["from_rule"] = rule["controls_from"]
            coverage.append(entry)
    return coverage


def capability(provider_id, control_ids=None):
    """The capability record for one provider, coverage rules expanded.

    ``control_ids`` narrows the coverage to the controls actually in play,
    which is what belongs in an envelope: the capability as exercised, not a
    catalogue of everything the provider could have been pointed at.
    """
    for record in load_registry()["providers"]:
        if record["provider_id"] == provider_id:
            expanded = copy.deepcopy(record)
            expanded.pop("coverage_rules", None)
            expanded["coverage"] = _expanded_coverage(record, control_ids)
            return expanded
    return None


def capabilities(control_ids=None):
    """Every bundled capability, in registry order."""
    return [capability(record["provider_id"], control_ids)
            for record in load_registry()["providers"]]


def instantiate(provider_id, control_ids=None, version=None,
                egress_destinations=None, network_targets=None):
    """A capability record ready to be attached to an envelope.

    The registry describes the destination of a run in prose ("the Supabase
    project URL supplied for the run") because it does not know the project.
    An envelope does, so the concrete destinations are filled in here rather
    than left as a description of a destination.
    """
    record = capability(provider_id, control_ids)
    if record is None:
        raise KeyError("no such provider: %r" % (provider_id,))
    if version:
        record["version"] = version
    if egress_destinations is not None:
        record.setdefault("data_egress", {})["destinations"] = \
            list(egress_destinations)
    if network_targets is not None:
        record.setdefault("network", {})["targets"] = list(network_targets)
    return record


def envelope_capabilities(envelope):
    """Capabilities an envelope declares, indexed by provider ID.

    An envelope is self-contained: what a provider could do is recorded with
    the evidence it produced, so a result stays readable years later even if
    the bundled registry has moved on.
    """
    return {record["provider_id"]: record
            for record in envelope.get("providers") or []
            if record.get("provider_id")}


def evidence_provider_block(provider_id, version=None):
    """The ``provider`` block that belongs on evidence from this provider."""
    record = capability(provider_id, control_ids=[])
    if record is None:
        raise KeyError("no such provider: %r" % (provider_id,))
    block = {"name": record["name"], "provider_ref": provider_id}
    resolved = version or record.get("version")
    if resolved:
        block["version"] = str(resolved)
    return block


def provider_max_strength(record, control_id):
    strengths = [entry.get("max_strength") for entry in record.get("coverage") or []
                 if entry.get("control_id") == control_id]
    if "decisive" in strengths:
        return "decisive"
    if "indicative" in strengths:
        return "indicative"
    return None


def entry_fills_coverage_cell(entry):
    """Whether one coverage entry's observation fills an authorization cell.

    An explicit ``fills_coverage_cell`` wins, because a live method can still
    be unable to settle a cell — a browser flow observes the routes somebody
    wrote assertions for, which is not a statement about default-deny. When the
    key is absent, the answer is derived: only a live operation on a
    coverage-tracked control fills a cell, and an operation the registry does
    not recognize is not a live one.
    """
    if "fills_coverage_cell" in entry:
        return bool(entry["fills_coverage_cell"])
    kinds = operation_kinds()
    operations = entry.get("operations") or []
    return (bool(operations)
            and all(kinds.get(operation) == "live" for operation in operations)
            and authz_mod.is_tracked_control(entry.get("control_id")))


def fills_coverage_cell(record, control_id):
    return any(entry_fills_coverage_cell(entry)
               for entry in record.get("coverage") or []
               if entry.get("control_id") == control_id)


def acts_on_a_live_system(record):
    """Whether running this provider does something to somebody's deployment.

    Reading the working tree the review was already pointed at is not acting
    in an environment, so a scoped authorization has nothing to say about it.
    Anything that needs permission, leaves the machine, or has an effect
    beyond reading is acting somewhere specific, and *where* is exactly what
    an authorization grants.
    """
    if (record.get("authorization") or {}).get("required"):
        return True
    if (record.get("network") or {}).get("outbound"):
        return True
    side_effects = record.get("side_effects") or {}
    return any(side_effects.get(name) for name in _SIDE_EFFECT_GRANTS)


# ---------------------------------------------------------------- requirements

def requirement(control_id, environment, cells=None, subjects=None,
                reason=None):
    """What this review needs observed.

    Cells are (object_class, actor, operation) triples in one environment —
    the same unit scripts/authz.py counts — so a requirement is always
    operation- and subject-specific rather than "check authorization".
    """
    return {
        "control_id": control_id,
        "environment": environment,
        "cells": [_normalize_cell(cell) for cell in cells or []],
        "subjects": list(subjects or []),
        "reason": reason or "",
    }


def _normalize_cell(cell):
    normalized = {
        "object_class": cell.get("object_class") or "unclassified",
        "actor": cell.get("actor"),
        "operation": cell.get("operation"),
    }
    for key in ("object_id", "object_ref"):
        if cell.get(key):
            normalized[key] = cell[key]
    return normalized


def cell_key(cell):
    return (cell.get("object_ref") or cell.get("object_id") or "",
            cell.get("object_class") or "unclassified",
            cell.get("actor") or "", cell.get("operation") or "")


def requirement_from_coverage(envelope, control_id, environment, now=None):
    """The still-uncovered cells of a coverage-tracked control, as a
    requirement. The coverage matrix reports the still-uncovered gaps;
    selection picks the provider that can close them."""
    state = authz_mod.coverage_state(envelope, control_id, environment, now)
    return requirement(
        control_id, environment,
        cells=state.get("gaps") or [],
        reason="coverage is %s for %s in %s: %d of %d required cell(s) observed"
               % (state.get("state"), control_id, environment,
                  state.get("satisfied_count", 0),
                  state.get("required_count", 0)))


# ----------------------------------------------------------------------- offer

def offer(environment=None, targets=None, tools=None, inputs=None,
          authorized_providers=None, authorized_effects=None,
          accepted_monetary=None, accepted_compute=None,
          accepted_egress_destinations=None, executors=None,
          unmet_prerequisites=None):
    """What is available for this run, and what has actually been authorized.

    The defaults are the safe posture and not a convenience: nothing is
    authorized, no credentials have been handed over, no money may be spent,
    and no request leaves the machine. Under that offer the only selectable
    providers are the ones that read what the review was already pointed at,
    and everything stronger appears as a gap with the grant that would open it.
    """
    return {
        "environment": environment,
        "targets": set(targets or []),
        "tools": set(tools or []),
        "inputs": set(inputs or []),
        "authorized_providers": (authorized_providers
                                 if authorized_providers == "all"
                                 else set(authorized_providers or [])),
        "authorized_effects": set(authorized_effects or []),
        "accepted_monetary": set(accepted_monetary or ["none"]),
        "accepted_compute": set(accepted_compute or ["low", "moderate"]),
        "accepted_egress_destinations": (accepted_egress_destinations
                                         if accepted_egress_destinations == "any"
                                         else set(accepted_egress_destinations)
                                         if accepted_egress_destinations is not None
                                         else None),
        "executors": set(executors or ["automation", "founder", "developer"]),
        "unmet_prerequisites": set(unmet_prerequisites or []),
    }


def _grants(off, provider_id):
    authorized = off.get("authorized_providers")
    return authorized == "all" or provider_id in authorized


# ------------------------------------------------------------------ evaluation

def _constraint(kind, detail, grant=None):
    spec = constraint_kinds().get(kind, {})
    record = {
        "kind": kind,
        "detail": detail,
        "resolvable_by": spec.get("resolvable_by", "never"),
        "records_coverage_gap": bool(spec.get("records_coverage_gap")),
        "applicability": bool(spec.get("applicability")),
    }
    if grant:
        record["grant"] = grant
    return record


def _required_inputs(record, control_id):
    """Inputs and fixtures this provider needs for this control."""
    needed = []
    for spec in record.get("required_inputs") or []:
        scope = spec.get("required_for")
        if scope and control_id not in scope:
            continue
        needed.append(spec)
    return needed


def _entry_effects(entry, record):
    """Effects running this coverage entry would exercise."""
    effects = set(entry.get("requires_effects") or [])
    if (record.get("network") or {}).get("outbound"):
        effects.add("network")
    if (record.get("data_egress") or {}).get("occurs"):
        effects.add("data_egress")
    side_effects = record.get("side_effects") or {}
    for name in _SIDE_EFFECT_GRANTS:
        if side_effects.get(name):
            effects.add(name)
    if record.get("required_inputs"):
        if any(spec.get("secret") for spec in record["required_inputs"]):
            effects.add("credentials")
    if (record.get("cost") or {}).get("monetary") not in ("none", None):
        effects.add("metered_cost")
    return effects


def _cell_matches(entry, cell):
    spec = entry.get("cells") or {}
    return (cell.get("actor") in (spec.get("actors") or [])
            and cell.get("operation") in (spec.get("operations") or [])
            and (cell.get("object_class") or "unclassified")
            in (spec.get("object_classes") or []))


def evaluate(record, req, off):
    """Whether one provider can serve one requirement under one offer.

    Returns applicability, eligibility, the requested cells it could actually
    observe, the cells it could observe with more authorization, and every
    constraint that stood in the way. Nothing is dropped: a constraint the
    user could resolve is the material the explanation is built from.
    """
    provider_id = record.get("provider_id")
    control_id = req["control_id"]
    result = {
        "provider_id": provider_id,
        "name": record.get("name", provider_id),
        "fallback_order": record.get("fallback_order", 99),
        "executor_role": record.get("executor_role", "automation"),
        "max_strength": provider_max_strength(record, control_id),
        "fills_coverage_cell": fills_coverage_cell(record, control_id),
        "applicable": True,
        "eligible": True,
        "covers_cells": [],
        "blocked_cells": [],
        "constraints": [],
        "operations": [],
        "closure_thresholds": [],
        "effects": [],
    }

    entries = [entry for entry in record.get("coverage") or []
               if entry.get("control_id") == control_id]
    if not entries:
        result["constraints"].append(_constraint(
            "control_not_covered",
            "%s makes no claim about %s." % (result["name"], control_id)))
        result["applicable"] = False
        result["eligible"] = False
        return result

    if req.get("subjects"):
        declared = set()
        for entry in entries:
            declared.update(entry.get("subjects") or [])
        if declared and not declared & set(req["subjects"]):
            result["constraints"].append(_constraint(
                "subject_not_covered",
                "%s observes %s, and this requirement is about %s."
                % (result["name"], ", ".join(sorted(declared)),
                   ", ".join(sorted(req["subjects"])))))
            result["applicable"] = False

    missing_targets = [target for target in record.get("required_targets") or []
                       if target not in off["targets"]]
    if missing_targets:
        result["constraints"].append(_constraint(
            "target_unavailable",
            "%s observes %s, which this review does not have."
            % (result["name"], ", ".join(missing_targets))))
        result["applicable"] = False

    environment = req.get("environment")
    if environment and environment not in (record.get("environments") or []):
        result["constraints"].append(_constraint(
            "environment_unsupported",
            "%s produces observations about %s, not about %s, and an "
            "observation never travels between environments."
            % (result["name"], ", ".join(record.get("environments") or ["nothing"]),
               environment)))
        result["eligible"] = False

    offer_environment = off.get("environment")
    if (offer_environment and environment and offer_environment != environment
            and acts_on_a_live_system(record)):
        result["constraints"].append(_constraint(
            "authorization_scope_mismatch",
            "this run is authorized for %s and the requirement is about %s; "
            "the grant does not stretch, and an observation made in %s would "
            "not answer the question anyway."
            % (offer_environment, environment, offer_environment),
            grant="authorize %s for %s" % (provider_id, environment)))
        result["eligible"] = False

    availability = record.get("availability") or {}
    if not availability.get("bundled"):
        missing_tools = [tool for tool in availability.get("requires_tools") or []
                         if tool not in off["tools"]]
        if missing_tools:
            result["constraints"].append(_constraint(
                "tool_unavailable",
                "%s is not bundled and needs %s, which is not installed here."
                % (result["name"], ", ".join(missing_tools)),
                grant="install " + ", ".join(missing_tools)))
            result["eligible"] = False

    if result["executor_role"] not in off["executors"]:
        result["constraints"].append(_constraint(
            "executor_unavailable",
            "%s has to be run by %s, and no %s is available for this review."
            % (result["name"], result["executor_role"], result["executor_role"])))
        result["eligible"] = False

    needed_inputs = _required_inputs(record, control_id)
    missing_secret = [spec["id"] for spec in needed_inputs
                      if spec.get("secret") and spec["id"] not in off["inputs"]]
    missing_plain = [spec["id"] for spec in needed_inputs
                     if not spec.get("secret") and spec["id"] not in off["inputs"]]
    if missing_secret:
        result["constraints"].append(_constraint(
            "credentials_missing",
            "%s needs %s, which has not been supplied."
            % (result["name"], ", ".join(missing_secret)),
            grant="supply " + ", ".join(missing_secret)))
        result["eligible"] = False
    if missing_plain:
        result["constraints"].append(_constraint(
            "input_missing",
            "%s needs %s, which has not been supplied."
            % (result["name"], ", ".join(missing_plain)),
            grant="supply " + ", ".join(missing_plain)))
        result["eligible"] = False

    unmet = [text for text in record.get("prerequisites") or []
             if text in off["unmet_prerequisites"]]
    if unmet:
        result["constraints"].append(_constraint(
            "prerequisite_unmet",
            "%s requires: %s" % (result["name"], " ".join(unmet))))
        result["eligible"] = False

    if (record.get("authorization") or {}).get("required") \
            and not _grants(off, provider_id):
        result["constraints"].append(_constraint(
            "authorization_not_granted",
            "%s declares that it requires authorization, and this run was not "
            "authorized to use it." % result["name"],
            grant="authorize %s" % provider_id))
        result["eligible"] = False

    cost = record.get("cost") or {}
    if cost.get("monetary") not in off["accepted_monetary"]:
        result["constraints"].append(_constraint(
            "cost_not_accepted",
            "%s has %s monetary cost and only %s was accepted."
            % (result["name"], cost.get("monetary", "unknown"),
               ", ".join(sorted(off["accepted_monetary"]))),
            grant="accept %s monetary cost" % cost.get("monetary", "unknown")))
        result["eligible"] = False
    if cost.get("compute") not in off["accepted_compute"]:
        result["constraints"].append(_constraint(
            "cost_not_accepted",
            "%s has %s compute cost and only %s was accepted."
            % (result["name"], cost.get("compute", "unknown"),
               ", ".join(sorted(off["accepted_compute"]))),
            grant="accept %s compute cost" % cost.get("compute", "unknown")))
        result["eligible"] = False

    network = record.get("network") or {}
    if network.get("outbound") and "network" not in off["authorized_effects"]:
        result["constraints"].append(_constraint(
            "network_not_accepted",
            "%s reaches %s and network access was not authorized."
            % (result["name"],
               ", ".join(network.get("targets") or ["the network"])),
            grant="authorize network access"))
        result["eligible"] = False

    egress = record.get("data_egress") or {}
    if egress.get("occurs"):
        if "data_egress" not in off["authorized_effects"]:
            result["constraints"].append(_constraint(
                "data_egress_not_accepted",
                "%s sends data to %s and data egress was not authorized."
                % (result["name"],
                   ", ".join(egress.get("destinations") or ["an external host"])),
                grant="authorize data egress"))
            result["eligible"] = False
        else:
            accepted = off.get("accepted_egress_destinations")
            if accepted is not None and accepted != "any":
                # Destinations match exactly. A hostname that merely starts
                # with an approved one is a different host.
                unapproved = [destination
                              for destination in egress.get("destinations") or []
                              if destination not in accepted]
                if unapproved:
                    result["constraints"].append(_constraint(
                        "data_egress_not_accepted",
                        "%s sends data to %s, which is not among the accepted "
                        "destinations." % (result["name"],
                                           ", ".join(unapproved)),
                        grant="accept " + ", ".join(unapproved)))
                    result["eligible"] = False

    side_effects = record.get("side_effects") or {}
    for name in _SIDE_EFFECT_GRANTS:
        if side_effects.get(name) and name not in off["authorized_effects"]:
            result["constraints"].append(_constraint(
                "side_effect_not_authorized",
                "%s always exercises a %s effect and that was not authorized."
                % (result["name"], name),
                grant="authorize %s" % name))
            result["eligible"] = False

    if not result["applicable"]:
        result["eligible"] = False

    # Per-entry: an entry may need effects the provider does not exercise by
    # default. The opt-in write probe is the case this exists for: the same
    # provider covers reads under a read-only offer and creates only under an
    # explicit write grant.
    covered, blocked, operations, thresholds, effects = [], [], [], [], set()
    for entry in entries:
        entry_effects = _entry_effects(entry, record)
        ungranted = sorted(effect for effect in entry_effects
                           if effect_policy().get(effect, {}).get(
                               "requires_authorization")
                           and effect not in off["authorized_effects"]
                           and not (effect == "credentials"
                                    and not missing_secret)
                           and not (effect == "metered_cost"
                                    and cost.get("monetary")
                                    in off["accepted_monetary"]))
        entry_cells = [cell for cell in req["cells"] if _cell_matches(entry, cell)]
        if ungranted:
            for cell in entry_cells:
                blocked.append({
                    "cell": cell,
                    "constraints": [_constraint(
                        "side_effect_not_authorized",
                        "observing this cell needs %s, which was not authorized."
                        % ", ".join(ungranted),
                        grant="authorize " + ", ".join(ungranted))],
                })
            continue
        if not result["eligible"]:
            continue
        effects.update(entry_effects)
        operations.extend(entry.get("operations") or [])
        if entry.get("closure_threshold"):
            thresholds.append(entry["closure_threshold"])
        covered.extend(entry_cells)

    seen = set()
    result["covers_cells"] = [cell for cell in covered
                              if not (cell_key(cell) in seen
                                      or seen.add(cell_key(cell)))]
    result["blocked_cells"] = blocked
    result["operations"] = sorted(set(operations))
    result["closure_thresholds"] = thresholds
    result["effects"] = sorted(effects)
    return result


def rank_key(evaluation):
    """The total order from the registry's rank_keys, as a sort key."""
    strength_rank = selection_policy()["strength_rank"]
    return (
        0 if evaluation["fills_coverage_cell"] else 1,
        -strength_rank.get(evaluation["max_strength"] or "", 0),
        evaluation["fallback_order"],
        evaluation["provider_id"],
    )


# -------------------------------------------------------------------- selection

def select(req, off, records=None):
    """A ranked, explainable plan for one requirement.

    Walks the ranking once, adding a provider while it still contributes a
    requested cell nothing earlier in the plan covers. When cells remain (or
    the requirement names none), the strongest eligible provider that produces
    material without closing anything is added as the last resort, so the plan
    is never empty while a reviewer with the source exists.
    """
    records = records if records is not None else capabilities()
    evaluations = sorted((evaluate(record, req, off) for record in records),
                         key=rank_key)

    plan, gaps = [], []
    remaining = {cell_key(cell): cell for cell in req["cells"]}

    if req["cells"]:
        for evaluation in evaluations:
            if not evaluation["eligible"] or not evaluation["fills_coverage_cell"]:
                continue
            contributes = [cell for cell in evaluation["covers_cells"]
                           if cell_key(cell) in remaining]
            if not contributes:
                continue
            for cell in contributes:
                remaining.pop(cell_key(cell), None)
            plan.append(_plan_step(evaluation, "observes_cells", contributes))
            if not remaining:
                break
        if remaining:
            for evaluation in evaluations:
                if not evaluation["eligible"] or evaluation["fills_coverage_cell"]:
                    continue
                plan.append(_plan_step(evaluation, "material_only", []))
                break
    else:
        # No cells named. Either the control is not coverage-tracked, or nobody
        # has said what this application's private objects are — and an empty
        # requirement is not a satisfied one. Name the best available method and
        # report the coverage as unestablished rather than as met.
        for evaluation in evaluations:
            if not evaluation["eligible"]:
                continue
            plan.append(_plan_step(
                evaluation,
                "observes_cells" if evaluation["fills_coverage_cell"]
                else "material_only", []))
            break

    selected_ids = {step["provider_id"] for step in plan}
    for evaluation in evaluations:
        if evaluation["provider_id"] in selected_ids:
            gaps.extend(_blocked_cell_gaps(evaluation))
            continue
        gaps.extend(_provider_gap(evaluation))
        gaps.extend(_blocked_cell_gaps(evaluation))

    uncovered = [remaining[key] for key in sorted(remaining)]
    return {
        "requirement": req,
        "registry": registry_ref(),
        "ranking": [_ranked_summary(evaluation) for evaluation in evaluations],
        "plan": plan,
        "selected": [step["provider_id"] for step in plan],
        "coverage": {
            "requested_cells": len(req["cells"]),
            "covered_cells": len(req["cells"]) - len(uncovered),
            "uncovered_cells": uncovered,
            "requested_cells_covered": bool(req["cells"]) and not uncovered,
            "cells_unestablished": not req["cells"],
            "closes_control": False,
            "closure_note": selection_policy()["closure_rule"],
        },
        "gaps": gaps,
        "authorization_requests": authorization_requests(plan, gaps),
    }


def _plan_step(evaluation, role, contributes):
    return {
        "provider_id": evaluation["provider_id"],
        "name": evaluation["name"],
        "role": role,
        "executor_role": evaluation["executor_role"],
        "operations": evaluation["operations"],
        "strength": evaluation["max_strength"],
        "covers_cells": contributes,
        "effects": evaluation["effects"],
        "closure_thresholds": evaluation["closure_thresholds"],
        "note": ("Produces material for a human decision and closes nothing; "
                 "it fills no coverage cell."
                 if role == "material_only" else
                 "Observes the listed cells in this environment only."),
    }


def _ranked_summary(evaluation):
    return {
        "provider_id": evaluation["provider_id"],
        "name": evaluation["name"],
        "rank_key": list(rank_key(evaluation)),
        "applicable": evaluation["applicable"],
        "eligible": evaluation["eligible"],
        "max_strength": evaluation["max_strength"],
        "fills_coverage_cell": evaluation["fills_coverage_cell"],
        "constraints": evaluation["constraints"],
    }


def _provider_gap(evaluation):
    if not evaluation["applicable"]:
        # Nothing was withheld: the provider observes something this
        # application does not have. That is not a gap in the review.
        return []
    reported = [constraint for constraint in evaluation["constraints"]
                if constraint["records_coverage_gap"]]
    if not reported:
        return []
    return [{
        "kind": "provider_excluded",
        "provider_id": evaluation["provider_id"],
        "name": evaluation["name"],
        "max_strength": evaluation["max_strength"],
        "fills_coverage_cell": evaluation["fills_coverage_cell"],
        "constraints": reported,
        "resolvable_by": sorted({constraint["resolvable_by"]
                                 for constraint in reported}),
    }]


def _blocked_cell_gaps(evaluation):
    if not evaluation["blocked_cells"] or not evaluation["eligible"]:
        # A provider that could not run at all is already reported as an
        # excluded provider; saying it could also cover more cells if only it
        # were authorized to write would be offering something untrue.
        return []
    return [{
        "kind": "cells_need_authorization",
        "provider_id": evaluation["provider_id"],
        "name": evaluation["name"],
        "cells": [blocked["cell"] for blocked in evaluation["blocked_cells"]],
        "constraints": evaluation["blocked_cells"][0]["constraints"],
        "resolvable_by": ["user_authorization"],
    }]


def authorization_requests(plan, gaps):
    """The exact grants this plan needs, and the ones that would strengthen it.

    A step that exercises an effect requiring authorization is a request, not
    an instruction: it names the provider, the effects, and what running it
    would touch, and the run may not start until that request is granted.
    """
    policy = effect_policy()
    requests = []
    for step in plan:
        needed = [effect for effect in step["effects"]
                  if policy.get(effect, {}).get("requires_authorization")]
        if not needed:
            continue
        requests.append({
            "reason": "required_to_run",
            "provider_id": step["provider_id"],
            "effects": needed,
            "prompt_en": "%s must be %s before this step runs."
                         % (step["name"],
                            "; ".join(policy[effect]["prompt_en"]
                                      for effect in needed)),
        })
    for gap in gaps:
        grants = sorted({constraint["grant"]
                         for constraint in gap.get("constraints") or []
                         if constraint.get("grant")})
        if not grants:
            continue
        requests.append({
            "reason": "would_strengthen_the_plan",
            "provider_id": gap["provider_id"],
            "grants": grants,
            "prompt_en": "%s is available but unused: %s."
                         % (gap["name"], "; ".join(grants)),
        })
    return requests


def explain(plan):
    """The plan as prose: what was chosen, what it is worth, and what was
    refused. Every ranked provider gets a line, so a stronger method that was
    excluded is visible next to the weaker one that replaced it."""
    lines = []
    requirement_ = plan["requirement"]
    lines.append("Requirement: %s in %s, %d cell(s)."
                 % (requirement_["control_id"], requirement_["environment"],
                    len(requirement_["cells"])))
    selected = set(plan["selected"])
    for entry in plan["ranking"]:
        if entry["provider_id"] in selected:
            step = next(step for step in plan["plan"]
                        if step["provider_id"] == entry["provider_id"])
            lines.append("SELECTED  %s — %s; %s"
                         % (entry["name"], entry["max_strength"] or "no claim",
                            "covers %d requested cell(s)"
                            % len(step["covers_cells"])
                            if step["covers_cells"] else
                            "material only, fills no coverage cell and closes "
                            "nothing"))
        elif not entry["applicable"]:
            lines.append("n/a       %s — %s"
                         % (entry["name"],
                            _first_detail(entry) or "not applicable here"))
        elif not entry["eligible"]:
            lines.append("EXCLUDED  %s — %s"
                         % (entry["name"], _first_detail(entry)))
        else:
            lines.append(
                "unused    %s — eligible, but a provider already in the plan "
                "covers everything it would have" % entry["name"])
    coverage = plan["coverage"]
    if coverage["cells_unestablished"]:
        lines.append("Coverage: the requirement names no cells, so coverage is "
                     "unestablished — a gap, never a met requirement.")
    else:
        lines.append("Coverage: %d of %d requested cell(s); this plan closes no "
                     "control."
                     % (coverage["covered_cells"], coverage["requested_cells"]))
    for gap in plan["gaps"]:
        if gap["kind"] == "cells_need_authorization":
            lines.append("GAP       %s could observe %d more cell(s): %s"
                         % (gap["name"], len(gap["cells"]),
                            gap["constraints"][0]["detail"]))
    for cell in coverage["uncovered_cells"]:
        lines.append("GAP       no available provider observes %s / %s / %s"
                     % (cell.get("object_class"), cell.get("actor"),
                        cell.get("operation")))
    return lines


def _first_detail(entry):
    for constraint in entry["constraints"]:
        return constraint["detail"]
    return ""


# ----------------------------------------------------------------- validation

def _resolve_capability(index, provider_ref):
    """The capability a provider_ref names: the envelope's own record first,
    the bundled registry only as a fallback. Resolved lazily, because
    expanding every bundled coverage rule to check one reference is work
    nobody asked for."""
    if provider_ref in index:
        return index[provider_ref]
    index[provider_ref] = capability(provider_ref)
    return index[provider_ref]


def _coverage_entries(record, control_id):
    return [entry for entry in record.get("coverage") or []
            if entry.get("control_id") == control_id]


def validate_providers(envelope):
    """Rule R24: provider evidence stays inside the declared capability.

    A capability record is a promise about what a provider can find out. This
    checks that the evidence in the envelope keeps it — the operation it used,
    the environment it observed, the strength it claimed, the coverage cells it
    filled, and the effects it had. The most important half is the last two:
    an observation that fills a coverage cell has to come from a provider whose
    capability says it can make one, which is how a source reading is refused a
    cell structurally rather than by remembering to check the operation name.
    """
    problems = []
    index = dict(envelope_capabilities(envelope))
    source_ops = set(source_operations())

    for record in envelope.get("providers") or []:
        problems.extend(_validate_capability(record, source_ops))

    for item in envelope.get("evidence") or []:
        provider = item.get("provider") or {}
        provider_ref = provider.get("provider_ref")
        if not provider_ref:
            continue
        evidence_id = item.get("evidence_id")
        record = _resolve_capability(index, provider_ref)
        if record is None:
            problems.append(
                "R24 %s: provider_ref %s resolves to no capability record"
                % (evidence_id, provider_ref))
            continue

        environments = record.get("environments") or []
        if environments and item.get("environment") not in environments:
            problems.append(
                "R24 %s: %s produces observations about %s, not %s"
                % (evidence_id, provider_ref, "/".join(environments),
                   item.get("environment")))

        control_ids = ((item.get("claim") or {}).get("control_ids")) or []
        operation = item.get("operation")
        for control_id in control_ids:
            entries = _coverage_entries(record, control_id)
            if not entries:
                problems.append(
                    "R24 %s: %s declares no coverage of %s but the evidence "
                    "claims it" % (evidence_id, provider_ref, control_id))
                continue
            # Per control, never pooled across them. An anonymous read is a
            # claim about anonymous access; adding object-level authorization
            # to the same record does not make the same request cover it, and
            # a union would let one covered control vouch for the rest.
            declared_ops = set()
            for entry in entries:
                declared_ops.update(entry.get("operations") or [])
            if declared_ops and operation not in declared_ops:
                problems.append(
                    "R24 %s: %s does not declare operation %r for %s"
                    % (evidence_id, provider_ref, operation, control_id))
            max_strength = provider_max_strength(record, control_id)
            if item.get("strength") == "decisive" and max_strength != "decisive":
                problems.append(
                    "R24 %s: %s can be at most %s about %s, and the evidence "
                    "claims decisive"
                    % (evidence_id, provider_ref, max_strength, control_id))

        problems.extend(_validate_coverage_cells(item, record, provider_ref,
                                                 control_ids))

        problems.extend(_validate_effects(item, record, provider_ref))

    return problems


def _validate_coverage_cells(item, record, provider_ref, control_ids):
    """A cell has to be one the capability says this provider can observe.

    The operation check above asks how the observation was made; this asks
    what it was an observation *of*. A provider that reads a table with the
    public key did not thereby watch a second account try to delete a row,
    and a capability that never claimed the actor cannot carry a cell naming
    it.
    """
    cells = item.get("coverage")
    if not cells:
        return []
    evidence_id = item.get("evidence_id")
    entries = [entry for control_id in control_ids
               for entry in _coverage_entries(record, control_id)
               if entry_fills_coverage_cell(entry)]
    if not entries:
        return ["R24 %s: %s fills no coverage cell for %s, so its observation "
                "cannot carry one"
                % (evidence_id, provider_ref,
                   ", ".join(control_ids) or "this claim")]

    described = [entry for entry in entries if entry.get("cells")]
    if not described:
        # A capability from before cells were declared. It says it can fill
        # one and does not say which; there is nothing to check it against.
        return []

    problems = []
    for cell in cells:
        if any(_cell_matches(entry, cell) for entry in described):
            continue
        problems.append(
            "R24 %s: %s does not declare that it can observe %s / %s, so its "
            "observation cannot carry that cell"
            % (evidence_id, provider_ref, cell.get("actor"),
               cell.get("operation")))
    return problems


def _opt_in_effects(record):
    """Effects a run of this provider may be opted into.

    ``requires_effects`` on a coverage entry is the precise statement, and the
    same one selection gates cells on. ``opt_in_flags`` on its own unlocks
    writing and nothing further: a flag that turns on an insert probe is not
    consent to remove data that was there before the review started, and
    reading it as if it were is how a read-only tool ends up excused for a
    delete it never declared.
    """
    effects = set()
    for entry in record.get("coverage") or []:
        effects.update(entry.get("requires_effects") or [])
    if (record.get("side_effects") or {}).get("opt_in_flags"):
        effects.add("write")
    return effects


def _validate_effects(item, record, provider_ref):
    problems = []
    evidence_id = item.get("evidence_id")
    observed = item.get("side_effects") or {}
    declared = record.get("side_effects") or {}
    opt_in = _opt_in_effects(record)
    for observed_key, declared_key in (("writes", "write"),
                                       ("destructive", "destructive"),
                                       ("external_accounts", "external_accounts")):
        if not observed.get(observed_key):
            continue
        if declared.get(declared_key) or declared_key in opt_in:
            continue
        problems.append(
            "R24 %s: %s declares no %s effect, and the evidence records one"
            % (evidence_id, provider_ref, declared_key))
    if observed.get("data_egress") and not (record.get("data_egress")
                                            or {}).get("occurs"):
        problems.append(
            "R24 %s: %s declares no data egress, and the evidence records it"
            % (evidence_id, provider_ref))
    return problems


def _validate_capability(record, source_ops):
    """Internal consistency of one capability record."""
    problems = []
    provider_id = record.get("provider_id", "?")
    tracked = set(authz_mod.requirements())
    for entry in record.get("coverage") or []:
        control_id = entry.get("control_id")
        if not entry.get("closure_threshold"):
            problems.append(
                "R24 %s: coverage of %s states no closure threshold, so what "
                "it would take to close the aspect is unstated"
                % (provider_id, control_id))
        if entry_fills_coverage_cell(entry):
            offending = sorted(set(entry.get("operations") or []) & source_ops)
            if offending:
                problems.append(
                    "R24 %s: %s is a source operation and can never fill a "
                    "coverage cell" % (provider_id, ", ".join(offending)))
            if control_id not in tracked:
                problems.append(
                    "R24 %s: %s is not a coverage-tracked control, so no "
                    "observation of it fills a cell" % (provider_id, control_id))
        elif (entry.get("max_strength") == "decisive"
              and control_id in tracked):
            problems.append(
                "R24 %s: coverage of %s is decisive but fills no cell; a "
                "coverage-tracked control can only be settled cell by cell"
                % (provider_id, control_id))
    return problems


# ----------------------------------------------------------------------- CLI

def _cli(argv=None):
    import argparse
    parser = argparse.ArgumentParser(
        description="Inspect the vibecheck verification provider registry.")
    parser.add_argument("--list", action="store_true",
                        help="list providers in fallback order")
    parser.add_argument("--capability", metavar="PROVIDER_ID",
                        help="print one capability record as JSON")
    parser.add_argument("--select", metavar="CONTROL_ID",
                        help="explain provider selection for one control")
    parser.add_argument("--environment", default="private_test")
    parser.add_argument("--target", action="append", default=[],
                        dest="targets")
    parser.add_argument("--input", action="append", default=[], dest="inputs",
                        help="ID of a required input or credential that is "
                             "available (values are never passed here)")
    parser.add_argument("--tool", action="append", default=[], dest="tools",
                        help="a tool that is installed on this machine")
    parser.add_argument("--authorize", action="append", default=[],
                        dest="authorized",
                        help="provider ID authorized for this run")
    parser.add_argument("--allow-effect", action="append", default=[],
                        dest="effects", help="one of: " + ", ".join(EFFECTS))
    args = parser.parse_args(argv)

    if args.capability:
        record = capability(args.capability)
        if record is None:
            parser.error("no such provider: %s" % args.capability)
        print(json.dumps(record, indent=2, ensure_ascii=False, sort_keys=True))
        return 0
    if args.select:
        plan = select(requirement(args.select, args.environment),
                      offer(environment=args.environment,
                            targets=args.targets or ["source_tree"],
                            tools=args.tools,
                            inputs=args.inputs,
                            authorized_providers=args.authorized,
                            authorized_effects=args.effects))
        print("\n".join(explain(plan)))
        return 0
    for record in sorted(load_registry()["providers"],
                         key=lambda item: item.get("fallback_order", 99)):
        print("%-2s %-30s %-11s %s"
              % (record.get("fallback_order", "?"), record["provider_id"],
                 record.get("executor_role", ""), record.get("summary_en", "")))
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli())
