# -*- coding: utf-8 -*-
"""Authorization coverage semantics (gh issue #7, Increment 5).

An authorization observation is small. A probe that reads one row of one table
as one actor establishes exactly that: one (object, actor, operation) cell in
one environment. The control it belongs to — "users cannot reach records they
don't own", "nothing is readable by an anonymous caller" — is a statement about
every private object type and every operation, so it can only close when the
whole required matrix has been observed.

This module keeps the two apart:

  required_cells(env, control_id)         what this application must observe
  observed_cells(env, environment, now)   what current evidence actually saw
  coverage_state(env, control_id, env_)   closed / partial / open / unestablished
  intended_exposures(env, environment)    confirmed public writes and their bounds
  validate_coverage(env)                  R20, R22 and R23 problems
  materialize_coverage_actions(env)       verify, decide and remediate Actions
  cells_from_probe_finding(finding)       supabase_probe.py output -> cells

The requirement comes from the representative private objects the context
declares (``context.authorization_objects``). With no inventory the coverage is
*unestablished*, which is a gap and never a closure: an empty requirement set is
not a met one.

Some writes are meant to be anonymous — a contact form, a booking request. The
tool never decides that: an undeclared write becomes a decide Action for the
owner, and only a confirmed `intended_operations` entry turns the cell from a
violation into an exception. Confirming it does not make it free. An
unauthenticated write is reachable by automation, so the exception carries
required bounds — the same actor must not be able to read the object back, and
the write path must be bounded by an enforced mechanism (throttle, bot-defence
challenge, or a review gate). An unbounded intended exposure keeps the control
open exactly like an unintended one (rule R23).

The model — object classes, actors, operations, requirement sets, the closure
rule and the legacy probe-verdict mapping — is reviewable data in
schema/authz-coverage.v1.json. Stdlib only, and it imports nothing from
canonical.py: canonical imports this module, not the other way round.
"""
import copy
import json
import os
import re

import context as ctx

MODEL_NAME = "vibecheck.authz_coverage"
MODEL_VERSION = "1.1.0"

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(REPO_ROOT, "schema", "authz-coverage.v1.json")

#: An observation of one of these never fills a cell: it is a signal about the
#: source tree, not about the deployment (closure.static_analysis_rule).
STATIC_OPERATIONS = ("static_pattern_scan", "code_review_of_diff",
                     "migration_analysis", "policy_source_review",
                     "git_history_scan", "dependency_audit",
                     "sast_code_scan")

_MODEL = None


def load_model():
    global _MODEL
    if _MODEL is None:
        with open(MODEL_PATH, encoding="utf-8") as fh:
            _MODEL = json.load(fh)
    return _MODEL


def model_ref():
    return {"name": MODEL_NAME, "version": MODEL_VERSION}


def requirements():
    return {entry["control_id"]: entry for entry in load_model()["requirements"]}


def requirement_for(control_id):
    return requirements().get(control_id)


def is_tracked_control(control_id):
    return control_id in requirements()


# ------------------------------------------------------------------ inventory

def inventory(envelope):
    """The representative objects the context declares, in a stable order."""
    context = envelope.get("context") or {}
    records = [obj for obj in context.get("authorization_objects") or []
               if isinstance(obj, dict)]
    return sorted(records, key=lambda obj: str(obj.get("object_id", "")))


def _locator_key(value):
    return re.sub(r"\s+", "", str(value or "")).casefold()


def _locator_keys(value):
    """Equivalent inventory keys for one object locator.

    PostgREST exposes tables from its default ``public`` schema as bare names
    (``orders``), while the inventory deliberately uses database-qualified
    names (``public.orders``). Those two spellings identify the same object.
    No other schema prefix is stripped: ``private.orders`` must not be confused
    with the public table of the same name.
    """
    key = _locator_key(value)
    keys = {key} if key else set()
    if key.startswith("public.") and key.count(".") == 1:
        keys.add(key[len("public."):])
    elif key and not any(separator in key for separator in (".", ":", "/")):
        keys.add("public." + key)
    return sorted(keys)


def _inventory_by_locator(envelope):
    resolved, ambiguous = {}, set()
    for obj in inventory(envelope):
        for key in _locator_keys(obj.get("locator")):
            previous = resolved.get(key)
            if previous is not None and previous.get("object_id") != obj.get("object_id"):
                ambiguous.add(key)
            else:
                resolved[key] = obj
    # Refuse to guess when two inventory entries claim equivalent locators.
    for key in ambiguous:
        resolved.pop(key, None)
    return resolved


def inventory_object_for_locator(envelope, locator):
    """Resolve a probe/object locator to one unambiguous inventory record."""
    by_locator = _inventory_by_locator(envelope)
    matches = {id(by_locator[key]): by_locator[key]
               for key in _locator_keys(locator) if key in by_locator}
    return next(iter(matches.values())) if len(matches) == 1 else None


def _effective_intent(obj):
    """Only a confirmed decision may exclude an object from the requirement."""
    intent = obj.get("intent")
    if intent == "intended_public" and obj.get("state") != "confirmed":
        return "unknown"
    return intent or "unknown"


# --------------------------------------------------------------- observations

def _current(record, at):
    observed = ctx.parse_instant(record.get("observed_at"))
    if observed is None or at is None or observed > at:
        return False
    if "valid_until" not in record:
        return True
    valid_until = ctx.parse_instant(record.get("valid_until"))
    return valid_until is not None and valid_until >= at


def coverage_evidence(envelope):
    """Evidence records that carry at least one coverage cell."""
    return [item for item in envelope.get("evidence") or []
            if isinstance(item, dict) and item.get("coverage")]


def cell_key(cell):
    return (str(cell.get("object_id") or cell.get("object_ref") or "?"),
            str(cell.get("actor") or "?"),
            str(cell.get("operation") or "?"))


def _cell_matches_claim(item, cell):
    """Whether a cell's actor/operation fits a control named by its evidence."""
    for control_id in (item.get("claim") or {}).get("control_ids") or []:
        requirement = requirement_for(control_id)
        if requirement is None:
            continue
        if (cell.get("actor") not in requirement["actors"]
                or cell.get("operation") not in requirement["operations"]):
            continue
        return True
    return False


def observed_cells(envelope, environment=None, now=None):
    """Current observations, keyed by cell, resolved against the inventory.

    The most recent observation for a cell wins, and an ``allowed`` observation
    wins a tie: a violation is only cleared by a later denial, never by a
    simultaneous one.
    """
    at = ctx.instant(now)
    by_locator = _inventory_by_locator(envelope)
    best = {}
    for item in coverage_evidence(envelope):
        if not _current(item, at):
            continue
        for cell in item.get("coverage") or []:
            if not isinstance(cell, dict) or not cell.get("observed"):
                continue
            if not _cell_matches_claim(item, cell):
                continue
            evidence_environment = item.get("environment")
            if (cell.get("environment") is not None
                    and cell.get("environment") != evidence_environment):
                # The evidence record is authoritative about where the
                # observation happened. Validation reports the contradiction;
                # derivation refuses to credit either spelling.
                continue
            cell_environment = evidence_environment
            if environment is not None and cell_environment != environment:
                continue
            resolved = dict(cell)
            resolved["environment"] = cell_environment
            resolved["evidence_ref"] = item.get("evidence_id")
            resolved["observed_at"] = item.get("observed_at")
            known = by_locator.get(_locator_key(cell.get("object_ref")))
            if known is not None:
                if cell.get("object_class") not in (
                        None, "unclassified", known.get("object_class")):
                    # The observation and the inventory disagree about what this
                    # object is. Validation reports it (R20); the derivation
                    # refuses to credit it either way rather than picking one.
                    continue
                resolved.setdefault("object_id", known.get("object_id"))
                resolved["inventory_class"] = known.get("object_class")
            key = cell_key(resolved)
            previous = best.get(key)
            if previous is None or _wins(resolved, previous):
                best[key] = resolved
    return best


def _wins(candidate, incumbent):
    later = ctx.parse_instant(candidate.get("observed_at"))
    earlier = ctx.parse_instant(incumbent.get("observed_at"))
    if later is not None and earlier is not None and later != earlier:
        return later > earlier
    return (candidate.get("observed") == "allowed"
            and incumbent.get("observed") != "allowed")


# ---------------------------------------------------------------- requirement

def required_cells(envelope, control_id):
    """The cells this application must observe for one control.

    Objects whose intent is unknown are included: an object nobody has decided
    about cannot be excluded, because that would resolve unknown toward the
    benign answer (closure.intent_rule).
    """
    requirement = requirement_for(control_id)
    if requirement is None:
        return {}
    classes = set(requirement["object_classes"])
    cells = {}
    for obj in inventory(envelope):
        if obj.get("object_class") not in classes:
            continue
        if _effective_intent(obj) == "intended_public":
            continue
        for actor in requirement["actors"]:
            for operation in requirement["operations"]:
                cell = {
                    "object_id": obj.get("object_id"),
                    "object_class": obj.get("object_class"),
                    "object_ref": obj.get("locator"),
                    "actor": actor,
                    "operation": operation,
                }
                cells[cell_key(cell)] = cell
    return cells


def intended_operation(obj, actor, operation):
    """The confirmed exception for one cell of one object, or None.

    An entry that is inferred, conflicting or unknown is not a decision: it
    leaves the cell a required denial, because guessing that an exposure was
    deliberate is the mistake this model exists to prevent.
    """
    for entry in (obj or {}).get("intended_operations") or []:
        if not isinstance(entry, dict):
            continue
        if (entry.get("actor") == actor and entry.get("operation") == operation
                and entry.get("state") == "confirmed"):
            return entry
    return None


def declared_operation(obj, actor, operation):
    """Any exception entry for a cell, confirmed or not."""
    for entry in (obj or {}).get("intended_operations") or []:
        if (isinstance(entry, dict) and entry.get("actor") == actor
                and entry.get("operation") == operation):
            return entry
    return None


def coverage_state(envelope, control_id, environment, now=None):
    """How far one control's required matrix is observed in one environment.

    An `allowed` observation on a cell the owner confirmed as intended is
    recorded separately, as an exposure by design rather than a violation. It
    still has to be bounded: see intended_exposures().
    """
    required = required_cells(envelope, control_id)
    observed = observed_cells(envelope, environment, now)
    by_id = {obj.get("object_id"): obj for obj in inventory(envelope)}
    satisfied, gaps, violations, by_design = [], [], [], []
    for key in sorted(required):
        cell = dict(required[key])
        seen = observed.get(key)
        if seen is None:
            cell["reason"] = "not_tested"
            gaps.append(cell)
            continue
        cell["evidence_ref"] = seen.get("evidence_ref")
        if seen.get("observed") == "denied":
            satisfied.append(cell)
        elif seen.get("observed") == "allowed":
            exception = intended_operation(
                by_id.get(cell.get("object_id")), cell["actor"], cell["operation"])
            if exception is not None:
                cell["intended"] = True
                cell["intent_rationale"] = exception.get("rationale")
                by_design.append(cell)
            else:
                cell["reason"] = "observed_allowed"
                gaps.append(cell)
                violations.append(cell)
        else:
            cell["reason"] = "inconclusive"
            gaps.append(cell)

    if not required:
        state = "unestablished"
    elif not gaps:
        state = "closed"
    elif satisfied or by_design:
        state = "partial"
    else:
        state = "open"
    return {
        "model": model_ref(),
        "control_id": control_id,
        "environment": environment,
        "state": state,
        "required_count": len(required),
        "satisfied_count": len(satisfied) + len(by_design),
        "satisfied": satisfied,
        "intended": by_design,
        "gaps": gaps,
        "violations": violations,
        "extra_observations": sorted(
            key for key in observed if key not in required),
    }


# --------------------------------------------------------- intended exposures

def _exposure_policy():
    return load_model().get("intended_exposure") or {}


def _current_assessment_status(envelope, control_id):
    for assessment in _current_assessments(envelope):
        if assessment.get("control_id") == control_id:
            return assessment.get("status")
    return None


def _safeguard_state(envelope, safeguard, cell, observed, expected_statuses):
    """(met, detail) for one required bound on one intended exposure."""
    if safeguard.get("kind") == "coverage_cell":
        paired = dict(cell)
        paired["operation"] = safeguard.get("operation", "read")
        seen = observed.get(cell_key(paired))
        state = (seen or {}).get("observed") or "not_tested"
        return state == safeguard.get("expect", "denied"), (
            "the same actor's %s of %s is %s"
            % (paired["operation"], cell.get("object_ref") or cell.get("object_id"),
               state))
    control_id = safeguard.get("control_id")
    status = _current_assessment_status(envelope, control_id)
    allowed = safeguard.get("expect_status") or expected_statuses
    return status in allowed, "%s is %s" % (
        control_id, status or "not assessed")


def intended_exposures(envelope, environment, now=None):
    """Confirmed exceptions in one environment, with the state of their bounds.

    Confirming that a public form may insert records is a statement about
    intent, not about safety: the path is reachable by automation, so the
    exception is only as good as the bound on it.
    """
    policy = _exposure_policy()
    observed = observed_cells(envelope, environment, now)
    expected = policy.get("expect_status") or ["pass"]
    exposures = []
    for obj in inventory(envelope):
        for entry in obj.get("intended_operations") or []:
            if not isinstance(entry, dict):
                continue
            cell = {
                "object_id": obj.get("object_id"),
                "object_class": obj.get("object_class"),
                "object_ref": obj.get("locator"),
                "actor": entry.get("actor"),
                "operation": entry.get("operation"),
            }
            seen = observed.get(cell_key(cell))
            safeguards = []
            for safeguard in policy.get("required_safeguards") or []:
                met, detail = _safeguard_state(
                    envelope, safeguard, cell, observed, expected)
                safeguards.append({"id": safeguard.get("id"), "required": True,
                                   "met": met, "detail": detail,
                                   "mechanisms": safeguard.get("mechanisms") or []})
            for safeguard in policy.get("recommended_safeguards") or []:
                met, detail = _safeguard_state(
                    envelope, safeguard, cell, observed, expected)
                safeguards.append({"id": safeguard.get("id"), "required": False,
                                   "met": met, "detail": detail})
            exposures.append({
                "object_id": cell["object_id"],
                "object_ref": cell["object_ref"],
                "actor": cell["actor"],
                "operation": cell["operation"],
                "environment": environment,
                "confirmed": entry.get("state") == "confirmed",
                "state": entry.get("state"),
                "rationale": entry.get("rationale"),
                "source": entry.get("source"),
                "observed": (seen or {}).get("observed") or "not_tested",
                "safeguards": safeguards,
                "unmet_required": [item["id"] for item in safeguards
                                   if item["required"] and not item["met"]],
            })
    return exposures


def unbounded_exposures(envelope, environment, now=None):
    """Confirmed exposures whose required bounds are not in place."""
    return [exposure for exposure in intended_exposures(envelope, environment, now)
            if exposure["confirmed"] and exposure["unmet_required"]]


def undeclared_exposures(envelope, environment, now=None):
    """Observed writes nobody has decided about, per control.

    These are the ones that need a founder's yes or no. Read operations are
    excluded: an anonymous read that is meant to be public is an object-level
    intent decision (intended_public), not a per-operation exception.
    """
    writes = ("create", "update", "delete")
    by_id = {obj.get("object_id"): obj for obj in inventory(envelope)}
    found = []
    for control_id in tracked_controls(envelope):
        if _current_assessment_status(envelope, control_id) in (
                "fail", "risk_accepted"):
            # Someone already judged this behaviour: a fail is a decision that
            # the requirement is not met, and an accepted risk is a decision to
            # live with it. Neither needs the tool to ask whether it was meant.
            continue
        state = coverage_state(envelope, control_id, environment, now)
        for cell in state["violations"]:
            if cell.get("operation") not in writes:
                continue
            entry = declared_operation(
                by_id.get(cell.get("object_id")), cell["actor"], cell["operation"])
            found.append({
                "control_id": control_id,
                "object_id": cell.get("object_id"),
                "object_ref": cell.get("object_ref"),
                "actor": cell["actor"],
                "operation": cell["operation"],
                "environment": environment,
                "evidence_ref": cell.get("evidence_ref"),
                "declared_state": (entry or {}).get("state"),
            })
    return found


def tracked_controls(envelope):
    """Controls this envelope actually tracks coverage for.

    A control enters the coverage model when something observed a cell for it
    or when an assessment rested on such an observation. Controls nobody has
    probed stay outside it: the point is to stop one observation from closing a
    control, not to demand a matrix from a review that never ran a probe.
    """
    tracked = set()
    for item in coverage_evidence(envelope):
        for control_id in (item.get("claim") or {}).get("control_ids") or []:
            if is_tracked_control(control_id):
                tracked.add(control_id)
    return sorted(tracked)


def coverage_gaps(envelope, environment, now=None):
    """{control_id: state} for every tracked control with anything missing."""
    states = {}
    for control_id in tracked_controls(envelope):
        state = coverage_state(envelope, control_id, environment, now)
        if state["state"] != "closed":
            states[control_id] = state
    return states


def _exposure_control(envelope, exposure):
    """Which tracked control an intended exposure belongs to.

    The actor and the object class decide it, exactly as they decide which
    required cells exist: an anonymous insert is the anon-access control's
    business, a cross-account one the object-level control's.
    """
    by_id = {obj.get("object_id"): obj for obj in inventory(envelope)}
    object_class = (by_id.get(exposure.get("object_id")) or {}).get("object_class")
    for control_id, requirement in sorted(requirements().items()):
        if (exposure.get("actor") in requirement["actors"]
                and exposure.get("operation") in requirement["operations"]
                and object_class in requirement["object_classes"]):
            return control_id
    return None


# ----------------------------------------------------------------- validation

def _current_assessments(envelope):
    items = envelope.get("assessments") or []
    superseded = {item.get("supersedes") for item in items
                  if item.get("supersedes")}
    return [item for item in items
            if item.get("assessment_id") not in superseded]


def _validate_inventory(envelope, problems):
    model = load_model()
    seen, locators = set(), {}
    for index, obj in enumerate(inventory(envelope)):
        where = obj.get("object_id") or "context.authorization_objects[%d]" % index
        if not obj.get("object_id"):
            problems.append("R20: %s has no object_id" % where)
        elif obj["object_id"] in seen:
            problems.append("R20: duplicate authorization object %s" % obj["object_id"])
        else:
            seen.add(obj["object_id"])
        if obj.get("object_class") not in model["object_classes"]:
            problems.append(
                "R20: authorization object %s has class %r, which is not in "
                "coverage model %s %s"
                % (where, obj.get("object_class"), MODEL_NAME, MODEL_VERSION))
        if obj.get("intent") not in ("private", "intended_public", "unknown"):
            problems.append(
                "R20: authorization object %s has intent %r; expected private, "
                "intended_public or unknown" % (where, obj.get("intent")))
        if obj.get("state") not in ctx.FIELD_STATES:
            problems.append(
                "R20: authorization object %s has state %r, expected one of %s"
                % (where, obj.get("state"), ", ".join(ctx.FIELD_STATES)))
        elif obj["state"] in ("confirmed", "inferred") and not obj.get("source"):
            problems.append(
                "R20: authorization object %s is %s but names no source"
                % (where, obj["state"]))
        if obj.get("intent") == "intended_public" and obj.get("state") != "confirmed":
            problems.append(
                "R20: authorization object %s is excluded from coverage as "
                "intended_public without a confirmed decision; unknown intent "
                "may not be resolved toward the benign answer" % where)
        if not obj.get("locator"):
            problems.append("R20: authorization object %s has no locator" % where)
        for locator in _locator_keys(obj.get("locator")):
            previous = locators.get(locator)
            if previous is not None and previous != obj.get("object_id"):
                problems.append(
                    "R20: authorization objects %s and %s have equivalent "
                    "locators; a probe result could not be assigned safely"
                    % (previous, obj.get("object_id")))
            else:
                locators[locator] = obj.get("object_id")


def _validate_cells(envelope, problems):
    model = load_model()
    by_locator = _inventory_by_locator(envelope)
    for item in coverage_evidence(envelope):
        evidence_id = item.get("evidence_id", "<missing id>")
        cells = item.get("coverage") or []
        if item.get("operation") in STATIC_OPERATIONS:
            problems.append(
                "R20: evidence %s records coverage cells for the static "
                "operation %r; static analysis is a signal about the source, "
                "never an observation of a live authorization path"
                % (evidence_id, item.get("operation")))
        for index, cell in enumerate(cells):
            where = "%s.coverage[%d]" % (evidence_id, index)
            if not isinstance(cell, dict):
                problems.append("R20: %s is not a coverage cell object" % where)
                continue
            if cell.get("actor") not in model["actors"]:
                problems.append("R20: %s has unknown actor %r"
                                % (where, cell.get("actor")))
            if cell.get("operation") not in model["operations"]:
                problems.append("R20: %s has unknown operation %r"
                                % (where, cell.get("operation")))
            if cell.get("observed") not in model["observations"]:
                problems.append("R20: %s has unknown observation %r"
                                % (where, cell.get("observed")))
            if cell.get("object_class") not in model["object_classes"]:
                problems.append("R20: %s has unknown object class %r"
                                % (where, cell.get("object_class")))
            if (cell.get("environment") is not None
                    and cell.get("environment") != item.get("environment")):
                problems.append(
                    "R20: %s says environment %r while its evidence record says "
                    "%r; a coverage cell cannot move an observation between "
                    "environments"
                    % (where, cell.get("environment"), item.get("environment")))
            if not _cell_matches_claim(item, cell):
                problems.append(
                    "R20: %s actor/operation does not fit any tracked "
                    "control named by the evidence claim"
                    % where)
            known = by_locator.get(_locator_key(cell.get("object_ref")))
            if (known is not None and cell.get("object_class")
                    not in (None, "unclassified", known.get("object_class"))):
                problems.append(
                    "R20: %s calls %s a %s while the context inventory "
                    "classifies it as %s"
                    % (where, cell.get("object_ref"), cell.get("object_class"),
                       known.get("object_class")))

        observations = {cell.get("observed") for cell in cells
                        if isinstance(cell, dict)}
        direction = item.get("direction")
        allowed_cells = [cell for cell in cells
                         if isinstance(cell, dict)
                         and cell.get("observed") == "allowed"]
        # An intended exposure is the one allowed observation that does not
        # refute the control: the requirement itself says "unless intended
        # public". It still may not *support* the claim, because what makes the
        # requirement met there is the bound on the path, not the path working.
        unintended = [cell for cell in allowed_cells
                      if intended_operation(
                          by_locator.get(_locator_key(cell.get("object_ref"))),
                          cell.get("actor"), cell.get("operation")) is None]
        if unintended and direction != "refutes":
            problems.append(
                "R20: evidence %s observed an actor reaching a private object "
                "but its direction is %r; an allowed observation refutes the "
                "claim that the control requirement is met"
                % (evidence_id, direction))
        if allowed_cells and not unintended and direction == "supports":
            problems.append(
                "R23: evidence %s reads an intended exposure as supporting the "
                "control; observing that a public write path works says nothing "
                "about whether anything bounds it" % evidence_id)
        if observations == {"inconclusive"} and direction == "supports":
            problems.append(
                "R20: evidence %s supports the claim on nothing but "
                "inconclusive observations; an unproven key, an empty table or "
                "a failed request is not a denial" % evidence_id)
        if observations == {"denied"} and direction == "refutes":
            problems.append(
                "R20: evidence %s observed every cell denied but records "
                "direction refutes" % evidence_id)


def _validate_exposures(envelope, problems):
    """R23: an intended exposure is a recorded decision, and it is bounded."""
    model = load_model()
    for obj in inventory(envelope):
        where = obj.get("object_id") or "authorization object"
        for index, entry in enumerate(obj.get("intended_operations") or []):
            label = "%s.intended_operations[%d]" % (where, index)
            if not isinstance(entry, dict):
                problems.append("R23: %s is not an exception record" % label)
                continue
            if entry.get("actor") not in model["actors"]:
                problems.append("R23: %s has unknown actor %r"
                                % (label, entry.get("actor")))
            if entry.get("operation") not in model["operations"]:
                problems.append("R23: %s has unknown operation %r"
                                % (label, entry.get("operation")))
            if entry.get("state") != "confirmed":
                problems.append(
                    "R23: %s records intent as %r; only a confirmed decision "
                    "makes an exposure intended, and an inferred one leaves the "
                    "cell a required denial with an open question"
                    % (label, entry.get("state")))
                continue
            for field in ("source", "rationale"):
                if not entry.get(field):
                    problems.append(
                        "R23: %s is confirmed but records no %s; a decision "
                        "nobody owns is not one" % (label, field))


def _validate_pass_coverage(envelope, problems):
    """R20: coverage-backed pass needs the whole matrix, not the easy cell."""
    evidence = {item.get("evidence_id"): item
                for item in envelope.get("evidence") or []}
    for assessment in _current_assessments(envelope):
        if assessment.get("status") != "pass":
            continue
        control_id = assessment.get("control_id")
        if not is_tracked_control(control_id):
            continue
        cited = [evidence[ref] for ref
                 in (assessment.get("basis") or {}).get("evidence_refs") or []
                 if ref in evidence and evidence[ref].get("coverage")]
        if not cited:
            continue
        for environment in sorted({item.get("environment") for item in cited}):
            state = coverage_state(envelope, control_id, environment,
                                   assessment.get("assessed_at"))
            unbounded = [exposure for exposure
                         in unbounded_exposures(envelope, environment,
                                                assessment.get("assessed_at"))
                         if _exposure_control(envelope, exposure) == control_id]
            for exposure in unbounded:
                problems.append(
                    "R23: %s reads pass on %s while the intended %s %s of %s is "
                    "unbounded (%s). Confirming that a public write is wanted "
                    "does not bound the automation that will use it"
                    % (assessment.get("assessment_id", "<missing id>"), control_id,
                       exposure["actor"], exposure["operation"],
                       exposure["object_ref"] or exposure["object_id"],
                       "; ".join(item["detail"] for item in exposure["safeguards"]
                                 if item["required"] and not item["met"])))
            if state["state"] == "closed":
                continue
            problems.append(
                "R20: %s reads pass on %s from live authorization "
                "observations while coverage in %s is %s (%d of %d required "
                "cells observed denied; missing %s). One observation covers "
                "one object, actor and operation, never the control"
                % (assessment.get("assessment_id", "<missing id>"), control_id,
                   environment, state["state"], state["satisfied_count"],
                   state["required_count"],
                   ", ".join("%s/%s/%s (%s)"
                             % (gap["object_id"], gap["actor"],
                                gap["operation"], gap["reason"])
                             for gap in state["gaps"][:6]) or "nothing"))


def _validate_write_records(envelope, problems):
    """R22: anything that wrote records consent, environment, result, cleanup."""
    for item in envelope.get("evidence") or []:
        side_effects = item.get("side_effects") or {}
        if not (side_effects.get("writes") or side_effects.get("destructive")):
            continue
        evidence_id = item.get("evidence_id", "<missing id>")
        if not item.get("authorization"):
            problems.append(
                "R22: evidence %s records a write with no authorization record; "
                "a data-writing probe is opt-in per run" % evidence_id)
        if not item.get("environment"):
            problems.append(
                "R22: evidence %s records a write without naming the target "
                "environment" % evidence_id)
        if not side_effects.get("details"):
            problems.append(
                "R22: evidence %s records a write without stating what it "
                "created and how it is cleaned up" % evidence_id)

    procedures = {item.get("procedure_id"): item
                  for item in envelope.get("procedures") or []}
    for attempt in envelope.get("attempts") or []:
        observed = attempt.get("side_effects_observed") or {}
        if not (observed.get("data") or observed.get("destructive")):
            continue
        attempt_id = attempt.get("attempt_id", "<missing id>")
        authorization = attempt.get("authorization") or {}
        if not authorization.get("record"):
            problems.append(
                "R22: attempt %s changed live data without a consent record"
                % attempt_id)
        if not attempt.get("execution_environment"):
            problems.append(
                "R22: attempt %s changed live data without naming the target "
                "environment" % attempt_id)
        if not attempt.get("result"):
            problems.append(
                "R22: attempt %s changed live data without recording a result"
                % attempt_id)
        rollback = attempt.get("rollback") or {}
        if not rollback.get("state"):
            problems.append(
                "R22: attempt %s changed live data without a cleanup or "
                "rollback state" % attempt_id)
        elif rollback["state"] == "not_needed" and not rollback.get("notes"):
            problems.append(
                "R22: attempt %s says cleanup was not needed after changing "
                "live data but does not say why" % attempt_id)
        procedure = procedures.get(attempt.get("procedure_ref")) or {}
        consent = (procedure.get("authorization") or {}).get("consent")
        if consent == "not_required":
            problems.append(
                "R22: attempt %s changed live data under a procedure that "
                "requires no consent; data-writing probes stay opt-in"
                % attempt_id)


def _version_tuple(value):
    try:
        return tuple(int(part) for part in str(value).split("."))
    except (TypeError, ValueError):
        return (0,)


def _validate_model_ref(envelope, problems):
    """The named coverage model must be readable by this build.

    Minor versions of the model are additive, exactly like the envelope schema
    (RFC §3.1): a 1.0 document has no intended-exposure records, and checking it
    under 1.1 is strictly better than refusing to check it. A different major
    version means the vocabulary moved, and then the cells cannot be read at all.
    """
    named = envelope.get("coverage_model")
    if named is not None and (
            named.get("name") != MODEL_NAME
            or _version_tuple(named.get("version"))[:1]
            != _version_tuple(MODEL_VERSION)[:1]):
        problems.append(
            "R20: coverage cells resolve against coverage model %s %s, which "
            "this build cannot read (has %s %s)"
            % (named.get("name"), named.get("version"), MODEL_NAME, MODEL_VERSION))
        return False
    if named is None and (coverage_evidence(envelope) or inventory(envelope)) and (
            _version_tuple(envelope.get("schema_version")) >= (1, 4, 0)):
        problems.append(
            "R20: an envelope carrying authorization coverage must name the "
            "coverage model it resolves against (%s %s)"
            % (MODEL_NAME, MODEL_VERSION))
    return True


def validate_coverage(envelope):
    """Return authorization-coverage problems (R20, R22) for an envelope."""
    problems = []
    if not _validate_model_ref(envelope, problems):
        return problems
    _validate_inventory(envelope, problems)
    _validate_cells(envelope, problems)
    _validate_exposures(envelope, problems)
    _validate_pass_coverage(envelope, problems)
    _validate_write_records(envelope, problems)
    return problems


# ------------------------------------------------------------ derived actions

def _slug(value):
    return re.sub(r"[^a-z0-9]+", "-", str(value or "").casefold()).strip("-")


def materialize_coverage_actions(envelope, now=None, environment=None):
    """One open verify Action per uncovered (object, actor) group.

    A gap that only lives in a coverage report is a gap nobody scheduled. The
    Action states exactly which operations are untested for which object and
    actor; it carries no blocking scope of its own, because what an untested
    authorization path means for a scope is the readiness derivation's call.
    """
    updated = copy.deepcopy(envelope)
    policy = load_model()["coverage_actions"]
    now_text = ctx.iso(ctx.instant(now))
    if environment is None:
        environment = (ctx.current_scope(updated.get("context") or {})
                       or {}).get("environment")
    actions = updated.setdefault("actions", [])
    taken = {key: {action.get(key) for action in actions}
             for key in ("action_id", "action_key")}

    def add(action_id, action_key, action):
        if action_id in taken["action_id"] or action_key in taken["action_key"]:
            return
        taken["action_id"].add(action_id)
        taken["action_key"].add(action_key)
        actions.append(action)

    exposure_policy = _exposure_policy()

    # An observed write nobody decided about is a question for the owner, not a
    # verdict from the tool: it is either the product working or a hole.
    decide = exposure_policy.get("decide_action") or {}
    for exposure in undeclared_exposures(updated, environment, now):
        suffix = "%s-%s-%s" % (_slug(exposure["object_id"]),
                               _slug(exposure["actor"]), exposure["operation"])
        add("%s-%s" % (decide["id_prefix"], suffix),
            "%s-%s" % (decide["id_prefix"].removeprefix("act-"), suffix), {
                "action_id": "%s-%s" % (decide["id_prefix"], suffix),
                "action_key": "%s-%s" % (
                    decide["id_prefix"].removeprefix("act-"), suffix),
                "revision": 1,
                "created_at": now_text,
                "kind": decide["kind"],
                "outcome": (
                    "A recorded decision, with its reason, on whether %s %s of "
                    "%s is meant to be possible — and if it is, the bounds it "
                    "runs under."
                    % (exposure["actor"], exposure["operation"],
                       exposure["object_ref"] or exposure["object_id"])),
                "reason": (
                    "An authorized test observed %s %s of %s in %s. That is "
                    "either the product working (a public form has to accept "
                    "submissions) or an open door, and only the owner knows "
                    "which. Until it is decided, it counts as open."
                    % (exposure["actor"], exposure["operation"],
                       exposure["object_ref"] or exposure["object_id"],
                       exposure["environment"])),
                "priority": "high",
                "urgency": decide["urgency"],
                "deadline": {
                    "kind": "unknown",
                    "rationale": ("The decision gates whether this path needs "
                                  "denying or bounding; both are work."),
                    "reassess_trigger": {"kind": "context_change"},
                },
                "blocking_scope": [],
                "owner": {"role": decide["owner_role"]},
                "state": "open",
                "state_history": [{"state": "open", "at": now_text,
                                   "by": "vibecheck authorization coverage"}],
                "control_refs": [exposure["control_id"]],
                **({"evidence_refs": [exposure["evidence_ref"]]}
                   if exposure.get("evidence_ref") else {}),
                "success_evidence": (
                    "The recorded decision. If the answer is yes, the exposure "
                    "is declared per operation with its reason and its bounds "
                    "are evidenced; if no, a re-probe showing it denied."),
                "reassess_control_ids": [exposure["control_id"]],
            })

    # A confirmed exposure that nothing bounds is the spam and cost story: the
    # same form that takes one enquiry takes ten thousand.
    bound = exposure_policy.get("bound_action") or {}
    for exposure in unbounded_exposures(updated, environment, now):
        control_id = _exposure_control(updated, exposure)
        suffix = "%s-%s-%s" % (_slug(exposure["object_id"]),
                               _slug(exposure["actor"]), exposure["operation"])
        missing = [item for item in exposure["safeguards"]
                   if item["required"] and not item["met"]]
        mechanisms = sorted({mechanism for item in missing
                             for mechanism in item.get("mechanisms") or []})
        add("%s-%s" % (bound["id_prefix"], suffix),
            "%s-%s" % (bound["id_prefix"].removeprefix("act-"), suffix), {
                "action_id": "%s-%s" % (bound["id_prefix"], suffix),
                "action_key": "%s-%s" % (
                    bound["id_prefix"].removeprefix("act-"), suffix),
                "revision": 1,
                "created_at": now_text,
                "kind": bound["kind"],
                "outcome": (
                    "The intended %s %s of %s is bounded and the bound is "
                    "observed: %s."
                    % (exposure["actor"], exposure["operation"],
                       exposure["object_ref"] or exposure["object_id"],
                       "; ".join(item["detail"] for item in missing))),
                "reason": (
                    "%s %s of %s is intended (%s), which makes it reachable by "
                    "automation as well as by customers. Unbounded, the same "
                    "path fills the table, sends the mail and spends the quota, "
                    "and the real submissions are buried in it.%s"
                    % (exposure["actor"], exposure["operation"],
                       exposure["object_ref"] or exposure["object_id"],
                       exposure.get("rationale") or "no reason recorded",
                       (" Any of these bounds it: %s." % ", ".join(mechanisms))
                       if mechanisms else "")),
                "priority": "high",
                "urgency": bound["urgency"],
                "deadline": {
                    "kind": "unknown",
                    "rationale": ("An unbounded public write is being abused or "
                                  "it is not; the deadline follows the exposure "
                                  "of the environment it runs in."),
                    "reassess_trigger": {"kind": "context_change"},
                },
                "blocking_scope": [],
                "owner": {"role": bound["owner_role"]},
                "state": "open",
                "state_history": [{"state": "open", "at": now_text,
                                   "by": "vibecheck authorization coverage"}],
                "control_refs": sorted({control_id} | {
                    safeguard["control_id"]
                    for safeguard in (exposure_policy.get("required_safeguards") or [])
                    if safeguard.get("control_id")
                    and safeguard.get("id") in exposure["unmet_required"]} - {None}),
                "success_evidence": (
                    "An observation of the bound working: the throttle or "
                    "challenge refusing a repeated automated submission, and "
                    "the same actor's read of the object still denied. A "
                    "configuration screenshot is not the bound."),
                "reassess_control_ids": [control_id] if control_id else [],
            })

    for control_id in tracked_controls(updated):
        state = coverage_state(updated, control_id, environment, now)
        grouped = {}
        for gap in state["gaps"]:
            grouped.setdefault((gap["object_id"], gap["actor"]), []).append(gap)
        for (object_id, actor), gaps in sorted(
                grouped.items(), key=lambda pair: (str(pair[0][0]), pair[0][1])):
            suffix = "%s-%s" % (_slug(object_id), _slug(actor))
            action_id = "%s-%s" % (policy["id_prefix"], suffix)
            action_key = "%s-%s" % (policy["id_prefix"].removeprefix("act-"), suffix)
            operations = sorted({gap["operation"] for gap in gaps})
            reasons = sorted({gap["reason"] for gap in gaps})
            add(action_id, action_key, {
                "action_id": action_id,
                "action_key": action_key,
                "revision": 1,
                "created_at": now_text,
                "kind": policy["kind"],
                "outcome": (
                    "An authorized test observes what %s can do to %s for %s, "
                    "and the result is recorded as evidence for each operation "
                    "separately."
                    % (actor, gaps[0].get("object_ref") or object_id,
                       ", ".join(operations))),
                "reason": (
                    "Coverage for %s in %s is %s: %d of %d required cells are "
                    "observed. These are %s (%s), and an untested operation is "
                    "not a denied one."
                    % (control_id, environment, state["state"],
                       state["satisfied_count"], state["required_count"],
                       ", ".join(operations), ", ".join(reasons))),
                "priority": "unknown",
                "urgency": policy["urgency"],
                "deadline": {
                    "kind": "unknown",
                    "rationale": ("The deadline follows from the scope this "
                                  "untested path would ride into; set it when "
                                  "the target environment and use are confirmed."),
                    "reassess_trigger": {"kind": "context_change"},
                },
                "blocking_scope": [],
                "owner": {"role": policy["owner_role"]},
                "state": "open",
                "state_history": [{"state": "open", "at": now_text,
                                   "by": "vibecheck authorization coverage"}],
                "control_refs": [control_id],
                "success_evidence": (
                    "One evidence record per observed cell, each naming the "
                    "object, actor, operation and environment it covers. A "
                    "denial observed for one operation never closes another."),
                "reassess_control_ids": [control_id],
            })
    return updated


# --------------------------------------------------------- probe cell mapping

def cells_from_probe_finding(finding, object_class=None, object_ref=None):
    """Coverage cells for one supabase_probe.py finding.

    Both current and archived output are mapped from the check name and verdict.
    A current probe's ``coverage`` block is a derived cache, not an authority:
    trusting it would let an UNKNOWN result relabel itself as a denial, change
    actor/operation, or move between environments during import.
    """
    if not isinstance(finding, dict):
        return []

    mapping = load_model()["probe_mapping"]["checks"].get(finding.get("check"))
    if mapping is None:
        return []
    verdict = str(finding.get("verdict", ""))
    rule = mapping["verdicts"].get(verdict)
    if rule is None:
        prefix = verdict.split("_", 1)[0]
        rule = mapping["verdicts"].get(prefix)
    if rule is None:
        return []
    observed = rule.get("observed")
    if (rule.get("observed_when_key_validated")
            and finding.get("key_validated")):
        observed = rule["observed_when_key_validated"]
    if not observed:
        return []  # NOT_TESTED-class results: no cell, an open verify action
    cell = {
        "object_ref": object_ref or finding.get("table") or "unknown object",
        "object_class": object_class or "unclassified",
        "actor": mapping["actor"],
        "operation": mapping["operation"],
        "observed": observed,
    }
    if finding.get("record_id"):
        cell["instance"] = str(finding["record_id"])
    return [cell]
