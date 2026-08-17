# -*- coding: utf-8 -*-
"""Environment-scoped readiness (RFC 0001 §4.2, gh issue #4, Increment 2).

"Is it ready?" is not answerable. "Is there a known blocker for a private test
with invited users, on today's evidence?" is, and that is the only question
this module answers — always for one explicit environment + intended-use pair:

    blocked  >  incomplete  >  conditional  >  no_known_blocker

None of those states is ever "secure", "certified" or "ready to ship". The
strongest statement available is *no known blocker for this scope, as of this
evidence*, and even that keeps its blockers, unknowns and conditions attached.

Three properties matter more than the state itself:

  * a narrow scope passing is never permission to widen it — every readiness
    object lists the more exposed target scopes and their own state under
    `blocked_transitions`;
  * unknown never quietly becomes fine — an unconfirmed context, an unassessed
    Critical control, a stale risk or a contradiction in the captured facts all
    keep readiness at `incomplete`, whatever the risk levels say;
  * the legacy checklist verdict stays visible beside the scoped state, with a
    written explanation whenever the two differ (`framework_verdict`), so the
    new model never quietly overrules the old one.

CLI: `python3 scripts/readiness.py ENVELOPE.json [--summary]` derives risks and
readiness for every target scope and writes the updated envelope to stdout.
"""
import argparse
import copy
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import canonical
import actions as actions_mod
import authz as authz_mod
import context as ctx
import risk as risk_mod
from controls import FRAMEWORK, FRAMEWORK_VERSION

POLICY_NAME = "vibecheck.readiness"
POLICY_VERSION = "1.0.0"

BLOCKING_LEVELS = ("critical", "high")
UNRESOLVED_STATUSES = ("fail", "partial")
OPEN_ACTION_STATES = ("open", "in_progress", "blocked")

#: Reviewer verdict ladder of the existing workbook, kept here so this module
#: stays stdlib-only. tests/test_context.py pins the wording against
#: build_workbook.STR, which is the authoring source.
VERDICTS = {
    "not_reviewed": "NOT REVIEWED",
    "incomplete": "INCOMPLETE REVIEW",
    "block": "BLOCK",
    "block_high": "BLOCK - RISK ACCEPTANCE REQUIRED",
    "fix": "FIX BEFORE RELEASE",
    "complete": "REVIEW COMPLETE - NO OPEN FAIL/PARTIAL",
}

#: Which readiness states the workbook verdict is consistent with. A pairing
#: outside this table is not an error — the two answer different questions —
#: but it must be explained, never hidden (schema requires the explanation).
_AGREEMENT = {
    "not_reviewed": ("incomplete",),
    "incomplete": ("incomplete",),
    "block": ("blocked",),
    "block_high": ("blocked",),
    "fix": ("blocked", "conditional"),
    "complete": ("no_known_blocker", "conditional"),
}


def _registry():
    return {c["control_id"]: c for c in canonical.load_registry()["controls"]}


def _scope_slug(scope):
    return "%s.%s" % (scope.get("environment"), scope.get("intended_use"))


def _covers(blocking_scope, scope):
    return any(ctx.same_scope(entry, scope) for entry in blocking_scope or [])


def _control_slug(control_id):
    return (control_id or "").split("vibecheck.control.")[-1]


def unknown_id(scope, code):
    """A stable id for one material unknown.

    Blockers can point at the object that blocks (an action, a risk, an
    assessment); several unknowns have no single object behind them — an
    unconfirmed context, a set of unassessed controls — and would otherwise be
    unaddressable. The founder report has to state every material unknown
    exactly once and prove it did (rule R12), so each one gets an id derived
    from its scope and what it is about, stable across re-derivations.
    """
    return "unk-%s-%s" % (_scope_slug(scope), code)


def _ensure_unknown_ids(readiness):
    """Give pre-1.2/hand-authored material unknowns a stable report identity."""
    scope = readiness.get("scope") or {}
    for unknown in readiness.get("unknowns") or []:
        if not unknown.get("material") or unknown.get("unknown_id"):
            continue
        seed = canonical.dumps({
            "ref": unknown.get("ref"),
            "description": unknown.get("description"),
            "material": True,
        }).encode("utf-8")
        unknown["unknown_id"] = unknown_id(
            scope, "legacy.%s" % hashlib.sha256(seed).hexdigest()[:16])


# ------------------------------------------------------------ legacy verdict

def framework_verdict(envelope):
    """The reviewer checklist verdict for the same assessments.

    Mirrors the workbook gate ladder: nothing reviewed -> NOT REVIEWED;
    unreviewed Critical/High, an unsupported Critical/High Pass, a missing N/A
    or acceptance reason, an open screening row, or coverage below 100% ->
    INCOMPLETE REVIEW; a Critical Fail or accepted Critical -> BLOCK; a High
    Fail -> BLOCK - RISK ACCEPTANCE REQUIRED; any other Fail/Partial -> FIX
    BEFORE RELEASE; otherwise the review is complete with no open failures.
    """
    registry = _registry()
    by_control = {}
    for assessment in canonical.current_assessments(envelope):
        if assessment.get("control_id") in registry:
            by_control[assessment["control_id"]] = assessment

    counts = dict(reviewed=0, applicable=0, not_applicable=0, fail=0, partial=0,
                  crit_fail=0, crit_accepted=0, high_fail=0,
                  unreviewed_crit_high=0, unsupported_pass=0, missing_reason=0,
                  open_screening=0, screening_answered=0)
    for control_id, entry in sorted(registry.items()):
        assessment = by_control.get(control_id)
        status = assessment.get("status") if assessment else None
        screening = entry["kind"] == "screening"
        critical_or_high = entry["severity"] in ("Critical", "High")

        if screening:
            if status in ("answered", "needs_specialist", "not_applicable"):
                counts["screening_answered"] += 1
            else:
                counts["open_screening"] += 1
            continue
        if status == "not_applicable":
            counts["not_applicable"] += 1
        else:
            counts["applicable"] += 1
        if status in ("pass", "partial", "fail", "risk_accepted"):
            counts["reviewed"] += 1
        if critical_or_high and status in (None, "not_tested"):
            counts["unreviewed_crit_high"] += 1
        if status == "pass" and critical_or_high and not (
                (assessment.get("basis") or {}).get("evidence_refs")):
            counts["unsupported_pass"] += 1
        if status == "not_applicable" and not (
                (assessment.get("basis") or {}).get("rationale")):
            counts["missing_reason"] += 1
        if status == "risk_accepted":
            if not (assessment.get("acceptance") or {}).get("reason"):
                counts["missing_reason"] += 1
            if entry["severity"] == "Critical":
                counts["crit_accepted"] += 1
        if status == "fail":
            counts["fail"] += 1
            if entry["severity"] == "Critical":
                counts["crit_fail"] += 1
            elif entry["severity"] == "High":
                counts["high_fail"] += 1
        if status == "partial":
            counts["partial"] += 1

    if (counts["reviewed"] + counts["not_applicable"]
            + counts["screening_answered"]) == 0:
        return "not_reviewed", counts
    if (counts["unreviewed_crit_high"] or counts["unsupported_pass"]
            or counts["missing_reason"] or counts["open_screening"]):
        return "incomplete", counts
    if counts["crit_fail"] or counts["crit_accepted"]:
        return "block", counts
    if counts["high_fail"]:
        return "block_high", counts
    if counts["reviewed"] < counts["applicable"]:
        return "incomplete", counts
    if counts["fail"] or counts["partial"]:
        return "fix", counts
    return "complete", counts


_DIFFERENCE = {
    ("block", "conditional"): (
        "A failed or accepted Critical control keeps the checklist at BLOCK "
        "whatever the environment. Readiness for this narrow scope is not "
        "blocked because the same failure carries lower contextual risk here "
        "and the listed conditions hold; the control is still failed, and the "
        "more exposed scopes stay listed under blocked_transitions."),
    ("block", "no_known_blocker"): (
        "A failed or accepted Critical control keeps the checklist at BLOCK "
        "whatever the environment. Readiness for this narrow scope finds no "
        "blocker because the same failure carries low or moderate contextual "
        "risk here. The control remains failed and every more exposed scope is "
        "listed under blocked_transitions."),
    ("block_high", "conditional"): (
        "A failed High control keeps the checklist at BLOCK - RISK ACCEPTANCE "
        "REQUIRED. In this scope the same failure is survivable under the "
        "listed enforced conditions; it is not resolved by them."),
    ("block_high", "no_known_blocker"): (
        "A failed High control keeps the checklist at BLOCK - RISK ACCEPTANCE "
        "REQUIRED. In this scope the same failure carries low or moderate "
        "contextual risk, so nothing blocks this scope specifically; the "
        "failure and the more exposed scopes remain."),
    ("fix", "no_known_blocker"): (
        "The checklist wants the open failures fixed before release. This "
        "scope is not a release: the same failures carry low or moderate "
        "contextual risk here, and the scopes they do block are listed under "
        "blocked_transitions."),
    ("complete", "incomplete"): (
        "The checklist counts the rows a reviewer filled in. Readiness also "
        "counts the context: an unconfirmed or expired context, a stale risk "
        "or a contradiction in the captured facts keeps the scope incomplete "
        "even when every filled row passes."),
    ("incomplete", "conditional"): (
        "The checklist is incomplete because rows below Critical and High are "
        "still unfilled. Readiness counts what could block this scope: every "
        "applicable Critical and High control here is assessed, and the scope "
        "runs under the listed enforced conditions. Finishing the review can "
        "still add blockers."),
    ("incomplete", "no_known_blocker"): (
        "The checklist is incomplete because rows below Critical and High are "
        "still unfilled. Readiness counts what could block this scope, and "
        "nothing known does. Finishing the review can still add blockers; it "
        "cannot remove one."),
    ("fix", "incomplete"): (
        "The checklist has open failures to fix before release. Readiness for "
        "this scope cannot even get that far: the context or the evidence "
        "behind those rows is not established enough to say what they mean "
        "here."),
    ("incomplete", "blocked"): (
        "The checklist is still incomplete, and readiness for this scope is "
        "already blocked by what is known: completing the review can add "
        "blockers, never remove this one."),
    ("not_reviewed", "blocked"): (
        "Nothing has been reviewed on the checklist, yet an action or risk "
        "already blocks this scope. Missing review is not the reason for the "
        "block."),
}


def _verdict_block(envelope, state):
    key, _counts = framework_verdict(envelope)
    aligned = state in _AGREEMENT[key]
    if aligned:
        explanation = (
            "The %s checklist verdict and the readiness state for this scope "
            "agree. The verdict is one judgement for the whole application; "
            "readiness is scoped to this environment and intended use."
            % FRAMEWORK)
    else:
        explanation = _DIFFERENCE.get(
            (key, state),
            "The checklist verdict judges the whole application on filled "
            "checklist rows; readiness judges one environment and intended use "
            "on evidence, contextual risk and unknowns. Both are reported; "
            "neither overrides the other.")
    return {
        "framework": FRAMEWORK,
        "framework_version": FRAMEWORK_VERSION,
        "profile": "reviewer",
        "verdict": VERDICTS[key],
        "agreement": "aligned" if aligned else "differs",
        "explanation": explanation,
    }


# ---------------------------------------------------------------- derivation

def _open_blocking_actions(envelope, scope):
    return [a for a in actions_mod.current_actions(envelope)
            if a.get("state") in OPEN_ACTION_STATES
            and _covers(a.get("blocking_scope"), scope)]


def _scope_risks(envelope, scope):
    return [r for r in risk_mod.current_risks(envelope)
            if ctx.same_scope(r.get("scope"), scope)]


def _unassessed_critical_high(envelope):
    registry = _registry()
    assessed = {a.get("control_id") for a in canonical.current_assessments(envelope)
                if a.get("status") not in (None, "not_tested")}
    return sorted(cid for cid, entry in registry.items()
                  if entry["severity"] in ("Critical", "High")
                  and entry["kind"] != "screening"
                  and cid not in assessed)


def _expired_pass_controls(envelope, now):
    """Critical/High passes resting on evidence that has since expired (R15)."""
    registry = _registry()
    evidence = {e.get("evidence_id"): e for e in envelope.get("evidence") or []}
    stale = []
    for assessment in canonical.current_assessments(envelope):
        entry = registry.get(assessment.get("control_id"))
        if (assessment.get("status") != "pass" or entry is None
                or entry["severity"] not in ("Critical", "High")):
            continue
        refs = (assessment.get("basis") or {}).get("evidence_refs") or []
        supporting = [evidence[r] for r in refs if r in evidence
                      and evidence[r].get("direction") == "supports"]
        if supporting and all(
                (ctx.parse_instant(e.get("valid_until")) is not None
                 and ctx.parse_instant(e.get("valid_until")) < now)
                for e in supporting):
            stale.append(assessment)
    return stale


def _conditions(envelope, scope, now):
    """Enforceable conditions this scope would run under.

    Only measures that name an enforcing mechanism and carry current evidence
    become conditions; an accepted risk becomes a condition with its review
    date, because an acceptance that is never revisited is not a condition.
    """
    context = envelope.get("context") or {}
    conditions = []
    for measure in context.get("compensating_controls") or []:
        if not measure.get("readiness_condition"):
            continue
        scopes = (measure.get("applies_to") or {}).get("scopes")
        if scopes and not any(ctx.same_scope(scope, s) for s in scopes):
            continue
        expiry = ctx.parse_instant(measure.get("valid_until"))
        if "valid_until" in measure and (
                expiry is None or expiry < now):
            continue  # a lapsed measure is not an enforceable condition
        if not risk_mod.current_supporting_evidence(
                envelope, measure.get("evidence_refs"), now):
            continue
        condition = {
            "condition_id": "cond-%s-%s" % (
                _scope_slug(scope),
                measure["compensating_control_id"].replace("cc-", "", 1)),
            "requirement": measure["description"],
            "enforced_by": measure["enforced_by"],
            "verification_evidence_refs": list(measure.get("evidence_refs") or []),
            "reassess_trigger": copy.deepcopy(
                measure.get("reassess_trigger") or {"kind": "context_change"}),
        }
        if measure.get("valid_until"):
            condition["expires_at"] = measure["valid_until"]
        conditions.append(condition)

    for assessment in canonical.current_assessments(envelope):
        if assessment.get("status") != "risk_accepted":
            continue
        acceptance = assessment.get("acceptance") or {}
        review_by = ctx.parse_instant(acceptance.get("review_by"))
        if review_by is None or review_by < now:
            continue
        conditions.append({
            "condition_id": "cond-%s-accepted.%s" % (
                _scope_slug(scope),
                assessment["control_id"].split("vibecheck.control.")[-1]),
            "requirement": (
                "The accepted risk on %s stays accepted only until %s, and only "
                "for this scope: %s"
                % (assessment["control_id"], acceptance.get("review_by", "?"),
                   acceptance.get("reason", "no reason recorded"))),
            "enforced_by": acceptance.get("accepted_by", "unrecorded"),
            "reassess_trigger": ({"kind": "calendar_date",
                                  "value": acceptance["review_by"]}
                                 if acceptance.get("review_by")
                                 else {"kind": "context_change"}),
            **({"expires_at": acceptance["review_by"]}
               if acceptance.get("review_by") else {}),
        })
    return conditions


def _valid_until(envelope, scope, conditions, now):
    context = envelope.get("context") or {}
    instants = []
    for value in [context.get("valid_until")] + \
            [c.get("expires_at") for c in conditions] + \
            [r.get("reassess_by") for r in _scope_risks(envelope, scope)]:
        instant = ctx.parse_instant(value)
        if instant is not None:
            instants.append(instant)
    return ctx.iso(min(instants)) if instants else None


def _assess_scope(envelope, scope, now):
    """(state, blockers, unknowns, conditions, rules) for one scope."""
    context = envelope.get("context") or {}
    blockers, unknowns, rules = [], [], []
    registry = _registry()

    for action in _open_blocking_actions(envelope, scope):
        blockers.append({
            "ref": action["action_id"],
            "reason": "Open %s action whose blocking scope covers this "
                      "environment and intended use: %s"
                      % (action.get("kind", "?"), action.get("outcome", "")),
        })
        rules.append("readiness.blocked.open_blocking_action")

    unresolved = {a.get("control_id"): a
                  for a in canonical.current_assessments(envelope)
                  if a.get("status") in UNRESOLVED_STATUSES}
    for risk in _scope_risks(envelope, scope):
        level = risk_mod.effective_level(risk, envelope, now)
        controls = [c for c in risk.get("control_refs") or [] if c in unresolved]
        if not controls:
            continue
        if level in BLOCKING_LEVELS:
            blockers.append({
                "ref": risk["risk_id"],
                "reason": "%s contextual %s risk in this scope for unresolved "
                          "control(s) %s (assessment status: %s)"
                          % (level.capitalize(), risk.get("domain", "?"),
                             ", ".join(controls),
                             ", ".join(sorted({unresolved[c]["status"]
                                               for c in controls}))),
            })
            rules.append("readiness.blocked.contextual_risk_%s" % level)
        elif level == "unknown":
            unknowns.append({
                "unknown_id": unknown_id(
                    scope, "risk.%s.%s"
                    % ("-".join(sorted(_control_slug(c) for c in controls)),
                       risk.get("horizon", {}).get("kind", "current"))),
                "ref": risk["risk_id"],
                "description": "Contextual risk for %s is unknown in this scope%s. "
                               "Unknown is never low and never permission to "
                               "proceed."
                               % (", ".join(controls),
                                  " (the recorded risk has gone stale)"
                                  if risk.get("level") != "unknown" else ""),
                "material": True,
            })
            rules.append("readiness.incomplete.unknown_risk")

    for assessment in canonical.current_assessments(envelope):
        entry = registry.get(assessment.get("control_id"))
        if (assessment.get("status") == "risk_accepted" and entry
                and entry["severity"] == "Critical"):
            blockers.append({
                "ref": assessment["assessment_id"],
                "reason": "Critical control %s is marked accepted risk. A "
                          "Critical control can never be accepted (rule R5); "
                          "the acceptance does not clear this scope."
                          % assessment["control_id"],
            })
            rules.append("readiness.blocked.critical_risk_accepted")

        if assessment.get("status") == "risk_accepted":
            acceptance = assessment.get("acceptance") or {}
            review_by = ctx.parse_instant(acceptance.get("review_by"))
            if review_by is None or review_by < now:
                unknowns.append({
                    "unknown_id": unknown_id(
                        scope, "acceptance.%s"
                        % _control_slug(assessment.get("control_id"))),
                    "ref": assessment.get("assessment_id"),
                    "description": "Risk acceptance for %s has no current "
                                   "review deadline: review_by %r is missing, "
                                   "invalid or past. The acceptance must be "
                                   "reviewed again before it can constrain "
                                   "operation in this scope."
                                   % (assessment.get("control_id"),
                                      acceptance.get("review_by")),
                    "material": True,
                })
                rules.append("readiness.incomplete.expired_risk_acceptance")

    current_by_control = {a.get("control_id"): a
                          for a in canonical.current_assessments(envelope)}
    for control_id, coverage in sorted(
            authz_mod.coverage_gaps(envelope, scope.get("environment"), now).items()):
        assessment = current_by_control.get(control_id)
        if assessment is None or assessment.get("status") not in ("pass", "partial"):
            # A failing control is already an unresolved blocker in its own
            # right; the coverage gap matters where the control otherwise
            # looks handled.
            continue
        unknowns.append({
            "unknown_id": unknown_id(
                scope, "authz_coverage.%s" % _control_slug(control_id)),
            "ref": assessment.get("assessment_id"),
            "description": "Authorization coverage for %s in this environment "
                           "is %s: %d of %d required (object, actor, "
                           "operation) cells are observed, and the rest are %s. "
                           "One denied request covers one cell, never the "
                           "control."
                           % (control_id, coverage["state"],
                              coverage["satisfied_count"],
                              coverage["required_count"],
                              ", ".join(sorted({"%s/%s/%s (%s)"
                                                % (gap["object_id"], gap["actor"],
                                                   gap["operation"], gap["reason"])
                                                for gap in coverage["gaps"]}))),
            "material": True,
            "control_ids": [control_id],
        })
        rules.append("readiness.incomplete.authorization_coverage_gap")

    for exposure in authz_mod.unbounded_exposures(
            envelope, scope.get("environment"), now):
        unknowns.append({
            "unknown_id": unknown_id(
                scope, "authz_exposure.%s.%s.%s"
                % (exposure["object_id"], exposure["actor"],
                   exposure["operation"])),
            "description": "%s %s of %s is intended (%s), but nothing bounds it "
                           "in this environment: %s. An unauthenticated write "
                           "path is reachable by automation as well as by "
                           "customers, so an unbounded one is an open question "
                           "about cost, spam and the usability of what it fills."
                           % (exposure["actor"], exposure["operation"],
                              exposure["object_ref"] or exposure["object_id"],
                              exposure.get("rationale") or "no reason recorded",
                              "; ".join(item["detail"]
                                        for item in exposure["safeguards"]
                                        if item["required"] and not item["met"])),
            "material": True,
        })
        rules.append("readiness.incomplete.unbounded_intended_exposure")

    confirmation = ctx.confirmation_state(context, now)
    if confirmation != "human_reviewed":
        unknowns.append({
            "unknown_id": unknown_id(scope, "context.%s" % confirmation),
            "ref": context.get("context_id"),
            "description": {
                "draft": "The application context has not been confirmed by a "
                         "human: every conclusion below rests on unconfirmed "
                         "facts.",
                "review_bypassed": "The human review of the technical overview "
                                   "was bypassed. The context is usable but "
                                   "unverified, and that gap stays visible.",
                "expired": "The application context is past its valid_until "
                           "and counts as unconfirmed until it is reconfirmed.",
                "not_yet_confirmed": "The application context records a human "
                                     "confirmation later than this assessment "
                                     "time. It does not count as reviewed yet.",
            }.get(confirmation,
                  "The application context confirmation state is %r." % confirmation),
            "material": True,
        })
        rules.append("readiness.incomplete.context_%s" % confirmation)

    missing = ctx.missing_dimensions(context)
    if missing:
        unknowns.append({
            "unknown_id": unknown_id(scope, "context.dimensions"),
            "ref": context.get("context_id"),
            "description": "Context dimensions that feed risk derivation are "
                           "unknown or conflicting: %s. Any risk that needed "
                           "them came out unknown." % ", ".join(missing),
            "material": True,
            "dimensions": missing,
        })
        rules.append("readiness.incomplete.unknown_context_dimensions")

    for note in ctx.consistency_notes(context):
        unknowns.append({
            "unknown_id": unknown_id(scope, "context.%s" % note["code"]),
            "ref": context.get("context_id"),
            "description": note["message"],
            "material": True,
            "code": note["code"],
        })
        rules.append("readiness.incomplete.context_contradiction")

    unassessed = _unassessed_critical_high(envelope)
    if unassessed:
        unknowns.append({
            "unknown_id": unknown_id(scope, "controls.unassessed_critical_high"),
            "description": "%d applicable Critical or High control(s) have no "
                           "current assessment. An unreviewed control is not a "
                           "passing one." % len(unassessed),
            "material": True,
            "control_ids": unassessed,
        })
        rules.append("readiness.incomplete.unassessed_critical_high")

    for assessment in _expired_pass_controls(envelope, now):
        unknowns.append({
            "unknown_id": unknown_id(
                scope, "evidence.expired.%s"
                % _control_slug(assessment.get("control_id"))),
            "ref": assessment["assessment_id"],
            "description": "Pass on %s rests only on evidence that has expired; "
                           "it needs re-verification before it can support this "
                           "scope (rule R15)." % assessment["control_id"],
            "material": True,
        })
        rules.append("readiness.incomplete.expired_supporting_evidence")

    conditions = _conditions(envelope, scope, now)
    material = [u for u in unknowns if u.get("material")]
    if blockers:
        state = "blocked"
    elif material:
        state = "incomplete"
    elif conditions:
        state = "conditional"
        rules.append("readiness.conditional.enforced_conditions")
    else:
        state = "no_known_blocker"
        rules.append("readiness.no_known_blocker")
    return state, blockers, unknowns, conditions, rules


def derive_readiness(envelope, scope, now=None, states=None):
    """Readiness for exactly one environment + intended-use pair."""
    now_dt = ctx.instant(now)
    context = envelope.get("context") or {}
    state, blockers, unknowns, conditions, rules = _assess_scope(
        envelope, scope, now_dt)

    transitions = []
    for target in ctx.more_exposed_scopes(context, scope):
        key = (target.get("environment"), target.get("intended_use"))
        if states is not None and key in states:
            target_state, target_blockers, target_unknowns = states[key]
        else:
            target_state, target_blockers, target_unknowns, _c, _r = _assess_scope(
                envelope, target, now_dt)
        transitions.append({
            "scope": dict(target),
            "state": target_state,
            "reason": "Moving to this scope is a separate question with its own "
                      "answer: %s (%d blocker(s), %d material unknown(s)). "
                      "Readiness here is not permission to go there."
                      % (target_state, len(target_blockers),
                         len([u for u in target_unknowns if u.get("material")])),
            "refs": [b["ref"] for b in target_blockers if b.get("ref")],
        })

    readiness = {
        "readiness_id": "rdy-%s" % _scope_slug(scope),
        "scope": {"environment": scope.get("environment"),
                  "intended_use": scope.get("intended_use")},
        "state": state,
        "blockers": blockers,
        "unknowns": unknowns,
        "assessed_at": ctx.iso(now_dt),
        "framework_verdict": _verdict_block(envelope, state),
        "derivation": {
            "policy": {"name": POLICY_NAME, "version": POLICY_VERSION},
            "context_revision": int(context.get("revision", 1)),
            "rules_applied": sorted(set(rules)),
        },
    }
    if conditions:
        readiness["conditions"] = conditions
    if transitions:
        readiness["blocked_transitions"] = transitions
    valid_until = _valid_until(envelope, scope, conditions, now_dt)
    if valid_until:
        readiness["valid_until"] = valid_until
    return readiness


def derive_all(envelope, now=None):
    """Readiness for every target scope, in target order."""
    now_dt = ctx.instant(now)
    scopes = (envelope.get("context") or {}).get("target_scopes") or []
    states = {}
    for scope in scopes:
        state, blockers, unknowns, _conditions, _rules = _assess_scope(
            envelope, scope, now_dt)
        states[(scope.get("environment"), scope.get("intended_use"))] = (
            state, blockers, unknowns)
    return [derive_readiness(envelope, scope, now_dt, states) for scope in scopes]


def apply_readiness(envelope, now=None):
    """Replace the readiness objects for the target scopes.

    Readiness is a derived view of everything else, not a historical record:
    recomputing it after new evidence is the point. Readiness for scopes this
    envelope no longer targets is left untouched rather than deleted.
    """
    updated = copy.deepcopy(envelope)
    derived = derive_all(updated, now)
    derived_ids = {r["readiness_id"] for r in derived}
    kept = [r for r in updated.get("readiness") or []
            if r.get("readiness_id") not in derived_ids]
    updated["readiness"] = kept + derived
    for readiness in updated["readiness"]:
        _ensure_unknown_ids(readiness)
    return updated


def derive_into(envelope, now=None):
    """Risks first, then readiness over those risks."""
    return apply_readiness(risk_mod.apply_risks(envelope, now), now)


# ------------------------------------------------------------------------ CLI

def summarize(envelope):
    lines = []
    context = envelope.get("context") or {}
    lines.append("context %s revision %d (%s)"
                 % (context.get("context_id"), context.get("revision", 1),
                    ctx.confirmation_state(context)))
    for readiness in envelope.get("readiness") or []:
        scope = readiness["scope"]
        lines.append("%s + %s: %s" % (scope["environment"], scope["intended_use"],
                                      readiness["state"].upper()))
        for blocker in readiness.get("blockers") or []:
            lines.append("    blocker  %s: %s" % (blocker["ref"], blocker["reason"]))
        for unknown in readiness.get("unknowns") or []:
            lines.append("    unknown  %s%s"
                         % ("[material] " if unknown.get("material") else "",
                            unknown["description"]))
        for condition in readiness.get("conditions") or []:
            lines.append("    condition %s (enforced by %s)"
                         % (condition["requirement"], condition["enforced_by"]))
        verdict = readiness.get("framework_verdict") or {}
        lines.append("    checklist verdict %r (%s): %s"
                     % (verdict.get("verdict"), verdict.get("agreement"),
                        verdict.get("explanation")))
    lines.append("Vibecheck reports known blockers for a stated scope. It is "
                 "not a certification and never states that an application is "
                 "secure.")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Derive contextual risk and environment-scoped readiness "
                    "for a vibecheck.assessment envelope")
    parser.add_argument("envelope", help="path to a vibecheck.assessment JSON file")
    parser.add_argument("--now", help="derivation timestamp (default: now, UTC)")
    parser.add_argument("--summary", action="store_true",
                        help="print a readable summary instead of the envelope")
    parser.add_argument("--out", help="write the updated envelope here")
    args = parser.parse_args(argv)

    with open(args.envelope, encoding="utf-8") as fh:
        envelope = json.load(fh)
    updated = derive_into(envelope, args.now)
    problems = canonical.validate_envelope(updated)
    for problem in problems:
        print("problem: %s" % problem, file=sys.stderr)

    if args.summary:
        print(summarize(updated))
    else:
        rendered = canonical.dumps(updated)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(rendered)
        else:
            sys.stdout.write(rendered)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
