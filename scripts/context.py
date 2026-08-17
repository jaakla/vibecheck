# -*- coding: utf-8 -*-
"""Versioned application context (RFC 0001 §4, gh issue #4, Increment 2).

The context says what the application is for, who can reach it, and what is at
stake. Everything downstream — contextual risk, environment-scoped readiness,
founder wording — is only as good as it, so the context is a first-class,
separately versioned record rather than a few fields on a report:

  * every captured fact carries its own state (confirmed / inferred /
    conflicting / unknown) with a source and a rationale, so a conclusion can
    never quietly rest on a guess (`field`, `profile`);
  * the context has its own revision, confirmation, expiry and reassessment
    triggers, independent of the source-code fingerprint (`revise`,
    `context_fingerprint`, `is_expired`) — changing what the application is for
    never pretends the code moved, and a code change never pretends the context
    was reconfirmed;
  * unknown and conflicting are kept distinct from the benign value; the risk
    derivation turns either of them into an unknown input, never a low one.

The dimension list, the allowed values and the standard environment/intended-use
bands are data: schema/vibecheck.context.v1.json. Labels are English only in
v1; founder-facing EN/ET wording arrives with the founder report (gh issue #5).

Stdlib only, like the rest of scripts/. This module deliberately imports
nothing from canonical.py: canonical imports it, not the other way round.
"""
import copy
import hashlib
import json
import os
from datetime import datetime, timezone

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(REPO_ROOT, "schema", "vibecheck.context.v1.json")

MODEL_NAME = "vibecheck.context_model"
MODEL_VERSION = "1.0.0"

FIELD_STATES = ("confirmed", "inferred", "conflicting", "unknown")
#: States that cannot feed a derivation input: neither may be resolved toward
#: the benign value, so both make the input they feed unknown.
UNRESOLVED_STATES = ("conflicting", "unknown")

_cache = {}


def load_model():
    if "model" not in _cache:
        with open(MODEL_PATH, encoding="utf-8") as fh:
            _cache["model"] = json.load(fh)
    return _cache["model"]


def dimensions():
    """dimension id -> dimension definition, in model order."""
    if "dimensions" not in _cache:
        _cache["dimensions"] = {d["id"]: d for d in load_model()["dimensions"]}
    return _cache["dimensions"]


def value_ids(dimension_id):
    return [v["id"] for v in dimensions()[dimension_id]["values"]]


def environment_bands():
    """environment -> exposure band; higher means more exposed."""
    if "env_bands" not in _cache:
        _cache["env_bands"] = {e["id"]: e["band"] for e in load_model()["environments"]}
    return _cache["env_bands"]


def intended_use_bands():
    if "use_bands" not in _cache:
        _cache["use_bands"] = {u["id"]: u["band"] for u in load_model()["intended_uses"]}
    return _cache["use_bands"]


# ----------------------------------------------------------------- timestamps

def parse_instant(value):
    """Parse a schema timestamp into a UTC-aware datetime, or None.

    JSON Schema permits both ``Z`` and numeric UTC offsets; comparing those
    strings lexicographically is wrong because different representations of the
    same instant do not sort chronologically.
    """
    if not isinstance(value, str):
        return None
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        instant = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if instant.tzinfo is None:
        return None
    return instant.astimezone(timezone.utc)


def iso(instant):
    return instant.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def instant(now):
    if now is None:
        return datetime.now(timezone.utc)
    if isinstance(now, datetime):
        return now.astimezone(timezone.utc)
    parsed = parse_instant(now)
    if parsed is None:
        raise ValueError("unparseable timestamp %r" % (now,))
    return parsed


# --------------------------------------------------------------------- fields

def field(value=None, state="confirmed", source=None, rationale=None,
          candidates=None, confirmed_at=None):
    """One profile field with its provenance.

    confirmed and inferred need a value and a source (inferred also a
    rationale); conflicting needs the competing candidates and a rationale;
    unknown carries no value at all, so it can never read as an answer.
    """
    if state not in FIELD_STATES:
        raise ValueError("unknown field state %r" % (state,))
    entry = {"state": state}
    if state == "unknown":
        if rationale:
            entry["rationale"] = rationale
        if source:
            entry["source"] = source
        return entry
    if state == "conflicting":
        entry["candidates"] = list(candidates or [])
        entry["rationale"] = rationale or ""
        if source:
            entry["source"] = source
        return entry
    entry["value"] = value
    if source:
        entry["source"] = source
    if rationale:
        entry["rationale"] = rationale
    if confirmed_at:
        entry["confirmed_at"] = confirmed_at
    return entry


def profile(answers, source=None, state="confirmed", confirmed_at=None):
    """Build a profile from {dimension: value} or {dimension: field-dict}.

    A dimension left out of ``answers`` is not silently benign: the derivation
    treats a missing dimension exactly like an explicit unknown.
    """
    built = {}
    for dimension_id, answer in answers.items():
        if isinstance(answer, dict):
            built[dimension_id] = dict(answer)
        elif answer is None:
            built[dimension_id] = field(state="unknown")
        else:
            built[dimension_id] = field(value=answer, state=state, source=source,
                                        confirmed_at=confirmed_at)
    return built


def field_state(context, dimension_id):
    """State of one profile field; a dimension that was never captured is
    unknown, not absent."""
    entry = ((context.get("profile") or {}).get(dimension_id)) or {}
    state = entry.get("state")
    return state if state in FIELD_STATES else "unknown"


def field_value(context, dimension_id):
    """Value of one profile field, or None when it is not usable (unknown,
    conflicting, or never captured)."""
    if field_state(context, dimension_id) in UNRESOLVED_STATES:
        return None
    entry = (context.get("profile") or {}).get(dimension_id) or {}
    return entry.get("value")


def missing_dimensions(context):
    """Derivation-input dimensions that are unknown, conflicting or absent."""
    return [d for d, spec in dimensions().items()
            if spec.get("role") == "derivation_input"
            and field_value(context, d) is None]


# --------------------------------------------------------------- construction

def build_context(context_id, application, target_scopes, profile=None,
                  current_scope=None, compensating_controls=None,
                  confirmation=None, data_summary=None, assumptions=None,
                  valid_until=None, reassess_triggers=None, extensions=None,
                  authorization_objects=None, revision=1):
    """A context at revision 1. Unconfirmed by default: an unattended import
    produces a draft, and a draft caps readiness at incomplete (RFC §4.2)."""
    context = {
        "context_id": context_id,
        "revision": revision,
        "context_model": {"name": MODEL_NAME, "version": MODEL_VERSION},
        "application": dict(application),
        "target_scopes": [dict(s) for s in target_scopes],
        "confirmation": dict(confirmation or {"state": "draft"}),
    }
    if current_scope:
        context["current_scope"] = dict(current_scope)
    if profile:
        context["profile"] = copy.deepcopy(profile)
    if compensating_controls:
        context["compensating_controls"] = copy.deepcopy(compensating_controls)
    if authorization_objects:
        context["authorization_objects"] = copy.deepcopy(authorization_objects)
    if extensions:
        context["extensions"] = copy.deepcopy(extensions)
    if data_summary:
        context["data_summary"] = data_summary
    if assumptions:
        context["assumptions"] = list(assumptions)
    if valid_until:
        context["valid_until"] = valid_until
    context["reassess_triggers"] = [
        dict(t) for t in (reassess_triggers
                          if reassess_triggers is not None
                          else load_model()["reassessment"]["default_triggers"])]
    return stamp_fingerprint(context)


#: Content fields that make up the context identity. Deliberately excludes the
#: revision, the confirmation block and the timestamps: the fingerprint answers
#: "are these the same recorded facts?", not "was this the same review?".
_FINGERPRINTED = ("application", "target_scopes", "current_scope", "profile",
                  "compensating_controls", "authorization_objects",
                  "extensions", "data_summary", "assumptions")


def context_fingerprint(context):
    """Digest of the recorded context facts.

    Independent of ``confirmation.source_fingerprint``, which digests the
    reviewed source tree: the two answer different questions and go stale for
    different reasons.
    """
    content = {k: context[k] for k in _FINGERPRINTED if k in context}
    payload = json.dumps(content, ensure_ascii=False, sort_keys=True,
                         separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(
        b"vibecheck-context-fingerprint-v1\0" + payload).hexdigest()


def stamp_fingerprint(context):
    context["context_fingerprint"] = context_fingerprint(context)
    return context


def revise(context, profile=None, target_scopes=None, current_scope=None,
           compensating_controls=None, application=None, data_summary=None,
           assumptions=None, valid_until=None, reassess_triggers=None,
           authorization_objects=None, confirmed_by=None, now=None):
    """A new context revision carrying the changed facts.

    ``profile`` is merged field by field, so a revision can correct one answer
    without restating the rest. The source fingerprint is never touched:
    changing what the application is for is not a claim that the code changed.
    Any change made without a human confirming it drops the context back to
    draft — the human-review gate survives the edit.
    """
    revised = copy.deepcopy(context)
    previous_revision = int(context.get("revision", 1))
    revised["revision"] = previous_revision + 1
    revised["supersedes_revision"] = previous_revision
    revised.setdefault("context_model", {"name": MODEL_NAME, "version": MODEL_VERSION})

    if profile:
        merged = copy.deepcopy(revised.get("profile") or {})
        merged.update(copy.deepcopy(profile))
        revised["profile"] = merged
    for key, value in (("target_scopes", target_scopes),
                       ("current_scope", current_scope),
                       ("compensating_controls", compensating_controls),
                       ("authorization_objects", authorization_objects),
                       ("application", application),
                       ("data_summary", data_summary),
                       ("assumptions", assumptions),
                       ("valid_until", valid_until),
                       ("reassess_triggers", reassess_triggers)):
        if value is not None:
            revised[key] = copy.deepcopy(value)

    confirmation = dict(revised.get("confirmation") or {})
    if confirmed_by:
        confirmation["state"] = "human_reviewed"
        confirmation["confirmed_by"] = confirmed_by
        confirmation["confirmed_at"] = iso(instant(now))
    else:
        # facts changed without anyone confirming them: unconfirmed again
        confirmation["state"] = "draft"
        confirmation.pop("confirmed_by", None)
        confirmation.pop("confirmed_at", None)
    revised["confirmation"] = confirmation
    return stamp_fingerprint(revised)


def revise_envelope_context(envelope, revised_context):
    """Put a revised context into a new envelope revision.

    The envelope revision moves and names the one it supersedes; the source
    fingerprint inside the context is left exactly as it was. Callers re-derive
    risks and readiness afterwards (readiness.derive_into).
    """
    updated = copy.deepcopy(envelope)
    previous = int(envelope.get("revision", 1))
    updated["revision"] = previous + 1
    updated["supersedes_revision"] = previous
    updated["context"] = copy.deepcopy(revised_context)
    return updated


# -------------------------------------------------------------------- scoping

def current_scope(context):
    """The scope the application is in today. Absent an explicit
    ``current_scope``, the first target scope is the primary confirmed
    target (schema wording) and is treated as current."""
    scope = context.get("current_scope")
    if scope:
        return dict(scope)
    targets = context.get("target_scopes") or []
    return dict(targets[0]) if targets else None


def resolve_environment(context, environment):
    """Standard environment an x_ extension inherits its semantics from."""
    if environment in environment_bands():
        return environment
    declared = (((context.get("extensions") or {}).get("environments") or {})
                .get(environment) or {})
    return declared.get("treat_as")


def resolve_intended_use(context, intended_use):
    if intended_use in intended_use_bands():
        return intended_use
    declared = (((context.get("extensions") or {}).get("intended_uses") or {})
                .get(intended_use) or {})
    return declared.get("treat_as")


def scope_bands(context, scope):
    """(environment band, intended-use band), or None when a value is an
    undeclared extension. Higher bands are more exposed."""
    environment = resolve_environment(context, scope.get("environment"))
    intended_use = resolve_intended_use(context, scope.get("intended_use"))
    if environment is None or intended_use is None:
        return None
    return (environment_bands()[environment], intended_use_bands()[intended_use])


def same_scope(a, b):
    return (a and b and a.get("environment") == b.get("environment")
            and a.get("intended_use") == b.get("intended_use"))


def more_exposed_scopes(context, scope):
    """Target scopes strictly more exposed than ``scope``, least first.

    A scope is more exposed when neither band is lower and at least one is
    higher; scopes that trade one band for another are not comparable and are
    left out rather than guessed at.
    """
    here = scope_bands(context, scope)
    if here is None:
        return []
    out = []
    for target in context.get("target_scopes") or []:
        if same_scope(target, scope):
            continue
        there = scope_bands(context, target)
        if there is None:
            continue
        if there[0] >= here[0] and there[1] >= here[1] and there != here:
            out.append((there, dict(target)))
    return [scope for _, scope in sorted(out, key=lambda pair: pair[0])]


# ------------------------------------------------------------------ freshness

def is_expired(context, now=None):
    """True when the context is past its own valid_until."""
    valid_until = parse_instant(context.get("valid_until"))
    return valid_until is not None and valid_until < instant(now)


def confirmation_state(context, now=None):
    """Effective confirmation state. An expired context is not confirmed any
    more, whatever it said when it was written. A human review also cannot
    count before its recorded confirmation time."""
    confirmation = context.get("confirmation") or {}
    state = confirmation.get("state") or "draft"
    now_dt = instant(now)
    if state == "human_reviewed":
        confirmed_at = parse_instant(confirmation.get("confirmed_at"))
        if confirmed_at is None or confirmed_at > now_dt:
            return "not_yet_confirmed"
    if state != "draft" and is_expired(context, now):
        return "expired"
    return state


def from_precheck(overview_state, fingerprint_result=None, confirmed_by=None,
                  confirmed_at=None):
    """Confirmation block from the precheck overview state (RFC §11.5).

    TECHNICAL_OVERVIEW.md states map straight across: DRAFT -> draft,
    HUMAN-REVIEWED -> human_reviewed, REVIEW-BYPASSED -> review_bypassed. The
    workspace fingerprint from precheck_fingerprint.py is stored as the source
    fingerprint, which is what makes context freshness and code freshness two
    separate questions.
    """
    states = {
        "DRAFT": "draft",
        "HUMAN-REVIEWED": "human_reviewed",
        "REVIEW-BYPASSED": "review_bypassed",
    }
    key = str(overview_state or "").strip().upper()
    if key not in states:
        raise ValueError("unknown technical overview state %r" % (overview_state,))
    confirmation = {"state": states[key]}
    if confirmed_by:
        confirmation["confirmed_by"] = confirmed_by
    if confirmed_at:
        confirmation["confirmed_at"] = confirmed_at
    if fingerprint_result:
        confirmation["source_fingerprint"] = (
            fingerprint_result.get("workspace_fingerprint")
            if isinstance(fingerprint_result, dict) else fingerprint_result)
    return confirmation


# ----------------------------------------------------------------- validation

def consistency_notes(context):
    """Contradictions between captured facts, as {code, message} entries.

    Checked against the scope the application is in *today*, never against the
    scopes it is heading for: intending to launch publicly is a plan, while
    being live in a developer-only environment is a contradiction, and only one
    of those means an answer is wrong. A contradiction is surfaced rather than
    averaged away, and it keeps readiness incomplete until someone resolves it.
    """
    notes = []
    scope = current_scope(context)
    if not scope:
        return notes
    environment = resolve_environment(context, scope.get("environment"))
    if environment is None:
        return notes

    lifecycle = field_value(context, "lifecycle")
    consistent = (dimensions()["lifecycle"].get("consistent_environments") or {})
    if lifecycle in consistent and environment not in consistent[lifecycle]:
        notes.append({
            "code": "lifecycle_environment_mismatch",
            "message": (
                "Lifecycle %r does not fit the current environment %r (expected "
                "one of %s). One of the two answers is wrong; readiness stays "
                "incomplete until the contradiction is resolved."
                % (lifecycle, scope.get("environment"),
                   ", ".join(consistent[lifecycle]))),
        })

    exposure = field_value(context, "network_exposure")
    if exposure in ("local_only", "private_network") and environment == "public_release":
        notes.append({
            "code": "exposure_environment_mismatch",
            "message": (
                "Network exposure %r contradicts the current environment "
                "public_release: either the deployment is reachable and the "
                "captured exposure is out of date, or it is not public at all."
                % exposure),
        })
    return notes


def validate_context(context):
    """Problems with the context record itself; empty list means usable.

    Called from canonical.validate_envelope, so every envelope check covers the
    context too.
    """
    problems = []
    model_dimensions = dimensions()

    named_model = context.get("context_model")
    if named_model and (named_model.get("name") != MODEL_NAME
                        or named_model.get("version") != MODEL_VERSION):
        problems.append(
            "context: profile resolves against context model %s %s, which this "
            "build does not carry (has %s %s)"
            % (named_model.get("name"), named_model.get("version"),
               MODEL_NAME, MODEL_VERSION))
        return problems

    for dimension_id, entry in sorted((context.get("profile") or {}).items()):
        where = "context.profile.%s" % dimension_id
        if dimension_id not in model_dimensions:
            if not dimension_id.startswith("x_"):
                problems.append(
                    "%s is not a dimension of context model %s %s (custom "
                    "dimensions must be x_-prefixed)"
                    % (where, MODEL_NAME, MODEL_VERSION))
            continue
        if not isinstance(entry, dict):
            problems.append("%s must be an object with a state" % where)
            continue
        state = entry.get("state")
        if state not in FIELD_STATES:
            problems.append("%s has state %r, expected one of %s"
                            % (where, state, ", ".join(FIELD_STATES)))
            continue
        allowed = value_ids(dimension_id)
        if state in ("confirmed", "inferred"):
            if entry.get("value") not in allowed:
                problems.append("%s has value %r, expected one of %s"
                                % (where, entry.get("value"), ", ".join(allowed)))
            if not entry.get("source"):
                problems.append("%s is %s but names no source" % (where, state))
            if state == "inferred" and not entry.get("rationale"):
                problems.append("%s is inferred but records no rationale" % where)
        elif state == "conflicting":
            candidates = entry.get("candidates") or []
            if len(candidates) < 2:
                problems.append("%s is conflicting but lists fewer than two "
                                "candidates" % where)
            for candidate in candidates:
                if candidate not in allowed:
                    problems.append("%s lists unknown candidate %r"
                                    % (where, candidate))
            if not entry.get("rationale"):
                problems.append("%s is conflicting but records no rationale" % where)
        elif "value" in entry:
            problems.append("%s is unknown but still carries a value: unknown "
                            "must never read as an answer" % where)

    scopes = list(context.get("target_scopes") or [])
    explicit_current = context.get("current_scope")
    if explicit_current and not any(same_scope(explicit_current, s) for s in scopes):
        problems.append("context.current_scope is not one of the target scopes")
    for scope in scopes + ([explicit_current] if explicit_current else []):
        for key, resolve in (("environment", resolve_environment),
                             ("intended_use", resolve_intended_use)):
            value = scope.get(key)
            if value is not None and resolve(context, value) is None:
                problems.append(
                    "context: %s %r is an undeclared extension; declare it in "
                    "context.extensions with a conservative treat_as (RFC §4.1)"
                    % (key, value))

    for i, measure in enumerate(context.get("compensating_controls") or []):
        where = "context.compensating_controls[%d]" % i
        applies = measure.get("applies_to") or {}
        if not (applies.get("control_ids") or applies.get("domains")):
            problems.append(
                "%s names no control or domain it applies to; a compensating "
                "control with unstated scope reduces nothing (R7)" % where)
        if not (measure.get("enforced_by") or "").strip():
            problems.append("%s has no enforcing mechanism or person (R7)" % where)

    confirmation = context.get("confirmation") or {}
    if confirmation.get("state") == "human_reviewed" and not (
            confirmation.get("confirmed_by") and confirmation.get("confirmed_at")):
        problems.append("context.confirmation is human_reviewed but does not "
                        "record who confirmed it and when")
    elif (confirmation.get("state") == "human_reviewed"
          and parse_instant(confirmation.get("confirmed_at")) is None):
        problems.append("context.confirmation.confirmed_at is not a parseable "
                        "timezone-aware timestamp")
    return problems
