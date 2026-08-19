# -*- coding: utf-8 -*-
"""Action / Procedure registry semantics.

The JSON Schema describes record shape.  This module enforces the relations
that a structural schema cannot express: revision lineages, lifecycle
transitions, dependency cycles, exact-attempt consent, observed effects being
inside the authorized scope, evidence-backed completion, and the staged
remediation checkpoints — patch, deploy, verify — that a remediation touching a
running system has to pass one at a time (rule R21).

AUTO / PROPOSE / ADVISORY is intentionally only a lossy derived display view.
It is never read to decide whether a Procedure may execute.
"""
import copy
import json
import os
import re

import context as ctx

POLICY_NAME = "vibecheck.action_policy"
REGISTRY_NAME = "vibecheck.action_registry"
REGISTRY_VERSION = "1.0.0"

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POLICY_PATH = os.path.join(REPO_ROOT, "schema", "action-policy.v1.json")

_POLICY = None


def load_policy():
    global _POLICY
    if _POLICY is None:
        with open(POLICY_PATH, encoding="utf-8") as fh:
            _POLICY = json.load(fh)
    return _POLICY


def registry_ref():
    return {"name": REGISTRY_NAME, "version": REGISTRY_VERSION}


def _version_tuple(value):
    try:
        return tuple(int(part) for part in str(value).split("."))
    except (TypeError, ValueError):
        return (0,)


def is_modern(envelope):
    return _version_tuple(envelope.get("schema_version")) >= (1, 3, 0)


def _index(items, key):
    return {item.get(key): item for item in items or [] if item.get(key)}


def _lineage_heads(items, id_key):
    superseded = {item.get("supersedes") for item in items or []
                  if item.get("supersedes")}
    return [item for item in items or [] if item.get(id_key) not in superseded]


def current_actions(envelope):
    return _lineage_heads(envelope.get("actions"), "action_id")


def current_procedures(envelope):
    return _lineage_heads(envelope.get("procedures"), "procedure_id")


def is_open(action):
    return action.get("state") in load_policy()["open_states"]


def open_escalation_controls(envelope):
    """Controls a live specialist escalation Action already covers.

    Only open Actions count. A done or rejected escalation stops covering the
    control it escalated, so an assessment still reading needs_specialist
    reappears as a screening row instead of falling between the two disclosure
    sets: the Action is no longer open and the assessment looked handled
    (rule R12).
    """
    return {
        control_id
        for action in current_actions(envelope)
        if is_open(action)
        and (action.get("kind") == "escalate"
             or (action.get("owner") or {}).get("role") == "specialist")
        for control_id in action.get("control_refs") or []
    }


def _effect_scope(record):
    if not isinstance(record, dict):
        return {}, set()
    flags = {key: bool(record.get(key))
             for key in load_policy()["effect_flags"]}
    return flags, set(record.get("targets") or [])


def _covers_target(outer, inner):
    """Is `inner` the same effect target as `outer`, or a part of it?

    Procedures declare the scope they may touch ("current source tree"); an
    authorization narrows it to the exact targets it grants, and an attempt
    reports what it actually touched. Plain set containment would force all
    three to repeat one string, which makes the narrowest and most useful
    statement — the exact target — impossible to record.
    """
    if inner == outer:
        return True
    separators = load_policy()["effect_target_refinement"]["separators"]
    return any(inner.startswith(outer + separator) for separator in separators)


def _inside_effect_scope(inner, outer):
    inner_flags, inner_targets = _effect_scope(inner)
    outer_flags, outer_targets = _effect_scope(outer)
    for key, happened in inner_flags.items():
        if happened and not outer_flags.get(key):
            return False, key
    extra_targets = [target for target in sorted(inner_targets)
                     if not any(_covers_target(outer_target, target)
                                for outer_target in outer_targets)]
    if extra_targets:
        return False, "targets %s" % ", ".join(extra_targets)
    inner_destinations = set((inner or {}).get("data_egress_destinations") or [])
    outer_destinations = set((outer or {}).get("data_egress_destinations") or [])
    extra_destinations = inner_destinations - outer_destinations
    if extra_destinations:
        return False, "data-egress destinations %s" % ", ".join(
            sorted(extra_destinations))
    return True, None


def _validate_lineages(items, id_key, key_key, label, problems):
    by_id = _index(items, id_key)
    children = {}
    for item in items or []:
        if item.get("supersedes") and item.get(id_key):
            children.setdefault(item["supersedes"], []).append(item.get(id_key))
    for previous_id, next_ids in sorted(children.items()):
        if len(next_ids) > 1:
            problems.append(
                "R13: %s %s has competing successor revisions %s"
                % (label, previous_id, ", ".join(sorted(next_ids))))
        if label == "action" and previous_id in by_id and (
                by_id[previous_id].get("state") != "superseded"):
            problems.append(
                "R16: superseded action revision %s must have state superseded"
                % previous_id)
    for item in items or []:
        item_id = item.get(id_key, "<missing id>")
        previous_id = item.get("supersedes")
        if not previous_id:
            if item.get("revision") is not None and item.get("revision") != 1:
                problems.append(
                    "R13: root %s %s must start at revision 1"
                    % (label, item_id))
            continue
        if previous_id not in by_id:
            problems.append(
                "R13: %s %s supersedes missing revision %s"
                % (label, item_id, previous_id))
            continue
        previous = by_id[previous_id]
        if item.get(key_key) != previous.get(key_key):
            problems.append(
                "R13: %s %s supersedes %s from a different %s"
                % (label, item_id, previous_id, key_key))
        if item.get("revision") != previous.get("revision", 0) + 1:
            problems.append(
                "R13: %s %s revision must be exactly one above %s"
                % (label, item_id, previous_id))
        before = ctx.parse_instant(previous.get("created_at"))
        after = ctx.parse_instant(item.get("created_at"))
        if before is not None and after is not None and after <= before:
            problems.append(
                "R13: %s %s must be created after superseded %s"
                % (label, item_id, previous_id))
        seen = {item_id}
        cursor = previous
        while cursor.get("supersedes") in by_id:
            cursor_id = cursor["supersedes"]
            if cursor_id in seen:
                problems.append("R13: %s lineage cycle reaches %s"
                                % (label, cursor_id))
                break
            seen.add(cursor_id)
            cursor = by_id[cursor_id]
    heads_by_key = {}
    for head in _lineage_heads(items, id_key):
        heads_by_key.setdefault(head.get(key_key), []).append(head.get(id_key))
    for lineage_key, head_ids in sorted(heads_by_key.items(), key=lambda pair: str(pair[0])):
        if lineage_key and len(head_ids) > 1:
            problems.append(
                "R13: %s lineage %s has multiple current revisions %s"
                % (label, lineage_key, ", ".join(sorted(head_ids))))
    if label == "action":
        for item in items or []:
            item_id = item.get(id_key)
            if item.get("state") == "superseded" and item_id not in children:
                problems.append(
                    "R16: superseded action revision %s has no successor"
                    % item_id)


def _validate_history(action, problems):
    action_id = action.get("action_id", "<missing id>")
    history = action.get("state_history") or []
    if not history:
        problems.append("R16: action %s has no state_history" % action_id)
        return
    policy = load_policy()["lifecycle"]
    if history[0].get("state") != policy["initial_state"]:
        problems.append("R16: action %s state_history must start at open" % action_id)
    if history[-1].get("state") != action.get("state"):
        problems.append(
            "R16: action %s state does not match final state_history entry"
            % action_id)
    last_at = None
    created_at = ctx.parse_instant(action.get("created_at"))
    for index, entry in enumerate(history):
        at = ctx.parse_instant(entry.get("at"))
        if index == 0 and created_at is not None and at is not None and at < created_at:
            problems.append(
                "R16: action %s state_history starts before the Action was created"
                % action_id)
        if at is not None and last_at is not None and at < last_at:
            problems.append(
                "R16: action %s state_history timestamps go backwards"
                % action_id)
        if at is not None:
            last_at = at
        if index:
            before = history[index - 1].get("state")
            after = entry.get("state")
            if after not in policy["transitions"].get(before, []):
                problems.append(
                    "R16: action %s has invalid state transition %s -> %s"
                    % (action_id, before, after))
    if action.get("state") == "rejected" and not (
            history[-1].get("decision_ref") or history[-1].get("note")):
        problems.append(
            "R16: rejected action %s needs a recorded decision" % action_id)


def _validate_dependencies(envelope, problems):
    current = _index(current_actions(envelope), "action_id")
    all_ids = set(_index(envelope.get("actions"), "action_id"))
    graph = {action_id: [ref for ref in action.get("depends_on") or []
                         if ref in current]
             for action_id, action in current.items()}
    visiting, visited = set(), set()

    def visit(action_id):
        if action_id in visiting:
            problems.append("R16: action dependency cycle reaches %s" % action_id)
            return
        if action_id in visited:
            return
        visiting.add(action_id)
        for dependency in graph.get(action_id, []):
            visit(dependency)
        visiting.remove(action_id)
        visited.add(action_id)

    for action_id in sorted(graph):
        stale = [ref for ref in current[action_id].get("depends_on") or []
                 if ref in all_ids and ref not in current]
        if stale:
            problems.append(
                "R16: action %s depends on superseded revisions %s"
                % (action_id, ", ".join(sorted(stale))))
        if action_id in graph[action_id]:
            problems.append("R16: action %s depends on itself" % action_id)
        visit(action_id)
        action = current[action_id]
        if action.get("state") == "done":
            unfinished = [ref for ref in graph[action_id]
                          if current[ref].get("state") != "done"]
            if unfinished:
                problems.append(
                    "R16: done action %s has unfinished dependencies %s"
                    % (action_id, ", ".join(sorted(unfinished))))


def _validate_offered_procedures(envelope, problems):
    """An Action must offer current Procedure revisions, like its dependencies.

    A superseded revision left in `procedure_refs` disappears from the derived
    legacy view, so an Action with three revised methods would read as having
    no executable method at all. Dangling refs stay R1's job.
    """
    current_ids = {procedure.get("procedure_id")
                   for procedure in current_procedures(envelope)}
    all_ids = set(_index(envelope.get("procedures"), "procedure_id"))
    for action in current_actions(envelope):
        stale = [ref for ref in action.get("procedure_refs") or []
                 if ref in all_ids and ref not in current_ids]
        if stale:
            problems.append(
                "R16: action %s offers superseded procedure revisions %s"
                % (action.get("action_id", "<missing id>"),
                   ", ".join(sorted(stale))))


def _validate_deadline(action, problems, modern):
    action_id = action.get("action_id", "<missing id>")
    deadline = action.get("deadline") or {}
    kind, value = deadline.get("kind"), deadline.get("value")
    if kind == "before_environment" and value not in (
            "developer_only", "private_test", "public_release"):
        problems.append("R17: action %s has invalid environment deadline %r"
                        % (action_id, value))
    if kind == "before_intended_use" and value not in (
            "prototype_demo", "internal_tool", "invite_only_pilot",
            "public_product", "sensitive_or_high_impact"):
        problems.append("R17: action %s has invalid intended-use deadline %r"
                        % (action_id, value))
    if kind == "calendar_date" and ctx.parse_instant(value) is None:
        problems.append("R17: action %s has an unreadable calendar deadline"
                        % action_id)
    if kind in ("immediate", "none", "unknown") and value is not None:
        problems.append("R17: action %s deadline kind %s may not carry value"
                        % (action_id, kind))
    blocking = action.get("blocking_scope") or []
    if modern and kind == "before_environment" and not any(
            scope.get("environment") == value for scope in blocking):
        problems.append(
            "R17: action %s deadline names environment %s but blocking_scope does not"
            % (action_id, value))
    if modern and kind == "before_intended_use" and not any(
            scope.get("intended_use") == value for scope in blocking):
        problems.append(
            "R17: action %s deadline names intended use %s but blocking_scope does not"
            % (action_id, value))


def _validate_attempt(attempt, actions, procedures, problems, modern):
    attempt_id = attempt.get("attempt_id", "<missing id>")
    action = actions.get(attempt.get("action_ref"))
    procedure = procedures.get(attempt.get("procedure_ref"))
    if action is None or procedure is None:
        return  # R1 reports dangling refs
    if procedure.get("procedure_id") not in (action.get("procedure_refs") or []):
        problems.append(
            "R18: attempt %s uses procedure %s not offered by action %s"
            % (attempt_id, procedure.get("procedure_id"), action.get("action_id")))

    authorization = attempt.get("authorization") or {}
    if modern and authorization.get("attempt_ref") != attempt_id:
        problems.append(
            "R18: attempt %s authorization is not bound to that exact attempt"
            % attempt_id)
    granted = ctx.parse_instant(authorization.get("granted_at"))
    started = ctx.parse_instant(attempt.get("started_at"))
    expires = ctx.parse_instant(authorization.get("expires_at"))
    finished = ctx.parse_instant(attempt.get("finished_at"))
    if granted is not None and started is not None and started < granted:
        problems.append("R18: attempt %s started before consent was granted"
                        % attempt_id)
    if expires is not None and started is not None and started > expires:
        problems.append("R18: attempt %s used expired consent" % attempt_id)
    if granted is not None and expires is not None and expires < granted:
        problems.append("R18: attempt %s consent expires before it was granted"
                        % attempt_id)
    if started is not None and finished is not None and finished < started:
        problems.append("R18: attempt %s finished before it started" % attempt_id)
    for record, label in ((action, "Action"), (procedure, "Procedure")):
        created = ctx.parse_instant(record.get("created_at"))
        if created is not None and granted is not None and granted < created:
            problems.append(
                "R18: attempt %s consent predates its exact %s revision"
                % (attempt_id, label))
        if created is not None and started is not None and started < created:
            problems.append(
                "R18: attempt %s started before its %s revision existed"
                % (attempt_id, label))

    policy = (procedure.get("authorization") or {}).get("consent")
    mode = authorization.get("mode")
    if policy == "explicit_consent_per_run" and mode != "explicit_consent":
        problems.append(
            "R18: attempt %s needs fresh explicit consent for this run"
            % attempt_id)
    if policy == "not_required" and mode != "not_required":
        problems.append(
            "R18: attempt %s must record not_required consent mode" % attempt_id)
    if policy in ("explicit_consent", "explicit_consent_per_run") and mode == "not_required":
        problems.append(
            "R18: attempt %s cannot bypass the procedure consent policy"
            % attempt_id)

    authorized = authorization.get("effects") or {}
    authorized_destinations = authorized.get("data_egress_destinations") or []
    if modern and bool(authorized.get("data_egress")) != bool(
            authorized_destinations):
        problems.append(
            "R18: attempt %s authorization must pair data egress with exact destinations"
            % attempt_id)
    planned = copy.deepcopy(procedure.get("effects") or {})
    planned["data_egress"] = bool((procedure.get("data_egress") or {}).get("occurs"))
    planned["data_egress_destinations"] = list(
        (procedure.get("data_egress") or {}).get("destinations") or [])
    inside, detail = _inside_effect_scope(authorized, planned)
    if not inside:
        problems.append(
            "R18: attempt %s authorizes effects outside procedure scope: %s"
            % (attempt_id, detail))
    observed = attempt.get("side_effects_observed") or {}
    observed_destinations = observed.get("data_egress_destinations") or []
    if modern and bool(observed.get("data_egress")) != bool(
            observed_destinations):
        problems.append(
            "R18: attempt %s observed data egress must name exact destinations"
            % attempt_id)
    inside, detail = _inside_effect_scope(observed, authorized)
    if not inside:
        problems.append(
            "R18: attempt %s observed unauthorized side effects: %s"
            % (attempt_id, detail))

    rollback = attempt.get("rollback") or {}
    observed_flags, _targets = _effect_scope(observed)
    effectful = any(observed_flags.values())
    if (attempt.get("result") in ("failed", "partially_succeeded", "aborted")
            and effectful
            and (procedure.get("effects") or {}).get("reversibility") != "irreversible"
            and rollback.get("state") == "not_needed"):
        problems.append(
            "R18: attempt %s had side effects but says rollback was not needed"
            % attempt_id)


def _validate_procedure(procedure, modern, problems):
    procedure_id = procedure.get("procedure_id", "<missing id>")
    effects = copy.deepcopy(procedure.get("effects") or {})
    effects["data_egress"] = bool(
        (procedure.get("data_egress") or {}).get("occurs"))
    flags, _targets = _effect_scope(effects)
    consent = (procedure.get("authorization") or {}).get("consent")
    network_required = bool((procedure.get("network") or {}).get("required"))
    legacy_effectful = any(value for key, value in flags.items()
                           if key != "data_egress")
    needs_consent = legacy_effectful or (modern and (
        flags.get("data_egress") or network_required))
    if needs_consent and consent not in (
            "explicit_consent", "explicit_consent_per_run"):
        problems.append(
            "R18: effectful or networked procedure %s requires explicit consent"
            % procedure_id)
    if modern and consent in ("explicit_consent", "explicit_consent_per_run") and not (
            procedure.get("authorization") or {}).get("scope"):
        problems.append(
            "R18: procedure %s explicit consent policy needs a bounded scope"
            % procedure_id)
    if modern and network_required and not (
            procedure.get("network") or {}).get("destinations"):
        problems.append(
            "R18: networked procedure %s must name its destinations" % procedure_id)
    if modern and effects["data_egress"] and not (
            procedure.get("data_egress") or {}).get("destinations"):
        problems.append(
            "R18: procedure %s data egress must name its destinations"
            % procedure_id)
    if modern and not effects["data_egress"] and (
            procedure.get("data_egress") or {}).get("destinations"):
        problems.append(
            "R18: procedure %s names data-egress destinations while egress is disabled"
            % procedure_id)
    if modern and effects["data_egress"] and not network_required:
        problems.append(
            "R18: procedure %s cannot declare data egress without network access"
            % procedure_id)
    if modern and (procedure.get("verification") or {}).get(
            "independent_from_executor") is not True:
        problems.append(
            "R19: procedure %s must define independent verification"
            % procedure_id)
    if modern and not (procedure.get("verification") or {}).get("provider"):
        problems.append(
            "R19: procedure %s must name its verification provider"
            % procedure_id)
    legacy_ref = procedure.get("verification_provider_ref")
    modern_ref = (procedure.get("verification") or {}).get("provider_ref")
    if legacy_ref and modern_ref and legacy_ref != modern_ref:
        problems.append(
            "R19: procedure %s has conflicting verification provider refs"
            % procedure_id)


def stage_policy():
    """The staged-remediation policy: which checkpoints exist, in which order."""
    return load_policy().get("remediation_stages") or {"order": [], "stages": {}}


def _validate_stage_procedure(procedure, problems):
    """A Procedure that claims a checkpoint must actually be that checkpoint."""
    stage = procedure.get("stage")
    if stage is None:
        return
    procedure_id = procedure.get("procedure_id", "<missing id>")
    policy = stage_policy()
    spec = (policy.get("stages") or {}).get(stage)
    if spec is None:
        problems.append("R21: procedure %s declares unknown remediation stage %r"
                        % (procedure_id, stage))
        return
    effects = procedure.get("effects") or {}
    for flag in spec.get("required_effects") or []:
        if not effects.get(flag):
            problems.append(
                "R21: %s procedure %s must declare the %s effect it performs"
                % (stage, procedure_id, flag))
    for flag in spec.get("forbidden_effects") or []:
        if effects.get(flag):
            problems.append(
                "R21: %s procedure %s declares the %s effect, which belongs to "
                "a separate checkpoint" % (stage, procedure_id, flag))
    allowed_consent = spec.get("consent")
    consent = (procedure.get("authorization") or {}).get("consent")
    if allowed_consent and consent not in allowed_consent:
        problems.append(
            "R21: %s procedure %s needs consent %s, not %r"
            % (stage, procedure_id, " or ".join(allowed_consent), consent))
    if spec.get("requires_independent_verification") and not (
            procedure.get("verification") or {}).get("independent_from_executor"):
        problems.append(
            "R21: %s procedure %s must be verified independently of whoever "
            "made and deployed the change" % (stage, procedure_id))


def _validate_stage_attempt(attempt, procedure, problems):
    """Diff-first for patches, a named target and revision for deployments."""
    stage = procedure.get("stage")
    spec = (stage_policy().get("stages") or {}).get(stage)
    if not spec:
        return
    attempt_id = attempt.get("attempt_id", "<missing id>")
    started = ctx.parse_instant(attempt.get("started_at"))

    if spec.get("requires_change_control"):
        change_control = attempt.get("change_control") or {}
        if not (change_control.get("diff_ref") or {}).get("value"):
            problems.append(
                "R21: %s attempt %s must record the exact diff that was shown "
                "before authorization" % (stage, attempt_id))
        if not change_control.get("branch"):
            problems.append(
                "R21: %s attempt %s must record the branch it wrote to; "
                "repository changes are branch-first" % (stage, attempt_id))
        if not change_control.get("approved_by"):
            problems.append(
                "R21: %s attempt %s must record who approved the diff"
                % (stage, attempt_id))
        approved = ctx.parse_instant(change_control.get("approved_at"))
        if approved is None:
            problems.append(
                "R21: %s attempt %s must record when the diff was approved"
                % (stage, attempt_id))
        elif started is not None and approved > started:
            problems.append(
                "R21: %s attempt %s was approved after it started; diff-first "
                "means the approval precedes the change" % (stage, attempt_id))

    if spec.get("requires_execution_context"):
        execution_context = attempt.get("execution_context") or {}
        forbidden = spec.get("forbidden_execution_context_kinds") or []
        if execution_context.get("kind") in forbidden:
            problems.append(
                "R21: %s attempt %s ran in execution context %r; a deployment "
                "has to name the running environment it changed"
                % (stage, attempt_id, execution_context.get("kind")))
        if not execution_context.get("source_ref"):
            problems.append(
                "R21: %s attempt %s must record the exact revision it deployed"
                % (stage, attempt_id))
        if attempt.get("result") == "succeeded" and not (
                attempt.get("side_effects_observed") or {}).get("deployment"):
            problems.append(
                "R21: %s attempt %s succeeded without observing a deployment "
                "effect" % (stage, attempt_id))


def _staged_attempts(envelope, action_id, stage, procedures):
    """Succeeded attempts of one checkpoint for one Action, oldest first."""
    selected = []
    for attempt in envelope.get("attempts") or []:
        if attempt.get("action_ref") != action_id:
            continue
        if attempt.get("result") != "succeeded":
            continue
        procedure = procedures.get(attempt.get("procedure_ref")) or {}
        if procedure.get("stage") != stage:
            continue
        selected.append(attempt)

    def order(item):
        # Compare instants, not their spellings: the same moment written with a
        # numeric offset and with Z does not sort chronologically as text.
        at = (ctx.parse_instant(item.get("finished_at"))
              or ctx.parse_instant(item.get("started_at")))
        return (at is None, at or ctx.instant("1970-01-01T00:00:00Z"),
                str(item.get("attempt_id")))

    return sorted(selected, key=order)


def _verification_provider_matches(procedure, record):
    expected = procedure.get("verification") or {}
    actual = record.get("provider") or {}
    if expected.get("provider_ref"):
        return actual.get("provider_ref") == expected["provider_ref"]
    return bool(expected.get("provider")
                and actual.get("name") == expected.get("provider"))


def _qualifying_stage_evidence(attempt, procedure, spec, evidence,
                               previous_attempt=None):
    """Evidence refs that actually establish this remediation checkpoint."""
    records = [evidence[ref] for ref in attempt.get("evidence_refs") or []
               if ref in evidence]
    if not records:
        return []

    forbidden = set(spec.get("forbidden_evidence_operations") or [])
    if forbidden:
        records = [record for record in records
                   if record.get("operation") not in forbidden]

    if spec.get("evidence_provider_must_match_procedure"):
        records = [record for record in records
                   if _verification_provider_matches(procedure, record)]

    if spec.get("evidence_environment_must_match_previous"):
        # A standalone verification Action has no deployment checkpoint. When
        # this stage is part of a remediation chain, however, both the attempt
        # and its evidence must target that deployment's environment.
        if previous_attempt is not None:
            target_environment = previous_attempt.get("execution_environment")
            if (not target_environment
                    or attempt.get("execution_environment") != target_environment):
                return []
            records = [record for record in records
                       if record.get("environment") == target_environment]

    if previous_attempt is not None:
        previous_finished = (
            ctx.parse_instant(previous_attempt.get("finished_at"))
            or ctx.parse_instant(previous_attempt.get("started_at")))
        if previous_finished is None:
            return []
        records = [record for record in records
                   if ctx.parse_instant(record.get("observed_at")) is not None
                   and ctx.parse_instant(record.get("observed_at"))
                   >= previous_finished]
    return [record.get("evidence_id") for record in records]


def _validate_required_stages(envelope, problems):
    """R21: an Action completes one checkpoint at a time, in order."""
    policy = stage_policy()
    order = policy.get("order") or []
    known = policy.get("stages") or {}
    procedures = _index(envelope.get("procedures"), "procedure_id")
    evidence = _index(envelope.get("evidence"), "evidence_id")

    for action in current_actions(envelope):
        stages = action.get("required_stages") or []
        if not stages:
            continue
        action_id = action.get("action_id", "<missing id>")
        unknown = [stage for stage in stages if stage not in known]
        if unknown:
            problems.append("R21: action %s requires unknown stage(s) %s"
                            % (action_id, ", ".join(sorted(unknown))))
        ordered = [stage for stage in order if stage in stages]
        if [stage for stage in stages if stage in order] != ordered:
            problems.append(
                "R21: action %s lists its stages out of order; the checkpoints "
                "run %s" % (action_id, " -> ".join(order)))
        offered = {(procedures.get(ref) or {}).get("stage")
                   for ref in action.get("procedure_refs") or []}
        for stage in ordered:
            if stage not in offered:
                problems.append(
                    "R21: action %s requires the %s checkpoint but offers no "
                    "Procedure that performs it" % (action_id, stage))

        if action.get("state") != "done":
            continue
        cursor, chosen = None, {}
        for stage in ordered:
            spec = known.get(stage) or {}
            previous = chosen.get(spec.get("must_follow"))
            candidates = _staged_attempts(
                envelope, action_id, stage, procedures)
            usable = None
            for attempt in candidates:
                started = ctx.parse_instant(attempt.get("started_at"))
                if cursor is not None and started is not None and started < cursor:
                    continue
                procedure = procedures.get(attempt.get("procedure_ref")) or {}
                if not _qualifying_stage_evidence(
                        attempt, procedure, spec, evidence, previous):
                    continue
                usable = attempt
                break
            if usable is None:
                live_detail = (
                    "; live verification needs fresh non-static evidence from "
                    "the Procedure's verification provider, observed in the "
                    "same environment as the deployment"
                    if stage == "live_verification" else "")
                problems.append(
                    "R21: done action %s has no succeeded %s attempt with "
                    "qualifying evidence%s%s"
                    % (action_id, stage,
                       "; a repository patch that was never deployed changes "
                       "nothing in the reviewed environment"
                       if stage == "deployment" else "",
                       live_detail))
                cursor = None
                continue
            chosen[stage] = usable
            cursor = (ctx.parse_instant(usable.get("finished_at"))
                      or ctx.parse_instant(usable.get("started_at")))


def _has_fresh_completion_chain(attempt, action, evidence, assessments):
    started = ctx.parse_instant(attempt.get("started_at"))
    finished = ctx.parse_instant(attempt.get("finished_at")) or started
    if started is None or finished is None:
        return False
    fresh_evidence = {}
    for ref in attempt.get("evidence_refs") or []:
        record = evidence.get(ref)
        observed = ctx.parse_instant((record or {}).get("observed_at"))
        if record is not None and observed is not None and observed >= started:
            fresh_evidence[ref] = observed
    if not fresh_evidence:
        return False
    expected_controls = set(action.get("reassess_control_ids") or [])
    for ref in attempt.get("reassessment_refs") or []:
        assessment = assessments.get(ref)
        assessed_at = ctx.parse_instant((assessment or {}).get("assessed_at"))
        cited = set(((assessment or {}).get("basis") or {}).get(
            "evidence_refs") or []) & set(fresh_evidence)
        if assessment is None or assessed_at is None or assessed_at < finished:
            continue
        if expected_controls and assessment.get("control_id") not in expected_controls:
            continue
        if cited and all(fresh_evidence[evidence_ref] <= assessed_at
                         for evidence_ref in cited):
            return True
    return False


def _validate_completion(envelope, problems):
    attempts = envelope.get("attempts") or []
    evidence = _index(envelope.get("evidence"), "evidence_id")
    assessments = _index(envelope.get("assessments"), "assessment_id")
    for action in current_actions(envelope):
        if action.get("state") != "done":
            continue
        candidates = [attempt for attempt in attempts
                      if attempt.get("action_ref") == action.get("action_id")
                      and attempt.get("result") == "succeeded"
                      and attempt.get("evidence_refs")
                      and attempt.get("reassessment_refs")
                      and _has_fresh_completion_chain(
                          attempt, action, evidence, assessments)]
        if not candidates:
            problems.append(
                "R19: done action %s has no succeeded attempt with a fresh, "
                "cited evidence-to-reassessment chain; failed/partial attempts "
                "never complete it"
                % action.get("action_id"))


def validate_registry(envelope):
    """Return semantic Action/Procedure/Attempt problems for an envelope."""
    problems = []
    actions = envelope.get("actions") or []
    procedures = envelope.get("procedures") or []
    attempts = envelope.get("attempts") or []
    modern = is_modern(envelope)
    if modern and (actions or procedures or attempts):
        if envelope.get("action_registry") != registry_ref():
            problems.append(
                "R16: schema 1.3 action records require action_registry %s %s"
                % (REGISTRY_NAME, REGISTRY_VERSION))
        for action in actions:
            for field in ("action_key", "revision", "created_at", "priority"):
                if field not in action:
                    problems.append("R16: action %s requires %s"
                                    % (action.get("action_id", "<missing id>"), field))
            deadline = action.get("deadline") or {}
            if "reassess_trigger" not in deadline:
                problems.append("R17: action %s deadline requires reassess_trigger"
                                % action.get("action_id", "<missing id>"))
        for procedure in procedures:
            for field in ("procedure_key", "revision", "created_at",
                          "execution_mode", "network", "verification"):
                if field not in procedure:
                    problems.append("R18: procedure %s requires %s"
                                    % (procedure.get("procedure_id", "<missing id>"), field))
        for attempt in attempts:
            for field in ("execution_environment", "execution_context", "input_refs",
                          "finished_at",
                          "side_effects_observed", "rollback"):
                if field not in attempt:
                    problems.append("R18: attempt %s requires %s"
                                    % (attempt.get("attempt_id", "<missing id>"), field))
            authorization = attempt.get("authorization") or {}
            for field in ("authorization_id", "attempt_ref", "record", "effects"):
                if not authorization.get(field):
                    problems.append("R18: attempt %s authorization requires %s"
                                    % (attempt.get("attempt_id", "<missing id>"), field))

    _validate_lineages(actions, "action_id", "action_key", "action", problems)
    _validate_lineages(procedures, "procedure_id", "procedure_key",
                       "procedure", problems)
    for action in actions:
        _validate_history(action, problems)
        _validate_deadline(action, problems, modern)
    for procedure in procedures:
        _validate_procedure(procedure, modern, problems)
        _validate_stage_procedure(procedure, problems)
    _validate_dependencies(envelope, problems)
    _validate_offered_procedures(envelope, problems)
    by_action = _index(actions, "action_id")
    by_procedure = _index(procedures, "procedure_id")
    for attempt in attempts:
        _validate_attempt(attempt, by_action, by_procedure, problems, modern)
        procedure = by_procedure.get(attempt.get("procedure_ref"))
        if procedure is not None:
            _validate_stage_attempt(attempt, procedure, problems)
    _validate_required_stages(envelope, problems)
    authorization_ids = [
        (attempt.get("authorization") or {}).get("authorization_id")
        for attempt in attempts
        if (attempt.get("authorization") or {}).get("authorization_id")]
    duplicates = sorted({auth_id for auth_id in authorization_ids
                         if authorization_ids.count(auth_id) > 1})
    for auth_id in duplicates:
        problems.append(
            "R18: authorization %s is reused across attempts; consent is single-attempt"
            % auth_id)
    _validate_completion(envelope, problems)
    return problems


def _current_assessments(envelope):
    items = envelope.get("assessments") or []
    superseded = {item.get("supersedes") for item in items
                  if item.get("supersedes")}
    return [item for item in items
            if item.get("assessment_id") not in superseded]


def materialize_specialist_actions(envelope, now=None):
    """Give each current needs_specialist assessment one schedulable Action.

    Pre-Increment-4 reports exposed these assessment refs directly because no
    Action existed yet.  The Action is deterministic and only states the
    escalation already decided by the assessment; it does not invent a
    specialist conclusion or a Procedure.
    """
    updated = copy.deepcopy(envelope)
    now_text = ctx.iso(ctx.instant(now))
    covered_controls = open_escalation_controls(updated)
    actions = updated.setdefault("actions", [])
    taken = {key: {action.get(key) for action in actions}
             for key in ("action_id", "action_key")}
    for assessment in sorted(_current_assessments(updated),
                             key=lambda item: item.get("assessment_id", "")):
        if assessment.get("status") != "needs_specialist":
            continue
        control_id = assessment.get("control_id")
        if not control_id or control_id in covered_controls:
            continue
        suffix = re.sub(r"[^A-Za-z0-9._:-]+", "-",
                        assessment["assessment_id"].removeprefix("asm-"))
        action_id = "act-escalate-%s-v1" % suffix
        action_key = "escalate-%s" % suffix.lower()
        if action_id in taken["action_id"] or action_key in taken["action_key"]:
            # A closed escalation for this control already exists under the
            # derived identity. Re-deriving must not fork its lineage; the
            # assessment stays visible as a screening row instead.
            continue
        taken["action_id"].add(action_id)
        taken["action_key"].add(action_key)
        actions.append({
            "action_id": action_id,
            "action_key": action_key,
            "revision": 1,
            "created_at": now_text,
            "kind": "escalate",
            "outcome": ("A qualified specialist records a scoped decision for %s "
                        "and the control is reassessed."
                        % control_id),
            "reason": ("Assessment %s is needs_specialist; the escalation must "
                       "be scheduled instead of remaining a report-only label."
                       % assessment["assessment_id"]),
            "priority": "unknown",
            "urgency": "next",
            "deadline": {
                "kind": "unknown",
                "rationale": ("The specialist deadline depends on the confirmed "
                              "use and applicable obligation."),
                "reassess_trigger": {"kind": "context_change"},
            },
            "blocking_scope": [],
            "owner": {"role": "specialist"},
            "state": "open",
            "state_history": [{
                "state": "open", "at": now_text,
                "by": "vibecheck action registry",
            }],
            "control_refs": [control_id],
            "success_evidence": (
                "The specialist's scoped decision, its assumptions, and a "
                "superseding assessment that cites it."),
            "reassess_control_ids": [control_id],
        })
        covered_controls.add(control_id)
    if is_modern(updated) and actions:
        updated.setdefault("action_registry", registry_ref())
    return updated


def is_overdue(action, now=None):
    deadline = action.get("deadline") or {}
    if deadline.get("kind") != "calendar_date":
        return False
    due = ctx.parse_instant(deadline.get("value"))
    now_dt = ctx.instant(now)
    return due is None or due < now_dt


def deadline_label_id(action, now=None):
    deadline = action.get("deadline") or {}
    kind = deadline.get("kind")
    value = deadline.get("value") or ""
    urgency = action.get("urgency")
    overdue = is_overdue(action, now)
    for rule in load_policy()["deadline_labels"]["rules"]:
        checks = []
        if "urgencies" in rule:
            checks.append(urgency in rule["urgencies"])
        if "deadline_kinds" in rule:
            checks.append(kind in rule["deadline_kinds"])
        if "deadline_values" in rule:
            checks.append(value in rule["deadline_values"])
        if "value_tokens" in rule:
            checks.append(any(token in value.lower()
                              for token in rule["value_tokens"]))
        if "overdue" in rule:
            checks.append(overdue == rule["overdue"])
        if not checks:
            return rule["label_id"]
        if any(checks) if rule.get("mode") == "any" else all(checks):
            return rule["label_id"]
    return "unscheduled"


def _legacy_procedure(procedure):
    execution_mode = procedure.get("execution_mode")
    if execution_mode is None:  # pre-1.3 compatibility only
        role = procedure.get("executor_role")
        execution_mode = ("automated" if role == "vibecheck_agent"
                          else "guided" if role == "developer" else "manual")
    role = procedure.get("executor_role")
    classification = "ADVISORY"
    for rule in load_policy()["legacy_view"]["procedure_rules"]:
        if execution_mode not in rule["execution_modes"]:
            continue
        if rule.get("executor_roles") and role not in rule["executor_roles"]:
            continue
        classification = rule["classification"]
        break
    return {
        "procedure_ref": procedure.get("procedure_id"),
        "classification": classification,
        "execution_mode": execution_mode,
        "executor_role": role,
        "consent": (procedure.get("authorization") or {}).get("consent"),
    }


def legacy_view(envelope):
    """Lossy AUTO/PROPOSE/ADVISORY compatibility view, never authorization."""
    procedures = _index(current_procedures(envelope), "procedure_id")
    legacy_policy = load_policy()["legacy_view"]
    precedence = legacy_policy["action_precedence"]
    rows = []
    for action in sorted(current_actions(envelope),
                         key=lambda item: item.get("action_id", "")):
        procedure_rows = [_legacy_procedure(procedures[ref])
                          for ref in action.get("procedure_refs") or []
                          if ref in procedures]
        present = {row["classification"] for row in procedure_rows}
        classification = next((tier for tier in precedence if tier in present),
                              legacy_policy["no_procedure_classification"])
        rows.append({
            "action_ref": action.get("action_id"),
            "classification": classification,
            "procedure_views": procedure_rows,
        })
    return {
        "schema": legacy_policy["schema"],
        "schema_version": legacy_policy["schema_version"],
        "derived_from": {
            "assessment_id": envelope.get("assessment_id"),
            "assessment_revision": envelope.get("revision"),
            "action_registry": copy.deepcopy(envelope.get("action_registry")),
        },
        "lossy": True,
        "warning": legacy_policy["warning"],
        "actions": rows,
    }
