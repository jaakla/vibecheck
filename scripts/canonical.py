# -*- coding: utf-8 -*-
"""Canonical vibecheck.assessment envelope library (RFC 0001, Increment 1).

Provides, stdlib-only:

  validate_envelope(env)   syntactic + semantic validation -> list of problems
  dumps(env) / loads(text) deterministic serialization (round-trip preserving)
  migrate(env, target)     explicit migration hooks between major versions
  bound_raw(text)          redact + cap raw values before they enter an envelope

JSON Schema validation runs additionally when the optional jsonschema package
is installed (requirements.txt); without it validate_envelope still enforces
reference integrity and the semantic rules below, so the stdlib-only scanner
workflow keeps working.

Semantic rules implemented here (numbering from RFC 0001 §10):
  R1   every _ref/_refs resolves in-envelope; control IDs resolve against the
       named control registry version (when it is the bundled registry)
  R3   pass requires >=1 current supporting evidence; neutral or expired
       evidence never counts (NO_SIGNAL is never Pass)
  R4   evidence refuting a current pass/partial must be listed in conflicts
       with a resolution
  R5   screening statuses only on screening controls; risk_accepted never on
       Critical severity
  R6   risk level = matrix(impact, exposure); unknown in -> unknown out;
       downgrades are at most one level below the matrix result and name
       supporting evidence that is current at the time of assessment
  R7   a compensating control lowers exposure only while at least one cited
       supporting evidence record is current
  R8   unknown is never low: a material unknown keeps readiness at incomplete
       or worse, and a listed blocker means the state is blocked
  R12  the report's mandatory disclosures are complete whatever the headline
       cap says, each one is placed exactly once in a visible section, and no
       mandatory item is filed as work that can wait
  R13  supersedes chains resolve and are acyclic; envelope revisions monotonic
  R16-R19 Action/Procedure lineage and lifecycle, usable deadlines, exact
          attempt authorization, and evidence-backed completion (actions.py)
  R20  authorization coverage: one observation covers one object, actor and
       operation in one environment, and a coverage-backed pass needs the whole
       required matrix (authz.py)
  R21  staged remediation: patch, deployment and live verification are
       authorized, ordered and evidenced separately (actions.py)
  R22  anything that wrote to a live system records its authorization, target
       environment, result and cleanup/rollback state (authz.py)

The application context is validated too (context.validate_context): profile
keys and values resolve against the context model, every field carries a usable
provenance state, undeclared x_ scope extensions are rejected, and a
compensating control with no enforcing mechanism or no stated scope is refused.

R2/R9/R10/R11/R14 are structural halves enforced by the JSON Schema itself;
R15's freshness reading of risks lives in the readiness derivation
(scripts/readiness.py), not here.
"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _redact
import actions as actions_mod
import authz as authz_mod
import context as context_mod

SCHEMA_VERSION = "1.4.0"
SCHEMA_NAME = "vibecheck.assessment"

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCHEMA_PATH = os.path.join(REPO_ROOT, "schema", "vibecheck.assessment.v1.schema.json")
REGISTRY_PATH = os.path.join(REPO_ROOT, "schema", "vibecheck.controls.v1.json")
MATRIX_PATH = os.path.join(REPO_ROOT, "schema", "risk-matrix.v1.json")
MAPPING_PATH = os.path.join(REPO_ROOT, "schema", "mappings", "vibecheck_v1.json")

PREFIX_TO_SECTION = {
    "sig-": "signals", "ev-": "evidence", "asm-": "assessments",
    "rsk-": "risks", "scn-": "scenarios", "act-": "actions",
    "prc-": "procedures", "att-": "attempts", "prov-": "providers",
    "rdy-": "readiness",
}
ID_KEYS = ("signal_id", "evidence_id", "assessment_id", "risk_id",
           "scenario_id", "action_id", "procedure_id", "attempt_id",
           "provider_id", "readiness_id")
CONTROL_ID_RE = re.compile(r"^vibecheck\.control\.[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$")

# Bounded raw values (issue #3: raw evidence references stay bounded and
# redacted). The scanner already caps one finding's evidence at 4000 chars;
# the signal bound sits above that so legacy JSONL lines survive verbatim and
# the export path stays byte-compatible.
MAX_RAW_SIGNAL = 6000
MAX_RAW_EVIDENCE = 2000


class MigrationError(Exception):
    pass


def _load_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


_cache = {}


def load_schema():
    if "schema" not in _cache:
        _cache["schema"] = _load_json(SCHEMA_PATH)
    return _cache["schema"]


def load_registry():
    if "registry" not in _cache:
        _cache["registry"] = _load_json(REGISTRY_PATH)
    return _cache["registry"]


def load_matrix():
    if "matrix" not in _cache:
        _cache["matrix"] = _load_json(MATRIX_PATH)
    return _cache["matrix"]


def load_framework_mapping():
    """The generated vibecheck_v1 mapping: item numbers, categories, the four
    wordings and the status map. Generated from items.py by gen_canonical.py."""
    if "mapping" not in _cache:
        _cache["mapping"] = _load_json(MAPPING_PATH)
    return _cache["mapping"]


# --------------------------------------------------------------- serialization

def dumps(env):
    """Deterministic serialization: same content -> same bytes, regardless of
    construction order. Unknown fields are preserved (round-trip rule)."""
    return json.dumps(env, ensure_ascii=False, sort_keys=True, indent=2) + "\n"


def loads(text):
    return json.loads(text)


# ------------------------------------------------------------------ redaction

def bound_raw(text, limit=MAX_RAW_EVIDENCE):
    """Redact credential shapes and cap length before a raw value enters an
    envelope. Values that already went through the scanner's redaction pass
    through unchanged as long as they are within the bound."""
    if text is None:
        return ""
    text = _redact.KNOWN.sub(_redact.cut, text)
    text = _redact.GENERIC.sub(_redact.cut, text)
    if len(text) > limit:
        text = text[:limit] + " ...[truncated]"
    return text


# ------------------------------------------------------------------ migration

# (from_major, to_major) -> callable(env) -> env. Populated when a new major
# version ships; same-major documents need no migration (readers accept any
# document of the major version they implement).
MIGRATIONS = {}


def register_migration(from_major, to_major, fn):
    MIGRATIONS[(int(from_major), int(to_major))] = fn


def _major(version):
    try:
        return int(str(version).split(".")[0])
    except ValueError:
        raise MigrationError("unparseable schema_version %r" % (version,))


def _version_tuple(version):
    try:
        parts = str(version).split(".")
        if len(parts) != 3:
            raise ValueError
        return tuple(int(part) for part in parts)
    except (TypeError, ValueError):
        raise MigrationError("unparseable schema_version %r" % (version,))


def migrate(env, target_version=SCHEMA_VERSION):
    """Return an envelope readable at target_version. Same major: unchanged.
    Different major: apply registered hooks one major at a time; raise
    MigrationError when a step is missing (never guess)."""
    have, want = _major(env.get("schema_version")), _major(target_version)
    if have == want:
        return env
    step = 1 if want > have else -1
    current = env
    for from_major in range(have, want, step):
        hook = MIGRATIONS.get((from_major, from_major + step))
        if hook is None:
            raise MigrationError(
                "no migration registered from schema major %d to %d"
                % (from_major, from_major + step))
        current = hook(current)
    return current


# ----------------------------------------------------------------- validation

#: Timestamp parsing lives in context.py so both modules read instants the same
#: way; comparing the string forms would be wrong, because different
#: representations of one instant do not sort chronologically.
_parse_instant = context_mod.parse_instant


def _iter_refs(node, path=""):
    if isinstance(node, dict):
        for key, value in node.items():
            where = "%s.%s" % (path, key) if path else key
            if key.endswith("_ref") and isinstance(value, str):
                yield where, value
            elif key.endswith("_refs") and isinstance(value, list):
                for v in value:
                    if isinstance(v, str):
                        yield where, v
            elif key == "ref" and isinstance(value, str):
                yield where, value
            else:
                yield from _iter_refs(value, where)
    elif isinstance(node, list):
        for i, value in enumerate(node):
            yield from _iter_refs(value, "%s[%d]" % (path, i))


def _collect_ids(env, problems):
    ids = set()
    for section in PREFIX_TO_SECTION.values():
        for obj in env.get(section) or []:
            if not isinstance(obj, dict):
                continue
            for key in ID_KEYS:
                if key in obj:
                    if obj[key] in ids:
                        problems.append("duplicate object id %r" % obj[key])
                    ids.add(obj[key])
    return ids


def _iter_control_ids(env):
    """Every place a control ID may appear, with its location."""
    for section in PREFIX_TO_SECTION.values():
        for i, obj in enumerate(env.get(section) or []):
            if not isinstance(obj, dict):
                continue
            where = "%s[%d]" % (section, i)
            if isinstance(obj.get("control_id"), str):
                yield where + ".control_id", obj["control_id"]
            claim = obj.get("claim")
            if isinstance(claim, dict):
                for cid in claim.get("control_ids") or []:
                    yield where + ".claim.control_ids", cid
            for key in ("control_refs", "reassess_control_ids"):
                for cid in obj.get(key) or []:
                    yield "%s.%s" % (where, key), cid
            for j, cov in enumerate(obj.get("coverage") or []):
                if isinstance(cov, dict) and isinstance(cov.get("control_id"), str):
                    yield "%s.coverage[%d]" % (where, j), cov["control_id"]
    for i, measure in enumerate((env.get("context") or {})
                                .get("compensating_controls") or []):
        for cid in (measure.get("applies_to") or {}).get("control_ids") or []:
            yield "context.compensating_controls[%d].applies_to" % i, cid
    for i, mapping in enumerate(env.get("framework_mappings") or []):
        for j, entry in enumerate(mapping.get("entries") or []):
            if isinstance(entry, dict) and isinstance(entry.get("control_id"), str):
                yield "framework_mappings[%d].entries[%d]" % (i, j), entry["control_id"]


def _registry_index(env):
    """control_id -> registry entry, when the envelope names the bundled
    registry. Envelopes pinned to another registry resolve elsewhere (R1
    allows it); their control IDs are only grammar-checked."""
    named = env.get("control_registry") or {}
    registry = load_registry()
    if (named.get("name") == registry["registry"]
            and named.get("version") == registry["version"]):
        return {c["control_id"]: c for c in registry["controls"]}
    return None


def _check_references(env, problems):
    ids = _collect_ids(env, problems)
    for where, ref in _iter_refs(env):
        prefix = ref.split("-", 1)[0] + "-"
        if prefix not in PREFIX_TO_SECTION:
            continue  # control ids, raw refs, condition ids, etc.
        if ref not in ids:
            problems.append("R1: dangling reference %s at %s" % (ref, where))

    index = _registry_index(env)
    for where, cid in _iter_control_ids(env):
        if not CONTROL_ID_RE.match(cid):
            problems.append("R1: malformed control id %r at %s" % (cid, where))
        elif index is not None and cid not in index:
            problems.append(
                "R1: control id %r at %s is not in registry %s %s"
                % (cid, where, env["control_registry"]["name"],
                   env["control_registry"]["version"]))


def _check_supersedes(env, problems):
    if "supersedes_revision" in env:
        if env["supersedes_revision"] >= env.get("revision", 0):
            problems.append("R13: supersedes_revision must be below revision")
    for section in ("assessments", "risks"):
        by_id = {}
        for obj in env.get(section) or []:
            for key in ID_KEYS:
                if key in obj:
                    by_id[obj[key]] = obj
        for obj in env.get(section) or []:
            seen, cur = set(), obj
            while "supersedes" in cur:
                target = cur["supersedes"]
                if target not in by_id:
                    problems.append("R13: supersedes %r dangles in %s" % (target, section))
                    break
                if target in seen:
                    problems.append("R13: supersedes cycle at %r in %s" % (target, section))
                    break
                target_obj = by_id[target]
                if (section == "assessments"
                        and cur.get("control_id") != target_obj.get("control_id")):
                    problems.append(
                        "R13: assessment %r supersedes %r with a different "
                        "control_id; supersedes links must keep the same control_id"
                        % (cur.get("assessment_id"), target))
                    break
                seen.add(target)
                cur = target_obj


def current_assessments(env):
    """Assessments not superseded by another one (heads of the chains)."""
    superseded = {a["supersedes"] for a in env.get("assessments") or []
                  if "supersedes" in a}
    return [a for a in env.get("assessments") or []
            if a.get("assessment_id") not in superseded]


def _check_assessments(env, problems):
    evidence = {e.get("evidence_id"): e for e in env.get("evidence") or []}
    assessments = {a.get("assessment_id"): a
                   for a in env.get("assessments") or []}
    index = _registry_index(env)
    for asm in current_assessments(env):
        aid = asm.get("assessment_id", "<no id>")
        status = asm.get("status")
        refs = (asm.get("basis") or {}).get("evidence_refs") or []
        assessed_at = asm.get("assessed_at", "")
        assessed_instant = _parse_instant(assessed_at)

        def current(ev):
            observed = _parse_instant(ev.get("observed_at"))
            if (observed is None or assessed_instant is None
                    or observed > assessed_instant):
                return False
            if "valid_until" not in ev:
                return True
            valid_until = _parse_instant(ev.get("valid_until"))
            return valid_until is not None and valid_until >= assessed_instant

        if status == "pass":
            supporting = [evidence[r] for r in refs if r in evidence
                          and evidence[r].get("direction") == "supports"
                          and current(evidence[r])]
            if not supporting:
                problems.append(
                    "R3: %s is pass without current supporting evidence "
                    "(neutral or expired evidence never counts)" % aid)
        if status in ("pass", "partial") and asm.get("supersedes"):
            previous = assessments.get(asm["supersedes"])
            if (previous is not None and previous.get("status") == "fail"
                    and previous.get("control_id") == asm.get("control_id")):
                previous_refs = ((previous.get("basis") or {})
                                 .get("evidence_refs") or [])
                refuting_instants = [
                    _parse_instant(evidence[r].get("observed_at"))
                    for r in previous_refs
                    if r in evidence
                    and evidence[r].get("direction") == "refutes"
                ]
                refuting_instants = [t for t in refuting_instants if t is not None]
                if refuting_instants:
                    latest_refutation = max(refuting_instants)
                    recovery_support = [
                        evidence[r] for r in refs
                        if r in evidence
                        and evidence[r].get("direction") == "supports"
                        and current(evidence[r])
                        and _parse_instant(evidence[r].get("observed_at"))
                        > latest_refutation
                    ]
                    if not recovery_support:
                        problems.append(
                            "R3: %s supersedes failed assessment %s without "
                            "supporting evidence that post-dates its latest "
                            "refutation" % (aid, previous.get("assessment_id")))
        if status in ("pass", "partial"):
            # Refuting evidence disagrees with a pass at any strength; with a
            # partial (which already concedes deficiency) only a decisive
            # refutation disagrees. Only evidence known at decision time
            # counts — later evidence calls for a superseding assessment.
            resolved = {c.get("evidence_ref")
                        for c in asm.get("conflicts") or []}
            control = asm.get("control_id")
            for ev in evidence.values():
                claim = ev.get("claim") or {}
                observed_instant = _parse_instant(ev.get("observed_at"))
                if (control in (claim.get("control_ids") or [])
                        and ev.get("direction") == "refutes"
                        and (status == "pass" or ev.get("strength") == "decisive")
                        and observed_instant is not None
                        and assessed_instant is not None
                        and observed_instant <= assessed_instant
                        and ev.get("evidence_id") not in refs
                        and ev.get("evidence_id") not in resolved):
                    problems.append(
                        "R4: %s is %s but refuting evidence %s is not "
                        "resolved in conflicts" % (aid, status, ev.get("evidence_id")))
        if index is not None and asm.get("control_id") in index:
            entry = index[asm["control_id"]]
            if status in ("answered", "needs_specialist") and entry["kind"] != "screening":
                problems.append(
                    "R5: %s uses screening status %r on non-screening control %s"
                    % (aid, status, asm["control_id"]))
            if status == "risk_accepted" and entry["severity"] == "Critical":
                problems.append(
                    "R5: %s marks Critical control %s risk_accepted"
                    % (aid, asm["control_id"]))


_LEVEL_ORDER = ["low", "moderate", "high", "critical"]


def _current_supporting_refs(env, refs, at):
    """Referenced evidence that supports its claim and is still valid at `at`."""
    evidence = {e.get("evidence_id"): e for e in env.get("evidence") or []}
    instant = _parse_instant(at)
    if instant is None:
        return []
    current = []
    for ref in refs or []:
        item = evidence.get(ref)
        if item is None or item.get("direction") != "supports":
            continue
        observed = _parse_instant(item.get("observed_at"))
        valid_until = _parse_instant(item.get("valid_until"))
        if observed is None or observed > instant:
            continue
        if "valid_until" in item and (
                valid_until is None or valid_until < instant):
            continue
        current.append(ref)
    return current


def _check_risks(env, problems):
    matrix = load_matrix()["matrix"]
    for rsk in env.get("risks") or []:
        rid = rsk.get("risk_id", "<no id>")
        inputs = rsk.get("inputs") or {}
        impact, exposure = inputs.get("impact"), inputs.get("exposure")
        level = rsk.get("level")

        # R7: a compensating control counts only while its evidence is current
        for i, measure in enumerate(inputs.get("compensating_controls") or []):
            if not measure.get("exposure_reduction_applied"):
                continue
            if not _current_supporting_refs(env, measure.get("evidence_refs"),
                                            rsk.get("assessed_at")):
                problems.append(
                    "R7: %s inputs.compensating_controls[%d] lowered exposure "
                    "without current supporting evidence" % (rid, i))

        if "unknown" in (impact, exposure):
            expected = "unknown"
        else:
            expected = (matrix.get(impact) or {}).get(exposure)
            if expected is None:
                continue  # schema validation reports the bad enum value
        if "downgrade" in rsk:
            if expected == "unknown":
                problems.append("R6: %s downgrades an unknown level" % rid)
            elif (level not in _LEVEL_ORDER
                    or _LEVEL_ORDER.index(level) != _LEVEL_ORDER.index(expected) - 1):
                problems.append(
                    "R6: %s downgrade must be exactly one level below the "
                    "matrix result %r, got %r" % (rid, expected, level))
            if not _current_supporting_refs(env, rsk["downgrade"].get("evidence_refs"),
                                            rsk.get("assessed_at")):
                problems.append(
                    "R6: %s is downgraded without current supporting evidence; "
                    "a downgrade must name the exact evidence that holds now"
                    % rid)
        elif expected == "unknown":
            if level != "unknown":
                problems.append(
                    "R6: %s has an unknown input but level %r — unknown in, "
                    "unknown out" % (rid, level))
        elif level == "unknown":
            pass  # unresolved conflicting inputs force unknown; always allowed
        elif (level not in _LEVEL_ORDER
                or _LEVEL_ORDER.index(level) < _LEVEL_ORDER.index(expected)):
            # raising above the matrix needs no ceremony (conservatism is
            # asymmetric); below it without a downgrade record fails
            problems.append(
                "R6: %s level %r is below matrix(%s, %s) = %r without a "
                "downgrade record" % (rid, level, impact, exposure, expected))


def _check_readiness(env, problems):
    """R8's structural half: a state that hides what it lists is invalid.

    Whether a *derivation* found the right blockers is readiness.py's job; what
    is checked here is that a stored readiness object cannot claim less than
    its own contents. A material unknown or a listed blocker can only coexist
    with a state that keeps the scope shut.
    """
    for i, readiness in enumerate(env.get("readiness") or []):
        if not isinstance(readiness, dict):
            continue
        where = readiness.get("readiness_id", "readiness[%d]" % i)
        state = readiness.get("state")
        if readiness.get("blockers") and state != "blocked":
            problems.append(
                "R8: %s lists %d blocker(s) but its state is %r; a listed "
                "blocker means blocked"
                % (where, len(readiness["blockers"]), state))
        material = [u for u in readiness.get("unknowns") or []
                    if isinstance(u, dict) and u.get("material")]
        if material and state not in ("incomplete", "blocked"):
            problems.append(
                "R8: %s carries %d material unknown(s) but its state is %r; "
                "unknown is never low and never permission to proceed"
                % (where, len(material), state))


def _check_report(env, problems):
    """R12: the headline cap may summarize, never hide.

    Each mandatory set is recomputed from the envelope and compared with what
    the stored report claims, so a report that quietly drops an unresolved
    Critical control, a readiness-blocking unknown, an incident, an escalation
    or a blocking deadline fails validation instead of shipping. The placement
    record is checked too: every mandatory ref is rendered exactly once, in a
    headline scenario or in the mandatory section, and never as deferrable
    work.
    """
    report = env.get("report")
    if not isinstance(report, dict):
        return
    # deferred: report.py imports this module, so it cannot be imported at
    # module load time. The derivation lives there because that is where the
    # rules data is read; duplicating it here would let the two drift.
    import report as report_mod

    try:
        modern = (_version_tuple(env.get("schema_version")) >= (1, 2, 0)
                  or "disclosure_placement" in report)
    except MigrationError:
        modern = "disclosure_placement" in report

    try:
        expected = report_mod.mandatory_disclosures(
            env, report.get("generated_at"))
    except (TypeError, ValueError) as exc:
        problems.append("R12: report disclosures cannot be checked: %s" % exc)
        return
    stored = report.get("mandatory_disclosures") or {}
    for category in report_mod.MANDATORY_CATEGORIES:
        expected_set = set(expected[category])
        stored_set = set(stored.get(category) or [])
        missing = sorted(expected_set - stored_set)
        if missing:
            problems.append(
                "R12: report.mandatory_disclosures.%s omits %s; the headline "
                "cap is a summary rule and may never drop a mandatory item"
                % (category, ", ".join(missing)))
        extra = sorted(stored_set - expected_set)
        if extra and modern:
            problems.append(
                "R12: report.mandatory_disclosures.%s contains non-mandatory "
                "or stale refs %s" % (category, ", ".join(extra)))

    deferred = set((report.get("sections") or {}).get("can_wait") or [])
    for ref in sorted(deferred & report_mod.mandatory_refs(stored)):
        problems.append(
            "R12: %s is a mandatory disclosure but is listed as work that can "
            "wait" % ref)

    scenario_ids = {s.get("scenario_id") for s in env.get("scenarios") or []}
    for ref in report.get("headline_scenario_refs") or []:
        if ref not in scenario_ids:
            problems.append("R12: headline scenario %s does not exist" % ref)

    if not modern:
        # The 1.0 RFC example has the five mandatory sets but predates stored
        # placement. Same-major additive compatibility keeps it readable.
        return

    for readiness in env.get("readiness") or []:
        for unknown in readiness.get("unknowns") or []:
            if unknown.get("material") and not unknown.get("unknown_id"):
                problems.append(
                    "R12: material readiness unknown in %s has no stable "
                    "unknown_id and therefore cannot be placed exactly once"
                    % readiness.get("readiness_id", "<unknown readiness>"))

    if not report.get("generated_at"):
        problems.append(
            "R12: a schema 1.2 report requires generated_at so deadline and "
            "freshness disclosures are reproducible")
        return
    try:
        expected_report = report_mod.derive_report(
            env, report.get("audience", "founder"), report.get("language", "en"),
            report["generated_at"])
    except (TypeError, ValueError) as exc:
        problems.append("R12: report cannot be re-derived: %s" % exc)
        return

    for field in ("headline_scenario_refs", "scenario_ranking",
                  "mandatory_disclosures", "disclosure_placement", "sections",
                  "context_summary", "readiness_refs", "appendix", "derivation"):
        if report.get(field) != expected_report.get(field):
            problems.append(
                "R12: report.%s does not match deterministic derivation at %s"
                % (field, report["generated_at"]))


def _schema_errors(env):
    try:
        from jsonschema import Draft202012Validator
    except ImportError:
        return []
    validator = Draft202012Validator(load_schema())
    return ["schema: %s at %s" % (e.message, "/".join(str(p) for p in e.path))
            for e in sorted(validator.iter_errors(env), key=str)]


def validate_envelope(env):
    """Return a list of problems; empty list means valid. Includes JSON Schema
    errors when jsonschema is installed, semantic rules always."""
    problems = []
    if env.get("schema") != SCHEMA_NAME:
        problems.append("schema must be %r" % SCHEMA_NAME)
    version = env.get("schema_version", "")
    try:
        if _major(version) != _major(SCHEMA_VERSION):
            problems.append(
                "schema_version %r has a different major than implemented %s; "
                "run migrate() first" % (version, SCHEMA_VERSION))
    except MigrationError:
        problems.append("unparseable schema_version %r" % version)
    problems.extend(_schema_errors(env))
    problems.extend(context_mod.validate_context(env.get("context") or {}))
    _check_references(env, problems)
    _check_supersedes(env, problems)
    _check_assessments(env, problems)
    _check_risks(env, problems)
    _check_readiness(env, problems)
    _check_report(env, problems)
    problems.extend(actions_mod.validate_registry(env))
    problems.extend(authz_mod.validate_coverage(env))
    return problems
