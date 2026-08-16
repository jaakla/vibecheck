#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Regenerate the golden context / risk / readiness cases (gh issue #4).

Each case in tests/golden/inputs/ states an application context, a handful of
assessed controls and, where relevant, a baseline review of the Critical, High
and screening controls. This script expands one into a complete
vibecheck.assessment envelope, derives contextual risk and environment-scoped
readiness from it, validates the result, and writes it to tests/golden/expected/.

The expanded envelopes are committed so that:

  * the derivation is reviewable as English prose and JSON, not only as code;
  * the same normalized inputs demonstrably produce the same risks, levels and
    readiness states (--check fails on any drift, in CI and in the tests);
  * the four scope profiles the epic cares about — developer-only prototype,
    private invite-only pilot, public product, and a sensitive/high-impact use
    with unknowns in the context — are pinned side by side.

Usage: python3 scripts/gen_goldens.py [--check]   (run from anywhere)
"""
import argparse
import copy
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import canonical
import context as ctx
import controls
import readiness as readiness_mod

REPO_ROOT = canonical.REPO_ROOT
INPUT_DIR = os.path.join(REPO_ROOT, "tests", "golden", "inputs")
OUTPUT_DIR = os.path.join(REPO_ROOT, "tests", "golden", "expected")


def _registry():
    return {c["control_id"]: c for c in canonical.load_registry()["controls"]}


def _title(control_id):
    return _registry()[control_id]["title"]["en"]


def _claim(control_ids, aspect=None):
    claim = {
        "control_ids": list(control_ids),
        "statement": "; ".join("The requirement of %s is met" % _title(c)
                               for c in control_ids),
    }
    if aspect:
        claim["aspect"] = aspect
    return claim


def _evidence(evidence_id, control_ids, spec, defaults):
    merged = dict(defaults)
    merged.update(spec)
    evidence = {
        "evidence_id": evidence_id,
        "provider": {"name": merged["provider"]},
        "subject": {"kind": merged["subject_kind"], "locator": merged["subject_locator"]},
        "environment": merged["environment"],
        "operation": merged["operation"],
        "scope": merged["scope"],
        "claim": _claim(control_ids, merged.get("aspect")),
        "direction": merged["direction"],
        "strength": merged["strength"],
        "observed_at": merged["observed_at"],
    }
    if merged.get("valid_until"):
        evidence["valid_until"] = merged["valid_until"]
    if merged.get("redaction"):
        evidence["redaction"] = merged["redaction"]
    return evidence


_DIRECTION_BY_STATUS = {
    "pass": "supports", "fail": "refutes", "partial": "refutes",
    "risk_accepted": "refutes",
}


def build_case(spec):
    """Expand one case specification into a derived, validated envelope."""
    now = spec["now"]
    context = ctx.build_context(
        context_id=spec["context_id"],
        application=spec["application"],
        target_scopes=spec["target_scopes"],
        profile=spec.get("profile"),
        current_scope=spec.get("current_scope"),
        compensating_controls=spec.get("compensating_controls"),
        confirmation=spec.get("confirmation"),
        data_summary=spec.get("data_summary"),
        assumptions=spec.get("assumptions"),
        valid_until=spec.get("context_valid_until"),
        reassess_triggers=spec.get("reassess_triggers"),
        extensions=spec.get("extensions"),
    )
    current_scope = ctx.current_scope(context)
    defaults = {
        "provider": "vibecheck reviewer",
        "subject_kind": "repo",
        "subject_locator": ".",
        "environment": current_scope["environment"],
        "operation": "reviewer_walkthrough",
        "strength": "indicative",
        "observed_at": now,
        "scope": "Stated in the case specification.",
    }

    envelope = {
        "schema": canonical.SCHEMA_NAME,
        "schema_version": canonical.SCHEMA_VERSION,
        "assessment_id": spec["assessment_id"],
        "revision": 1,
        "created_at": now,
        "context": context,
        "control_registry": {"name": controls.REGISTRY_NAME,
                             "version": controls.REGISTRY_VERSION},
        "evidence": [],
        "assessments": [],
        "actions": list(copy.deepcopy(spec.get("actions") or [])),
        "procedures": list(copy.deepcopy(spec.get("procedures") or [])),
    }

    for extra in spec.get("extra_evidence") or []:
        entry = dict(extra)
        envelope["evidence"].append(_evidence(
            entry.pop("evidence_id"), entry.pop("control_ids"), entry, defaults))

    covered = set()
    for index, finding in enumerate(spec.get("findings") or [], 1):
        control_id = finding["control_id"]
        covered.add(control_id)
        slug = control_id.split("vibecheck.control.")[-1]
        status = finding["status"]
        assessed_at = finding.get("assessed_at", now)
        assessment = {
            "assessment_id": "asm-%s" % slug,
            "control_id": control_id,
            "status": status,
            "assessor": {"kind": finding.get("assessor_kind", "human"),
                         "id": finding.get("assessor", spec["reviewer"])},
            "assessed_at": assessed_at,
            "basis": {"rationale": finding["rationale"], "evidence_refs": []},
        }
        if finding.get("evidence") is not None:
            evidence_spec = dict(finding["evidence"])
            evidence_spec.setdefault(
                "direction", _DIRECTION_BY_STATUS.get(status, "neutral"))
            evidence_spec.setdefault("observed_at", assessed_at)
            evidence_id = "ev-%s-%02d" % (slug.split(".")[-1], index)
            envelope["evidence"].append(
                _evidence(evidence_id, [control_id], evidence_spec, defaults))
            assessment["basis"]["evidence_refs"].append(evidence_id)
        if finding.get("acceptance"):
            assessment["acceptance"] = dict(finding["acceptance"])
        if finding.get("conflicts"):
            assessment["conflicts"] = copy.deepcopy(finding["conflicts"])
        envelope["assessments"].append(assessment)

    baseline = spec.get("baseline")
    if baseline:
        baseline_evidence_id = "ev-baseline-review"
        envelope["evidence"].append(_evidence(
            baseline_evidence_id,
            sorted(cid for cid, entry in _registry().items()
                   if entry["severity"] in ("Critical", "High")
                   and cid not in covered),
            dict(baseline["evidence"], direction="supports"), defaults))
        for control_id, entry in sorted(_registry().items()):
            if control_id in covered:
                continue
            slug = control_id.split("vibecheck.control.")[-1]
            if entry["kind"] == "screening":
                envelope["assessments"].append({
                    "assessment_id": "asm-%s" % slug,
                    "control_id": control_id,
                    "status": baseline["screening_status"],
                    "assessor": {"kind": "human", "id": spec["reviewer"]},
                    "assessed_at": now,
                    "basis": {"rationale": baseline["screening_rationale"],
                              "evidence_refs": []},
                })
            elif entry["severity"] in ("Critical", "High"):
                envelope["assessments"].append({
                    "assessment_id": "asm-%s" % slug,
                    "control_id": control_id,
                    "status": baseline["status"],
                    "assessor": {"kind": "human", "id": spec["reviewer"]},
                    "assessed_at": now,
                    "basis": {"rationale": baseline["rationale"],
                              "evidence_refs": [baseline_evidence_id]},
                })

    envelope["evidence"].sort(key=lambda e: e["evidence_id"])
    envelope["assessments"].sort(key=lambda a: a["assessment_id"])
    derived = readiness_mod.derive_into(envelope, now)
    problems = canonical.validate_envelope(derived)
    if problems:
        raise SystemExit("case %s does not validate:\n  %s"
                         % (spec["case_id"], "\n  ".join(problems)))
    return derived


def load_specs():
    specs = []
    for name in sorted(os.listdir(INPUT_DIR)):
        if name.endswith(".json"):
            with open(os.path.join(INPUT_DIR, name), encoding="utf-8") as fh:
                specs.append(json.load(fh))
    return specs


def artifacts():
    return {os.path.join(OUTPUT_DIR, "%s.json" % spec["case_id"]):
            canonical.dumps(build_case(spec))
            for spec in load_specs()}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true",
                        help="fail if a committed case differs; do not modify it")
    args = parser.parse_args()
    stale = []
    for path, rendered in sorted(artifacts().items()):
        rel = os.path.relpath(path, REPO_ROOT)
        if args.check:
            try:
                with open(path, encoding="utf-8") as fh:
                    current = fh.read()
            except OSError:
                current = ""
            if current != rendered:
                stale.append(rel)
            else:
                print("current: %s" % rel)
        else:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(rendered)
            print("wrote %s" % rel)
    if stale:
        for rel in stale:
            print("stale: %s (run python3 scripts/gen_goldens.py)" % rel,
                  file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
