#!/usr/bin/env python3
"""Versioned context, contextual risk and readiness.

Pins the acceptance criteria:
  - golden cases for a developer-only prototype, a private invite-only pilot, a
    public product and a sensitive/high-impact use with unknowns in the context,
  - the same normalized inputs always produce the same risks and readiness,
  - changing only the context creates a new context and envelope revision
    without pretending the source code changed,
  - expired evidence or an expired context forces reassessment and keeps
    readiness incomplete,
  - the existing checklist verdict stays available, and any difference from the
    scoped readiness state is explained rather than hidden,

and the guardrails around them: unknown never becomes low, a compensating
control only ever moves exposure and only with current evidence, a failed
Critical control stays failed however narrow the scope, and no readiness state
is ever rendered as secure, certified or ready to ship.

Stdlib-only, like the other suites; parts that need jsonschema or openpyxl skip
cleanly when those are absent.
"""
import copy
import json
import os
import subprocess
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "scripts"))

import canonical  # noqa: E402
import context as ctx  # noqa: E402
import controls  # noqa: E402
import gen_goldens  # noqa: E402
import readiness as readiness_mod  # noqa: E402
import risk as risk_mod  # noqa: E402

try:
    from jsonschema import Draft202012Validator
    HAVE_JSONSCHEMA = True
except ImportError:  # pragma: no cover
    HAVE_JSONSCHEMA = False

try:
    import openpyxl  # noqa: F401
    HAVE_OPENPYXL = True
except ImportError:
    HAVE_OPENPYXL = False

GOLDEN_DIR = os.path.join(REPO, "tests", "golden", "expected")
NOW = "2026-08-16T12:00:00Z"
LATER = "2027-01-01T12:00:00Z"

ANON = "vibecheck.control.authz.anon_data_access"          # Critical, security
BACKUPS = "vibecheck.control.data.tested_backups"          # High, reliability
ERRORS = "vibecheck.control.obs.error_tracking"            # Medium, reliability
EXPORT = "vibecheck.control.continuity.data_export"        # Medium, reliability


def load_golden(case_id):
    with open(os.path.join(GOLDEN_DIR, "%s.json" % case_id), encoding="utf-8") as fh:
        return json.load(fh)


CONFIRMED = {
    "lifecycle": "piloting",
    "audience_scale": "known_group",
    "network_exposure": "unlisted_public_url",
    "authentication": "invite_only_accounts",
    "tenancy": "single_tenant",
    "data_sensitivity": "personal_data",
    "financial_operations": "none",
    "privileged_operations": "none",
    "business_criticality": "supporting",
}


def make_context(overrides=None, **kwargs):
    answers = dict(CONFIRMED)
    answers.update(overrides or {})
    profile = ctx.profile(answers, source="founder:test")
    defaults = dict(
        context_id="ctx-test",
        application={"name": "Test app"},
        target_scopes=[{"environment": "private_test",
                        "intended_use": "invite_only_pilot"},
                       {"environment": "public_release",
                        "intended_use": "public_product"}],
        current_scope={"environment": "private_test",
                       "intended_use": "invite_only_pilot"},
        confirmation={"state": "human_reviewed", "confirmed_by": "founder:test",
                      "confirmed_at": NOW, "source_fingerprint": "sha256:abc"},
        profile=profile,
    )
    defaults.update(kwargs)
    return ctx.build_context(**defaults)


def make_envelope(context=None, statuses=None, evidence=None, actions=None):
    """A minimal valid envelope with one assessment per requested control."""
    context = context if context is not None else make_context()
    envelope = {
        "schema": canonical.SCHEMA_NAME,
        "schema_version": canonical.SCHEMA_VERSION,
        "assessment_id": "va-test",
        "revision": 1,
        "created_at": NOW,
        "context": context,
        "control_registry": {"name": controls.REGISTRY_NAME,
                             "version": controls.REGISTRY_VERSION},
        "evidence": list(evidence or []),
        "assessments": [],
        "actions": list(actions or []),
    }
    for index, (control_id, status) in enumerate(sorted((statuses or {}).items()), 1):
        evidence_id = "ev-%02d" % index
        envelope["evidence"].append({
            "evidence_id": evidence_id,
            "provider": {"name": "test"},
            "subject": {"kind": "repo", "locator": "."},
            "environment": "private_test",
            "operation": "static_pattern_scan",
            "scope": "test fixture",
            "claim": {"control_ids": [control_id],
                      "statement": "The control requirement is met"},
            "direction": "supports" if status == "pass" else "refutes",
            "strength": "indicative",
            "observed_at": NOW,
            "valid_until": "2026-09-15T12:00:00Z",
        })
        assessment = {
            "assessment_id": "asm-%02d" % index,
            "control_id": control_id,
            "status": status,
            "assessor": {"kind": "human", "id": "reviewer:test"},
            "assessed_at": NOW,
            "basis": {"rationale": "test fixture", "evidence_refs": [evidence_id]},
        }
        if status == "risk_accepted":
            assessment["acceptance"] = {"accepted_by": "founder:test",
                                        "reason": "test fixture",
                                        "review_by": "2026-12-01T00:00:00Z"}
        envelope["assessments"].append(assessment)
    return envelope


def only_risk(envelope, control_id, environment, now=NOW):
    derived = [r for r in risk_mod.derive_risks(envelope, now)
               if control_id in r["control_refs"]
               and r["scope"]["environment"] == environment]
    assert len(derived) == 1, derived
    return derived[0]


# ------------------------------------------------------------- context model

class TestContextModel(unittest.TestCase):
    def test_model_is_self_consistent(self):
        model = ctx.load_model()
        self.assertEqual(ctx.MODEL_NAME, model["schema"])
        self.assertEqual(ctx.MODEL_VERSION, model["schema_version"])
        ids = [d["id"] for d in model["dimensions"]]
        self.assertEqual(len(ids), len(set(ids)))
        for dimension in model["dimensions"]:
            with self.subTest(dimension=dimension["id"]):
                self.assertIn(dimension["role"],
                              ("derivation_input", "captured_only"))
                values = [v["id"] for v in dimension["values"]]
                bands = [v["band"] for v in dimension["values"]]
                self.assertEqual(len(values), len(set(values)))
                self.assertEqual(bands, sorted(bands))
                for value in dimension["values"]:
                    self.assertTrue(value["description"].strip())

    def test_dimensions_cover_the_issue_list(self):
        # the facts the context model requires capturing
        for dimension_id in ("lifecycle", "audience_scale", "network_exposure",
                             "authentication", "tenancy", "data_sensitivity",
                             "financial_operations", "privileged_operations",
                             "business_criticality"):
            self.assertIn(dimension_id, ctx.dimensions())

    def test_standard_scopes_match_the_envelope_schema(self):
        schema = canonical.load_schema()["$defs"]
        self.assertEqual(
            set(schema["environment"]["anyOf"][0]["enum"]),
            set(ctx.environment_bands()))
        self.assertEqual(
            set(schema["intended_use"]["anyOf"][0]["enum"]),
            set(ctx.intended_use_bands()))

    def test_more_exposed_scopes_are_ordered_and_incomparable_ones_left_out(self):
        context = make_context(target_scopes=[
            {"environment": "developer_only", "intended_use": "prototype_demo"},
            {"environment": "public_release", "intended_use": "public_product"},
            {"environment": "private_test", "intended_use": "invite_only_pilot"},
            # more exposed environment, less exposed use: not comparable
            {"environment": "public_release", "intended_use": "prototype_demo"},
        ], current_scope={"environment": "developer_only",
                          "intended_use": "prototype_demo"})
        here = {"environment": "developer_only", "intended_use": "prototype_demo"}
        self.assertEqual(
            [("private_test", "invite_only_pilot"),
             ("public_release", "public_product")],
            [(s["environment"], s["intended_use"])
             for s in ctx.more_exposed_scopes(context, here)
             if s["intended_use"] != "prototype_demo"])

    def test_declared_extension_resolves_to_its_conservative_standard(self):
        context = make_context(
            target_scopes=[{"environment": "x_staging",
                            "intended_use": "invite_only_pilot"}],
            current_scope={"environment": "x_staging",
                           "intended_use": "invite_only_pilot"},
            extensions={"environments": {"x_staging": {
                "description": "Staging mirror of production data.",
                "treat_as": "public_release"}}})
        self.assertEqual("public_release",
                         ctx.resolve_environment(context, "x_staging"))
        self.assertEqual([], ctx.validate_context(context))


class TestContextValidation(unittest.TestCase):
    def problems(self, **kwargs):
        return ctx.validate_context(make_context(**kwargs))

    def test_clean_context_has_no_problems(self):
        self.assertEqual([], ctx.validate_context(make_context()))

    def test_rejects_unknown_dimension_and_unknown_value(self):
        context = make_context()
        context["profile"]["not_a_dimension"] = ctx.field("x", source="s")
        context["profile"]["tenancy"] = ctx.field("wat", source="s")
        problems = " ".join(ctx.validate_context(context))
        self.assertIn("not_a_dimension", problems)
        self.assertIn("'wat'", problems)

    def test_unknown_field_may_not_carry_a_value(self):
        context = make_context()
        context["profile"]["data_sensitivity"] = {"state": "unknown",
                                                  "value": "synthetic_or_none"}
        self.assertTrue(any("unknown must never read as an answer" in p
                            for p in ctx.validate_context(context)))

    def test_provenance_is_required_for_every_state(self):
        context = make_context()
        context["profile"]["authentication"] = {"state": "confirmed",
                                                "value": "open_signup"}
        context["profile"]["network_exposure"] = {
            "state": "inferred", "value": "public_internet", "source": "deploy config"}
        context["profile"]["financial_operations"] = {
            "state": "conflicting", "candidates": ["none"], "rationale": "x"}
        problems = " ".join(ctx.validate_context(context))
        self.assertIn("names no source", problems)
        self.assertIn("records no rationale", problems)
        self.assertIn("fewer than two candidates", problems)

    def test_rejects_undeclared_extension_scope(self):
        problems = self.problems(
            target_scopes=[{"environment": "x_staging",
                            "intended_use": "invite_only_pilot"}],
            current_scope={"environment": "x_staging",
                           "intended_use": "invite_only_pilot"})
        self.assertTrue(any("undeclared extension" in p for p in problems))

    def test_current_scope_must_be_a_target_scope(self):
        problems = self.problems(
            current_scope={"environment": "public_release",
                           "intended_use": "sensitive_or_high_impact"})
        self.assertTrue(any("current_scope is not one of the target scopes" in p
                            for p in problems))

    def test_compensating_control_needs_scope_and_enforcement(self):
        problems = self.problems(compensating_controls=[{
            "compensating_control_id": "cc-hope",
            "description": "We intend to restrict signups.",
            "enforced_by": "   ",
            "evidence_refs": ["ev-01"],
        }])
        self.assertTrue(any("names no control or domain" in p for p in problems))
        self.assertTrue(any("no enforcing mechanism" in p for p in problems))

    def test_human_reviewed_must_say_who_and_when(self):
        problems = self.problems(confirmation={"state": "human_reviewed"})
        self.assertTrue(any("does not record who confirmed it" in p
                            for p in problems))

    @unittest.skipUnless(HAVE_JSONSCHEMA, "jsonschema not installed")
    def test_profile_fields_validate_against_the_envelope_schema(self):
        validator = Draft202012Validator(canonical.load_schema())
        self.assertEqual([], list(validator.iter_errors(make_envelope())))

    @unittest.skipUnless(HAVE_JSONSCHEMA, "jsonschema not installed")
    def test_schema_rejects_a_valued_unknown_field(self):
        envelope = make_envelope()
        envelope["context"]["profile"]["data_sensitivity"] = {
            "state": "unknown", "value": "synthetic_or_none"}
        validator = Draft202012Validator(canonical.load_schema())
        self.assertTrue(list(validator.iter_errors(envelope)))

    @unittest.skipUnless(HAVE_JSONSCHEMA, "jsonschema not installed")
    def test_schema_rejects_a_compensating_control_that_reduces_impact(self):
        envelope = make_envelope()
        envelope["context"]["compensating_controls"] = [{
            "compensating_control_id": "cc-x",
            "description": "x",
            "enforced_by": "y",
            "evidence_refs": ["ev-01"],
            "reduces_impact": True,
        }]
        validator = Draft202012Validator(canonical.load_schema())
        self.assertTrue(list(validator.iter_errors(envelope)))


class TestContextRevisions(unittest.TestCase):
    def test_fingerprint_is_content_addressed_and_order_independent(self):
        first = make_context()
        second = make_context()
        second["profile"] = dict(reversed(list(second["profile"].items())))
        self.assertEqual(ctx.context_fingerprint(first),
                         ctx.context_fingerprint(second))

    def test_fingerprint_ignores_revision_and_confirmation(self):
        context = make_context()
        before = ctx.context_fingerprint(context)
        context["revision"] = 7
        context["confirmation"] = {"state": "draft"}
        self.assertEqual(before, ctx.context_fingerprint(context))

    def test_fingerprint_changes_when_a_recorded_fact_changes(self):
        before = ctx.context_fingerprint(make_context())
        after = ctx.context_fingerprint(
            make_context({"data_sensitivity": "special_category_or_financial"}))
        self.assertNotEqual(before, after)

    def test_revision_keeps_the_source_fingerprint_untouched(self):
        original = make_context()
        revised = ctx.revise(original, profile=ctx.profile(
            {"audience_scale": "open_large"}, source="founder:test"),
            confirmed_by="founder:test", now=LATER)
        self.assertEqual(2, revised["revision"])
        self.assertEqual(1, revised["supersedes_revision"])
        self.assertEqual(original["confirmation"]["source_fingerprint"],
                         revised["confirmation"]["source_fingerprint"])
        self.assertNotEqual(original["context_fingerprint"],
                            revised["context_fingerprint"])
        self.assertEqual("open_large",
                         ctx.field_value(revised, "audience_scale"))
        # untouched fields survive a field-wise revision
        self.assertEqual(ctx.field_value(original, "tenancy"),
                         ctx.field_value(revised, "tenancy"))

    def test_unconfirmed_revision_drops_back_to_draft(self):
        revised = ctx.revise(make_context(), profile=ctx.profile(
            {"audience_scale": "open_large"}, source="inference"))
        self.assertEqual("draft", revised["confirmation"]["state"])
        self.assertNotIn("confirmed_by", revised["confirmation"])

    def test_envelope_revision_moves_with_the_context(self):
        envelope = make_envelope(statuses={ANON: "fail"})
        revised = ctx.revise(envelope["context"], profile=ctx.profile(
            {"audience_scale": "open_large"}, source="founder:test"),
            confirmed_by="founder:test", now=LATER)
        updated = ctx.revise_envelope_context(envelope, revised)
        self.assertEqual(2, updated["revision"])
        self.assertEqual(1, updated["supersedes_revision"])
        self.assertEqual(1, envelope["revision"])  # original untouched

    def test_from_precheck_maps_overview_states(self):
        for state, expected in (("DRAFT", "draft"),
                                ("HUMAN-REVIEWED", "human_reviewed"),
                                ("REVIEW-BYPASSED", "review_bypassed")):
            confirmation = ctx.from_precheck(
                state, {"workspace_fingerprint": "sha256:deadbeef"})
            self.assertEqual(expected, confirmation["state"])
            self.assertEqual("sha256:deadbeef", confirmation["source_fingerprint"])
        with self.assertRaises(ValueError):
            ctx.from_precheck("MAYBE")

    def test_expiry_is_independent_of_the_source_fingerprint(self):
        context = make_context(
            valid_until="2026-07-01T00:00:00Z",
            confirmation={"state": "human_reviewed",
                          "confirmed_by": "founder:test",
                          "confirmed_at": "2026-05-01T00:00:00Z",
                          "source_fingerprint": "sha256:abc"})
        self.assertTrue(ctx.is_expired(context, NOW))
        self.assertEqual("expired", ctx.confirmation_state(context, NOW))
        self.assertEqual("human_reviewed",
                         ctx.confirmation_state(context, "2026-06-01T00:00:00Z"))

    def test_contradiction_is_reported_for_today_not_for_the_plan(self):
        planning = make_context(
            {"lifecycle": "building", "network_exposure": "local_only"},
            current_scope={"environment": "private_test",
                           "intended_use": "invite_only_pilot"})
        self.assertEqual([], ctx.consistency_notes(planning))
        live_in_a_sandbox = make_context(
            {"lifecycle": "live"},
            target_scopes=[{"environment": "developer_only",
                            "intended_use": "prototype_demo"}],
            current_scope={"environment": "developer_only",
                           "intended_use": "prototype_demo"})
        codes = [n["code"] for n in ctx.consistency_notes(live_in_a_sandbox)]
        self.assertEqual(["lifecycle_environment_mismatch"], codes)


# ------------------------------------------------------------------- risk

class TestRiskDerivation(unittest.TestCase):
    def test_same_inputs_produce_the_same_risks(self):
        envelope = make_envelope(statuses={ANON: "fail", BACKUPS: "fail"})
        first = risk_mod.derive_risks(envelope, NOW)
        second = risk_mod.derive_risks(copy.deepcopy(envelope), NOW)
        self.assertEqual(canonical.dumps(first), canonical.dumps(second))

    def test_level_follows_the_shipped_matrix(self):
        matrix = canonical.load_matrix()["matrix"]
        envelope = make_envelope(statuses={ANON: "fail"})
        for risk in risk_mod.derive_risks(envelope, NOW):
            with self.subTest(risk=risk["risk_id"]):
                self.assertEqual(
                    matrix[risk["inputs"]["impact"]][risk["inputs"]["exposure"]],
                    risk["level"])

    def test_scope_changes_the_level_not_the_status(self):
        prototype = make_context(
            {"lifecycle": "building", "audience_scale": "none_yet",
             "network_exposure": "local_only", "authentication": "none",
             "tenancy": "single_user", "data_sensitivity": "synthetic_or_none",
             "business_criticality": "experiment"},
            target_scopes=[{"environment": "developer_only",
                            "intended_use": "prototype_demo"},
                           {"environment": "public_release",
                            "intended_use": "public_product"}],
            current_scope={"environment": "developer_only",
                           "intended_use": "prototype_demo"})
        envelope = make_envelope(prototype, {ANON: "fail"})
        here = only_risk(envelope, ANON, "developer_only")
        later = only_risk(envelope, ANON, "public_release")
        self.assertEqual("low", here["level"])
        self.assertIn(later["level"], ("high", "critical"))
        self.assertEqual("current", here["horizon"]["kind"])
        self.assertEqual("event_triggered", later["horizon"]["kind"])
        # the status is untouched by either of them
        self.assertEqual(["fail"], [a["status"] for a in envelope["assessments"]])

    def test_intrinsic_severity_bounds_the_impact(self):
        context = make_context(
            {"data_sensitivity": "special_category_or_financial",
             "financial_operations": "custody_of_user_funds",
             "business_criticality": "sole_revenue_or_safety",
             "audience_scale": "open_large"})
        envelope = make_envelope(context, {ANON: "fail", ERRORS: "fail"})
        critical = only_risk(envelope, ANON, "private_test")
        medium = only_risk(envelope, ERRORS, "private_test")
        self.assertEqual("severe", critical["inputs"]["impact"])
        # a Medium control cannot be pushed past its ceiling by context alone
        self.assertEqual("moderate", medium["inputs"]["impact"])

    def test_unknown_dimension_yields_unknown_never_low(self):
        context = make_context({"data_sensitivity": None})
        envelope = make_envelope(context, {ANON: "fail"})
        risk = only_risk(envelope, ANON, "private_test")
        self.assertEqual("unknown", risk["inputs"]["impact"])
        self.assertEqual("unknown", risk["level"])
        self.assertTrue(any("data_sensitivity" in u
                            for u in risk["derivation"]["unknown_inputs"]))

    def test_conflicting_dimension_is_treated_like_unknown(self):
        context = make_context()
        context["profile"]["network_exposure"] = ctx.field(
            state="conflicting", candidates=["local_only", "public_internet"],
            rationale="the founder and the deploy config disagree")
        ctx.stamp_fingerprint(context)
        risk = only_risk(make_envelope(context, {ANON: "fail"}), ANON, "private_test")
        self.assertEqual("unknown", risk["inputs"]["exposure"])
        self.assertEqual("unknown", risk["level"])

    def test_a_dimension_that_cannot_move_this_domain_does_not_blank_it(self):
        # data sensitivity is unknown, but it has no bearing on a reliability
        # risk, so that risk is still derivable
        context = make_context({"data_sensitivity": None})
        envelope = make_envelope(context, {ANON: "fail", BACKUPS: "fail"})
        self.assertEqual("unknown",
                         only_risk(envelope, ANON, "private_test")["level"])
        reliability = only_risk(envelope, BACKUPS, "private_test")
        self.assertEqual("reliability", reliability["domain"])
        self.assertNotEqual("unknown", reliability["level"])

    def test_statuses_that_derive_no_risk(self):
        envelope = make_envelope(statuses={ANON: "pass", BACKUPS: "not_tested"})
        self.assertEqual([], risk_mod.derive_risks(envelope, NOW))

    def test_accepted_risk_still_derives_a_risk(self):
        envelope = make_envelope(statuses={EXPORT: "risk_accepted"})
        risk = only_risk(envelope, EXPORT, "private_test")
        self.assertTrue(any("does not remove the exposure" in a
                            for a in risk["assumptions"]))

    def test_inferred_answers_lower_confidence_and_stay_visible(self):
        context = make_context()
        for dimension_id in ("audience_scale", "data_sensitivity",
                             "business_criticality"):
            context["profile"][dimension_id] = ctx.field(
                CONFIRMED[dimension_id], state="inferred", source="repository",
                rationale="read from the code, not confirmed")
        risk = only_risk(make_envelope(context, {ANON: "fail"}), ANON, "private_test")
        self.assertEqual("low", risk["confidence"])
        self.assertEqual(3, len([a for a in risk["assumptions"]
                                 if "is inferred from" in a]))

    def test_draft_context_caps_confidence(self):
        context = make_context(confirmation={"state": "draft"})
        risk = only_risk(make_envelope(context, {ANON: "fail"}), ANON, "private_test")
        self.assertEqual("medium", risk["confidence"])

    def test_future_context_confirmation_does_not_raise_confidence(self):
        context = make_context(confirmation={
            "state": "human_reviewed", "confirmed_by": "founder:test",
            "confirmed_at": "2026-08-17T12:00:00Z",
        })
        risk = only_risk(make_envelope(context, {ANON: "fail"}),
                         ANON, "private_test")
        self.assertEqual("medium", risk["confidence"])
        self.assertEqual("not_yet_confirmed",
                         ctx.confirmation_state(context, NOW))

    def test_derived_risk_never_carries_a_status_or_severity(self):
        envelope = make_envelope(statuses={ANON: "fail"})
        for risk in risk_mod.derive_risks(envelope, NOW):
            for banned in ("status", "control_status", "intrinsic_severity",
                           "severity"):
                self.assertNotIn(banned, risk)
                self.assertNotIn(banned, risk["derivation"])


class TestCompensatingControls(unittest.TestCase):
    def measure(self, **overrides):
        measure = {
            "compensating_control_id": "cc-proxy",
            "description": "Identity-aware proxy in front of the API.",
            "enforced_by": "Cloudflare Access policy, owned by founder:test",
            "evidence_refs": ["ev-proxy"],
            "applies_to": {"domains": ["security"]},
        }
        measure.update(overrides)
        return measure

    def evidence(self, valid_until="2026-09-15T00:00:00Z", observed=NOW):
        return [{
            "evidence_id": "ev-proxy",
            "provider": {"name": "reviewer"},
            "subject": {"kind": "config", "locator": "access-policy"},
            "environment": "private_test",
            "operation": "config_export_review",
            "scope": "the exported policy",
            "claim": {"control_ids": [ANON],
                      "statement": "The control requirement is met"},
            "direction": "supports",
            "strength": "decisive",
            "observed_at": observed,
            "valid_until": valid_until,
        }]

    def risk_with(self, measures, evidence=None):
        context = make_context(compensating_controls=measures)
        envelope = make_envelope(context, {ANON: "fail"},
                                 evidence=evidence or self.evidence())
        return only_risk(envelope, ANON, "private_test")

    def test_baseline_without_any_measure(self):
        risk = only_risk(make_envelope(statuses={ANON: "fail"}), ANON, "private_test")
        self.assertEqual("plausible", risk["inputs"]["exposure"])

    def test_measure_lowers_exposure_by_exactly_one_step(self):
        risk = self.risk_with([self.measure()])
        self.assertEqual("unlikely", risk["inputs"]["exposure"])
        self.assertTrue(risk["inputs"]["compensating_controls"][0]
                        ["exposure_reduction_applied"])

    def test_two_measures_still_only_move_one_step(self):
        risk = self.risk_with([self.measure(),
                               self.measure(compensating_control_id="cc-second")])
        self.assertEqual("unlikely", risk["inputs"]["exposure"])
        self.assertEqual([True, False],
                         [c["exposure_reduction_applied"]
                          for c in risk["inputs"]["compensating_controls"]])

    def test_measure_never_touches_impact(self):
        without = only_risk(make_envelope(statuses={ANON: "fail"}),
                            ANON, "private_test")
        with_measure = self.risk_with([self.measure()])
        self.assertEqual(without["inputs"]["impact"],
                         with_measure["inputs"]["impact"])

    def test_expired_evidence_disables_the_measure(self):
        risk = self.risk_with([self.measure()],
                              evidence=self.evidence("2026-07-01T00:00:00Z"))
        self.assertEqual("plausible", risk["inputs"]["exposure"])
        self.assertEqual([], risk["inputs"]["compensating_controls"])

    def test_evidence_observed_after_derivation_time_does_not_count(self):
        # support that has not been observed yet cannot already be lowering
        # anything: the same reading the assessment rules apply to a pass
        risk = self.risk_with([self.measure()],
                              evidence=self.evidence(observed="2026-10-01T00:00:00Z"))
        self.assertEqual("plausible", risk["inputs"]["exposure"])
        self.assertEqual([], risk["inputs"]["compensating_controls"])

    def test_measure_expiry_moves_the_reassessment_deadline(self):
        envelope = make_envelope(
            make_context(compensating_controls=[
                self.measure(valid_until="2026-08-20T00:00:00Z")]),
            {ANON: "fail"}, evidence=self.evidence())
        risk = only_risk(envelope, ANON, "private_test")
        self.assertEqual("2026-08-20T00:00:00Z", risk["reassess_by"])

    def test_lapsed_measure_support_makes_the_risk_stale(self):
        envelope = risk_mod.apply_risks(make_envelope(
            make_context(compensating_controls=[self.measure()]),
            {ANON: "fail"},
            evidence=self.evidence("2026-09-01T00:00:00Z")), NOW)
        risk = [r for r in envelope["risks"]
                if r["scope"]["environment"] == "private_test"][0]
        self.assertTrue(risk["inputs"]["compensating_controls"][0]
                        ["exposure_reduction_applied"])
        after = "2026-09-10T00:00:00Z"
        self.assertTrue(risk_mod.is_stale(risk, envelope, after))
        self.assertEqual("unknown", risk_mod.effective_level(risk, envelope, after))

    def test_measure_outside_its_declared_scope_does_nothing(self):
        measure = self.measure(applies_to={
            "domains": ["security"],
            "scopes": [{"environment": "developer_only",
                        "intended_use": "prototype_demo"}]})
        self.assertEqual("plausible",
                         self.risk_with([measure])["inputs"]["exposure"])

    def test_measure_for_another_domain_does_nothing(self):
        measure = self.measure(applies_to={"domains": ["reliability"]})
        self.assertEqual("plausible",
                         self.risk_with([measure])["inputs"]["exposure"])


class TestScopeProjection(unittest.TestCase):
    def test_projection_only_raises(self):
        context = make_context(
            {"audience_scale": "open_large", "network_exposure": "public_internet",
             "authentication": "open_signup"},
            target_scopes=[{"environment": "public_release",
                            "intended_use": "public_product"},
                           {"environment": "private_test",
                            "intended_use": "invite_only_pilot"}],
            current_scope={"environment": "public_release",
                           "intended_use": "public_product"})
        envelope = make_envelope(context, {ANON: "fail"})
        public = only_risk(envelope, ANON, "public_release")
        pilot = only_risk(envelope, ANON, "private_test")
        # the pilot scope must not be softened by projecting a smaller audience
        self.assertEqual("open_large", ctx.field_value(context, "audience_scale"))
        self.assertNotIn("impact.scope_projection.audience_scale=named_handful",
                         pilot["derivation"]["rules_applied"])
        self.assertEqual("severe", public["inputs"]["impact"])
        self.assertEqual("severe", pilot["inputs"]["impact"])

    def test_projection_does_not_answer_an_unknown(self):
        context = make_context({"network_exposure": None})
        risk = only_risk(make_envelope(context, {ANON: "fail"}),
                         ANON, "public_release")
        self.assertEqual("unknown", risk["inputs"]["exposure"])
        self.assertEqual("unknown", risk["level"])


class TestRiskFreshnessAndHistory(unittest.TestCase):
    def test_stale_risk_reads_as_unknown(self):
        envelope = risk_mod.apply_risks(make_envelope(statuses={ANON: "fail"}), NOW)
        risk = [r for r in envelope["risks"]
                if r["scope"]["environment"] == "private_test"][0]
        self.assertNotEqual("unknown", risk_mod.effective_level(risk, envelope, NOW))
        self.assertTrue(risk_mod.is_stale(risk, envelope, LATER))
        self.assertEqual("unknown", risk_mod.effective_level(risk, envelope, LATER))

    def test_re_deriving_unchanged_inputs_adds_nothing(self):
        once = risk_mod.apply_risks(make_envelope(statuses={ANON: "fail"}), NOW)
        twice = risk_mod.apply_risks(once, NOW)
        self.assertEqual(canonical.dumps(once), canonical.dumps(twice))

    def test_new_evidence_at_the_same_revision_supersedes_under_a_new_id(self):
        first = risk_mod.apply_risks(make_envelope(statuses={ANON: "fail"}), NOW)
        # a superseding assessment at the same context revision: the derived
        # risk changes substance while its natural id stays the same
        original = first["assessments"][0]
        first["evidence"].append({
            "evidence_id": "ev-reprobe",
            "provider": {"name": "vibecheck supabase probe"},
            "subject": {"kind": "table", "locator": "public.orders"},
            "environment": "private_test",
            "operation": "http_select_anon_head",
            "scope": "anon reads denied on a table established as non-empty; "
                     "the write path was not probed",
            "claim": {"control_ids": [ANON],
                      "statement": "The control requirement is met"},
            "direction": "supports",
            "strength": "decisive",
            "observed_at": "2026-08-17T09:00:00Z",
            "valid_until": "2026-09-16T09:00:00Z",
        })
        first["assessments"].append(dict(
            original, assessment_id="asm-01b", status="partial",
            assessed_at="2026-08-17T10:00:00Z",
            supersedes=original["assessment_id"],
            basis={"rationale": "the read path is fixed, the write path is not",
                   "evidence_refs": ["ev-reprobe"]},
            conflicts=[{"evidence_ref": original["basis"]["evidence_refs"][0],
                        "resolution": "superseded by the re-probe above"}]))
        second = risk_mod.apply_risks(first, NOW)
        heads = risk_mod.current_risks(second)
        self.assertGreater(len(second["risks"]), len(first["risks"]))
        self.assertEqual(len(heads), len(risk_mod.current_risks(first)))
        for head in heads:
            self.assertIn("supersedes", head)
            self.assertNotEqual(head["risk_id"], head["supersedes"])
        self.assertEqual(len({r["risk_id"] for r in second["risks"]}),
                         len(second["risks"]))
        self.assertEqual([], canonical.validate_envelope(second))
        # and re-running is still idempotent afterwards
        self.assertEqual(canonical.dumps(second),
                         canonical.dumps(risk_mod.apply_risks(second, NOW)))

    def test_context_change_supersedes_instead_of_rewriting(self):
        first = risk_mod.apply_risks(make_envelope(statuses={ANON: "fail"}), NOW)
        revised = ctx.revise(first["context"], profile=ctx.profile(
            {"data_sensitivity": "special_category_or_financial"},
            source="founder:test"), confirmed_by="founder:test", now=NOW)
        second = risk_mod.apply_risks(
            ctx.revise_envelope_context(first, revised), NOW)
        heads = risk_mod.current_risks(second)
        self.assertGreater(len(second["risks"]), len(first["risks"]))
        # every old object is retained, and each head names what it replaced
        for risk in first["risks"]:
            self.assertIn(risk["risk_id"],
                          [r["risk_id"] for r in second["risks"]])
        for head in heads:
            self.assertEqual(2, head["derivation"]["context_revision"])
            self.assertIn("supersedes", head)
        self.assertEqual([], canonical.validate_envelope(second))


# -------------------------------------------------------------- readiness

class TestReadinessDerivation(unittest.TestCase):
    def full_review(self, statuses=None, **kwargs):
        """An envelope where every Critical/High control is assessed, so the
        state is not dominated by 'nobody looked at it yet'."""
        registry = {c["control_id"]: c for c in canonical.load_registry()["controls"]}
        every = {}
        for control_id, entry in registry.items():
            if entry["kind"] == "screening":
                continue
            if entry["severity"] in ("Critical", "High"):
                every[control_id] = "pass"
        every.update(statuses or {})
        return make_envelope(statuses=every, **kwargs)

    def state_for(self, envelope, environment="private_test", now=NOW):
        derived = readiness_mod.derive_into(envelope, now)
        return [r for r in derived["readiness"]
                if r["scope"]["environment"] == environment][0]

    def test_clean_scope_reaches_no_known_blocker(self):
        readiness = self.state_for(self.full_review())
        self.assertEqual("no_known_blocker", readiness["state"])
        self.assertEqual([], readiness["blockers"])

    def test_unassessed_critical_control_keeps_it_incomplete(self):
        readiness = self.state_for(make_envelope(statuses={ANON: "pass"}))
        self.assertEqual("incomplete", readiness["state"])
        self.assertTrue(any(u.get("control_ids") for u in readiness["unknowns"]))

    def test_draft_context_keeps_it_incomplete(self):
        envelope = self.full_review(context=make_context(
            confirmation={"state": "draft"}))
        readiness = self.state_for(envelope)
        self.assertEqual("incomplete", readiness["state"])
        self.assertIn("readiness.incomplete.context_draft",
                      readiness["derivation"]["rules_applied"])

    def test_bypassed_review_stays_visible_as_a_gap(self):
        envelope = self.full_review(context=make_context(
            confirmation={"state": "review_bypassed"}))
        readiness = self.state_for(envelope)
        self.assertEqual("incomplete", readiness["state"])
        self.assertIn("readiness.incomplete.context_review_bypassed",
                      readiness["derivation"]["rules_applied"])

    def test_future_human_review_does_not_open_the_gate(self):
        envelope = self.full_review(context=make_context(confirmation={
            "state": "human_reviewed", "confirmed_by": "founder:test",
            "confirmed_at": "2026-08-17T12:00:00Z",
        }))
        readiness = self.state_for(envelope)
        self.assertEqual("incomplete", readiness["state"])
        self.assertIn("readiness.incomplete.context_not_yet_confirmed",
                      readiness["derivation"]["rules_applied"])

    def test_expired_context_forces_reassessment(self):
        envelope = self.full_review(context=make_context(
            valid_until="2026-07-01T00:00:00Z",
            confirmation={"state": "human_reviewed",
                          "confirmed_by": "founder:test",
                          "confirmed_at": "2026-05-01T00:00:00Z"}))
        self.assertEqual("no_known_blocker",
                         self.state_for(envelope, now="2026-06-01T00:00:00Z")["state"])
        later = self.state_for(envelope)
        self.assertEqual("incomplete", later["state"])
        self.assertIn("readiness.incomplete.context_expired",
                      later["derivation"]["rules_applied"])

    def test_expired_supporting_evidence_unseats_a_pass(self):
        envelope = self.full_review()
        readiness = self.state_for(envelope, now=LATER)
        self.assertEqual("incomplete", readiness["state"])
        self.assertIn("readiness.incomplete.expired_supporting_evidence",
                      readiness["derivation"]["rules_applied"])

    def test_high_contextual_risk_blocks_the_scope(self):
        envelope = self.full_review({ANON: "fail"})
        readiness = self.state_for(envelope, "public_release")
        self.assertEqual("blocked", readiness["state"])
        self.assertTrue(readiness["blockers"])

    def test_open_blocking_action_blocks_on_its_own(self):
        action = {
            "action_id": "act-block",
            "kind": "remediate",
            "outcome": "Rotate the leaked key and confirm the old one is dead.",
            "reason": "A provider key was committed.",
            "urgency": "immediate",
            "deadline": {"kind": "immediate", "rationale": "The key is live."},
            "blocking_scope": [{"environment": "private_test",
                                "intended_use": "invite_only_pilot"}],
            "owner": {"role": "developer"},
            "state": "open",
        }
        readiness = self.state_for(self.full_review(actions=[action]))
        self.assertEqual("blocked", readiness["state"])
        self.assertEqual(["act-block"], [b["ref"] for b in readiness["blockers"]])

    def test_accepted_critical_control_blocks(self):
        envelope = self.full_review({ANON: "risk_accepted"})
        readiness = self.state_for(envelope)
        self.assertEqual("blocked", readiness["state"])
        self.assertTrue(any("can never be accepted" in b["reason"]
                            for b in readiness["blockers"]))

    def test_expired_risk_acceptance_is_incomplete_not_conditional(self):
        envelope = self.full_review({BACKUPS: "risk_accepted"})
        accepted = [a for a in envelope["assessments"]
                    if a["control_id"] == BACKUPS][0]
        accepted["acceptance"]["review_by"] = "2026-08-01T00:00:00Z"
        readiness = self.state_for(envelope)
        self.assertEqual("incomplete", readiness["state"])
        self.assertIn("readiness.incomplete.expired_risk_acceptance",
                      readiness["derivation"]["rules_applied"])
        self.assertFalse(any("accepted.data.tested_backups" in
                             c.get("condition_id", "")
                             for c in readiness.get("conditions") or []))

    def test_unknown_risk_is_material_and_never_low(self):
        envelope = self.full_review({ANON: "fail"},
                                    context=make_context({"data_sensitivity": None}))
        readiness = self.state_for(envelope)
        self.assertEqual("incomplete", readiness["state"])
        self.assertTrue(all(u["material"] for u in readiness["unknowns"]))

    def test_conditional_state_lists_enforceable_conditions(self):
        measure = {
            "compensating_control_id": "cc-proxy",
            "description": "Identity-aware proxy in front of the API.",
            "enforced_by": "Cloudflare Access policy, owned by founder:test",
            "evidence_refs": ["ev-proxy"],
            "applies_to": {"domains": ["security"]},
            "valid_until": "2026-09-15T00:00:00Z",
            "readiness_condition": True,
            "reassess_trigger": {"kind": "before_environment",
                                 "value": "public_release"},
        }
        evidence = [{
            "evidence_id": "ev-proxy",
            "provider": {"name": "reviewer"},
            "subject": {"kind": "config", "locator": "access-policy"},
            "environment": "private_test",
            "operation": "config_export_review",
            "scope": "the exported policy",
            "claim": {"control_ids": [ANON],
                      "statement": "The control requirement is met"},
            "direction": "supports",
            "strength": "decisive",
            "observed_at": NOW,
            "valid_until": "2026-09-15T00:00:00Z",
        }]
        envelope = self.full_review(context=make_context(
            compensating_controls=[measure]), evidence=evidence)
        readiness = self.state_for(envelope)
        self.assertEqual("conditional", readiness["state"])
        condition = readiness["conditions"][0]
        self.assertTrue(condition["enforced_by"].strip())
        self.assertIn("reassess_trigger", condition)
        self.assertEqual("2026-09-15T00:00:00Z", condition["expires_at"])

    def test_lapsed_measure_is_no_longer_an_enforceable_condition(self):
        measure = {
            "compensating_control_id": "cc-proxy",
            "description": "Identity-aware proxy in front of the API.",
            "enforced_by": "Cloudflare Access policy, owned by founder:test",
            "evidence_refs": ["ev-proxy"],
            "applies_to": {"domains": ["security"]},
            # the measure lapses before its evidence does
            "valid_until": "2026-08-01T00:00:00Z",
            "readiness_condition": True,
        }
        evidence = [{
            "evidence_id": "ev-proxy",
            "provider": {"name": "reviewer"},
            "subject": {"kind": "config", "locator": "access-policy"},
            "environment": "private_test",
            "operation": "config_export_review",
            "scope": "the exported policy",
            "claim": {"control_ids": [ANON],
                      "statement": "The control requirement is met"},
            "direction": "supports",
            "strength": "decisive",
            "observed_at": NOW,
            "valid_until": "2026-12-01T00:00:00Z",
        }]
        readiness = self.state_for(self.full_review(
            context=make_context(compensating_controls=[measure]),
            evidence=evidence))
        self.assertEqual("no_known_blocker", readiness["state"])
        self.assertNotIn("conditions", readiness)

    def test_renewed_context_moves_the_reassessment_deadline(self):
        envelope = readiness_mod.derive_into(
            make_envelope(make_context(valid_until="2026-08-20T00:00:00Z"),
                          {ANON: "fail"}), NOW)
        before = [r for r in risk_mod.current_risks(envelope)
                  if r["scope"]["environment"] == "private_test"][0]
        self.assertEqual("2026-08-20T00:00:00Z", before["reassess_by"])
        renewed = ctx.revise(envelope["context"],
                             valid_until="2027-06-01T00:00:00Z",
                             confirmed_by="founder:test", now=NOW)
        updated = readiness_mod.derive_into(
            ctx.revise_envelope_context(envelope, renewed), NOW)
        after = [r for r in risk_mod.current_risks(updated)
                 if r["scope"]["environment"] == "private_test"][0]
        self.assertNotEqual(before["reassess_by"], after["reassess_by"])
        self.assertEqual(before["risk_id"], after["supersedes"])
        self.assertFalse(risk_mod.is_stale(after, updated, "2026-09-01T00:00:00Z"))
        self.assertEqual([], canonical.validate_envelope(updated))

    def test_blocked_beats_incomplete_beats_conditional(self):
        # a draft context alone is incomplete; add a blocking failure and the
        # scope is blocked, not merely incomplete
        draft = make_context(confirmation={"state": "draft"})
        self.assertEqual("incomplete", self.state_for(
            self.full_review(context=draft))["state"])
        self.assertEqual("blocked", self.state_for(
            self.full_review({ANON: "fail"}, context=draft),
            "public_release")["state"])

    def test_narrow_scope_never_grants_the_wider_one(self):
        prototype = make_context(
            {"lifecycle": "building", "audience_scale": "none_yet",
             "network_exposure": "local_only", "authentication": "none",
             "tenancy": "single_user", "data_sensitivity": "synthetic_or_none",
             "business_criticality": "experiment"},
            target_scopes=[{"environment": "developer_only",
                            "intended_use": "prototype_demo"},
                           {"environment": "public_release",
                            "intended_use": "public_product"}],
            current_scope={"environment": "developer_only",
                           "intended_use": "prototype_demo"})
        envelope = self.full_review({ANON: "fail"}, context=prototype)
        here = self.state_for(envelope, "developer_only")
        self.assertEqual("no_known_blocker", here["state"])
        transitions = here["blocked_transitions"]
        self.assertEqual(1, len(transitions))
        self.assertEqual("public_release", transitions[0]["scope"]["environment"])
        self.assertEqual("blocked", transitions[0]["state"])
        # and the control is still failed
        self.assertEqual("fail", [a for a in envelope["assessments"]
                                  if a["control_id"] == ANON][0]["status"])

    def test_readiness_is_recomputed_not_appended(self):
        envelope = self.full_review()
        once = readiness_mod.derive_into(envelope, NOW)
        twice = readiness_mod.derive_into(once, NOW)
        self.assertEqual(len(once["readiness"]), len(twice["readiness"]))
        self.assertEqual(canonical.dumps(once["readiness"]),
                         canonical.dumps(twice["readiness"]))

    def test_no_readiness_object_claims_safety(self):
        envelope = readiness_mod.derive_into(self.full_review(), NOW)
        for readiness in envelope["readiness"]:
            for banned in ("secure", "certified", "ready_to_ship"):
                self.assertNotIn(banned, readiness)
            rendered = json.dumps(readiness, ensure_ascii=False).lower()
            for phrase in ("is secure", "certified", "ready to ship"):
                self.assertNotIn(phrase, rendered)


class TestFrameworkVerdict(unittest.TestCase):
    def verdict(self, statuses, **kwargs):
        envelope = make_envelope(statuses=statuses, **kwargs)
        key, _counts = readiness_mod.framework_verdict(envelope)
        return key

    def test_ladder(self):
        registry = {c["control_id"]: c for c in canonical.load_registry()["controls"]}
        complete = {cid: "pass" for cid, entry in registry.items()
                    if entry["kind"] != "screening"}
        complete.update({cid: "answered" for cid, entry in registry.items()
                         if entry["kind"] == "screening"})
        self.assertEqual("not_reviewed", self.verdict({}))
        self.assertEqual("complete", self.verdict(complete))
        self.assertEqual("incomplete", self.verdict(
            dict(complete, **{ANON: "not_tested"})))
        self.assertEqual("block", self.verdict(dict(complete, **{ANON: "fail"})))
        self.assertEqual("block_high", self.verdict(
            dict(complete, **{BACKUPS: "fail"})))
        self.assertEqual("fix", self.verdict(dict(complete, **{ERRORS: "fail"})))

    @unittest.skipUnless(HAVE_OPENPYXL, "openpyxl not installed")
    def test_wording_matches_the_workbook(self):
        import build_workbook
        english = build_workbook.STR["en"]
        self.assertEqual(
            {"not_reviewed": english["v_notrev"],
             "incomplete": english["v_incomplete"],
             "block": english["v_block"],
             "block_high": english["v_block_high"],
             "fix": english["v_fix"],
             "complete": english["v_rc"]},
            readiness_mod.VERDICTS)

    def test_every_difference_is_explained(self):
        for case_id in ("developer-only-prototype", "private-invite-only-pilot",
                        "public-product", "sensitive-high-impact-unknowns"):
            for readiness in load_golden(case_id)["readiness"]:
                with self.subTest(case=case_id, scope=readiness["readiness_id"]):
                    verdict = readiness["framework_verdict"]
                    self.assertIn(verdict["agreement"], ("aligned", "differs"))
                    self.assertTrue(verdict["explanation"].strip())
                    self.assertEqual(controls.FRAMEWORK, verdict["framework"])

    def test_block_versus_no_known_blocker_is_explained_specifically(self):
        readiness = [r for r in load_golden("developer-only-prototype")["readiness"]
                     if r["scope"]["environment"] == "developer_only"][0]
        verdict = readiness["framework_verdict"]
        self.assertEqual("BLOCK", verdict["verdict"])
        self.assertEqual("no_known_blocker", readiness["state"])
        self.assertEqual("differs", verdict["agreement"])
        self.assertIn("blocked_transitions", verdict["explanation"])


# ---------------------------------------------------------------- goldens

class TestGoldenCases(unittest.TestCase):
    def test_cases_are_current(self):
        for path, rendered in gen_goldens.artifacts().items():
            rel = os.path.relpath(path, REPO)
            with self.subTest(case=rel):
                with open(path, encoding="utf-8") as fh:
                    self.assertEqual(fh.read(), rendered,
                                     "%s is stale: run python3 scripts/gen_goldens.py"
                                     % rel)

    def test_cases_validate(self):
        for spec in gen_goldens.load_specs():
            with self.subTest(case=spec["case_id"]):
                self.assertEqual([], canonical.validate_envelope(
                    load_golden(spec["case_id"])))

    def test_four_scope_profiles_are_covered(self):
        covered = set()
        for spec in gen_goldens.load_specs():
            for scope in spec["target_scopes"]:
                covered.add((scope["environment"], scope["intended_use"]))
        for expected in (("developer_only", "prototype_demo"),
                         ("private_test", "invite_only_pilot"),
                         ("public_release", "public_product"),
                         ("public_release", "sensitive_or_high_impact")):
            self.assertIn(expected, covered)

    def test_every_readiness_state_is_exercised(self):
        states = set()
        for spec in gen_goldens.load_specs():
            for readiness in load_golden(spec["case_id"])["readiness"]:
                states.add(readiness["state"])
        self.assertEqual({"no_known_blocker", "conditional", "blocked",
                          "incomplete"}, states)

    def test_prototype_case_keeps_the_failures_and_blocks_the_public_scope(self):
        envelope = load_golden("developer-only-prototype")
        statuses = {a["control_id"]: a["status"] for a in envelope["assessments"]}
        self.assertEqual("fail", statuses[ANON])
        by_scope = {r["scope"]["environment"]: r for r in envelope["readiness"]}
        self.assertEqual("no_known_blocker", by_scope["developer_only"]["state"])
        self.assertEqual("blocked", by_scope["public_release"]["state"])

    def test_unknown_case_stays_incomplete_in_every_scope(self):
        envelope = load_golden("sensitive-high-impact-unknowns")
        levels = {r["level"] for r in envelope["risks"]}
        self.assertIn("unknown", levels)
        self.assertNotIn("low", levels)
        for readiness in envelope["readiness"]:
            self.assertEqual("incomplete", readiness["state"])

    def test_pilot_case_is_conditional_on_an_enforced_measure(self):
        envelope = load_golden("private-invite-only-pilot")
        pilot = [r for r in envelope["readiness"]
                 if r["scope"]["environment"] == "private_test"][0]
        self.assertEqual("conditional", pilot["state"])
        self.assertTrue(pilot["conditions"])
        self.assertTrue(all(c["enforced_by"].strip() for c in pilot["conditions"]))

    def test_public_case_blocks_on_the_open_action_as_well_as_the_risk(self):
        envelope = load_golden("public-product")
        readiness = envelope["readiness"][0]
        self.assertEqual("blocked", readiness["state"])
        refs = [b["ref"] for b in readiness["blockers"]]
        self.assertIn("act-close-anon-read", refs)

    def test_context_only_change_creates_a_new_revision(self):
        envelope = load_golden("developer-only-prototype")
        before = [r for r in envelope["readiness"]
                  if r["scope"]["environment"] == "developer_only"][0]
        revised = ctx.revise(
            envelope["context"],
            profile=ctx.profile({"data_sensitivity": "personal_data",
                                 "audience_scale": "known_group",
                                 "network_exposure": "public_internet",
                                 "business_criticality": "core_operation"},
                                source="founder:kai"),
            confirmed_by="founder:kai", now=NOW)
        updated = readiness_mod.derive_into(
            ctx.revise_envelope_context(envelope, revised), NOW)
        after = [r for r in updated["readiness"]
                 if r["scope"]["environment"] == "developer_only"][0]

        self.assertEqual(2, updated["revision"])
        self.assertEqual(2, updated["context"]["revision"])
        self.assertEqual(
            envelope["context"]["confirmation"]["source_fingerprint"],
            updated["context"]["confirmation"]["source_fingerprint"],
            "a context revision must not pretend the source code changed")
        self.assertNotEqual(envelope["context"]["context_fingerprint"],
                            updated["context"]["context_fingerprint"])
        self.assertEqual("no_known_blocker", before["state"])
        self.assertEqual("blocked", after["state"])
        self.assertEqual([], canonical.validate_envelope(updated))
        # the assessments themselves are untouched: only the context moved
        self.assertEqual(canonical.dumps(envelope["assessments"]),
                         canonical.dumps(updated["assessments"]))


class TestCli(unittest.TestCase):
    def test_cli_derives_and_validates(self):
        path = os.path.join(GOLDEN_DIR, "public-product.json")
        result = subprocess.run(
            [sys.executable, os.path.join(REPO, "scripts", "readiness.py"),
             path, "--now", NOW],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        self.assertEqual(0, result.returncode, result.stderr.decode())
        envelope = json.loads(result.stdout.decode())
        self.assertEqual([], canonical.validate_envelope(envelope))
        self.assertEqual(canonical.dumps(envelope), result.stdout.decode())

    def test_summary_states_what_vibecheck_is_not(self):
        path = os.path.join(GOLDEN_DIR, "developer-only-prototype.json")
        result = subprocess.run(
            [sys.executable, os.path.join(REPO, "scripts", "readiness.py"),
             path, "--now", NOW, "--summary"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        self.assertEqual(0, result.returncode, result.stderr.decode())
        output = result.stdout.decode()
        self.assertIn("NO_KNOWN_BLOCKER", output)
        self.assertIn("not a certification", output)


class TestSemanticGuards(unittest.TestCase):
    """R8's structural half in canonical.validate_envelope."""

    def envelope_with_readiness(self, readiness):
        envelope = make_envelope(statuses={ANON: "fail"})
        envelope["readiness"] = [readiness]
        return envelope

    def base_readiness(self, **overrides):
        readiness = {
            "readiness_id": "rdy-private_test.invite_only_pilot",
            "scope": {"environment": "private_test",
                      "intended_use": "invite_only_pilot"},
            "state": "no_known_blocker",
            "blockers": [],
            "unknowns": [],
            "assessed_at": NOW,
        }
        readiness.update(overrides)
        return readiness

    def test_material_unknown_cannot_coexist_with_a_clean_state(self):
        problems = canonical.validate_envelope(self.envelope_with_readiness(
            self.base_readiness(unknowns=[{"description": "unknown thing",
                                           "material": True}])))
        self.assertTrue(any(p.startswith("R8:") for p in problems), problems)

    def test_listed_blocker_forces_blocked(self):
        problems = canonical.validate_envelope(self.envelope_with_readiness(
            self.base_readiness(state="conditional",
                                blockers=[{"ref": "act-x", "reason": "y"}],
                                conditions=[{"condition_id": "cond-x",
                                             "requirement": "y",
                                             "enforced_by": "z",
                                             "reassess_trigger": {
                                                 "kind": "context_change"}}])))
        self.assertTrue(any(p.startswith("R8:") for p in problems), problems)

    def test_immaterial_unknown_is_allowed(self):
        problems = canonical.validate_envelope(self.envelope_with_readiness(
            self.base_readiness(unknowns=[{"description": "noted",
                                           "material": False}])))
        self.assertEqual([], problems)

    def envelope_with_risk(self, risk, evidence_valid_until):
        envelope = make_envelope(statuses={ANON: "fail"})
        envelope["evidence"].append({
            "evidence_id": "ev-support",
            "provider": {"name": "reviewer"},
            "subject": {"kind": "config", "locator": "access-policy"},
            "environment": "private_test",
            "operation": "config_export_review",
            "scope": "the exported policy",
            "claim": {"control_ids": [ANON],
                      "statement": "The control requirement is met"},
            "direction": "supports",
            "strength": "decisive",
            "observed_at": NOW,
            "valid_until": evidence_valid_until,
        })
        envelope["risks"] = [risk]
        return envelope

    def hand_authored_risk(self, **overrides):
        risk = {
            "risk_id": "rsk-hand-authored",
            "control_refs": [ANON],
            "domain": "security",
            "scope": {"environment": "private_test",
                      "intended_use": "invite_only_pilot"},
            "horizon": {"kind": "current"},
            "method": {"name": "vibecheck.risk_matrix", "version": "1.0.0"},
            "inputs": {
                "impact": "major",
                "exposure": "plausible",
                "affected": "pilot customer records",
                "plausibility_rationale": "reachable with the public anon key",
                "blast_radius": "every row in public.orders",
            },
            "level": "high",
            "confidence": "high",
            "assessed_at": NOW,
        }
        risk.update(overrides)
        return risk

    def test_downgrade_needs_evidence_that_holds_now(self):
        downgrade = {"from_level": "high",
                     "rationale": "the proxy in front of the API is enforced",
                     "evidence_refs": ["ev-support"],
                     "approved_by": "reviewer:test"}
        stale = canonical.validate_envelope(self.envelope_with_risk(
            self.hand_authored_risk(level="moderate", downgrade=downgrade),
            "2026-07-01T00:00:00Z"))
        self.assertTrue(any("downgraded without current supporting evidence" in p
                            for p in stale), stale)
        fresh = canonical.validate_envelope(self.envelope_with_risk(
            self.hand_authored_risk(level="moderate", downgrade=downgrade),
            "2026-12-01T00:00:00Z"))
        self.assertEqual([], fresh)

    def test_compensating_control_needs_evidence_that_holds_now(self):
        inputs_with_measure = {
            "impact": "major",
            "exposure": "unlikely",
            "affected": "pilot customer records",
            "plausibility_rationale": "reachable only through the proxy",
            "blast_radius": "every row in public.orders",
            "compensating_controls": [{
                "description": "identity-aware proxy",
                "evidence_refs": ["ev-support"],
                "exposure_reduction_applied": True,
            }],
        }
        stale = canonical.validate_envelope(self.envelope_with_risk(
            self.hand_authored_risk(inputs=inputs_with_measure, level="moderate"),
            "2026-07-01T00:00:00Z"))
        self.assertTrue(any(p.startswith("R7:") for p in stale), stale)
        fresh = canonical.validate_envelope(self.envelope_with_risk(
            self.hand_authored_risk(inputs=inputs_with_measure, level="moderate"),
            "2026-12-01T00:00:00Z"))
        self.assertEqual([], fresh)

    def test_expired_downgrade_evidence_makes_stored_risk_stale(self):
        downgrade = {"from_level": "high",
                     "rationale": "the proxy in front of the API is enforced",
                     "evidence_refs": ["ev-support"],
                     "approved_by": "reviewer:test"}
        risk = self.hand_authored_risk(level="moderate", downgrade=downgrade)
        envelope = self.envelope_with_risk(
            risk, "2026-12-01T00:00:00Z")
        self.assertEqual([], canonical.validate_envelope(envelope))
        self.assertTrue(risk_mod.is_stale(
            risk, envelope, "2027-01-01T00:00:00Z"))
        self.assertEqual("unknown", risk_mod.effective_level(
            risk, envelope, "2027-01-01T00:00:00Z"))


if __name__ == "__main__":
    unittest.main()
