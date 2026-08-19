#!/usr/bin/env python3
"""Action/Procedure registry and exact attempts."""
import copy
import json
import os
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "scripts"))

import actions  # noqa: E402
import adapters  # noqa: E402
import canonical  # noqa: E402

try:
    from jsonschema import Draft202012Validator
    HAVE_JSONSCHEMA = True
except ImportError:  # pragma: no cover
    HAVE_JSONSCHEMA = False

EXAMPLE = os.path.join(
    REPO, "schema", "examples", "action-procedure-registry.json")
NOW = "2026-08-16T13:00:00Z"


def load_example():
    with open(EXAMPLE, encoding="utf-8") as fh:
        return json.load(fh)


class TestRegistryExample(unittest.TestCase):
    def test_example_is_a_valid_modern_envelope(self):
        self.assertEqual([], canonical.validate_envelope(load_example()))

    def test_one_outcome_offers_automated_guided_and_specialist_methods(self):
        env = load_example()
        self.assertEqual(1, len(env["actions"]))
        procedures = {p["procedure_id"]: p for p in env["procedures"]}
        offered = [procedures[ref] for ref in env["actions"][0]["procedure_refs"]]
        self.assertEqual(
            {"automated", "guided", "manual"},
            {p["execution_mode"] for p in offered})
        self.assertIn("specialist", {p["executor_role"] for p in offered})

    def test_legacy_classification_is_derived_and_explicitly_lossy(self):
        env = load_example()
        view = actions.legacy_view(env)
        self.assertEqual(view, adapters.export_legacy_action_view(env))
        rows = view["actions"][0]["procedure_views"]
        self.assertEqual(["AUTO", "PROPOSE", "ADVISORY"],
                         [row["classification"] for row in rows])
        self.assertTrue(view["lossy"])
        self.assertIn("not permission", view["warning"])
        serialized = canonical.dumps(env)
        for legacy in ("AUTO", "PROPOSE", "ADVISORY"):
            self.assertNotIn(legacy, serialized,
                             "legacy tiers must not become canonical fields")

    def test_automated_does_not_mean_pre_authorized(self):
        env = load_example()
        procedure = next(p for p in env["procedures"]
                         if p["execution_mode"] == "automated")
        legacy = actions.legacy_view(env)["actions"][0]["procedure_views"][0]
        self.assertEqual("AUTO", legacy["classification"])
        self.assertEqual("not_required", procedure["authorization"]["consent"])
        # Change only consent: classification stays a description of method,
        # not a grant of permission.
        procedure["authorization"]["consent"] = "explicit_consent_per_run"
        changed = actions.legacy_view(env)["actions"][0]["procedure_views"][0]
        self.assertEqual("AUTO", changed["classification"])
        self.assertEqual("explicit_consent_per_run", changed["consent"])

    def test_every_former_fix_tier_example_fits_orthogonal_fields(self):
        base = load_example()["procedures"][0]
        cases = {
            "untrack_env": ("vibecheck_agent", "automated", "repo_hygiene", ["write"]),
            "cors_allowlist": ("developer", "guided", "code_change", ["write"]),
            "empty_catch": ("developer", "guided", "code_change", ["write"]),
            "redact_logging": ("developer", "guided", "code_change", ["write"]),
            "gitignore": ("vibecheck_agent", "automated", "repo_hygiene", ["write"]),
            "lockfile": ("vibecheck_agent", "automated", "registry_resolution", ["write"]),
            "rls_missing": ("developer", "guided", "sql_migration", ["write", "deployment"]),
            "rls_permissive": ("developer", "guided", "sql_migration", ["write", "deployment"]),
            "sql_injection": ("developer", "guided", "code_change", ["write"]),
            "llm_exec": ("developer", "guided", "code_change", ["write"]),
            "tool_agent": ("developer", "guided", "code_change", ["write"]),
            "client_llm": ("developer", "guided", "architecture_change", ["write", "deployment"]),
            "webhook_signature": ("developer", "guided", "code_change", ["write"]),
            "secret_rotation": ("platform", "manual", "provider_rotation", ["external_accounts"]),
            "history_purge": ("developer", "guided", "history_rewrite", ["write", "destructive"]),
            "backup_budget_dpa_legal": ("specialist", "manual", "specialist_or_dashboard_review", []),
        }
        env = load_example()
        env["actions"] = []
        env["attempts"] = []
        env["procedures"] = []
        for name, (role, mode, mechanism, effects) in cases.items():
            procedure = copy.deepcopy(base)
            procedure.update({
                "procedure_id": "prc-%s-v1" % name.replace("_", "-"),
                "procedure_key": name.replace("_", "-"),
                "title": name,
                "executor_role": role,
                "execution_mode": mode,
                "mechanism": mechanism,
            })
            for flag in ("write", "destructive", "deployment", "data",
                         "external_accounts"):
                procedure["effects"][flag] = flag in effects
            effectful = bool(effects)
            procedure["authorization"] = {
                "consent": "explicit_consent" if effectful else "not_required",
                **({"scope": "%s targets only" % name} if effectful else {}),
            }
            network = name in ("lockfile", "secret_rotation")
            procedure["network"] = {
                "required": network,
                **({"destinations": ["named provider endpoint"]} if network else {}),
            }
            env["procedures"].append(procedure)
        self.assertEqual([], actions.validate_registry(env))


class TestAttemptConsent(unittest.TestCase):
    def setUp(self):
        self.env = load_example()
        self.attempt = self.env["attempts"][0]

    def problems(self):
        return actions.validate_registry(self.env)

    def test_consent_is_bound_to_the_exact_attempt(self):
        self.attempt["authorization"]["attempt_ref"] = "att-some-later-run"
        self.assertTrue(any("not bound to that exact attempt" in p
                            for p in self.problems()))

    def test_consent_cannot_predate_the_exact_revisions(self):
        self.attempt["authorization"]["granted_at"] = "2026-08-16T11:59:00Z"
        problems = self.problems()
        self.assertTrue(any("consent predates its exact Action revision" in p
                            for p in problems))
        self.assertTrue(any("consent predates its exact Procedure revision" in p
                            for p in problems))

    def test_authorization_record_cannot_be_reused_for_a_later_attempt(self):
        later = copy.deepcopy(self.attempt)
        later["attempt_id"] = "att-read-only-plan-2"
        later["authorization"]["attempt_ref"] = later["attempt_id"]
        self.env["attempts"].append(later)
        self.assertTrue(any("is reused across attempts" in p
                            for p in self.problems()))

    def test_later_or_different_side_effect_is_not_authorized(self):
        self.attempt["side_effects_observed"]["write"] = True
        self.assertTrue(any("unauthorized side effects: write" in p
                            for p in self.problems()))

    def test_target_scope_is_exact_not_only_effect_type(self):
        self.attempt["authorization"]["effects"]["targets"] = [
            "current source tree"]
        self.attempt["side_effects_observed"]["targets"] = [
            "a later production repository"]
        self.assertTrue(any("a later production repository" in p
                            for p in self.problems()))

    def test_data_egress_destination_cannot_change_after_consent(self):
        procedure = next(p for p in self.env["procedures"]
                         if p["procedure_id"] == self.attempt["procedure_ref"])
        procedure["authorization"] = {
            "consent": "explicit_consent",
            "scope": "Send the bounded result to approved.example only.",
        }
        procedure["network"] = {
            "required": True, "destinations": ["approved.example"]}
        procedure["data_egress"] = {
            "occurs": True, "destinations": ["approved.example"]}
        self.attempt["authorization"]["mode"] = "explicit_consent"
        self.attempt["authorization"]["effects"]["data_egress"] = True
        self.attempt["authorization"]["effects"][
            "data_egress_destinations"] = ["approved.example"]
        self.attempt["side_effects_observed"]["data_egress"] = True
        self.attempt["side_effects_observed"][
            "data_egress_destinations"] = ["unapproved.example"]
        self.assertTrue(any("data-egress destinations unapproved.example" in p
                            for p in self.problems()))

    def test_egress_boolean_and_destinations_cannot_disagree(self):
        self.attempt["authorization"]["effects"]["data_egress"] = True
        self.assertTrue(any("must pair data egress with exact destinations" in p
                            for p in self.problems()))

    def test_disabled_procedure_egress_cannot_hide_destinations(self):
        procedure = next(p for p in self.env["procedures"]
                         if p["procedure_id"] == self.attempt["procedure_ref"])
        procedure["data_egress"]["destinations"] = ["hidden.example"]
        self.assertTrue(any("while egress is disabled" in p
                            for p in self.problems()))

    def test_per_run_consent_cannot_be_reused_as_preauthorization(self):
        procedure = next(p for p in self.env["procedures"]
                         if p["procedure_id"] == self.attempt["procedure_ref"])
        procedure["authorization"]["consent"] = "explicit_consent_per_run"
        self.attempt["authorization"]["mode"] = "pre_authorized"
        self.assertTrue(any("fresh explicit consent" in p
                            for p in self.problems()))

    def test_inputs_are_references_not_secret_values(self):
        self.assertTrue(self.attempt["input_refs"])
        for ref in self.attempt["input_refs"]:
            self.assertNotIn("value", ref)
            self.assertIn("locator", ref)

    def _targets(self, authorized, observed):
        self.attempt["authorization"]["effects"]["targets"] = authorized
        self.attempt["side_effects_observed"]["targets"] = observed
        return [p for p in self.problems() if "targets" in p]

    def test_consent_may_narrow_a_declared_target_to_an_exact_one(self):
        """The Procedure declares the scope; consent names the exact target.

        Plain set containment would force all three layers to repeat the
        Procedure's one string, which is the opposite of an exact scope.
        """
        self.assertEqual([], self._targets(
            ["current source tree/src/orders.ts"], []))
        self.assertEqual([], self._targets(
            ["current source tree"], ["current source tree:orders"]))

    def test_a_target_outside_the_declared_scope_is_still_refused(self):
        self.assertTrue(self._targets(["a later production repository"], []))
        self.assertTrue(self._targets(
            ["current source tree"], ["a later production repository"]))

    def test_a_lookalike_prefix_is_not_a_refinement(self):
        self.assertTrue(self._targets(["current source tree evil"], []))


class TestCompletionAndLifecycle(unittest.TestCase):
    def setUp(self):
        self.env = load_example()
        self.action = self.env["actions"][0]
        self.attempt = self.env["attempts"][0]

    def mark_done(self):
        self.action["state"] = "done"
        self.action["state_history"].append({
            "state": "done", "at": NOW, "by": "reviewer:example"})

    def test_failed_attempt_does_not_complete_action(self):
        self.mark_done()
        self.attempt["result"] = "failed"
        problems = actions.validate_registry(self.env)
        self.assertTrue(any("failed/partial attempts" in p
                            for p in problems))

    def test_partial_attempt_does_not_complete_action(self):
        self.mark_done()
        self.attempt["result"] = "partially_succeeded"
        problems = actions.validate_registry(self.env)
        self.assertTrue(any("failed/partial attempts" in p
                            for p in problems))

    def test_success_without_evidence_or_reassessment_does_not_complete(self):
        self.mark_done()
        self.attempt["result"] = "succeeded"
        self.assertTrue(any("no succeeded attempt with a fresh" in p
                            for p in actions.validate_registry(self.env)))

    def test_success_evidence_and_reassessment_complete(self):
        self.mark_done()
        self.attempt["result"] = "succeeded"
        self.attempt["evidence_refs"] = ["ev-independent-result"]
        self.attempt["reassessment_refs"] = ["asm-reassessment"]
        self.env["evidence"] = [{
            "evidence_id": "ev-independent-result",
            "observed_at": "2026-08-16T12:06:00Z",
        }]
        self.env["assessments"] = [{
            "assessment_id": "asm-reassessment",
            "assessed_at": "2026-08-16T12:07:00Z",
            "basis": {"evidence_refs": ["ev-independent-result"]},
        }]
        self.assertFalse(any(p.startswith("R19:")
                             for p in actions.validate_registry(self.env)))

    def test_stale_evidence_does_not_complete_action(self):
        self.mark_done()
        self.attempt["result"] = "succeeded"
        self.attempt["evidence_refs"] = ["ev-old-result"]
        self.attempt["reassessment_refs"] = ["asm-reassessment"]
        self.env["evidence"] = [{
            "evidence_id": "ev-old-result",
            "observed_at": "2026-08-16T11:00:00Z",
        }]
        self.env["assessments"] = [{
            "assessment_id": "asm-reassessment",
            "assessed_at": "2026-08-16T12:07:00Z",
            "basis": {"evidence_refs": ["ev-old-result"]},
        }]
        self.assertTrue(any("fresh" in p
                            for p in actions.validate_registry(self.env)))

    def test_reassessment_must_cite_the_fresh_evidence(self):
        self.mark_done()
        self.attempt["result"] = "succeeded"
        self.attempt["evidence_refs"] = ["ev-independent-result"]
        self.attempt["reassessment_refs"] = ["asm-reassessment"]
        self.env["evidence"] = [{
            "evidence_id": "ev-independent-result",
            "observed_at": "2026-08-16T12:06:00Z",
        }]
        self.env["assessments"] = [{
            "assessment_id": "asm-reassessment",
            "assessed_at": "2026-08-16T12:07:00Z",
            "basis": {"evidence_refs": []},
        }]
        self.assertTrue(any("fresh" in p
                            for p in actions.validate_registry(self.env)))

    def test_invalid_state_jump_is_rejected(self):
        self.action["state"] = "done"
        self.action["state_history"] = [
            self.action["state_history"][0],
            {"state": "done", "at": NOW, "by": "reviewer:example"},
        ]
        self.assertTrue(any("invalid state transition open -> done" in p
                            for p in actions.validate_registry(self.env)))


class TestVersionLineages(unittest.TestCase):
    def setUp(self):
        self.env = load_example()
        old = self.env["actions"][0]
        old["state"] = "superseded"
        old["state_history"].append({
            "state": "superseded", "at": NOW, "by": "reviewer:example"})
        self.new = copy.deepcopy(old)
        self.new.update({
            "action_id": "act-enforce-order-access-v2",
            "revision": 2,
            "supersedes": old["action_id"],
            "created_at": "2026-08-16T13:01:00Z",
            "state": "open",
            "state_history": [{
                "state": "open", "at": "2026-08-16T13:01:00Z",
                "by": "reviewer:example",
            }],
        })
        self.env["actions"].append(self.new)

    def test_only_latest_revision_is_current(self):
        self.assertEqual([self.new["action_id"]],
                         [a["action_id"] for a in actions.current_actions(self.env)])
        self.assertFalse(any(p.startswith("R13:")
                             for p in actions.validate_registry(self.env)))

    def test_revision_must_be_monotonic(self):
        self.new["revision"] = 4
        self.assertTrue(any("revision must be exactly one above" in p
                            for p in actions.validate_registry(self.env)))

    def test_lineage_cannot_fork_into_two_current_revisions(self):
        fork = copy.deepcopy(self.new)
        fork["action_id"] = "act-enforce-order-access-v2b"
        self.env["actions"].append(fork)
        problems = actions.validate_registry(self.env)
        self.assertTrue(any("competing successor revisions" in p
                            for p in problems))
        self.assertTrue(any("multiple current revisions" in p
                            for p in problems))

    def test_supersedes_target_must_be_retained(self):
        self.new["supersedes"] = "act-missing-v1"
        self.assertTrue(any("supersedes missing revision" in p
                            for p in actions.validate_registry(self.env)))

    def test_root_lineage_starts_at_revision_one(self):
        self.env["actions"] = [self.new]
        self.new.pop("supersedes")
        self.assertTrue(any("must start at revision 1" in p
                            for p in actions.validate_registry(self.env)))

    def test_superseded_state_needs_an_actual_successor(self):
        self.env["actions"] = [self.env["actions"][0]]
        self.assertTrue(any("has no successor" in p
                            for p in actions.validate_registry(self.env)))

    def test_an_action_may_not_offer_a_superseded_procedure_revision(self):
        """The derived legacy view drops non-current revisions.

        An Action left pointing at revised methods would read as having no
        executable method at all, so it is refused the same way a stale
        depends_on is.
        """
        env = load_example()
        old = env["procedures"][1]
        env["procedures"].append({
            **copy.deepcopy(old),
            "procedure_id": "prc-guided-code-change-v2",
            "revision": 2,
            "supersedes": old["procedure_id"],
            "created_at": "2026-08-16T12:30:00Z",
        })
        self.assertTrue(any("offers superseded procedure revisions" in p
                            for p in actions.validate_registry(env)))
        env["actions"][0]["procedure_refs"] = [
            "prc-read-only-plan-v1", "prc-guided-code-change-v2",
            "prc-specialist-review-v1"]
        self.assertEqual([], actions.validate_registry(env))
        self.assertEqual(
            ["AUTO", "PROPOSE", "ADVISORY"],
            [row["classification"] for row
             in actions.legacy_view(env)["actions"][0]["procedure_views"]])


class TestDeadlineModel(unittest.TestCase):
    def action(self, urgency="planned", kind="none", value=None):
        deadline = {"kind": kind, "rationale": "test",
                    "reassess_trigger": {"kind": "context_change"}}
        if value is not None:
            deadline["value"] = value
        return {"urgency": urgency, "deadline": deadline,
                "blocking_scope": []}

    def test_all_founder_labels_are_deterministic(self):
        cases = [
            (self.action("immediate", "unknown"), "fix_now"),
            (self.action(kind="before_environment", value="private_test"),
             "before_inviting_users"),
            (self.action(kind="before_environment", value="public_release"),
             "before_public_launch"),
            (self.action(kind="before_intended_use",
                         value="sensitive_or_high_impact"),
             "before_sensitive_data"),
            (self.action(kind="before_event", value="traffic scaling"),
             "before_scaling"),
            (self.action("backlog", "none"), "backlog"),
            (self.action("unknown", "unknown"), "unknown"),
        ]
        for action, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(expected, actions.deadline_label_id(action, NOW))

    def test_calendar_deadline_becomes_overdue(self):
        action = self.action(kind="calendar_date", value="2026-08-15T00:00:00Z")
        self.assertEqual("overdue", actions.deadline_label_id(action, NOW))

    def test_parameterized_deadline_must_match_a_blocked_transition(self):
        env = load_example()
        env["actions"][0]["blocking_scope"] = []
        self.assertTrue(any("blocking_scope does not" in p
                            for p in actions.validate_registry(env)))


@unittest.skipUnless(HAVE_JSONSCHEMA, "jsonschema not installed")
class TestStructuralSafety(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = canonical.load_schema()

    def test_effectful_egress_requires_explicit_consent(self):
        env = load_example()
        procedure = env["procedures"][0]
        procedure["data_egress"] = {
            "occurs": True, "destinations": ["example.invalid"]}
        procedure["network"] = {
            "required": True, "destinations": ["example.invalid"]}
        procedure["authorization"]["consent"] = "not_required"
        self.assertTrue(any("requires explicit consent" in problem
                            for problem in canonical.validate_envelope(env)))

    def test_attempt_input_rejects_inline_secret(self):
        attempt = copy.deepcopy(load_example()["attempts"][0])
        attempt["input_refs"][0]["value"] = "do-not-store-this"
        validator = Draft202012Validator({
            "$defs": self.schema["$defs"], "$ref": "#/$defs/procedure_attempt"})
        self.assertFalse(validator.is_valid(attempt))


if __name__ == "__main__":
    unittest.main()
