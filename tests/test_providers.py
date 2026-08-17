#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Increment 6 (gh issue #8): the verification provider registry.

The acceptance criteria of the issue, one class each:

  TestRegistryIsCoherent      the registry says what it claims to say
  TestDeterministicSelection  same requirement + same capabilities -> same plan
  TestRefusalsAreExplained    a stronger method that was refused stays visible
  TestCoverageIsPerCell       requirements are operation- and subject-specific
  TestConstraintsExclude      cost, egress, credentials, environment, effects
  TestProvidersOnlyMakeEvidence  a provider never concludes, never closes
  TestBundledToolsAreProviders   scanner and probe compatibility
  TestSelectionGoldens        the committed fallback chain is current
"""
import copy
import json
import os
import random
import subprocess
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "scripts"))

import adapters  # noqa: E402
import authz as authz_mod  # noqa: E402
import canonical  # noqa: E402
import controls  # noqa: E402
import gen_provider_goldens  # noqa: E402
import items  # noqa: E402
import providers  # noqa: E402

ANON = "vibecheck.control.authz.anon_data_access"
IDOR = "vibecheck.control.authz.object_level"
SECRETS = "vibecheck.control.secrets.no_frontend_literals"

PROBE_INPUTS = ["supabase_url", "supabase_anon_key", "test_account_a_token",
                "test_account_b_token", "known_private_record_id"]
LIVE_EFFECTS = ["network", "data_egress", "credentials"]

NOW = "2026-08-16T12:00:00Z"


def cells(actor, operations, object_class="user_owned_record",
          object_ref="public.orders"):
    return [{"actor": actor, "object_class": object_class,
             "object_ref": object_ref, "operation": operation}
            for operation in operations]


def probe_offer(**overrides):
    kwargs = dict(
        environment="private_test",
        targets=["source_tree", "supabase_project"],
        inputs=PROBE_INPUTS,
        authorized_providers=["prov-supabase-probe"],
        authorized_effects=list(LIVE_EFFECTS),
    )
    kwargs.update(overrides)
    return providers.offer(**kwargs)


def evaluation_for(plan_or_records, provider_id):
    for entry in plan_or_records["ranking"]:
        if entry["provider_id"] == provider_id:
            return entry
    raise AssertionError("%s is not in the ranking" % provider_id)


def constraint_kinds_of(entry):
    return {constraint["kind"] for constraint in entry["constraints"]}


class TestRegistryIsCoherent(unittest.TestCase):
    """The registry is reviewable data, so it has to hold together on its own."""

    @classmethod
    def setUpClass(cls):
        cls.registry = providers.load_registry()
        cls.capabilities = providers.capabilities()

    def test_every_capability_validates_against_the_schema(self):
        try:
            from jsonschema import Draft202012Validator
        except ImportError:
            self.skipTest("jsonschema not installed")
        schema = canonical.load_schema()
        validator = Draft202012Validator(
            {"$ref": "#/$defs/provider_capability", "$defs": schema["$defs"]})
        for record in self.capabilities:
            with self.subTest(provider=record["provider_id"]):
                self.assertEqual(
                    [], [error.message
                         for error in validator.iter_errors(record)])

    def test_every_capability_is_internally_consistent(self):
        source_ops = set(providers.source_operations())
        for record in self.capabilities:
            with self.subTest(provider=record["provider_id"]):
                self.assertEqual(
                    [], providers._validate_capability(record, source_ops))

    def test_the_source_operations_are_the_ones_authz_refuses_a_cell(self):
        # Two modules must not disagree about what a source reading is: the
        # registry decides what a provider may claim, authz decides what an
        # observation may fill, and a drift between them is a hole.
        self.assertEqual(set(authz_mod.STATIC_OPERATIONS),
                         set(providers.source_operations()))

    def test_every_declared_control_exists_in_the_registry(self):
        known = set(controls.CONTROL_IDS.values())
        for record in self.capabilities:
            for entry in record["coverage"]:
                self.assertIn(entry["control_id"], known)

    def test_fallback_order_is_a_total_order(self):
        orders = [record.get("fallback_order")
                  for record in self.registry["providers"]]
        self.assertEqual(len(orders), len(set(orders)))
        self.assertNotIn(None, orders)

    def test_the_issue_fallback_chain_is_the_declared_one(self):
        by_id = {record["provider_id"]: record.get("fallback_order")
                 for record in self.registry["providers"]}
        chain = ["prov-supabase-probe", "prov-playwright-two-account",
                 "prov-guided-browser-test", "prov-code-policy-review"]
        self.assertEqual(sorted(chain, key=lambda pid: by_id[pid]), chain)

    def test_a_coverage_rule_stays_in_step_with_the_scanner_check_map(self):
        scanner = providers.capability("prov-static-scanner")
        covered = {entry["control_id"] for entry in scanner["coverage"]}
        expected = {controls.CONTROL_IDS[number]
                    for item_numbers, _tier in items.SCANNER_CHECKS.values()
                    for number in item_numbers
                    if number in controls.CONTROL_IDS}
        self.assertEqual(expected, covered)

    def test_narrowing_a_capability_keeps_only_the_controls_in_play(self):
        narrowed = providers.capability("prov-code-policy-review",
                                        control_ids=[IDOR])
        self.assertEqual([IDOR],
                         [entry["control_id"] for entry in narrowed["coverage"]])

    def test_an_unknown_provider_has_no_capability(self):
        self.assertIsNone(providers.capability("prov-does-not-exist"))
        with self.assertRaises(KeyError):
            providers.instantiate("prov-does-not-exist")


class TestDeterministicSelection(unittest.TestCase):
    """Acceptance: selection is deterministic for the same requirement and the
    same available capabilities."""

    def setUp(self):
        self.requirement = providers.requirement(
            IDOR, "private_test",
            cells=cells("other_account", ["read", "create", "update", "delete"]))
        self.offer = probe_offer(
            targets=["source_tree", "supabase_project", "deployed_web_app"],
            tools=["node", "playwright"],
            inputs=PROBE_INPUTS + ["deployment_base_url", "test_account_a_login",
                                   "test_account_b_login",
                                   "two_account_flow_spec"],
            authorized_providers=["prov-supabase-probe",
                                  "prov-playwright-two-account"],
            authorized_effects=LIVE_EFFECTS + ["write", "destructive"])

    def test_the_same_inputs_produce_the_same_plan(self):
        first = providers.select(self.requirement, self.offer)
        for _ in range(5):
            self.assertEqual(json.dumps(first, sort_keys=True, default=str),
                             json.dumps(providers.select(self.requirement,
                                                         self.offer),
                                        sort_keys=True, default=str))

    def test_the_load_order_of_the_capabilities_does_not_matter(self):
        baseline = providers.select(self.requirement, self.offer,
                                    providers.capabilities())
        rng = random.Random(20260817)
        for _ in range(10):
            shuffled = providers.capabilities()
            rng.shuffle(shuffled)
            self.assertEqual(
                baseline["selected"],
                providers.select(self.requirement, self.offer,
                                 shuffled)["selected"])
            self.assertEqual(
                json.dumps(baseline, sort_keys=True, default=str),
                json.dumps(providers.select(self.requirement, self.offer,
                                            shuffled),
                           sort_keys=True, default=str))

    def test_the_strongest_safe_applicable_method_goes_first(self):
        plan = providers.select(self.requirement, self.offer)
        self.assertEqual("prov-supabase-probe", plan["selected"][0])

    def test_equal_strength_is_broken_by_the_declared_fallback_order(self):
        # The probe and the Playwright flow are both decisive and both fill
        # cells; the declared order is what decides, not dictionary order.
        plan = providers.select(self.requirement, self.offer)
        self.assertLess(plan["selected"].index("prov-supabase-probe"),
                        plan["selected"].index("prov-playwright-two-account"))

    def test_a_live_observation_outranks_a_source_reading(self):
        plan = providers.select(self.requirement, self.offer)
        ranking = [entry["provider_id"] for entry in plan["ranking"]]
        self.assertLess(ranking.index("prov-supabase-probe"),
                        ranking.index("prov-code-policy-review"))
        self.assertLess(ranking.index("prov-code-policy-review"),
                        ranking.index("prov-static-scanner"))


class TestRefusalsAreExplained(unittest.TestCase):
    """Acceptance: the system explains why higher-ranked providers were
    unavailable or unsafe."""

    def test_an_unauthorized_stronger_provider_is_a_gap_not_a_skip(self):
        plan = providers.select(
            providers.requirement(IDOR, "private_test",
                                  cells=cells("other_account", ["read"])),
            providers.offer(environment="private_test",
                            targets=["source_tree", "supabase_project"],
                            inputs=PROBE_INPUTS))
        gap = next(gap for gap in plan["gaps"]
                   if gap["provider_id"] == "prov-supabase-probe")
        self.assertEqual("provider_excluded", gap["kind"])
        self.assertIn("user_authorization", gap["resolvable_by"])

    def test_the_gap_names_the_exact_grant_that_would_resolve_it(self):
        plan = providers.select(
            providers.requirement(IDOR, "private_test",
                                  cells=cells("other_account", ["read"])),
            providers.offer(environment="private_test",
                            targets=["source_tree", "supabase_project"],
                            inputs=PROBE_INPUTS))
        request = next(item for item in plan["authorization_requests"]
                       if item["provider_id"] == "prov-supabase-probe")
        self.assertEqual("would_strengthen_the_plan", request["reason"])
        self.assertIn("authorize prov-supabase-probe", request["grants"])

    def test_missing_credentials_are_named(self):
        plan = providers.select(
            providers.requirement(IDOR, "private_test",
                                  cells=cells("other_account", ["read"])),
            probe_offer(inputs=["supabase_url"]))
        entry = evaluation_for(plan, "prov-supabase-probe")
        self.assertIn("credentials_missing", constraint_kinds_of(entry))
        self.assertIn("test_account_a_token", _details(entry))

    def test_a_provider_with_nothing_to_observe_is_not_a_withheld_one(self):
        # No Supabase project in this application: the probe is inapplicable,
        # which is different from being refused, and reporting it as a gap
        # would invent work nobody can do.
        plan = providers.select(
            providers.requirement(IDOR, "private_test",
                                  cells=cells("other_account", ["read"])),
            providers.offer(environment="private_test",
                            targets=["source_tree"]))
        entry = evaluation_for(plan, "prov-supabase-probe")
        self.assertFalse(entry["applicable"])
        self.assertIn("target_unavailable", constraint_kinds_of(entry))
        self.assertEqual([], [gap for gap in plan["gaps"]
                              if gap["provider_id"] == "prov-supabase-probe"])

    def test_an_uninstalled_provider_is_a_gap_naming_the_install(self):
        plan = providers.select(
            providers.requirement(IDOR, "public_release",
                                  cells=cells("other_account", ["read"])),
            providers.offer(environment="public_release",
                            targets=["source_tree", "deployed_web_app"]))
        gap = next(gap for gap in plan["gaps"]
                   if gap["provider_id"] == "prov-playwright-two-account")
        self.assertIn("installation", gap["resolvable_by"])

    def test_the_explanation_lists_every_ranked_provider(self):
        requirement = providers.requirement(
            IDOR, "private_test", cells=cells("other_account", ["read"]))
        plan = providers.select(requirement, probe_offer())
        text = "\n".join(providers.explain(plan))
        for record in providers.capabilities():
            self.assertIn(record["name"], text)

    def test_the_explanation_never_claims_the_plan_closed_a_control(self):
        plan = providers.select(
            providers.requirement(ANON, "private_test",
                                  cells=cells("anonymous", ["read"])),
            probe_offer())
        self.assertTrue(plan["coverage"]["requested_cells_covered"])
        self.assertFalse(plan["coverage"]["closes_control"])
        self.assertIn("closes no control", "\n".join(providers.explain(plan)))


def _details(entry):
    return " ".join(constraint["detail"] for constraint in entry["constraints"])


class TestCoverageIsPerCell(unittest.TestCase):
    """Acceptance: coverage requirements are operation- and subject-specific,
    and partial coverage cannot close a broader control."""

    def test_the_probe_covers_the_read_cell_and_not_the_update_cell(self):
        plan = providers.select(
            providers.requirement(
                IDOR, "private_test",
                cells=cells("other_account", ["read", "update"])),
            probe_offer(authorized_effects=LIVE_EFFECTS + ["write"]))
        step = plan["plan"][0]
        self.assertEqual([("other_account", "read")],
                         [(cell["actor"], cell["operation"])
                          for cell in step["covers_cells"]])
        self.assertEqual([("other_account", "update")],
                         [(cell["actor"], cell["operation"])
                          for cell in plan["coverage"]["uncovered_cells"]])

    def test_covering_every_requested_cell_is_still_not_a_closed_control(self):
        plan = providers.select(
            providers.requirement(IDOR, "private_test",
                                  cells=cells("other_account", ["read"])),
            probe_offer())
        self.assertTrue(plan["coverage"]["requested_cells_covered"])
        self.assertFalse(plan["coverage"]["closes_control"])
        self.assertIn("closure_note", plan["coverage"])

    def test_a_requirement_can_be_built_from_the_coverage_state(self):
        envelope = _envelope_with_inventory()
        requirement = providers.requirement_from_coverage(
            envelope, IDOR, "private_test", now=NOW)
        self.assertEqual(4, len(requirement["cells"]))
        self.assertEqual({"read", "create", "update", "delete"},
                         {cell["operation"] for cell in requirement["cells"]})
        self.assertIn("coverage is open", requirement["reason"])

    def test_a_requirement_with_no_cells_is_unestablished_not_met(self):
        # An empty requirement is not a satisfied one: it means nobody has
        # said what this application's private objects are.
        plan = providers.select(
            providers.requirement(IDOR, "private_test"), probe_offer())
        self.assertTrue(plan["coverage"]["cells_unestablished"])
        self.assertFalse(plan["coverage"]["requested_cells_covered"])
        self.assertEqual(1, len(plan["plan"]))
        self.assertIn("unestablished", "\n".join(providers.explain(plan)))

    def test_a_requirement_with_no_cells_still_names_the_best_method(self):
        plan = providers.select(
            providers.requirement(IDOR, "private_test"), probe_offer())
        self.assertEqual(["prov-supabase-probe"], plan["selected"])

    def test_a_subject_the_provider_cannot_observe_makes_it_inapplicable(self):
        requirement = providers.requirement(
            SECRETS, "developer_only", subjects=["table"])
        plan = providers.select(
            requirement,
            providers.offer(environment="developer_only",
                            targets=["source_tree"]))
        entry = evaluation_for(plan, "prov-static-scanner")
        self.assertFalse(entry["applicable"])
        self.assertIn("subject_not_covered", constraint_kinds_of(entry))

    def test_no_provider_claims_a_control_wide_conclusion(self):
        for record in providers.capabilities():
            for entry in record["coverage"]:
                with self.subTest(provider=record["provider_id"],
                                  control=entry["control_id"]):
                    self.assertTrue(entry["closure_threshold"].strip())

    def test_a_source_reading_can_never_fill_a_cell(self):
        for record in providers.capabilities():
            for entry in record["coverage"]:
                if not providers.entry_fills_coverage_cell(entry):
                    continue
                for operation in entry["operations"]:
                    self.assertNotIn(operation, providers.source_operations())

    def test_a_live_method_may_still_declare_that_it_closes_nothing(self):
        # The browser flow asserts on the routes somebody wrote tests for, and
        # default-deny is a statement about the routes nobody did.
        playwright = providers.capability("prov-playwright-two-account")
        entry = next(
            entry for entry in playwright["coverage"]
            if entry["control_id"]
            == "vibecheck.control.authz.server_side_default_deny")
        self.assertFalse(providers.entry_fills_coverage_cell(entry))


class TestConstraintsExclude(unittest.TestCase):
    """Acceptance: cost, data egress, credentials, environment and side effects
    can each exclude a provider."""

    REQUIREMENT = None

    def setUp(self):
        self.requirement = providers.requirement(
            ANON, "private_test", cells=cells("anonymous", ["read", "create"]))

    def _entry(self, off, provider_id="prov-supabase-probe"):
        return evaluation_for(providers.select(self.requirement, off),
                              provider_id)

    def test_an_unauthorized_network_call_excludes_the_provider(self):
        entry = self._entry(probe_offer(authorized_effects=["credentials"]))
        self.assertFalse(entry["eligible"])
        self.assertIn("network_not_accepted", constraint_kinds_of(entry))

    def test_unauthorized_data_egress_excludes_the_provider(self):
        entry = self._entry(probe_offer(
            authorized_effects=["network", "credentials"]))
        self.assertIn("data_egress_not_accepted", constraint_kinds_of(entry))

    def test_an_unapproved_egress_destination_excludes_the_provider(self):
        record = providers.instantiate(
            "prov-supabase-probe",
            egress_destinations=["https://evil.example.supabase.co"])
        entry = providers.evaluate(
            record, self.requirement,
            probe_offer(accepted_egress_destinations=[
                "https://evil.example.supabase.co.attacker.test"]))
        self.assertFalse(entry["eligible"])
        self.assertIn("data_egress_not_accepted", constraint_kinds_of(entry))

    def test_missing_credentials_exclude_the_provider(self):
        entry = self._entry(probe_offer(inputs=["supabase_url"]))
        self.assertIn("credentials_missing", constraint_kinds_of(entry))

    def test_an_unsupported_environment_excludes_the_provider(self):
        requirement = providers.requirement(
            ANON, "public_release", cells=cells("anonymous", ["read"]))
        record = copy.deepcopy(providers.capability("prov-supabase-probe"))
        record["environments"] = ["developer_only"]
        entry = providers.evaluate(record, requirement,
                                   probe_offer(environment="public_release"))
        self.assertFalse(entry["eligible"])
        self.assertIn("environment_unsupported", constraint_kinds_of(entry))

    def test_a_cost_above_what_was_accepted_excludes_the_provider(self):
        record = copy.deepcopy(providers.capability("prov-supabase-probe"))
        record["cost"] = {"monetary": "metered", "compute": "low"}
        entry = providers.evaluate(record, self.requirement, probe_offer())
        self.assertFalse(entry["eligible"])
        self.assertIn("cost_not_accepted", constraint_kinds_of(entry))

    def test_an_unknown_cost_is_not_a_free_one(self):
        record = copy.deepcopy(providers.capability("prov-supabase-probe"))
        record["cost"] = {"monetary": "unknown", "compute": "unknown"}
        entry = providers.evaluate(record, self.requirement, probe_offer())
        self.assertFalse(entry["eligible"])

    def test_an_unauthorized_write_excludes_the_cell_not_the_provider(self):
        plan = providers.select(self.requirement, probe_offer())
        entry = evaluation_for(plan, "prov-supabase-probe")
        self.assertTrue(entry["eligible"])
        self.assertEqual(["read"], [cell["operation"]
                                    for cell in plan["plan"][0]["covers_cells"]])
        gap = next(gap for gap in plan["gaps"]
                   if gap["kind"] == "cells_need_authorization")
        self.assertEqual(["create"], [cell["operation"] for cell in gap["cells"]])

    def test_authorizing_the_write_covers_the_cell(self):
        plan = providers.select(
            self.requirement,
            probe_offer(authorized_effects=LIVE_EFFECTS + ["write"]))
        self.assertEqual({"read", "create"},
                         {cell["operation"]
                          for cell in plan["plan"][0]["covers_cells"]})
        self.assertEqual([], plan["coverage"]["uncovered_cells"])

    def test_an_unavailable_executor_excludes_the_provider(self):
        requirement = providers.requirement(
            IDOR, "public_release", cells=cells("other_account", ["read"]))
        plan = providers.select(
            requirement,
            providers.offer(environment="public_release",
                            targets=["source_tree", "deployed_web_app"],
                            executors=["automation"]))
        entry = evaluation_for(plan, "prov-guided-browser-test")
        self.assertFalse(entry["eligible"])
        self.assertIn("executor_unavailable", constraint_kinds_of(entry))

    def test_an_authorization_granted_elsewhere_does_not_reach_here(self):
        # Permission to probe the staging project is not permission to probe
        # production, and an observation made in staging would not answer the
        # question anyway. Both halves fail at once.
        requirement = providers.requirement(
            ANON, "public_release", cells=cells("anonymous", ["read"]))
        plan = providers.select(requirement,
                                probe_offer(environment="private_test"))
        entry = evaluation_for(plan, "prov-supabase-probe")
        self.assertFalse(entry["eligible"])
        self.assertIn("authorization_scope_mismatch", constraint_kinds_of(entry))
        self.assertNotIn("prov-supabase-probe", plan["selected"])

    def test_the_scope_mismatch_names_the_environment_it_would_need(self):
        requirement = providers.requirement(
            ANON, "public_release", cells=cells("anonymous", ["read"]))
        plan = providers.select(requirement,
                                probe_offer(environment="private_test"))
        gap = next(gap for gap in plan["gaps"]
                   if gap["provider_id"] == "prov-supabase-probe")
        self.assertEqual(
            ["authorize prov-supabase-probe for public_release"],
            [constraint["grant"] for constraint in gap["constraints"]])

    def test_reading_the_source_is_not_acting_in_an_environment(self):
        # The last resort of the chain must survive a scope mismatch: nobody
        # needs permission to keep reading the tree the review was pointed at.
        requirement = providers.requirement(
            ANON, "public_release", cells=cells("anonymous", ["read"]))
        plan = providers.select(requirement,
                                probe_offer(environment="private_test"))
        self.assertEqual(["prov-code-policy-review"], plan["selected"])
        self.assertFalse(
            providers.acts_on_a_live_system(
                providers.capability("prov-code-policy-review")))
        self.assertTrue(
            providers.acts_on_a_live_system(
                providers.capability("prov-supabase-probe")))

    def test_a_matching_scope_is_not_a_mismatch(self):
        requirement = providers.requirement(
            ANON, "private_test", cells=cells("anonymous", ["read"]))
        plan = providers.select(requirement,
                                probe_offer(environment="private_test"))
        self.assertIn("prov-supabase-probe", plan["selected"])

    def test_an_offer_that_names_no_environment_still_selects(self):
        # An offer with no environment states nothing about scope, so it
        # constrains nothing; the requirement's environment still applies.
        requirement = providers.requirement(
            ANON, "private_test", cells=cells("anonymous", ["read"]))
        plan = providers.select(requirement, probe_offer(environment=None))
        self.assertIn("prov-supabase-probe", plan["selected"])

    def test_a_prerequisite_the_caller_knows_is_unmet_excludes_it(self):
        record = providers.capability("prov-supabase-probe")
        entry = providers.evaluate(
            record, self.requirement,
            probe_offer(unmet_prerequisites=record["prerequisites"]))
        self.assertFalse(entry["eligible"])
        self.assertIn("prerequisite_unmet", constraint_kinds_of(entry))

    def test_the_default_offer_authorizes_nothing_effectful(self):
        default = providers.offer()
        self.assertEqual(set(), default["authorized_effects"])
        self.assertEqual({"none"}, default["accepted_monetary"])
        self.assertEqual(set(), default["authorized_providers"])

    def test_a_plan_step_with_effects_carries_its_authorization_request(self):
        plan = providers.select(self.requirement, probe_offer())
        request = next(item for item in plan["authorization_requests"]
                       if item["reason"] == "required_to_run")
        self.assertEqual("prov-supabase-probe", request["provider_id"])
        self.assertEqual({"network", "data_egress", "credentials"},
                         set(request["effects"]))


class TestProvidersOnlyMakeEvidence(unittest.TestCase):
    """Acceptance: provider results create normalized Evidence only, and a
    provider never produces a conclusion (rule R24)."""

    def setUp(self):
        self.env = _envelope_with_probe_evidence()

    def test_the_baseline_envelope_validates(self):
        self.assertEqual([], canonical.validate_envelope(self.env))

    def test_a_provider_cannot_claim_a_control_it_does_not_cover(self):
        env = copy.deepcopy(self.env)
        env["evidence"][0]["claim"]["control_ids"] = [SECRETS]
        self.assertIn("declares no coverage of",
                      " ".join(canonical.validate_envelope(env)))

    def test_a_provider_cannot_claim_more_strength_than_it_has(self):
        env = copy.deepcopy(self.env)
        self.assertEqual("decisive", env["evidence"][0]["strength"])
        for entry in env["providers"][0]["coverage"]:
            entry["max_strength"] = "indicative"
            entry["fills_coverage_cell"] = True
        self.assertIn("can be at most indicative",
                      " ".join(canonical.validate_envelope(env)))

    def test_a_provider_cannot_report_an_operation_it_does_not_declare(self):
        env = copy.deepcopy(self.env)
        env["evidence"][0]["operation"] = "psychic_inspection"
        self.assertIn("does not declare operation",
                      " ".join(canonical.validate_envelope(env)))

    def test_one_covered_control_does_not_vouch_for_another(self):
        # The probe's anonymous read is declared for anon access and not for
        # object-level authorization. Adding the second control to the same
        # record must not let the first control's operation cover it.
        env = copy.deepcopy(self.env)
        env["providers"][0] = providers.instantiate(
            "prov-supabase-probe", control_ids=[ANON, IDOR],
            egress_destinations=["https://demo.supabase.co"])
        env["evidence"][0]["claim"]["control_ids"] = [ANON, IDOR]
        self.assertIn(
            "does not declare operation 'http_select_anon_head' for %s" % IDOR,
            " ".join(canonical.validate_envelope(env)))

    def test_an_operation_declared_for_the_claimed_control_is_accepted(self):
        env = copy.deepcopy(self.env)
        self.assertEqual([ANON], env["evidence"][0]["claim"]["control_ids"])
        self.assertEqual([], canonical.validate_envelope(env))

    def test_a_cell_naming_an_actor_the_provider_never_watched_is_refused(self):
        # The operation check asks how the observation was made; this asks
        # what it was an observation of. An anonymous read did not watch a
        # second account.
        env = copy.deepcopy(self.env)
        env["evidence"][0]["coverage"][0]["actor"] = "other_account"
        self.assertIn("does not declare that it can observe other_account",
                      " ".join(canonical.validate_envelope(env)))

    def test_a_cell_naming_an_operation_the_provider_never_ran_is_refused(self):
        env = copy.deepcopy(self.env)
        env["evidence"][0]["coverage"][0]["operation"] = "delete"
        self.assertIn("does not declare that it can observe anonymous / delete",
                      " ".join(canonical.validate_envelope(env)))

    def test_a_provider_cannot_report_an_environment_it_cannot_observe(self):
        env = copy.deepcopy(self.env)
        env["providers"][0]["environments"] = ["developer_only"]
        self.assertIn("produces observations about developer_only",
                      " ".join(canonical.validate_envelope(env)))

    def test_a_source_reading_provider_cannot_carry_a_coverage_cell(self):
        env = copy.deepcopy(self.env)
        env["providers"][0] = providers.instantiate("prov-migration-analysis",
                                                    control_ids=[ANON])
        env["providers"][0]["provider_id"] = "prov-supabase-probe"
        env["evidence"][0]["operation"] = "migration_analysis"
        env["evidence"][0]["strength"] = "indicative"
        self.assertIn("fills no coverage cell",
                      " ".join(canonical.validate_envelope(env)))

    def test_a_read_only_provider_cannot_report_an_external_account_effect(self):
        env = copy.deepcopy(self.env)
        env["evidence"][0]["side_effects"]["external_accounts"] = True
        self.assertIn("declares no external_accounts effect",
                      " ".join(canonical.validate_envelope(env)))

    def test_an_opt_in_write_effect_is_allowed_once_declared(self):
        env = copy.deepcopy(self.env)
        env["evidence"][0]["side_effects"]["writes"] = True
        self.assertEqual([], [problem
                              for problem in canonical.validate_envelope(env)
                              if "no write effect" in problem])

    def test_an_opt_in_write_flag_is_not_consent_to_delete(self):
        # --write-probe turns on an insert. A provider that declares
        # destructive: false may not record a destructive observation because
        # it happens to have an opt-in flag for something else.
        capability = providers.capability("prov-supabase-probe")
        self.assertFalse(capability["side_effects"]["destructive"])
        self.assertTrue(capability["side_effects"]["opt_in_flags"])
        env = copy.deepcopy(self.env)
        env["evidence"][0]["side_effects"]["destructive"] = True
        self.assertIn("declares no destructive effect",
                      " ".join(canonical.validate_envelope(env)))

    def test_a_provider_that_declares_the_delete_cell_may_record_one(self):
        # Playwright names delete cells behind requires_effects, so the same
        # rule that refuses the probe admits the flow.
        self.assertEqual(
            {"write", "destructive"},
            providers._opt_in_effects(
                providers.capability("prov-playwright-two-account")))
        self.assertEqual(
            {"write"},
            providers._opt_in_effects(
                providers.capability("prov-supabase-probe")))

    def test_an_opt_in_flag_never_excuses_an_external_account_effect(self):
        env = copy.deepcopy(self.env)
        env["evidence"][0]["side_effects"]["external_accounts"] = True
        self.assertIn("declares no external_accounts effect",
                      " ".join(canonical.validate_envelope(env)))

    def test_undeclared_data_egress_is_refused(self):
        env = copy.deepcopy(self.env)
        env["providers"][0]["data_egress"] = {"occurs": False}
        env["evidence"][0]["side_effects"]["data_egress"] = True
        self.assertIn("declares no data egress",
                      " ".join(canonical.validate_envelope(env)))

    def test_an_unresolvable_provider_ref_is_refused(self):
        env = copy.deepcopy(self.env)
        env["evidence"][0]["provider"]["provider_ref"] = "prov-invented"
        problems = " ".join(canonical.validate_envelope(env))
        self.assertIn("prov-invented", problems)

    def test_evidence_from_an_unregistered_name_is_left_alone(self):
        # A reviewer writing down what they saw is evidence too. Only a record
        # that names a capability is held to that capability.
        env = copy.deepcopy(self.env)
        env["evidence"][0]["provider"] = {"name": "a reviewer, by hand"}
        env["evidence"][0].pop("coverage", None)
        self.assertEqual([], canonical.validate_envelope(env))

    def test_a_capability_that_is_decisive_without_a_cell_is_refused(self):
        env = copy.deepcopy(self.env)
        env["providers"][0]["coverage"][0]["fills_coverage_cell"] = False
        problems = " ".join(canonical.validate_envelope(env))
        self.assertIn("decisive but fills no cell", problems)

    def test_a_capability_without_a_closure_threshold_is_refused(self):
        env = copy.deepcopy(self.env)
        env["providers"][0]["coverage"][0].pop("closure_threshold")
        self.assertIn("states no closure threshold",
                      " ".join(canonical.validate_envelope(env)))


class TestBundledToolsAreProviders(unittest.TestCase):
    """Scope: the bundled scanner and Supabase probe move behind the provider
    contract while their public outputs stay exactly as they were."""

    STREAM = [
        json.dumps({"scanner": "vibecheck", "version": "0.4.0"}),
        json.dumps({"check": "secrets.hardcoded", "status": "WARN",
                    "checklist_items": [7], "title": "hardcoded secret",
                    "evidence": "src/app.js: const KEY = \"abc\""}),
        json.dumps({"check": "rls.missing", "status": "NO_SIGNAL",
                    "checklist_items": [14], "title": "no rls signal",
                    "evidence": ""}),
        json.dumps({"done": True}),
    ]

    PROBE = {
        "url": "https://demo.supabase.co",
        "findings": [
            {"check": "anon_select", "table": "public.orders", "http": 200,
             "verdict": "REVIEW_rows_readable_by_anon",
             "rows_visible_to_anon": 3, "note": "3 rows visible"},
        ],
    }

    def test_the_scanner_import_stamps_the_provider_and_its_capability(self):
        env = adapters.import_scanner_jsonl(self.STREAM, now=NOW)
        self.assertEqual([], canonical.validate_envelope(env))
        self.assertEqual(["prov-static-scanner"],
                         [record["provider_id"] for record in env["providers"]])
        for item in env["evidence"]:
            self.assertEqual("prov-static-scanner",
                             item["provider"]["provider_ref"])
            self.assertEqual("0.4.0", item["provider"]["version"])

    def test_the_attached_capability_is_narrowed_to_what_was_claimed(self):
        env = adapters.import_scanner_jsonl(self.STREAM, now=NOW)
        self.assertEqual(
            {SECRETS, ANON},
            {entry["control_id"] for entry in env["providers"][0]["coverage"]})

    def test_the_scanner_jsonl_export_is_still_byte_compatible(self):
        env = adapters.import_scanner_jsonl(self.STREAM, now=NOW)
        self.assertEqual("".join(line + "\n" for line in self.STREAM),
                         adapters.export_scanner_jsonl(env))

    def test_the_probe_import_stamps_the_provider_and_its_destination(self):
        env = adapters.import_supabase_probe(self.PROBE, "private_test",
                                             now=NOW)
        self.assertEqual([], canonical.validate_envelope(env))
        record = env["providers"][0]
        self.assertEqual("prov-supabase-probe", record["provider_id"])
        self.assertEqual(["https://demo.supabase.co"],
                         record["data_egress"]["destinations"])
        self.assertEqual(["https://demo.supabase.co"],
                         record["network"]["targets"])

    def test_the_probe_signals_name_their_provider(self):
        env = adapters.import_supabase_probe(self.PROBE, "private_test",
                                             now=NOW)
        self.assertEqual({"prov-supabase-probe"},
                         {signal["source"]["provider_ref"]
                          for signal in env["signals"]})

    def test_the_migration_analysis_import_stays_indicative_and_cell_free(self):
        env = adapters.import_rls_analysis(
            {"missing_rls": ["public.orders"], "created": ["public.orders"],
             "permissive": ["orders_all"]}, now=NOW)
        self.assertEqual([], canonical.validate_envelope(env))
        for item in env["evidence"]:
            self.assertEqual("indicative", item["strength"])
            self.assertNotIn("coverage", item)

    def test_the_envelope_records_which_registry_version_it_used(self):
        env = adapters.import_scanner_jsonl(self.STREAM, now=NOW)
        self.assertEqual(providers.registry_ref(), env["provider_registry"])

    def test_the_probe_can_describe_itself_without_running(self):
        result = subprocess.run(
            [sys.executable, os.path.join(REPO, "scripts", "supabase_probe.py"),
             "--capability"],
            capture_output=True, text=True, check=True)
        self.assertEqual(providers.capability("prov-supabase-probe"),
                         json.loads(result.stdout))

    def test_the_scanner_can_describe_itself_without_running(self):
        result = subprocess.run(
            ["bash", os.path.join(REPO, "scripts", "vibecheck.sh"),
             "--capability"],
            capture_output=True, text=True, check=True)
        self.assertEqual(providers.capability("prov-static-scanner"),
                         json.loads(result.stdout))

    def test_the_declared_scanner_version_matches_the_script(self):
        with open(os.path.join(REPO, "scripts", "vibecheck.sh"),
                  encoding="utf-8") as fh:
            declared = next(line for line in fh if line.startswith("VERSION="))
        self.assertIn(providers.capability("prov-static-scanner")["version"],
                      declared)


class TestSelectionGoldens(unittest.TestCase):
    """The committed fallback chain is reviewable prose, and it is current."""

    def test_the_committed_goldens_are_current(self):
        with open(gen_provider_goldens.OUTPUT_PATH, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), gen_provider_goldens.render(),
                             "stale provider golden: run "
                             "python3 scripts/gen_provider_goldens.py")

    def test_the_goldens_cover_the_whole_declared_chain(self):
        with open(gen_provider_goldens.OUTPUT_PATH, encoding="utf-8") as fh:
            text = fh.read()
        for provider_id in ("prov-supabase-probe", "prov-playwright-two-account",
                            "prov-guided-browser-test",
                            "prov-code-policy-review"):
            self.assertIn(providers.capability(provider_id)["name"], text)


# ------------------------------------------------------------------ fixtures

def _envelope_with_inventory():
    env = adapters.import_supabase_probe(
        {"url": "https://demo.supabase.co", "findings": []},
        "private_test", now=NOW,
        authorization_objects=[{
            "object_id": "obj-orders",
            "object_class": "user_owned_record",
            "locator": "public.orders",
            "description": "A customer's order.",
            "intent": "private",
            "provenance": {"state": "confirmed", "source": "founder"},
        }])
    return env


def _envelope_with_probe_evidence():
    env = adapters.import_supabase_probe(
        {"url": "https://demo.supabase.co",
         "findings": [{"check": "anon_select", "table": "public.orders",
                       "http": 200, "verdict": "REVIEW_rows_readable_by_anon",
                       "rows_visible_to_anon": 2, "note": "2 rows visible"}]},
        "private_test", now=NOW)
    return env


if __name__ == "__main__":
    unittest.main()
