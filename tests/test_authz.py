#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Supabase authorization vertical slice.

The acceptance criteria of the issue, one class each:

  TestLifecycleFixture        the whole lifecycle exists and validates
  TestDeploymentCheckpoint    a patch that was never deployed does not close
  TestCoverageIsPerCell       one denied request covers one cell, nothing more
  TestInconclusiveResults     invalid keys, failures, empty tables stay unknown
  TestLegacyProbeOutput       archived CLI output still imports
  TestWriteAccountability     anything that wrote records consent and cleanup
  TestIntendedExposure        a public form is confirmed, then bounded
"""
import contextlib
import copy
import io
import json
import os
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "scripts"))

import actions as actions_mod  # noqa: E402
import adapters  # noqa: E402
import authz  # noqa: E402
import canonical  # noqa: E402
import gen_authz_fixture  # noqa: E402
import items  # noqa: E402
import supabase_probe  # noqa: E402

FIXTURE = os.path.join(REPO, "schema", "examples",
                       "supabase-authz-lifecycle.json")
INTENDED_FIXTURE = os.path.join(REPO, "schema", "examples",
                                "intended-anon-write.json")
NOW = gen_authz_fixture.NOW
ANON = gen_authz_fixture.ANON
IDOR = gen_authz_fixture.IDOR


def load_fixture():
    with open(FIXTURE, encoding="utf-8") as fh:
        return json.load(fh)


def action(envelope, action_id):
    return next(a for a in envelope["actions"] if a["action_id"] == action_id)


def attempt(envelope, attempt_id):
    return next(a for a in envelope["attempts"] if a["attempt_id"] == attempt_id)


def problems_matching(envelope, needle):
    return [p for p in canonical.validate_envelope(envelope) if needle in p]


class TestLifecycleFixture(unittest.TestCase):
    def setUp(self):
        self.env = load_fixture()

    def test_committed_fixture_is_current_and_valid(self):
        self.assertEqual(canonical.dumps(gen_authz_fixture.build_fixture()),
                         canonical.dumps(self.env),
                         "stale fixture: run python3 scripts/gen_authz_fixture.py")
        self.assertEqual([], canonical.validate_envelope(self.env))

    def test_the_whole_loop_is_present_in_order(self):
        """signal -> evidence -> failed control -> patch -> deploy -> verify
        -> fresh evidence -> reassessment."""
        statuses = [a["status"] for a in self.env["assessments"]
                    if a["control_id"] == ANON]
        self.assertEqual(["fail", "partial", "fail"], statuses)
        stages = [next(p for p in self.env["procedures"]
                       if p["procedure_id"] == a["procedure_ref"])["stage"]
                  for a in self.env["attempts"]
                  if a["action_ref"] == "act-enforce-order-read-access-v1"]
        self.assertEqual(["repository_patch", "deployment", "live_verification"],
                         stages)
        verify = attempt(self.env, "att-orders-rls-verify-1")
        self.assertEqual(["asm-anon-access-2", "asm-object-level-2"],
                         verify["reassessment_refs"])

    def test_each_checkpoint_carries_its_own_consent(self):
        records = [attempt(self.env, aid)["authorization"] for aid in (
            "att-orders-rls-patch-1", "att-orders-rls-deploy-1",
            "att-orders-rls-verify-1")]
        self.assertEqual(3, len({r["authorization_id"] for r in records}))
        self.assertEqual(3, len({r["granted_at"] for r in records}))
        # approving a diff is not approving a deploy
        self.assertFalse(records[0]["effects"]["deployment"])
        self.assertTrue(records[1]["effects"]["deployment"])

    def test_repository_changes_are_diff_first_and_branch_first(self):
        change = attempt(self.env, "att-orders-rls-patch-1")["change_control"]
        self.assertEqual("fix/orders-rls", change["branch"])
        self.assertTrue(change["diff_ref"]["value"])
        self.assertLess(change["approved_at"],
                        attempt(self.env, "att-orders-rls-patch-1")["started_at"])

    def test_an_approval_after_the_change_is_not_diff_first(self):
        attempt(self.env, "att-orders-rls-patch-1")["change_control"][
            "approved_at"] = "2026-08-13T15:30:00Z"
        self.assertTrue(problems_matching(self.env, "diff-first"))

    def test_a_patch_without_a_recorded_diff_is_refused(self):
        del attempt(self.env, "att-orders-rls-patch-1")["change_control"]["diff_ref"]
        self.assertTrue(problems_matching(self.env, "must record the exact diff"))

    def test_verification_is_independent_of_who_deployed(self):
        procedure = next(p for p in self.env["procedures"]
                         if p["stage"] == "live_verification"
                         and p["procedure_id"] == "prc-anon-read-reprobe-v1")
        self.assertTrue(procedure["verification"]["independent_from_executor"])
        self.assertNotEqual(
            attempt(self.env, "att-orders-rls-deploy-1")["executor"]["id"],
            attempt(self.env, "att-orders-rls-verify-1")["executor"]["id"])

    def test_readiness_blockers_are_scope_specific(self):
        states = {r["scope"]["environment"]: r for r in self.env["readiness"]}
        self.assertEqual({"private_test", "public_release"}, set(states))
        for readiness in states.values():
            self.assertEqual("blocked", readiness["state"])
        # the same control is high in the pilot and critical at public launch
        levels = {r["scope"]["environment"]: r["level"] for r in self.env["risks"]
                  if ANON in r.get("control_refs", [])}
        self.assertEqual("high", levels["private_test"])
        self.assertEqual("critical", levels["public_release"])

    def test_no_readiness_state_claims_the_application_is_secure(self):
        rendered = canonical.dumps(self.env).lower()
        for forbidden in ('"secure"', '"certified"', "ready to ship"):
            self.assertNotIn(forbidden, rendered)


class TestDeploymentCheckpoint(unittest.TestCase):
    """A repository patch changes nothing in the reviewed environment."""

    def setUp(self):
        self.env = load_fixture()
        self.action = action(self.env, "act-enforce-order-read-access-v1")

    def test_missing_deployment_attempt_keeps_the_action_incomplete(self):
        self.env["attempts"] = [a for a in self.env["attempts"]
                                if a["attempt_id"] != "att-orders-rls-deploy-1"]
        problems = actions_mod.validate_registry(self.env)
        self.assertTrue(any("no succeeded deployment attempt" in p
                            for p in problems), problems)

    def test_deployment_without_produced_evidence_does_not_count(self):
        attempt(self.env, "att-orders-rls-deploy-1")["evidence_refs"] = []
        self.assertTrue(any("no succeeded deployment attempt" in p
                            for p in actions_mod.validate_registry(self.env)))

    def test_failed_deployment_does_not_count(self):
        attempt(self.env, "att-orders-rls-deploy-1")["result"] = "failed"
        self.assertTrue(any("no succeeded deployment attempt" in p
                            for p in actions_mod.validate_registry(self.env)))

    def test_checkpoints_have_to_happen_in_order(self):
        deploy = attempt(self.env, "att-orders-rls-deploy-1")
        deploy["started_at"] = "2026-08-13T14:00:00Z"
        deploy["finished_at"] = "2026-08-13T14:30:00Z"
        problems = actions_mod.validate_registry(self.env)
        self.assertTrue(any("no succeeded deployment attempt" in p
                            for p in problems), problems)

    def test_verification_must_watch_the_deployed_behaviour(self):
        """Evidence observed before the deploy verifies the previous state."""
        verify = attempt(self.env, "att-orders-rls-verify-1")
        verify["evidence_refs"] = ["ev-rls-migration-diff"]
        self.assertTrue(any("fresh non-static evidence" in p
                            for p in actions_mod.validate_registry(self.env)))

    def test_static_analysis_after_deployment_is_not_live_verification(self):
        static = next(e for e in self.env["evidence"]
                      if e["evidence_id"] == "ev-rls-static-missing")
        static["observed_at"] = "2026-08-14T08:55:00Z"
        verify = attempt(self.env, "att-orders-rls-verify-1")
        verify["evidence_refs"] = [static["evidence_id"]]
        problems = actions_mod.validate_registry(self.env)
        self.assertTrue(any("fresh non-static evidence" in p for p in problems),
                        problems)

    def test_verification_environment_must_match_the_deployment(self):
        verify = attempt(self.env, "att-orders-rls-verify-1")
        verify["execution_environment"] = "public_release"
        problems = actions_mod.validate_registry(self.env)
        self.assertTrue(any("same environment as the deployment" in p
                            for p in problems), problems)

    def test_an_action_must_offer_a_procedure_for_every_checkpoint(self):
        self.action["procedure_refs"] = ["prc-orders-rls-migration-v1"]
        problems = actions_mod.validate_registry(self.env)
        self.assertTrue(any("requires the deployment checkpoint but offers no"
                            in p for p in problems), problems)

    def test_a_deployment_procedure_must_declare_the_deployment_effect(self):
        procedure = next(p for p in self.env["procedures"]
                         if p["procedure_id"] == "prc-pilot-migration-deploy-v1")
        procedure["effects"]["deployment"] = False
        self.assertTrue(any("must declare the deployment effect" in p
                            for p in actions_mod.validate_registry(self.env)))

    def test_a_deployment_must_name_its_target_and_revision(self):
        deploy = attempt(self.env, "att-orders-rls-deploy-1")
        deploy["execution_context"] = {"kind": "local", "locator": "laptop"}
        problems = actions_mod.validate_registry(self.env)
        self.assertTrue(any("has to name the running environment" in p
                            for p in problems), problems)
        self.assertTrue(any("must record the exact revision it deployed" in p
                            for p in problems), problems)

    def test_the_open_follow_up_remediation_still_needs_all_three(self):
        follow_up = action(self.env, "act-deny-anon-order-writes-v1")
        self.assertEqual(["repository_patch", "deployment", "live_verification"],
                         follow_up["required_stages"])
        follow_up["state"] = "done"
        follow_up["state_history"].extend([
            {"state": "in_progress", "at": NOW, "by": "dev:priit"},
            {"state": "done", "at": NOW, "by": "dev:priit"}])
        problems = actions_mod.validate_registry(self.env)
        for stage in ("repository_patch", "deployment", "live_verification"):
            self.assertTrue(any("no succeeded %s attempt" % stage in p
                                for p in problems), (stage, problems))


class TestCoverageIsPerCell(unittest.TestCase):
    """One successful record/read test is positive evidence for that scope only."""

    def setUp(self):
        self.env = load_fixture()

    def state(self, control_id, environment="private_test", envelope=None):
        return authz.coverage_state(envelope or self.env, control_id,
                                    environment, NOW)

    def test_one_denied_read_leaves_the_control_partial(self):
        state = self.state(IDOR)
        self.assertEqual("partial", state["state"])
        self.assertEqual(1, state["satisfied_count"])
        self.assertEqual(8, state["required_count"])
        self.assertEqual(
            {("obj-orders", "other_account", "read")},
            {(cell["object_id"], cell["actor"], cell["operation"])
             for cell in state["satisfied"]})

    def test_a_denied_read_says_nothing_about_write_operations(self):
        missing = {(gap["operation"], gap["reason"]) for gap in self.state(IDOR)["gaps"]
                   if gap["object_id"] == "obj-orders"}
        self.assertEqual({("create", "not_tested"), ("update", "not_tested"),
                          ("delete", "not_tested")}, missing)

    def test_a_denied_read_says_nothing_about_another_object_type(self):
        gaps = {gap["object_id"] for gap in self.state(IDOR)["gaps"]}
        self.assertIn("obj-invitations", gaps)

    def test_observations_do_not_travel_between_environments(self):
        pilot = self.state(IDOR, "private_test")
        public = self.state(IDOR, "public_release")
        self.assertEqual(1, pilot["satisfied_count"])
        self.assertEqual(0, public["satisfied_count"])
        self.assertEqual("open", public["state"])

    def test_a_cell_cannot_override_its_evidence_environment(self):
        evidence = next(e for e in self.env["evidence"]
                        if e["evidence_id"] == "ev-idor-orders-denied")
        evidence["coverage"][0]["environment"] = "public_release"
        self.assertEqual(0, self.state(IDOR, "private_test")["satisfied_count"])
        self.assertEqual(0, self.state(IDOR, "public_release")["satisfied_count"])
        self.assertTrue(any("cannot move an observation between environments" in p
                            for p in authz.validate_coverage(self.env)))

    def test_a_coverage_backed_pass_needs_the_whole_matrix(self):
        assessment = next(a for a in self.env["assessments"]
                          if a["assessment_id"] == "asm-object-level-2")
        assessment["status"] = "pass"
        assessment["basis"]["evidence_refs"] = ["ev-idor-orders-denied"]
        assessment.pop("conflicts")
        self.assertTrue(any("One observation covers one object, actor and "
                            "operation, never the control" in p
                            for p in authz.validate_coverage(self.env)))

    def test_a_pass_resting_on_no_live_observation_is_left_to_other_rules(self):
        """Coverage governs live observations; it does not invent a matrix for
        a control nobody probed."""
        envelope = {"schema_version": "1.4.0",
                    "coverage_model": authz.model_ref(),
                    "assessments": [{
                        "assessment_id": "asm-x", "control_id": IDOR,
                        "status": "pass",
                        "basis": {"evidence_refs": ["ev-walkthrough"]}}],
                    "evidence": [{"evidence_id": "ev-walkthrough",
                                  "direction": "supports"}]}
        self.assertEqual([], authz.validate_coverage(envelope))

    def test_an_allowed_observation_is_a_gap_not_a_covered_cell(self):
        state = self.state(ANON)
        self.assertEqual(
            [("obj-orders", "create")],
            [(cell["object_id"], cell["operation"])
             for cell in state["violations"]])

    def test_a_later_denial_supersedes_an_earlier_exposure(self):
        satisfied = {(cell["object_id"], cell["operation"])
                     for cell in self.state(ANON)["satisfied"]}
        self.assertIn(("obj-orders", "read"), satisfied)

    def test_an_unclassified_object_never_satisfies_a_required_cell(self):
        evidence = next(e for e in self.env["evidence"]
                        if e["evidence_id"] == "ev-idor-orders-denied")
        evidence["coverage"][0].update({"object_class": "unclassified",
                                        "object_ref": "some other table"})
        evidence["coverage"][0].pop("object_id")
        self.assertEqual(0, self.state(IDOR)["satisfied_count"])

    def test_an_observation_that_contradicts_the_inventory_credits_nothing(self):
        evidence = next(e for e in self.env["evidence"]
                        if e["evidence_id"] == "ev-idor-orders-denied")
        evidence["coverage"][0]["object_class"] = "reference_data"
        self.assertEqual(0, self.state(IDOR)["satisfied_count"])
        self.assertTrue(any("while the context inventory classifies it as" in p
                            for p in authz.validate_coverage(self.env)))

    def test_coverage_without_an_inventory_is_unestablished_not_met(self):
        del self.env["context"]["authorization_objects"]
        state = self.state(IDOR)
        self.assertEqual("unestablished", state["state"])
        self.assertEqual(0, state["required_count"])

    def test_only_a_confirmed_decision_excludes_an_object_as_public(self):
        objects = self.env["context"]["authorization_objects"]
        tiers = next(o for o in objects if o["object_id"] == "obj-plan-tiers")
        self.assertNotIn("obj-plan-tiers",
                         {gap["object_id"] for gap in self.state(ANON)["gaps"]})
        tiers["state"] = "inferred"
        tiers["object_class"] = "user_owned_record"
        self.assertTrue(any("without a confirmed decision" in p
                            for p in authz.validate_coverage(self.env)))
        self.assertIn("obj-plan-tiers",
                      {gap["object_id"] for gap in self.state(ANON)["gaps"]})

    def test_static_analysis_never_fills_a_cell(self):
        static = next(e for e in self.env["evidence"]
                      if e["evidence_id"] == "ev-rls-static-missing")
        self.assertNotIn("coverage", static)
        static["coverage"] = [{"object_ref": "public.orders",
                               "object_class": "user_owned_record",
                               "actor": "anonymous", "operation": "read",
                               "observed": "denied"}]
        self.assertTrue(any("never an observation of a live authorization path"
                            in p for p in authz.validate_coverage(self.env)))

    def test_every_gap_becomes_a_scheduled_verify_action(self):
        coverage_actions = [a for a in self.env["actions"]
                            if a["action_id"].startswith("act-authz-coverage")]
        self.assertEqual(
            {"act-authz-coverage-obj-orders-anonymous",
             "act-authz-coverage-obj-invitations-anonymous",
             "act-authz-coverage-obj-orders-other-account",
             "act-authz-coverage-obj-invitations-other-account"},
            {a["action_id"] for a in coverage_actions})
        for derived in coverage_actions:
            self.assertEqual("verify", derived["kind"])
            self.assertEqual("open", derived["state"])
            self.assertEqual([], derived["blocking_scope"])

    def test_materializing_coverage_actions_twice_changes_nothing(self):
        again = authz.materialize_coverage_actions(self.env, NOW)
        self.assertEqual(canonical.dumps(self.env), canonical.dumps(again))

    def test_readiness_reports_the_gap_as_a_material_unknown(self):
        pilot = next(r for r in self.env["readiness"]
                     if r["scope"]["environment"] == "private_test")
        gap = next(u for u in pilot["unknowns"]
                   if "Authorization coverage" in u["description"])
        self.assertTrue(gap["material"])
        self.assertEqual([IDOR], gap["control_ids"])


class TestInconclusiveResults(unittest.TestCase):
    """Invalid tokens, network errors, empty tables and non-200 responses."""

    PROBE = {
        "supabase_probe": True,
        "url": "https://demo.supabase.co",
        "write_probe_enabled": False,
        "tables_probed": ["orders"],
        "findings": [
            {"check": "anon_select", "table": "orders", "http": 200,
             "verdict": "NO_ROWS_VISIBLE_UNCONFIRMED", "rows_visible_to_anon": 0,
             "note": "no rows returned to anon"},
            {"check": "anon_select", "table": "invoices", "http": 401,
             "verdict": "BLOCKED_OR_KEY_INVALID", "note": "blocked"},
            {"check": "anon_select", "table": "legacy", "http": -1,
             "verdict": "UNKNOWN_-1", "note": "network unreachable"},
            {"check": "anon_select", "table": "internal", "http": 404,
             "verdict": "INFO_not_exposed", "note": "not exposed"},
            {"check": "idor", "table": "orders", "record_id": "7",
             "http": 500, "verdict": "UNKNOWN_account_b_request_failed",
             "note": "B's request failed"},
            {"check": "idor", "table": "orders", "record_id": "9", "http": 200,
             "verdict": "NOT_TESTED_target_not_visible_to_a",
             "note": "the supplied record is not visible to account A"},
        ],
    }

    def setUp(self):
        self.env = adapters.import_supabase_probe(
            copy.deepcopy(self.PROBE), "private_test", now=NOW,
            authorized_by="owner:demo")

    def test_the_envelope_validates(self):
        self.assertEqual([], canonical.validate_envelope(self.env))

    def test_nothing_inconclusive_supports_the_claim(self):
        self.assertEqual([], [e for e in self.env["evidence"]
                              if e["direction"] == "supports"])

    def test_every_mapped_cell_is_inconclusive(self):
        observed = {cell["observed"] for e in self.env["evidence"]
                    for cell in e.get("coverage") or []}
        self.assertEqual({"inconclusive"}, observed)

    def test_an_unproven_key_is_not_a_denial(self):
        cell = next(cell for e in self.env["evidence"]
                    for cell in e.get("coverage") or []
                    if e["subject"]["locator"] == "invoices")
        self.assertEqual("inconclusive", cell["observed"])

    def test_a_proven_key_turns_a_refusal_into_a_denial(self):
        probe = copy.deepcopy(self.PROBE)
        for finding in probe["findings"]:
            finding["key_validated"] = True
        env = adapters.import_supabase_probe(probe, "private_test", now=NOW)
        cell = next(cell for e in env["evidence"]
                    for cell in e.get("coverage") or []
                    if e["subject"]["locator"] == "invoices")
        self.assertEqual("denied", cell["observed"])
        evidence = next(e for e in env["evidence"]
                        if e["subject"]["locator"] == "invoices")
        self.assertEqual(("supports", "indicative"),
                         (evidence["direction"], evidence["strength"]))

    def test_a_record_invisible_to_account_a_is_not_tested(self):
        self.assertEqual(
            [], [cell for e in self.env["evidence"]
                 for cell in e.get("coverage") or []
                 if cell["actor"] == "other_account"
                 and cell["operation"] == "read"
                 and e["raw_result_ref"]["value"].startswith("the supplied")])

    def test_imported_coverage_cache_cannot_promote_or_relabel_unknown(self):
        probe = {
            "supabase_probe": True,
            "url": "https://demo.supabase.co",
            "environment": "private_test",
            "write_probe_enabled": False,
            "findings": [{
                "check": "idor", "table": "orders", "record_id": "7",
                "http": -1, "verdict": "UNKNOWN_account_b_request_failed",
                "note": "network unreachable",
                "coverage": {
                    "object_ref": "orders", "object_class": "user_owned_record",
                    "actor": "other_account", "operation": "read",
                    "observed": "denied", "environment": "public_release",
                },
            }],
        }
        objects = [{"object_id": "obj-orders",
                    "object_class": "user_owned_record",
                    "locator": "public.orders", "intent": "private",
                    "state": "confirmed", "source": "founder:demo"}]
        env = adapters.import_supabase_probe(
            probe, "private_test", now=NOW, authorization_objects=objects)
        (cell,) = env["evidence"][0]["coverage"]
        self.assertEqual("inconclusive", cell["observed"])
        self.assertEqual("private_test", cell["environment"])
        public = authz.coverage_state(env, IDOR, "public_release", NOW)
        self.assertEqual(0, public["satisfied_count"])
        self.assertEqual([], canonical.validate_envelope(env))

    def test_an_empty_table_stays_unknown_until_someone_shows_it_is_not(self):
        calls = []

        def fake_req(url, headers, method="GET", body=None, timeout=15):
            calls.append(headers.get("Authorization"))
            if len(calls) == 1:  # anon window: nothing visible
                return 200, "", {"Content-Range": "*/0"}
            return 200, "", {"Content-Range": "0-2/3"}  # test account: 3 rows

        original = supabase_probe.req
        supabase_probe.req = fake_req
        try:
            unknown = supabase_probe.probe_select(
                "https://x.supabase.co", {"apikey": "k"}, "orders", 5)
            self.assertEqual("NO_ROWS_VISIBLE_UNCONFIRMED", unknown["verdict"])
            calls.clear()
            denied = supabase_probe.probe_select(
                "https://x.supabase.co", {"apikey": "k"}, "orders", 5,
                {"apikey": "k", "Authorization": "Bearer a"})
        finally:
            supabase_probe.req = original
        self.assertEqual("PASS_no_anon_rows_on_non_empty_table", denied["verdict"])
        self.assertEqual(3, denied["rows_visible_to_test_account"])
        self.assertEqual("denied",
                         authz.cells_from_probe_finding(denied)[0]["observed"])


class TestLegacyProbeOutput(unittest.TestCase):
    """Existing Supabase CLI output stays supported through the adapter."""

    LEGACY = {
        "supabase_probe": True,
        "url": "https://demo.supabase.co",
        "anon_key": "eyJh...[masked]",
        "write_probe_enabled": False,
        "tables_probed": ["orders"],
        "confirmed_failures": 1,
        "probe_complete": False,
        "findings": [
            {"check": "discovery", "status": "INFO", "http": 200,
             "detail": "root status 200; discovered 1 table definition"},
            {"check": "anon_select", "table": "orders", "http": 200,
             "verdict": "REVIEW_rows_readable_by_anon", "rows_visible_to_anon": 3,
             "note": "3 row(s) visible"},
            {"check": "idor", "table": "orders", "record_id": "42", "http": 200,
             "verdict": "FAIL_cross_account_read", "rows_visible_to_b": 1,
             "note": "account B could read the record"},
            {"check": "anon_insert_probe", "verdict": "NOT_TESTED",
             "note": "anon write was not probed (default)"},
        ],
    }

    OBJECTS = [{"object_id": "obj-orders", "object_class": "user_owned_record",
                "locator": "orders", "intent": "private", "state": "confirmed",
                "source": "founder:demo"}]

    def setUp(self):
        self.env = adapters.import_supabase_probe(
            copy.deepcopy(self.LEGACY), "private_test", now=NOW,
            authorized_by="owner:demo",
            authorization_objects=copy.deepcopy(self.OBJECTS))

    def test_output_without_coverage_annotations_still_imports(self):
        for finding in self.LEGACY["findings"]:
            self.assertNotIn("coverage", finding)
        self.assertEqual([], canonical.validate_envelope(self.env))

    def test_verdicts_are_mapped_to_cells_through_the_shared_model(self):
        cells = {(cell["actor"], cell["operation"], cell["observed"])
                 for e in self.env["evidence"] for cell in e.get("coverage") or []}
        self.assertEqual({("anonymous", "read", "allowed"),
                          ("other_account", "read", "allowed")}, cells)

    def test_declared_objects_classify_what_the_probe_only_named(self):
        classes = {cell["object_class"] for e in self.env["evidence"]
                   for cell in e.get("coverage") or []}
        self.assertEqual({"user_owned_record"}, classes)

    def test_bare_postgrest_table_resolves_to_public_schema_inventory(self):
        probe = copy.deepcopy(self.LEGACY)
        probe["findings"] = [{
            "check": "idor", "table": "orders", "record_id": "42",
            "http": 200,
            "verdict": "PASS_no_cross_account_read_of_known_private_record",
            "rows_visible_to_b": 0,
            "note": "account B could not read the record",
        }]
        objects = copy.deepcopy(self.OBJECTS)
        objects[0]["locator"] = "public.orders"
        env = adapters.import_supabase_probe(
            probe, "private_test", now=NOW,
            authorized_by="owner:demo", authorization_objects=objects)
        (cell,) = env["evidence"][0]["coverage"]
        self.assertEqual("public.orders", cell["object_ref"])
        self.assertEqual("obj-orders", cell["object_id"])
        state = authz.coverage_state(env, IDOR, "private_test", NOW)
        self.assertEqual(1, state["satisfied_count"])
        self.assertEqual([], canonical.validate_envelope(env))

    def test_untested_operations_become_open_verify_actions(self):
        derived = [a for a in self.env["actions"]
                   if a["action_id"].startswith("act-authz-coverage")]
        self.assertTrue(derived)
        self.assertIn("create", " ".join(a["outcome"] for a in derived))

    def test_relabelling_the_environment_of_a_recorded_probe_is_refused(self):
        probe = copy.deepcopy(self.LEGACY)
        probe["environment"] = "private_test"
        with self.assertRaises(ValueError):
            adapters.import_supabase_probe(probe, "public_release", now=NOW)

    def test_migration_analysis_imports_without_filling_any_cell(self):
        env = adapters.import_rls_analysis(
            {"created": ["public.orders"], "rls_enabled": [],
             "missing_rls": ["public.orders"],
             "permissive": ["001_init.sql:12: using (true)"],
             "anon_write": []}, now=NOW)
        self.assertEqual([], canonical.validate_envelope(env))
        self.assertNotIn("assessments", env)
        for evidence in env["evidence"]:
            self.assertNotIn("coverage", evidence)
            self.assertEqual("indicative", evidence["strength"])
        (verify,) = [a for a in env["actions"] if a["kind"] == "verify"]
        self.assertIn("live observation", verify["reason"])


class TestWriteAccountability(unittest.TestCase):
    """Read-only stays the default; a write records what it did."""

    def setUp(self):
        self.env = load_fixture()
        self.attempt = attempt(self.env, "att-anon-write-probe-1")

    def test_the_write_attempt_records_all_four_facts(self):
        self.assertTrue(self.attempt["authorization"]["record"])
        self.assertEqual("private_test", self.attempt["execution_environment"])
        self.assertEqual("succeeded", self.attempt["result"])
        self.assertEqual("succeeded", self.attempt["rollback"]["state"])
        self.assertIn("deleted", self.attempt["rollback"]["notes"])

    def test_a_write_without_a_consent_record_is_refused(self):
        del self.attempt["authorization"]["record"]
        self.assertTrue(problems_matching(self.env, "without a consent record"))

    def test_a_write_without_a_target_environment_is_refused(self):
        del self.attempt["execution_environment"]
        self.assertTrue(problems_matching(
            self.env, "without naming the target environment"))

    def test_a_write_without_a_cleanup_state_is_refused(self):
        del self.attempt["rollback"]
        self.assertTrue(problems_matching(
            self.env, "without a cleanup or rollback state"))

    def test_claiming_cleanup_was_unnecessary_needs_a_reason(self):
        self.attempt["rollback"] = {"state": "not_needed"}
        self.assertTrue(problems_matching(self.env, "does not say why"))

    def test_a_data_writing_probe_cannot_be_consent_free(self):
        procedure = next(p for p in self.env["procedures"]
                         if p["procedure_id"] == "prc-anon-write-probe-v1")
        procedure["authorization"]["consent"] = "not_required"
        self.assertTrue(problems_matching(self.env, "data-writing probes stay opt-in"))

    def test_evidence_of_a_write_states_what_it_created(self):
        evidence = next(e for e in self.env["evidence"]
                        if e["evidence_id"] == "ev-anon-write-orders-open")
        self.assertTrue(evidence["side_effects"]["writes"])
        self.assertIn("90ab41c2", evidence["side_effects"]["details"])
        del evidence["side_effects"]["details"]
        self.assertTrue(problems_matching(self.env, "how it is cleaned up"))

    def test_the_probe_refuses_a_write_run_without_accountability(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = supabase_probe.main([
                "--url", "https://demo.supabase.co", "--anon", "sb_publishable_x",
                "--write-probe"])
        self.assertEqual(2, code)
        self.assertIn("--environment", json.loads(out.getvalue())["error"])

    def test_the_default_run_probes_no_writes(self):
        finding = {"check": "anon_insert_probe", "verdict": "NOT_TESTED",
                   "note": "anon write was not probed (default)"}
        self.assertEqual([], authz.cells_from_probe_finding(finding))

    def test_a_refused_insert_needs_no_cleanup_but_says_so(self):
        def fake_req(url, headers, method="GET", body=None, timeout=15):
            return 403, "permission denied", {}

        original = supabase_probe.req
        supabase_probe.req = fake_req
        try:
            finding = supabase_probe.probe_insert(
                "https://x.supabase.co", {"apikey": "k"}, "orders", 5,
                "private_test")
        finally:
            supabase_probe.req = original
        self.assertEqual("not_needed", finding["cleanup"]["state"])
        self.assertTrue(finding["cleanup"]["note"])
        self.assertEqual("private_test", finding["target_environment"])

    def test_a_created_row_is_reported_with_its_exact_cleanup_target(self):
        def fake_req(url, headers, method="GET", body=None, timeout=15):
            return 201, "", {"Location": "/orders?id=eq.90ab41c2"}

        original = supabase_probe.req
        supabase_probe.req = fake_req
        try:
            finding = supabase_probe.probe_insert(
                "https://x.supabase.co", {"apikey": "k"}, "orders", 5,
                "private_test")
        finally:
            supabase_probe.req = original
        self.assertEqual("FAIL_anon_write_succeeded", finding["verdict"])
        self.assertEqual("pending", finding["cleanup"]["state"])
        self.assertIn("90ab41c2", finding["cleanup"]["target"])

    def test_importing_a_created_row_opens_a_cleanup_action(self):
        probe = {
            "supabase_probe": True, "url": "https://demo.supabase.co",
            "write_probe_enabled": True, "environment": "private_test",
            "authorization": {"authorized_by": "founder:demo",
                              "granted_at": "2026-08-16T11:00:00Z",
                              "scope": "one write probe of orders"},
            "findings": [{
                "check": "anon_insert_probe", "table": "orders", "http": 201,
                "verdict": "FAIL_anon_write_succeeded", "note": "",
                "target_environment": "private_test",
                "created_row_hint": "/orders?id=eq.90ab41c2",
                "cleanup": {"state": "pending",
                            "target": "/orders?id=eq.90ab41c2",
                            "instructions": "delete the row"}}],
        }
        env = adapters.import_supabase_probe(probe, "private_test", now=NOW)
        self.assertEqual([], canonical.validate_envelope(env))
        (cleanup,) = [a for a in env["actions"] if a["kind"] == "remediate"]
        self.assertIn("90ab41c2", cleanup["outcome"])
        self.assertEqual("immediate", cleanup["urgency"])


class TestIntendedExposure(unittest.TestCase):
    """An anonymous write is the owner's decision, and then it needs a bound."""

    LIVE = "public_release"
    BOUNDED_WRITE = "vibecheck.control.cost.expensive_endpoints_auth"

    def setUp(self):
        with open(INTENDED_FIXTURE, encoding="utf-8") as fh:
            self.env = json.load(fh)
        self.bookings = next(
            obj for obj in self.env["context"]["authorization_objects"]
            if obj["object_id"] == "obj-bookings")

    def exposures(self):
        return authz.intended_exposures(self.env, self.LIVE, NOW)

    def unbounded(self):
        return authz.unbounded_exposures(self.env, self.LIVE, NOW)

    def bound_the_write(self, status="pass"):
        """Record that the public write path is limited and evidenced."""
        self.env["evidence"].append({
            "evidence_id": "ev-form-throttle",
            "provider": {"name": "reviewer, load test"},
            "subject": {"kind": "endpoint", "locator": "public booking form"},
            "environment": self.LIVE,
            "operation": "repeated_submission_test",
            "scope": "Twenty submissions from one source in a minute: the first "
                     "was accepted, the rest were refused by the Turnstile "
                     "challenge and the per-source throttle.",
            "claim": {"control_ids": [self.BOUNDED_WRITE],
                      "statement": "The requirement is met",
                      "aspect": "unauthenticated write path bounded"},
            "direction": "supports",
            "strength": "decisive",
            "observed_at": "2026-08-16T11:30:00Z",
            "valid_until": "2026-09-13T00:00:00Z",
            "side_effects": {"writes": False, "destructive": False,
                             "external_accounts": False, "data_egress": True},
        })
        self.env["assessments"].append({
            "assessment_id": "asm-bounded-write",
            "control_id": self.BOUNDED_WRITE,
            "status": status,
            "assessor": {"kind": "human", "id": "reviewer:jaak"},
            "assessed_at": "2026-08-16T11:40:00Z",
            "basis": {"rationale": "Throttle and challenge observed refusing "
                                   "repeated automated submissions.",
                      "evidence_refs": ["ev-form-throttle"]},
        })

    def test_the_committed_fixture_is_current_and_valid(self):
        self.assertEqual(
            canonical.dumps(gen_authz_fixture.build_intended_write_fixture()),
            canonical.dumps(self.env),
            "stale fixture: run python3 scripts/gen_authz_fixture.py")
        self.assertEqual([], canonical.validate_envelope(self.env))

    def test_a_confirmed_write_is_not_counted_as_a_violation(self):
        state = authz.coverage_state(self.env, ANON, self.LIVE, NOW)
        self.assertEqual([], state["violations"])
        self.assertEqual([("obj-bookings", "create")],
                         [(cell["object_id"], cell["operation"])
                          for cell in state["intended"]])

    def test_an_unconfirmed_write_asks_the_owner_first(self):
        self.bookings["intended_operations"][0]["state"] = "inferred"
        self.bookings["intended_operations"][0]["rationale"] = "looks like a form"
        undeclared = authz.undeclared_exposures(self.env, self.LIVE, NOW)
        self.assertEqual([("obj-bookings", "anonymous", "create")],
                         [(e["object_id"], e["actor"], e["operation"])
                          for e in undeclared])
        problems = authz.validate_coverage(self.env)
        self.assertTrue(any("only a confirmed decision makes an exposure "
                            "intended" in p for p in problems), problems)

    def test_an_undeclared_write_becomes_a_decide_action_for_the_founder(self):
        self.bookings.pop("intended_operations")
        derived = authz.materialize_coverage_actions(self.env, NOW, self.LIVE)
        (decide,) = [a for a in derived["actions"] if a["kind"] == "decide"]
        self.assertEqual("founder", decide["owner"]["role"])
        self.assertIn("public.bookings", decide["outcome"])
        self.assertIn("only the owner knows which", decide["reason"])
        # the tool asks; it does not answer
        self.assertNotIn("should be", decide["outcome"])

    def test_a_confirmed_decision_needs_a_source_and_a_reason(self):
        del self.bookings["intended_operations"][0]["rationale"]
        self.assertTrue(any("records no rationale" in p
                            for p in authz.validate_coverage(self.env)))

    def test_confirming_the_write_does_not_bound_it(self):
        (exposure,) = self.unbounded()
        self.assertEqual(["bounded_public_write"], exposure["unmet_required"])
        self.assertIn("not assessed",
                      " ".join(item["detail"] for item in exposure["safeguards"]))

    def test_an_unbounded_public_form_is_an_open_remediation(self):
        (bound,) = [a for a in self.env["actions"]
                    if a["action_id"].startswith("act-authz-bound")]
        self.assertEqual("remediate", bound["kind"])
        self.assertEqual("immediate", bound["urgency"])
        self.assertEqual("developer", bound["owner"]["role"])
        self.assertIn(self.BOUNDED_WRITE, bound["control_refs"])
        self.assertIn("fills the table, sends the mail", bound["reason"])
        for mechanism in ("rate_limit", "bot_defence", "queue_or_review_gate"):
            self.assertIn(mechanism, bound["reason"])

    def test_the_bound_must_be_observed_not_configured(self):
        (bound,) = [a for a in self.env["actions"]
                    if a["action_id"].startswith("act-authz-bound")]
        self.assertIn("refusing a repeated automated submission",
                      bound["success_evidence"])
        self.assertIn("screenshot is not the bound", bound["success_evidence"])

    def test_readiness_reports_the_unbounded_form_as_a_material_unknown(self):
        (readiness,) = self.env["readiness"]
        unknown = next(u for u in readiness["unknowns"]
                       if "nothing bounds it" in u["description"])
        self.assertTrue(unknown["material"])
        self.assertIn("spam", unknown["description"])

    def test_an_evidenced_bound_closes_the_exposure(self):
        self.bound_the_write()
        self.assertEqual([], self.unbounded())
        (exposure,) = self.exposures()
        self.assertEqual([], exposure["unmet_required"])

    def test_a_partly_bounded_path_is_not_bounded(self):
        self.bound_the_write(status="partial")
        self.assertEqual(["bounded_public_write"],
                         self.unbounded()[0]["unmet_required"])

    def test_a_readable_table_is_never_a_valid_intended_write(self):
        """Write plus read is a full dump with extra steps."""
        read = next(e for e in self.env["evidence"]
                    if e["evidence_id"] == "ev-bookings-read-denied")
        read["coverage"][0]["observed"] = "allowed"
        read["direction"] = "refutes"
        self.bound_the_write()
        (exposure,) = self.unbounded()
        self.assertEqual(["no_read_back"], exposure["unmet_required"])

    def test_a_pass_cannot_ride_on_an_unbounded_exposure(self):
        assessment = next(a for a in self.env["assessments"]
                          if a["control_id"] == ANON)
        assessment["status"] = "pass"
        problems = authz.validate_coverage(self.env)
        self.assertTrue(any("Confirming that a public write is wanted does not "
                            "bound the automation" in p for p in problems),
                        problems)

    def test_intended_evidence_may_not_claim_to_support_the_control(self):
        evidence = next(e for e in self.env["evidence"]
                        if e["evidence_id"] == "ev-bookings-create-open")
        self.assertEqual("neutral", evidence["direction"])
        evidence["direction"] = "supports"
        self.assertTrue(any("says nothing about whether anything bounds it" in p
                            for p in authz.validate_coverage(self.env)))

    def test_the_scanner_flags_an_unguarded_public_write(self):
        checks = json.loads(json.dumps(items.SCANNER_CHECKS["cost.public_write_abuse"]))
        self.assertEqual([[26], "EVIDENCE"], checks)


if __name__ == "__main__":
    unittest.main()
