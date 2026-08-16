#!/usr/bin/env python3
"""Increment 3 (gh issue #5): risk scenarios and completeness-safe reports."""
import copy
import json
import os
import re
import sys
import unicodedata
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "scripts"))

import canonical  # noqa: E402
import gen_goldens  # noqa: E402
import gen_report_goldens  # noqa: E402
import report  # noqa: E402
import scenarios  # noqa: E402
import wording  # noqa: E402

try:
    import openpyxl  # noqa: F401
    HAVE_OPENPYXL = True
except ImportError:  # pragma: no cover
    HAVE_OPENPYXL = False

NOW = "2026-08-16T12:00:00Z"
REPORT_INPUT = os.path.join(
    REPO, "tests", "golden", "report-inputs",
    "many-scenarios-conflicting-evidence.json")


def load_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def build_spec(path):
    spec = load_json(path)
    envelope = gen_goldens.build_case(spec)
    return spec, envelope


def built_report(path=REPORT_INPUT, profile="founder", language="en"):
    spec, envelope = build_spec(path)
    return spec, envelope, report.derive_into(
        envelope, audience=profile, language=language, now=spec["now"])


class TestScenarioPolicy(unittest.TestCase):
    def test_every_registry_control_has_exactly_one_story(self):
        policy = scenarios.load_policy()
        groups = policy["scenario_groups"]
        self.assertEqual(len(groups), len({g["group_id"] for g in groups}))
        namespaces = [namespace for group in groups
                      for namespace in group["namespaces"]]
        self.assertEqual(len(namespaces), len(set(namespaces)))
        for control in canonical.load_registry()["controls"]:
            with self.subTest(control=control["control_id"]):
                self.assertIsNotNone(scenarios.group_of(control["control_id"]))

    def test_every_story_has_both_languages(self):
        for group in scenarios.load_policy()["scenario_groups"]:
            for language in wording.LANGUAGES:
                for part in ("title", "opener"):
                    self.assertTrue(wording.group_wording(
                        group["group_id"], part, language).strip())

    def test_ranking_is_deterministic_and_capped(self):
        _spec, source, first = built_report()
        second = report.derive_into(source, now=NOW)
        self.assertEqual(first["scenarios"], second["scenarios"])
        self.assertEqual(first["report"], second["report"])
        self.assertEqual(7, len(first["scenarios"]))
        self.assertEqual(5, len(first["report"]["headline_scenario_refs"]))
        self.assertEqual(7, len(first["report"]["scenario_ranking"]))

    def test_current_private_and_future_public_stay_separate(self):
        path = os.path.join(REPO, "tests", "golden", "inputs",
                            "private-invite-only-pilot.json")
        spec, source = build_spec(path)
        derived = report.derive_into(source, now=spec["now"])
        scene = next(s for s in derived["scenarios"]
                     if s["group_id"] == "unauthorised_data_access")
        readings = {(r["scope"]["environment"], r["horizon"]["kind"]): r["level"]
                    for r in scene["risk_by_scope"]}
        self.assertIn(("private_test", "current"), readings)
        self.assertIn(("public_release", "event_triggered"), readings)
        self.assertNotEqual(readings[("private_test", "current")],
                            readings[("public_release", "event_triggered")])

    def test_every_headline_has_full_normalized_traceability(self):
        _spec, _source, derived = built_report()
        by_id = {s["scenario_id"]: s for s in derived["scenarios"]}
        all_assessments = {a["assessment_id"] for a in derived["assessments"]}
        all_evidence = {e["evidence_id"] for e in derived["evidence"]}
        all_risks = {r["risk_id"] for r in derived["risks"]}
        for ref in derived["report"]["headline_scenario_refs"]:
            trace = scenarios.traceability(derived, by_id[ref])
            with self.subTest(scenario=ref):
                self.assertTrue(trace["control_refs"])
                self.assertTrue(trace["assessment_refs"])
                self.assertTrue(trace["risk_refs"])
                self.assertTrue(trace["evidence_refs"])
                self.assertLessEqual(set(trace["assessment_refs"]), all_assessments)
                self.assertLessEqual(set(trace["risk_refs"]), all_risks)
                self.assertLessEqual(set(trace["evidence_refs"]), all_evidence)

    def test_conflicting_evidence_survives_scenario_and_rendering(self):
        _spec, _source, derived = built_report(profile="reviewer")
        scene = next(s for s in derived["scenarios"]
                     if s["group_id"] == "unauthorised_data_access")
        self.assertIn("ev-object-level-support", scene["evidence_refs"])
        markdown = report.render(derived, "reviewer", "en", NOW)
        self.assertIn("Evidence that disagrees", markdown)
        self.assertIn("`ev-object-level-support`", markdown)

    def test_compensating_control_evidence_is_in_the_scenario_trace(self):
        path = os.path.join(REPO, "tests", "golden", "inputs",
                            "private-invite-only-pilot.json")
        spec, source = build_spec(path)
        derived = report.derive_into(source, now=spec["now"])
        scene = next(s for s in derived["scenarios"]
                     if s["group_id"] == "unauthorised_data_access")
        self.assertIn("ev-access-proxy-config", scene["evidence_refs"])

    def test_aggregation_never_changes_status_or_acceptance(self):
        _spec, source = build_spec(REPORT_INPUT)
        before = {a["assessment_id"]: copy.deepcopy(a)
                  for a in source["assessments"]}
        derived = report.derive_into(source, now=NOW)
        after = {a["assessment_id"]: a for a in derived["assessments"]}
        self.assertEqual(before, after)
        for scene in derived["scenarios"]:
            for forbidden in ("status", "control_status", "intrinsic_severity",
                              "severity", "acceptance"):
                self.assertNotIn(forbidden, scene)

    def test_stale_risk_reads_unknown_with_low_confidence(self):
        path = os.path.join(REPO, "tests", "golden", "inputs",
                            "private-invite-only-pilot.json")
        spec, source = build_spec(path)
        derived = report.derive_into(source, now="2027-01-01T12:00:00Z")
        self.assertTrue(any(s["current_level"] == "unknown"
                            for s in derived["scenarios"]))
        self.assertTrue(all(s.get("confidence") == "low"
                            for s in derived["scenarios"]
                            if s["current_level"] == "unknown"))

    def test_legacy_custom_scenario_cannot_duplicate_a_headline(self):
        envelope = load_json(os.path.join(
            REPO, "schema", "examples", "end-to-end.json"))
        derived = report.derive_into(envelope, now=NOW)
        ranking = {r["scenario_ref"]: r for r in derived["report"]["scenario_ranking"]}
        self.assertFalse(ranking["scn-anon-orders"]["headline"])
        self.assertTrue(ranking["scn-unauthorised_data_access"]["headline"])
        self.assertEqual([], canonical.validate_envelope(derived))


class TestCompletenessSafeReport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.spec, cls.source, cls.derived = built_report()

    def test_overlapping_categories_get_one_placement(self):
        target = "act-contain-cross-account-incident"
        entries = [p for p in self.derived["report"]["disclosure_placement"]
                   if p["ref"] == target]
        self.assertEqual(1, len(entries))
        self.assertEqual(
            ["incident_response_action_refs", "specialist_escalation_refs",
             "deadline_blocking_action_refs"], entries[0]["categories"])
        disclosure_view = "\n".join(
            report._render_scenarios(self.derived, self.derived["report"],
                                     "founder", "en")
            + report._render_mandatory(self.derived, self.derived["report"],
                                       "founder", "en"))
        self.assertEqual(1, disclosure_view.count("`%s`" % target))

    def test_every_mandatory_ref_has_exactly_one_placement(self):
        disclosures = self.derived["report"]["mandatory_disclosures"]
        expected = report.mandatory_refs(disclosures)
        placed = [p["ref"] for p in self.derived["report"]["disclosure_placement"]]
        self.assertEqual(expected, set(placed))
        self.assertEqual(len(placed), len(set(placed)))

    def test_unknowns_are_named_once_in_disclosure_view_not_repeated_in_readiness(self):
        path = os.path.join(REPO, "tests", "golden", "inputs",
                            "sensitive-high-impact-unknowns.json")
        spec, source = build_spec(path)
        derived = report.derive_into(source, now=spec["now"])
        summary = "\n".join(report._render_readiness(
            derived, derived["report"], "founder", "en"))
        disclosure = "\n".join(
            report._render_scenarios(derived, derived["report"], "founder", "en")
            + report._render_mandatory(derived, derived["report"], "founder", "en"))
        refs = derived["report"]["mandatory_disclosures"][
            "readiness_blocking_unknown_refs"]
        self.assertTrue(refs)
        for ref in refs:
            with self.subTest(ref=ref):
                self.assertNotIn("`%s`" % ref, summary)
                self.assertEqual(1, disclosure.count("`%s`" % ref))

    def test_action_sections_partition_open_actions_and_never_defer_mandatory(self):
        sections = self.derived["report"]["sections"]
        listed = [ref for values in sections.values() for ref in values]
        open_ids = {a["action_id"] for a in self.derived["actions"]
                    if a["state"] in ("open", "in_progress", "blocked")}
        self.assertEqual(open_ids, set(listed))
        self.assertEqual(len(listed), len(set(listed)))
        self.assertFalse(set(sections["can_wait"]) & report.mandatory_refs(
            self.derived["report"]["mandatory_disclosures"]))
        self.assertEqual(["act-verify-error-paths"],
                         sections["vibecheck_can_do_now"])

    def test_overdue_nonblocking_action_is_still_mandatory(self):
        source = copy.deepcopy(self.source)
        source["actions"].append({
            "action_id": "act-overdue-review",
            "kind": "verify",
            "outcome": "Complete the overdue provider-settings review.",
            "reason": "The recorded review date has passed.",
            "urgency": "planned",
            "deadline": {"kind": "calendar_date",
                         "value": "2026-08-15T00:00:00Z",
                         "rationale": "Quarterly review deadline."},
            "blocking_scope": [],
            "owner": {"role": "developer"},
            "state": "open",
        })
        derived = report.derive_into(source, now=NOW)
        self.assertIn("act-overdue-review", derived["report"][
            "mandatory_disclosures"]["deadline_blocking_action_refs"])
        action = next(a for a in derived["actions"]
                      if a["action_id"] == "act-overdue-review")
        self.assertEqual("overdue", report.deadline_label_id(action, NOW))

    def test_needs_specialist_screening_materializes_one_visible_action(self):
        source = copy.deepcopy(self.source)
        screening = next(a for a in source["assessments"]
                         if a["status"] == "answered")
        screening["status"] = "needs_specialist"
        derived = report.derive_into(source, now=NOW)
        self.assertEqual([], derived["report"]["mandatory_disclosures"][
            "specialist_assessment_refs"])
        refs = derived["report"]["mandatory_disclosures"][
            "specialist_escalation_refs"]
        action = next(a for a in derived["actions"]
                      if a["action_id"] in refs
                      and screening["control_id"] in a.get("control_refs", []))
        self.assertEqual("specialist", action["owner"]["role"])
        self.assertEqual([screening["control_id"]], action["control_refs"])
        placement = next(p for p in derived["report"]["disclosure_placement"]
                         if p["ref"] == action["action_id"])
        self.assertEqual("mandatory_section", placement["rendered_in"])

    def _screening_source(self, escalation_state=None):
        source = copy.deepcopy(self.source)
        screening = next(a for a in source["assessments"]
                         if a["status"] == "answered")
        screening["status"] = "needs_specialist"
        if escalation_state is not None:
            history = [{"state": "open", "at": NOW}]
            if escalation_state == "done":
                history.append({"state": "in_progress", "at": NOW})
            if escalation_state != "open":
                history.append({"state": escalation_state, "at": NOW,
                                "note": "recorded decision"})
            source["actions"].append({
                "action_id": "act-escalate-existing", "revision": 1,
                "action_key": "escalate-existing", "created_at": NOW,
                "kind": "escalate", "outcome": "A specialist decides.",
                "reason": "Screening row needs a specialist.",
                "priority": "unknown", "urgency": "next",
                "deadline": {"kind": "unknown", "rationale": "Depends on the use.",
                             "reassess_trigger": {"kind": "context_change"}},
                "blocking_scope": [], "owner": {"role": "specialist"},
                "state": escalation_state, "state_history": history,
                "control_refs": [screening["control_id"]],
            })
        return source, screening

    def test_closed_escalation_never_hides_a_needs_specialist_row(self):
        """A done or rejected escalation must not fall between both sets.

        specialist_escalations() lists open actions only, so counting a closed
        one as coverage would drop the screening row out of the escalation set
        and the assessment set at the same time (rule R12).
        """
        for state in ("done", "rejected"):
            with self.subTest(state=state):
                source, screening = self._screening_source(state)
                derived = report.derive_into(source, now=NOW)
                disclosures = derived["report"]["mandatory_disclosures"]
                covering = {
                    a["action_id"] for a in derived["actions"]
                    if screening["control_id"] in (a.get("control_refs") or [])
                    and (a.get("kind") == "escalate"
                         or (a.get("owner") or {}).get("role") == "specialist")
                    and a["state"] in report.load_policy()[
                        "mandatory_disclosures"]["open_action_states"]}
                visible = (
                    ({screening["assessment_id"]}
                     & set(disclosures["specialist_assessment_refs"]))
                    | (covering & set(disclosures["specialist_escalation_refs"])))
                self.assertTrue(
                    visible,
                    "this screening row is in no mandatory set: the closed "
                    "escalation stopped it counting as an assessment without "
                    "it counting as an open escalation")
                placed = {p["ref"]
                          for p in derived["report"]["disclosure_placement"]}
                self.assertTrue(visible <= placed)

    def test_open_escalation_still_covers_the_screening_row_once(self):
        source, screening = self._screening_source("open")
        derived = report.derive_into(source, now=NOW)
        disclosures = derived["report"]["mandatory_disclosures"]
        self.assertEqual([], disclosures["specialist_assessment_refs"])
        self.assertIn("act-escalate-existing",
                      disclosures["specialist_escalation_refs"])
        self.assertEqual(
            [], [a for a in derived["actions"]
                 if a["action_id"].startswith("act-escalate-")
                 and a["action_id"] != "act-escalate-existing"])

    def test_closing_a_derived_escalation_reopens_the_screening_row(self):
        """Re-deriving must not fork the derived Action's own lineage."""
        source, screening = self._screening_source()
        once = report.derive_into(source, now=NOW)
        derived_action = next(a for a in once["actions"]
                              if a["action_id"].startswith("act-escalate-"))
        derived_action["state"] = "rejected"
        derived_action["state_history"].append(
            {"state": "rejected", "at": NOW, "note": "specialist declined"})
        twice = report.derive_into(once, now=NOW)
        self.assertEqual(
            [derived_action["action_id"]],
            [a["action_id"] for a in twice["actions"]
             if a["action_id"].startswith("act-escalate-")])
        self.assertEqual([screening["assessment_id"]],
                         twice["report"]["mandatory_disclosures"][
                             "specialist_assessment_refs"])
        self.assertEqual([], canonical.validate_envelope(twice))

    def test_an_unset_optional_field_never_renders_as_the_word_none(self):
        """priority and execution_mode are optional below schema 1.3."""
        source = copy.deepcopy(self.source)
        source["schema_version"] = "1.2.0"
        for action in source["actions"]:
            action.pop("priority", None)
        for procedure in source["procedures"]:
            procedure.pop("execution_mode", None)
        for language in wording.LANGUAGES:
            with self.subTest(language=language):
                markdown = report.render(
                    report.derive_into(source, now=NOW), "reviewer",
                    language, NOW)
                self.assertNotIn("| None |", markdown)
        self.assertEqual("", wording.label("priorities", None, "en"))
        self.assertEqual("bogus", wording.label("priorities", "bogus", "en"),
                         "an unmapped enum must still show up in the output")

    def test_appendix_has_all_89_items_and_full_trace_chain(self):
        appendix = self.derived["report"]["appendix"]
        self.assertEqual(89, appendix["item_count"])
        self.assertEqual(2, len(appendix["procedure_refs"]))
        markdown = report.render(self.derived, "founder", "en", NOW)
        self.assertIn("| 89 |", markdown)
        self.assertIn("Stack choices are mainstream and maintainable", markdown)
        self.assertIn("`prc-contain-cross-account-incident`", markdown)
        self.assertIn("F. Procedures", markdown)

    def test_profile_and_language_never_change_identity_or_selection(self):
        invariant_fields = (
            "headline_scenario_refs", "scenario_ranking", "mandatory_disclosures",
            "disclosure_placement", "sections", "readiness_refs", "appendix")
        reports = {}
        for profile in wording.PROFILES:
            for language in wording.LANGUAGES:
                reports[(profile, language)] = report.derive_report(
                    self.derived, profile, language, NOW)
        baseline = reports[("founder", "en")]
        for key, candidate in reports.items():
            with self.subTest(profile=key[0], language=key[1]):
                for field in invariant_fields:
                    self.assertEqual(baseline[field], candidate[field])
        en = report.render(self.derived, "founder", "en", NOW)
        et = report.render(self.derived, "reviewer", "et", NOW)
        self.assertIn("What can go wrong", en)
        self.assertIn("Mis võib valesti minna", et)
        self.assertIn("vibecheck.control.authz.object_level", en)
        self.assertIn("vibecheck.control.authz.object_level", et)

    def test_readiness_never_claims_security_certification_or_shipping(self):
        markdown = report.render(self.derived, "founder", "en", NOW)
        body = "\n".join(line for line in markdown.splitlines()
                         if not line.startswith(">"))
        for phrase in (r"\bis secure\b", r"\bcertified\b", r"\bready to ship\b"):
            self.assertIsNone(re.search(phrase, body, re.IGNORECASE))


class TestReportValidation(unittest.TestCase):
    def test_missing_mandatory_ref_fails(self):
        _spec, _source, derived = built_report()
        broken = copy.deepcopy(derived)
        broken["report"]["mandatory_disclosures"][
            "unresolved_critical_high_refs"].pop()
        problems = canonical.validate_envelope(broken)
        self.assertTrue(any("omits" in p for p in problems), problems)

    def test_duplicate_or_tampered_placement_fails(self):
        _spec, _source, derived = built_report()
        broken = copy.deepcopy(derived)
        broken["report"]["disclosure_placement"].append(copy.deepcopy(
            broken["report"]["disclosure_placement"][0]))
        problems = canonical.validate_envelope(broken)
        self.assertTrue(any("disclosure_placement" in p for p in problems), problems)

    def test_material_unknown_requires_stable_identity(self):
        path = os.path.join(REPO, "tests", "golden", "inputs",
                            "sensitive-high-impact-unknowns.json")
        spec, source = build_spec(path)
        derived = report.derive_into(source, now=spec["now"])
        broken = copy.deepcopy(derived)
        broken["readiness"][0]["unknowns"][0].pop("unknown_id")
        problems = canonical.validate_envelope(broken)
        self.assertTrue(any("no stable unknown_id" in p for p in problems), problems)

    def test_pre_1_2_rfc_report_remains_readable(self):
        envelope = load_json(os.path.join(
            REPO, "schema", "examples", "end-to-end.json"))
        self.assertEqual([], canonical.validate_envelope(envelope))


class TestReportGoldensAndWording(unittest.TestCase):
    def test_committed_markdown_reports_are_current(self):
        for path, rendered in gen_report_goldens.artifacts().items():
            with self.subTest(path=os.path.basename(path)):
                with open(path, encoding="utf-8") as fh:
                    self.assertEqual(fh.read(), rendered,
                                     "stale report golden: run "
                                     "python3 scripts/gen_report_goldens.py")

    def test_every_fixed_wording_has_en_and_et(self):
        data = wording.load_wording()

        def visit(node, path=""):
            if isinstance(node, dict):
                if set(node) & set(wording.LANGUAGES):
                    self.assertEqual(set(wording.LANGUAGES),
                                     set(node) & set(wording.LANGUAGES), path)
                for key, value in node.items():
                    visit(value, "%s.%s" % (path, key))
            elif isinstance(node, list):
                for index, value in enumerate(node):
                    visit(value, "%s[%d]" % (path, index))

        visit(data["text"], "text")
        visit(data["templates"], "templates")
        visit(data["labels"], "labels")

    @unittest.skipUnless(HAVE_OPENPYXL, "openpyxl not installed")
    def test_framework_verdict_wording_matches_workbook(self):
        import build_workbook

        def fold(value):
            return "".join(c for c in unicodedata.normalize("NFKD", value)
                           if not unicodedata.combining(c))

        keys = set(report.load_policy()["framework_verdict_profiles"][
            "reviewer"].values()) | set(report.load_policy()[
                "framework_verdict_profiles"]["founder"].values())
        for language in wording.LANGUAGES:
            for key in keys:
                with self.subTest(language=language, key=key):
                    self.assertEqual(
                        fold(build_workbook.STR[language][key]),
                        fold(wording.label("framework_verdicts", key, language)))


if __name__ == "__main__":
    unittest.main()
