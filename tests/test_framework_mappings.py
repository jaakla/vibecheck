#!/usr/bin/env python3
"""Increment 8 (gh issue #10): framework mappings and model cutover.

Pins the acceptance criteria:
  - the versioned vibecheck_v1 mapping is the canonical projection the workbook
    and checklist map consume (the mapping is the lossless source and generated
    outputs are byte-identical),
  - a second sample framework (founder_focus) reuses existing control records
    without duplicating them (many-to-many items <-> controls),
  - legacy workbook rows import into canonical assessments and round-trip
    status, notes, evidence references, acceptance and item mapping,
  - historical envelopes keep schema_version and mapping version at assessment
    time,
  - direct legacy paths (positional items.py tuples and scanner-check maps)
    have a documented deprecation window and produce no silent behaviour
    change.

Stdlib-only; parts needing jsonschema/openpyxl skip cleanly when absent.
"""
import json
import os
import subprocess
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "scripts"))

import adapters  # noqa: E402
import canonical  # noqa: E402
import controls  # noqa: E402
import items  # noqa: E402

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


def load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def registry_sev(control_id):
    for entry in controls.build_registry()["controls"]:
        if entry["control_id"] == control_id:
            return entry["severity"]
    return None


class TestVibecheckV1MappingCanonical(unittest.TestCase):
    """The mapping is canonical: it carries provenance and full item data."""

    @classmethod
    def setUpClass(cls):
        cls.mapping = controls.build_framework_mapping()
        cls.by_number = {e["item_number"]: e for e in cls.mapping["entries"]}

    def test_mapping_has_explicit_provenance(self):
        self.assertIn("provenance", self.mapping)
        for key in ("source", "established_at", "method", "change_policy"):
            self.assertIn(key, self.mapping["provenance"])
        self.assertIn("new framework_version",
                      self.mapping["provenance"]["change_policy"])

    def test_every_entry_round_trips_item_and_severity(self):
        self.assertEqual(89, len(self.by_number))
        for n, entry in self.by_number.items():
            self.assertEqual(n, entry["item_number"])
            self.assertEqual(items.WEIGHT[entry["severity"]], entry["weight"])
            self.assertIn("wording", entry)
            self.assertIn("verification", entry)

    @unittest.skipUnless(HAVE_JSONSCHEMA, "jsonschema not installed")
    def test_mapping_validates_with_provenance(self):
        schema = canonical.load_schema()
        validator = Draft202012Validator(
            {"$defs": schema["$defs"], "$ref": "#/$defs/framework_mapping"})
        self.assertEqual([], [e.message
                              for e in validator.iter_errors(self.mapping)])


class TestSecondFrameworkReusesControls(unittest.TestCase):
    """Gap analysis: a second framework reuses controls without duplication."""

    @classmethod
    def setUpClass(cls):
        cls.focus = controls.build_focus_framework()
        cls.focus_by_number = {e["item_number"]: e
                               for e in cls.focus["entries"]}
        cls.registry_ids = {c["control_id"] for c in
                            controls.build_registry()["controls"]}

    def test_second_framework_has_own_coordinates(self):
        self.assertEqual("founder_focus", self.focus["framework"])
        self.assertTrue(all(1 <= e["item_number"] <= 8
                            for e in self.focus["entries"]))

    def test_every_referenced_control_is_in_the_registry(self):
        self.assertTrue(self.focus["entries"])
        for entry in self.focus["entries"]:
            ids = [entry["control_id"]] + list(entry.get("related_control_ids") or [])
            for cid in ids:
                self.assertIn(cid, self.registry_ids,
                              "founder_focus references unknown control %r" % cid)

    def test_no_control_record_is_duplicated(self):
        self.assertEqual(89, len(controls.build_registry()["controls"]))
        for cid in {e["control_id"] for e in self.focus["entries"]}:
            self.assertIn(cid, self.registry_ids)

    def test_many_to_many_edges_are_explicit(self):
        spanning = [e for e in self.focus["entries"]
                    if e.get("related_control_ids")]
        self.assertTrue(spanning, "expected an item spanning several controls")
        for entry in spanning:
            self.assertTrue(entry.get("provenance"))
            self.assertTrue(all(cid in self.registry_ids
                                for cid in entry["related_control_ids"]))

    def test_framework_owns_wording_control_owns_identity(self):
        entry = self.focus_by_number[1]
        control_title = None
        for c in controls.build_registry()["controls"]:
            if c["control_id"] == entry["control_id"]:
                control_title = c["title"]["en"]
        self.assertIsNotNone(control_title)
        self.assertNotEqual(entry["wording"]["plain_en"], control_title)

    def test_generated_artifact_is_current(self):
        rendered = json.dumps(self.focus, ensure_ascii=False, indent=2) + "\n"
        with open(os.path.join(REPO, "schema", "mappings",
                               "founder_focus_v1.json"), encoding="utf-8") as fh:
            self.assertEqual(rendered, fh.read())

    @unittest.skipUnless(HAVE_JSONSCHEMA, "jsonschema not installed")
    def test_focus_validates_against_schema(self):
        schema = canonical.load_schema()
        validator = Draft202012Validator(
            {"$defs": schema["$defs"], "$ref": "#/$defs/framework_mapping"})
        self.assertEqual([], [e.message for e in validator.iter_errors(self.focus)])


class TestCutoverIsLossless(unittest.TestCase):
    """Cutover: workbook/map consumers read the canonical mapping; output is
    byte-identical to the legacy items.py path (no silent behaviour change)."""

    @unittest.skipUnless(HAVE_OPENPYXL, "openpyxl required to import build_workbook")
    def test_workbook_bank_matches_items(self):
        from build_workbook import _canonical_categories, VERIFICATION
        cats = _canonical_categories()

        def bank(source_cats):
            out = []
            for cat in source_cats:
                for it in cat["items"]:
                    out.append((cat["en"], it[0], it[1], it[2], it[3],
                                it[4], it[5], it[6]))
            return out

        self.assertEqual(bank(cats), bank(items.CATEGORIES))
        for n in range(1, 90):
            self.assertEqual(list(items.VERIFICATION[n][0]),
                             list(VERIFICATION[n][0]))
            self.assertEqual(items.VERIFICATION[n][1], VERIFICATION[n][1])

    def test_gen_map_check_passes_after_cutover(self):
        r = subprocess.run([sys.executable,
                            os.path.join(REPO, "scripts", "gen_map.py"),
                            "--check"], capture_output=True, text=True)
        self.assertEqual(0, r.returncode, r.stderr)

    def test_scanner_tier_reads_from_the_mapping(self):
        check, (_nums, tier) = next(iter(items.SCANNER_CHECKS.items()))
        self.assertEqual(tier, controls.scanner_tier(check))
        self.assertIsNone(controls.scanner_tier("no-such-check"))


class TestLegacyMigrationRoundTrip(unittest.TestCase):
    """A legacy workbook assessment migrates and round-trips losslessly."""

    SAMPLE = {
        14: {"status": "Fail", "notes": "No row-level security on orders"},
        33: {"status": "Accepted risk",
             "notes": "Legacy debt [Accepted by jaak: acceptable for MVP; review by 2026-09-01]"},
        60: {"status": "Answered", "notes": "Screened: not high-risk"},
    }

    def test_import_preserves_status_notes_mapping_and_severity(self):
        env, problems = adapters.import_workbook_rows(self.SAMPLE, lang="en")
        self.assertEqual([], problems)
        by_control = {a["control_id"]: a for a in env["assessments"]}

        cid14 = controls.CONTROL_IDS[14]
        asm = by_control[cid14]
        self.assertEqual("fail", asm["status"])
        self.assertEqual("No row-level security on orders",
                         asm["basis"]["rationale"])
        self.assertEqual("Critical", registry_sev(cid14))
        self.assertNotIn("acceptance", asm)

        asm33 = by_control[controls.CONTROL_IDS[33]]
        self.assertEqual("risk_accepted", asm33["status"])
        self.assertEqual("Legacy debt", asm33["basis"]["rationale"])
        self.assertEqual("jaak", asm33["acceptance"]["accepted_by"])
        # review_by is normalized to a full timestamp for the schema; the
        # workbook export renders it back as the date-only cell value
        self.assertEqual("2026-09-01T00:00:00Z", asm33["acceptance"]["review_by"])

        asm60 = by_control[controls.CONTROL_IDS[60]]
        self.assertEqual("answered", asm60["status"])
        self.assertEqual("Screened: not high-risk", asm60["basis"]["rationale"])

    def test_accepted_risk_round_trips_exactly(self):
        env, problems = adapters.import_workbook_rows(self.SAMPLE, lang="en")
        self.assertEqual([], problems)
        out = adapters.export_workbook_rows(env, lang="en")
        for n, cell in self.SAMPLE.items():
            self.assertEqual(cell, out[n], "item %d must round-trip" % n)

    def test_blank_status_imports_no_assessment(self):
        rows = {14: {}, 33: {"status": "", "notes": ""}}
        env, problems = adapters.import_workbook_rows(rows, lang="en")
        self.assertEqual([], problems)
        self.assertEqual([], env["assessments"])

    def test_unknown_status_is_refused_not_guessed(self):
        env, problems = adapters.import_workbook_rows(
            {14: {"status": "Maybe"}, 33: {"status": "Fail", "notes": "x"}},
            lang="en")
        self.assertTrue(any("Maybe" in p for p in problems))
        self.assertEqual([controls.ITEM_NUMBERS[a["control_id"]]
                          for a in env["assessments"]], [33])

    def test_na_on_critical_or_high_is_refused(self):
        env, problems = adapters.import_workbook_rows(
            {14: {"status": "N/A", "notes": "feature not used"}}, lang="en")
        self.assertTrue(any("N/A" in p and "reason" in p for p in problems))
        self.assertEqual([], env["assessments"])

    def test_na_on_low_or_medium_is_preserved(self):
        n = next(num for num in range(1, 90)
                 if registry_sev(controls.CONTROL_IDS[num]) in ("Low", "Medium"))
        env, problems = adapters.import_workbook_rows(
            {n: {"status": "N/A", "notes": "really not applicable"}}, lang="en")
        self.assertEqual([], problems)
        self.assertEqual("not_applicable", env["assessments"][0]["status"])
        self.assertEqual(controls.CONTROL_IDS[n],
                         env["assessments"][0]["control_id"])
        self.assertIn("N/A reason: really not applicable",
                      env["assessments"][0]["basis"]["rationale"])


class TestHistoricalVersions(unittest.TestCase):
    """Historical envelopes keep their schema and mapping version."""

    def test_round_trip_retains_schema_and_mapping_versions(self):
        env = {
            "schema": "vibecheck.assessment",
            "schema_version": "1.2.0",
            "assessment_id": "old",
            "revision": 3,
            "created_at": "2026-01-15T00:00:00Z",
            "context": {"context_id": "ctx",
                        "revision": 1,
                        "application": {"name": "old app"},
                        "target_scopes": [{"environment": "developer_only",
                                           "intended_use": "prototype_demo"}],
                        "confirmation": {"state": "draft"}},
            "control_registry": {"name": controls.REGISTRY_NAME,
                                 "version": "1.0.0"},
            "framework_mappings": [{
                "framework": "vibecheck_v1",
                "framework_version": "2026.01",
                "entries": [{
                    "control_id": controls.CONTROL_IDS[14],
                    "item_number": 14,
                    "category": {"number": 3, "en": "x", "et": "y"},
                    "severity": "Critical",
                    "weight": 5,
                    "wording": {"tech_en": "a", "tech_et": "b", "plain_en": "c",
                                "plain_et": "d", "test_en": "e", "test_et": "f"},
                    "verification": {"codes": ["AI"], "tools": "t"},
                    "scanner_checks": [],
                    "workbook_profiles": ["reviewer"],
                }],
            }],
        }
        back = canonical.loads(canonical.dumps(env))
        self.assertEqual("1.2.0", back["schema_version"])
        self.assertEqual("2026.01",
                         back["framework_mappings"][0]["framework_version"])
        self.assertEqual(controls.CONTROL_IDS[14],
                         back["framework_mappings"][0]["entries"][0]["control_id"])


if __name__ == "__main__":
    unittest.main()
