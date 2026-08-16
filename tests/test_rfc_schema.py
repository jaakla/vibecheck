#!/usr/bin/env python3
"""Machine checks for the RFC 0001 schema deliverables.

These tests pin the acceptance criteria of the schema RFC (gh issue #2):
the JSON Schema is itself valid, every shipped example validates, the
structural invariants hold (evidence can never carry a control status,
readiness is always scoped, unknown is never low), the risk matrix is total
and deterministic, references resolve, and the vibecheck_v1 framework
mapping round-trips against scripts/items.py without losing anything.

The suite skips (rather than fails) when the optional jsonschema package is
missing, so the stdlib-only scanner workflow stays dependency-free. CI
installs requirements.txt and therefore always runs it.
"""
import copy
import json
import os
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "scripts"))

import items  # noqa: E402

try:
    import openpyxl  # noqa: F401  # build_workbook sys.exits without it
    HAVE_OPENPYXL = True
except ImportError:  # normal stdlib-only scanner test runs may omit workbook deps
    HAVE_OPENPYXL = False

try:
    import jsonschema
    from jsonschema import Draft202012Validator
    HAVE_JSONSCHEMA = True
except ImportError:  # pragma: no cover
    HAVE_JSONSCHEMA = False

SCHEMA_PATH = os.path.join(REPO, "schema", "vibecheck.assessment.v1.schema.json")
MATRIX_PATH = os.path.join(REPO, "schema", "risk-matrix.v1.json")
EXAMPLES_DIR = os.path.join(REPO, "schema", "examples")


def load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def example_paths():
    return sorted(
        os.path.join(EXAMPLES_DIR, name)
        for name in os.listdir(EXAMPLES_DIR)
        if name.endswith(".json")
    )


def subschema_validator(schema, def_name):
    """Validator for one $defs entry, self-contained against the same $defs."""
    return Draft202012Validator(
        {"$defs": schema["$defs"], "$ref": "#/$defs/" + def_name}
    )


@unittest.skipUnless(HAVE_JSONSCHEMA, "jsonschema not installed (pip install -r requirements.txt)")
class SchemaAndExamples(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = load(SCHEMA_PATH)
        cls.validator = Draft202012Validator(cls.schema)

    def test_schema_is_valid_2020_12(self):
        Draft202012Validator.check_schema(self.schema)

    def test_every_example_validates(self):
        for path in example_paths():
            with self.subTest(example=os.path.basename(path)):
                errors = sorted(self.validator.iter_errors(load(path)), key=str)
                self.assertEqual(
                    [], [e.message for e in errors],
                    "%s does not validate" % os.path.basename(path))

    def test_examples_exist(self):
        names = [os.path.basename(p) for p in example_paths()]
        for required in ("end-to-end.json", "legacy-scanner-mapping.json",
                         "legacy-workbook-row.json",
                         "vibecheck-v1-framework-mapping.json",
                         "action-procedure-registry.json"):
            self.assertIn(required, names)


@unittest.skipUnless(HAVE_JSONSCHEMA, "jsonschema not installed")
class StructuralInvariants(unittest.TestCase):
    """Acceptance criteria that the schema must enforce structurally."""

    @classmethod
    def setUpClass(cls):
        cls.schema = load(SCHEMA_PATH)
        end_to_end = load(os.path.join(EXAMPLES_DIR, "end-to-end.json"))
        cls.good_evidence = end_to_end["evidence"][0]
        cls.good_assessment = end_to_end["assessments"][0]
        cls.good_readiness = end_to_end["readiness"][0]
        cls.good_procedure = end_to_end["procedures"][0]
        cls.good_report = end_to_end["report"]

    def assert_invalid(self, def_name, instance, why):
        v = subschema_validator(self.schema, def_name)
        self.assertFalse(v.is_valid(instance), why)

    def assert_valid(self, def_name, instance):
        v = subschema_validator(self.schema, def_name)
        errors = [e.message for e in v.iter_errors(instance)]
        self.assertEqual([], errors)

    def test_evidence_cannot_set_control_status(self):
        # "An evidence record cannot directly set a control-wide Pass."
        self.assert_valid("evidence", self.good_evidence)
        for forbidden in ("status", "verdict", "control_status", "assessment_status"):
            bad = copy.deepcopy(self.good_evidence)
            bad[forbidden] = "pass"
            self.assert_invalid("evidence", bad,
                                "evidence with %r must be rejected" % forbidden)

    def test_signal_asserts_nothing(self):
        end_to_end = load(os.path.join(EXAMPLES_DIR, "end-to-end.json"))
        good = end_to_end["signals"][0]
        self.assert_valid("signal", good)
        for forbidden in ("status", "verdict", "direction", "control_status"):
            bad = copy.deepcopy(good)
            bad[forbidden] = "WARN"
            self.assert_invalid("signal", bad,
                                "signal with %r must be rejected" % forbidden)

    def test_pass_requires_evidence(self):
        bad = copy.deepcopy(self.good_assessment)
        bad["status"] = "pass"
        bad["basis"]["evidence_refs"] = []
        self.assert_invalid("assessment", bad, "pass with no evidence refs must be rejected")

    def test_risk_accepted_requires_acceptance_record(self):
        bad = copy.deepcopy(self.good_assessment)
        bad["status"] = "risk_accepted"
        bad.pop("acceptance", None)
        self.assert_invalid("assessment", bad,
                            "risk_accepted without accepted_by/reason/review_by must be rejected")

    def test_assessment_cannot_carry_risk_or_severity(self):
        for forbidden in ("contextual_risk", "intrinsic_severity"):
            bad = copy.deepcopy(self.good_assessment)
            bad[forbidden] = "low"
            self.assert_invalid("assessment", bad,
                                "assessment with %r must be rejected" % forbidden)

    def test_readiness_requires_full_scope(self):
        # "Readiness is always scoped to an environment and intended use."
        self.assert_valid("readiness", self.good_readiness)
        for dropped in ("environment", "intended_use"):
            bad = copy.deepcopy(self.good_readiness)
            del bad["scope"][dropped]
            self.assert_invalid("readiness", bad,
                                "readiness without scope.%s must be rejected" % dropped)
        bad = copy.deepcopy(self.good_readiness)
        del bad["scope"]
        self.assert_invalid("readiness", bad, "readiness without scope must be rejected")

    def test_readiness_cannot_claim_secure(self):
        for forbidden in ("secure", "certified"):
            bad = copy.deepcopy(self.good_readiness)
            bad[forbidden] = True
            self.assert_invalid("readiness", bad,
                                "readiness with %r must be rejected" % forbidden)

    def test_conditional_readiness_requires_conditions(self):
        bad = copy.deepcopy(self.good_readiness)
        bad["state"] = "conditional"
        bad["conditions"] = []
        self.assert_invalid("readiness", bad,
                            "conditional readiness with no machine-readable conditions must be rejected")

    def test_effectful_procedure_requires_explicit_consent(self):
        # "Procedure authorization and side effects are unambiguous."
        self.assert_valid("procedure", self.good_procedure)
        for effect in ("write", "destructive", "deployment", "data", "external_accounts"):
            bad = copy.deepcopy(self.good_procedure)
            for key in ("write", "destructive", "deployment", "data", "external_accounts"):
                bad["effects"][key] = key == effect
            bad["authorization"]["consent"] = "not_required"
            self.assert_invalid("procedure", bad,
                                "procedure with %s effect and consent=not_required must be rejected" % effect)

    def test_headline_cap_is_five(self):
        bad = copy.deepcopy(self.good_report)
        bad["headline_scenario_refs"] = ["scn-%d" % i for i in range(6)]
        self.assert_invalid("report", bad, "more than 5 headline scenarios must be rejected")

    def test_report_requires_all_mandatory_disclosure_sets(self):
        for dropped in ("unresolved_critical_high_refs", "readiness_blocking_unknown_refs",
                        "incident_response_action_refs", "specialist_escalation_refs",
                        "deadline_blocking_action_refs"):
            bad = copy.deepcopy(self.good_report)
            del bad["mandatory_disclosures"][dropped]
            self.assert_invalid("report", bad,
                                "report without mandatory_disclosures.%s must be rejected" % dropped)


class RiskMatrix(unittest.TestCase):
    """The contextual-risk method must be total, deterministic, and unknown-safe."""

    @classmethod
    def setUpClass(cls):
        cls.matrix_doc = load(MATRIX_PATH)

    def test_matrix_is_total_and_levels_are_valid(self):
        doc = self.matrix_doc
        levels = set(doc["risk_levels"])
        self.assertEqual(set(doc["matrix"]), set(doc["impact_levels"]))
        for impact in doc["impact_levels"]:
            row = doc["matrix"][impact]
            self.assertEqual(set(row), set(doc["exposure_levels"]),
                             "matrix row %r is not total over exposure levels" % impact)
            for exposure, level in row.items():
                self.assertIn(level, levels)
                self.assertNotEqual(level, "unknown",
                                    "known inputs must never yield unknown")

    def test_matrix_is_monotonic(self):
        """More impact or more exposure never lowers the risk level."""
        doc = self.matrix_doc
        rank = {"low": 0, "moderate": 1, "high": 2, "critical": 3}
        impacts = doc["impact_levels"]     # minor .. severe, ascending
        exposures = doc["exposure_levels"]  # rare .. expected, ascending
        for i, impact in enumerate(impacts):
            for j, exposure in enumerate(exposures):
                here = rank[doc["matrix"][impact][exposure]]
                if i + 1 < len(impacts):
                    self.assertGreaterEqual(
                        rank[doc["matrix"][impacts[i + 1]][exposure]], here)
                if j + 1 < len(exposures):
                    self.assertGreaterEqual(
                        rank[doc["matrix"][impact][exposures[j + 1]]], here)

    def test_unknown_input_yields_unknown_never_low(self):
        # "Unknown cannot be interpreted as Low or as permission to proceed."
        doc = self.matrix_doc
        self.assertIn("unknown", doc["risk_levels"])
        self.assertNotIn("unknown", doc["impact_levels"])
        self.assertNotIn("unknown", doc["exposure_levels"])
        self.assertIn("level is unknown", doc["unknown_rule"])
        self.assertIn("never", doc["unknown_rule"])

    def test_worked_examples_from_end_to_end(self):
        """The example envelope's risk levels equal the matrix lookup of their inputs."""
        doc = self.matrix_doc
        envelope = load(os.path.join(EXAMPLES_DIR, "end-to-end.json"))
        for risk in envelope["risks"]:
            impact = risk["inputs"]["impact"]
            exposure = risk["inputs"]["exposure"]
            if "unknown" in (impact, exposure):
                expected = "unknown"
            else:
                expected = doc["matrix"][impact][exposure]
            if "downgrade" in risk:
                continue
            self.assertEqual(expected, risk["level"],
                             "%s level does not match matrix(%s, %s)"
                             % (risk["risk_id"], impact, exposure))


class ReferenceIntegrity(unittest.TestCase):
    """Every *_ref / *_refs in the shipped examples must resolve in its envelope."""

    PREFIX_TO_SECTION = {
        "sig-": "signals", "ev-": "evidence", "asm-": "assessments",
        "rsk-": "risks", "scn-": "scenarios", "act-": "actions",
        "prc-": "procedures", "att-": "attempts", "prov-": "providers",
        "rdy-": "readiness",
    }
    ID_KEYS = ("signal_id", "evidence_id", "assessment_id", "risk_id",
               "scenario_id", "action_id", "procedure_id", "attempt_id",
               "provider_id", "readiness_id")

    def collect_ids(self, envelope):
        ids = set()
        for section in self.PREFIX_TO_SECTION.values():
            for obj in envelope.get(section, []) or []:
                for key in self.ID_KEYS:
                    if key in obj:
                        ids.add(obj[key])
        return ids

    def iter_refs(self, node, path=""):
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
                    yield from self.iter_refs(value, where)
        elif isinstance(node, list):
            for i, value in enumerate(node):
                yield from self.iter_refs(value, "%s[%d]" % (path, i))

    def test_all_refs_resolve(self):
        for example in example_paths():
            envelope = load(example)
            ids = self.collect_ids(envelope)
            with self.subTest(example=os.path.basename(example)):
                for where, ref in self.iter_refs(envelope):
                    prefix = ref.split("-", 1)[0] + "-"
                    if prefix not in self.PREFIX_TO_SECTION:
                        continue  # control ids, raw refs, etc.
                    self.assertIn(ref, ids,
                                  "dangling reference %s at %s" % (ref, where))

    def test_supersedes_chains_are_acyclic_and_resolve(self):
        envelope = load(os.path.join(EXAMPLES_DIR, "end-to-end.json"))
        for section in ("assessments", "risks"):
            by_id = {}
            for obj in envelope.get(section, []):
                for key in self.ID_KEYS:
                    if key in obj:
                        by_id[obj[key]] = obj
            for obj in envelope.get(section, []):
                seen = set()
                cur = obj
                while "supersedes" in cur:
                    target = cur["supersedes"]
                    self.assertIn(target, by_id, "supersedes %r dangles" % target)
                    self.assertNotIn(target, seen, "supersedes cycle at %r" % target)
                    seen.add(target)
                    cur = by_id[target]

    def test_failed_control_remains_failed_until_new_evidence(self):
        """The superseding assessment must cite evidence observed after the
        refuting evidence it overrides — a disappeared warning is not enough."""
        envelope = load(os.path.join(EXAMPLES_DIR, "end-to-end.json"))
        evidence = {e["evidence_id"]: e for e in envelope["evidence"]}
        assessments = {a["assessment_id"]: a for a in envelope["assessments"]}
        for asm in envelope["assessments"]:
            if "supersedes" not in asm or asm["status"] not in ("pass", "partial"):
                continue
            old = assessments[asm["supersedes"]]
            self.assertEqual("fail", old["status"])
            old_obs = max(evidence[r]["observed_at"] for r in old["basis"]["evidence_refs"])
            supporting = [evidence[r] for r in asm["basis"]["evidence_refs"]
                          if evidence[r]["direction"] == "supports"]
            self.assertTrue(supporting, "recovery needs supporting evidence")
            self.assertTrue(any(e["observed_at"] > old_obs for e in supporting),
                            "recovery evidence must post-date the refuting evidence")
            # and the disagreement is recorded, not silently overwritten
            conflict_refs = {c["evidence_ref"] for c in asm.get("conflicts", [])}
            refuting_old = {r for r in old["basis"]["evidence_refs"]
                            if evidence[r]["direction"] == "refutes"
                            and evidence[r]["strength"] == "decisive"}
            self.assertTrue(refuting_old <= conflict_refs,
                            "decisive refuting evidence must appear in conflicts with a resolution")


class LegacyMappingSemantics(unittest.TestCase):
    """The scanner-status mapping rules the RFC documents, pinned on the example."""

    @classmethod
    def setUpClass(cls):
        cls.envelope = load(os.path.join(EXAMPLES_DIR, "legacy-scanner-mapping.json"))

    def evidence_for_signal(self, signal_id):
        return [e for e in self.envelope.get("evidence", [])
                if signal_id in e.get("signal_refs", [])]

    def signal_status(self, signal):
        return json.loads(signal["raw_ref"]["value"])["status"]

    def test_warn_maps_to_refuting_indicative_evidence(self):
        for signal in self.envelope["signals"]:
            if self.signal_status(signal) != "WARN":
                continue
            mapped = self.evidence_for_signal(signal["signal_id"])
            self.assertTrue(mapped)
            for e in mapped:
                self.assertEqual("refutes", e["direction"])
                self.assertEqual("indicative", e["strength"],
                                 "a regex hit is never decisive")

    def test_no_signal_maps_to_neutral_evidence(self):
        # "NO_SIGNAL is never Pass": neutral evidence cannot support a pass (R3).
        found = False
        for signal in self.envelope["signals"]:
            if self.signal_status(signal) != "NO_SIGNAL":
                continue
            for e in self.evidence_for_signal(signal["signal_id"]):
                found = True
                self.assertEqual("neutral", e["direction"])
        self.assertTrue(found, "example must include a NO_SIGNAL mapping")

    def test_manual_maps_to_open_action_not_evidence(self):
        manual = [s for s in self.envelope["signals"]
                  if self.signal_status(s) == "MANUAL"]
        self.assertTrue(manual, "example must include a MANUAL mapping")
        for signal in manual:
            self.assertEqual([], self.evidence_for_signal(signal["signal_id"]),
                             "MANUAL produces no evidence")
            check_id = signal["source"]["check_id"]
            todo = [a for a in self.envelope.get("actions", [])
                    if a["kind"] == "verify" and check_id in a["reason"]]
            self.assertTrue(todo, "MANUAL must produce an open verify action")
            self.assertEqual("open", todo[0]["state"])


class VibecheckV1RoundTrip(unittest.TestCase):
    """The vibecheck_v1 mapping example must round-trip against items.py exactly."""

    @classmethod
    def setUpClass(cls):
        envelope = load(os.path.join(EXAMPLES_DIR, "vibecheck-v1-framework-mapping.json"))
        (cls.mapping,) = envelope["framework_mappings"]
        # item number -> (category dict, item tuple), same numbering as the workbook
        cls.bank = {}
        number = 0
        for category_number, cat in enumerate(items.CATEGORIES, 1):
            for tup in cat["items"]:
                number += 1
                cls.bank[number] = (category_number, cat, tup)

    def test_wording_severity_weight_round_trip(self):
        for entry in self.mapping["entries"]:
            n = entry["item_number"]
            category_number, cat, tup = self.bank[n]
            severity, tech_en, tech_et, plain_en, plain_et, test_en, test_et = tup
            with self.subTest(item=n):
                self.assertEqual(severity, entry["severity"])
                self.assertEqual(items.WEIGHT[severity], entry["weight"])
                self.assertEqual(category_number, entry["category"]["number"])
                self.assertEqual(cat["en"], entry["category"]["en"])
                self.assertEqual(cat["et"], entry["category"]["et"])
                w = entry["wording"]
                self.assertEqual(
                    (tech_en, tech_et, plain_en, plain_et, test_en, test_et),
                    (w["tech_en"], w["tech_et"], w["plain_en"],
                     w["plain_et"], w["test_en"], w["test_et"]))

    def test_verification_round_trip(self):
        for entry in self.mapping["entries"]:
            codes, tools = items.VERIFICATION[entry["item_number"]]
            self.assertEqual(codes, entry["verification"]["codes"])
            self.assertEqual(tools, entry["verification"]["tools"])

    def test_scanner_checks_round_trip(self):
        for entry in self.mapping["entries"]:
            n = entry["item_number"]
            expected = {check: tier for check, (nums, tier) in items.SCANNER_CHECKS.items()
                        if n in nums}
            got = {c["check_id"]: c["tier"] for c in entry["scanner_checks"]}
            self.assertEqual(expected, got,
                             "scanner check coverage for item %d must be lossless" % n)

    @unittest.skipUnless(HAVE_OPENPYXL, "openpyxl required to import build_workbook")
    def test_status_map_matches_workbook_wordings(self):
        from build_workbook import STR
        status_map = self.mapping["status_map"]
        expected_keys = {
            "pass": "pass", "partial": "partial", "fail": "fail",
            "not_tested": "nottested", "not_applicable": "na",
            "risk_accepted": "acc", "answered": "ans", "needs_specialist": "spec",
        }
        self.assertEqual(set(expected_keys), set(status_map))
        for canonical, workbook_key in expected_keys.items():
            for lang in ("en", "et"):
                self.assertEqual(STR[lang][workbook_key], status_map[canonical][lang],
                                 "status %r (%s) must match the workbook wording"
                                 % (canonical, lang))

    def test_control_ids_are_stable_semantic_ids(self):
        seen = set()
        for entry in self.mapping["entries"]:
            cid = entry["control_id"]
            self.assertRegex(cid, r"^vibecheck\.control\.[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$")
            self.assertNotIn(cid, seen, "control ids must be unique")
            seen.add(cid)
            self.assertNotIn(str(entry["item_number"]), cid.split(".")[-1],
                             "control ids must not encode checklist row numbers")


if __name__ == "__main__":
    unittest.main()
