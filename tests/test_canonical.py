#!/usr/bin/env python3
"""Canonical schema, stable control IDs and scanner adapters.

Pins the acceptance criteria:
  - every checklist item has a stable control ID and a lossless vibecheck_v1
    mapping entry (generated artifacts stay current with items.py),
  - scanner fixtures import into a valid artifact without NO_SIGNAL becoming
    a pass,
  - Supabase probe results import as scoped evidence, never control-wide
    conclusions,
  - unknown and conflicting evidence survive serialization,
  - the scanner JSONL export is byte-compatible with the imported stream,
  - schema version, object IDs, references and migrations are covered.

Stdlib-only, like the other suites; parts that need jsonschema or openpyxl
skip cleanly when those are absent.
"""
import copy
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "scripts"))

import adapters  # noqa: E402
import canonical  # noqa: E402
import controls  # noqa: E402
import gen_canonical  # noqa: E402
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

EXAMPLES_DIR = os.path.join(REPO, "schema", "examples")
NOW = "2026-08-16T12:00:00Z"


def load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


# --------------------------------------------------------- stable control IDs

class TestControlRegistry(unittest.TestCase):
    def setUp(self):
        self.registry = controls.build_registry()

    def test_every_item_has_exactly_one_control(self):
        self.assertEqual(items.item_count(), 89)
        self.assertEqual(sorted(controls.CONTROL_IDS), list(range(1, 90)))
        self.assertEqual(len(self.registry["controls"]), 89)
        self.assertEqual(len({c["control_id"] for c in self.registry["controls"]}), 89)

    def test_id_grammar_and_namespaces(self):
        pattern = re.compile(
            r"^vibecheck\.control\.([a-z][a-z0-9_]*)\.([a-z][a-z0-9_]*)$")
        allowed = set(controls.NAMESPACE_BY_CATEGORY.values())
        for cid in controls.CONTROL_IDS.values():
            m = pattern.match(cid)
            self.assertIsNotNone(m, "bad control id %r" % cid)
            self.assertIn(m.group(1), allowed)

    def test_row_numbers_never_leak_into_slugs(self):
        # renumbering the workbook must never move a control's identity
        for n, cid in controls.CONTROL_IDS.items():
            slug = cid.split(".")[-1]
            self.assertNotRegex(slug, r"[0-9]",
                                "slug %r may encode a row number" % slug)
            self.assertNotIn(str(n), slug)

    def test_ids_pinned_by_rfc_examples_are_stable(self):
        pinned = {
            7: "vibecheck.control.secrets.no_frontend_literals",
            13: "vibecheck.control.authz.object_level",
            14: "vibecheck.control.authz.anon_data_access",
            15: "vibecheck.control.authz.tenant_isolation",
            24: "vibecheck.control.cost.budget_caps",
            29: "vibecheck.control.input.sql_parameterized",
        }
        for n, cid in pinned.items():
            self.assertEqual(cid, controls.CONTROL_IDS[n])

    def test_registry_matches_items_severity_and_kind(self):
        bank = []
        for cat in items.CATEGORIES:
            bank.extend(tup[0] for tup in cat["items"])
        for entry, severity in zip(self.registry["controls"], bank):
            self.assertEqual(severity, entry["severity"])
            self.assertEqual(items.WEIGHT[severity], entry["weight"])
            self.assertEqual("screening" if severity == "Triage" else "control",
                             entry["kind"])
            self.assertEqual("active", entry["status"])

    def test_registry_version_matches_envelope_default(self):
        self.assertEqual(controls.REGISTRY_NAME, self.registry["registry"])
        self.assertEqual(controls.REGISTRY_VERSION, self.registry["version"])


class TestGeneratedArtifactsCurrent(unittest.TestCase):
    """The committed registry/mapping artifacts must match regeneration."""

    def test_artifacts_are_current(self):
        for path, rendered in gen_canonical.artifacts().items():
            rel = os.path.relpath(path, REPO)
            with self.subTest(artifact=rel):
                with open(path, encoding="utf-8") as fh:
                    self.assertEqual(fh.read(), rendered,
                                     "%s is stale: run python3 scripts/gen_canonical.py" % rel)


class TestFrameworkMappingLossless(unittest.TestCase):
    """The full 89-entry vibecheck_v1 mapping round-trips items.py exactly."""

    @classmethod
    def setUpClass(cls):
        cls.mapping = controls.build_framework_mapping()
        cls.by_number = {e["item_number"]: e for e in cls.mapping["entries"]}
        cls.bank = {}
        n = 0
        for category_number, cat in enumerate(items.CATEGORIES, 1):
            for tup in cat["items"]:
                n += 1
                cls.bank[n] = (category_number, cat, tup)

    def test_covers_all_89_items(self):
        self.assertEqual(sorted(self.by_number), list(range(1, 90)))

    def test_wording_severity_weight_category_round_trip(self):
        for n, (category_number, cat, tup) in self.bank.items():
            severity, tech_en, tech_et, plain_en, plain_et, test_en, test_et = tup
            entry = self.by_number[n]
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

    def test_verification_and_scanner_checks_round_trip(self):
        for n, entry in self.by_number.items():
            codes, tools = items.VERIFICATION[n]
            self.assertEqual(list(codes), entry["verification"]["codes"])
            self.assertEqual(tools, entry["verification"]["tools"])
            expected = {check: tier
                        for check, (nums, tier) in items.SCANNER_CHECKS.items()
                        if n in nums}
            got = {c["check_id"]: c["tier"] for c in entry["scanner_checks"]}
            self.assertEqual(expected, got)

    def test_matches_rfc_example_entries(self):
        """Items 13 and 14 were shipped with the RFC as the pattern; the full
        mapping must contain those exact entries."""
        envelope = load(os.path.join(EXAMPLES_DIR,
                                     "vibecheck-v1-framework-mapping.json"))
        (example,) = envelope["framework_mappings"]
        self.assertEqual(example["status_map"], self.mapping["status_map"])
        self.assertEqual(example["framework"], self.mapping["framework"])
        self.assertEqual(example["framework_version"],
                         self.mapping["framework_version"])
        for entry in example["entries"]:
            self.assertEqual(entry, self.by_number[entry["item_number"]])

    @unittest.skipUnless(HAVE_OPENPYXL, "openpyxl required to import build_workbook")
    def test_status_map_matches_workbook_wordings(self):
        from build_workbook import STR
        expected_keys = {
            "pass": "pass", "partial": "partial", "fail": "fail",
            "not_tested": "nottested", "not_applicable": "na",
            "risk_accepted": "acc", "answered": "ans", "needs_specialist": "spec",
        }
        self.assertEqual(set(expected_keys), set(self.mapping["status_map"]))
        for canonical_status, workbook_key in expected_keys.items():
            for lang in ("en", "et"):
                self.assertEqual(STR[lang][workbook_key],
                                 self.mapping["status_map"][canonical_status][lang])

    @unittest.skipUnless(HAVE_JSONSCHEMA, "jsonschema not installed")
    def test_mapping_validates_against_schema(self):
        schema = canonical.load_schema()
        validator = Draft202012Validator(
            {"$defs": schema["$defs"], "$ref": "#/$defs/framework_mapping"})
        errors = [e.message for e in validator.iter_errors(self.mapping)]
        self.assertEqual([], errors)


# ------------------------------------------------------------------ validator

def mini_envelope(**sections):
    env = {
        "schema": "vibecheck.assessment",
        "schema_version": canonical.SCHEMA_VERSION,
        "assessment_id": "va-test",
        "revision": 1,
        "created_at": NOW,
        "context": {
            "context_id": "ctx-test",
            "revision": 1,
            "application": {"name": "validator test"},
            "target_scopes": [{"environment": "developer_only",
                               "intended_use": "prototype_demo"}],
            "confirmation": {"state": "draft"},
        },
        "control_registry": {"name": controls.REGISTRY_NAME,
                             "version": controls.REGISTRY_VERSION},
    }
    env.update(sections)
    return env


def evidence(evidence_id, control_id, direction, observed_at=NOW, **over):
    ev = {
        "evidence_id": evidence_id,
        "provider": {"name": "test"},
        "subject": {"kind": "repo", "locator": "."},
        "environment": "developer_only",
        "operation": "test",
        "scope": "test scope",
        "claim": {"control_ids": [control_id],
                  "statement": "the control requirement is met"},
        "direction": direction,
        "strength": "indicative",
        "observed_at": observed_at,
    }
    ev.update(over)
    return ev


def assessment(assessment_id, control_id, status, refs, **over):
    asm = {
        "assessment_id": assessment_id,
        "control_id": control_id,
        "status": status,
        "assessor": {"kind": "human", "id": "reviewer:test"},
        "assessed_at": NOW,
        "basis": {"rationale": "test rationale", "evidence_refs": refs},
    }
    asm.update(over)
    return asm


def risk(risk_id, impact, exposure, level, **over):
    rsk = {
        "risk_id": risk_id,
        "domain": "security",
        "scope": {"environment": "developer_only",
                  "intended_use": "prototype_demo"},
        "horizon": {"kind": "current"},
        "method": {"name": "vibecheck.risk_matrix", "version": "1.0.0"},
        "inputs": {"impact": impact, "exposure": exposure,
                   "affected": "test data",
                   "plausibility_rationale": "test",
                   "blast_radius": "one table"},
        "level": level,
        "confidence": "medium",
        "assessed_at": NOW,
    }
    rsk.update(over)
    return rsk


CONTROL = controls.CONTROL_IDS[14]          # Critical, kind=control
SCREENING = controls.CONTROL_IDS[60]        # Triage, kind=screening
MEDIUM_CONTROL = controls.CONTROL_IDS[33]   # Medium severity


class TestEnvelopeValidator(unittest.TestCase):
    def test_shipped_examples_validate(self):
        for name in sorted(os.listdir(EXAMPLES_DIR)):
            if name.endswith(".json"):
                with self.subTest(example=name):
                    self.assertEqual(
                        [], canonical.validate_envelope(
                            load(os.path.join(EXAMPLES_DIR, name))))

    def assert_problem(self, env, fragment):
        problems = canonical.validate_envelope(env)
        self.assertTrue(any(fragment in p for p in problems),
                        "expected a problem containing %r, got %r"
                        % (fragment, problems))

    def test_dangling_reference(self):
        env = mini_envelope(evidence=[
            evidence("ev-a", CONTROL, "neutral", signal_refs=["sig-ghost"])])
        self.assert_problem(env, "dangling reference sig-ghost")

    def test_duplicate_ids(self):
        env = mini_envelope(evidence=[
            evidence("ev-a", CONTROL, "neutral"),
            evidence("ev-a", CONTROL, "neutral")])
        self.assert_problem(env, "duplicate object id")

    def test_unknown_control_id_in_named_registry(self):
        env = mini_envelope(evidence=[
            evidence("ev-a", "vibecheck.control.authz.no_such_control", "neutral")])
        self.assert_problem(env, "not in registry")

    def test_other_registries_are_not_resolved(self):
        env = mini_envelope(evidence=[
            evidence("ev-a", "vibecheck.control.authz.no_such_control", "neutral")])
        env["control_registry"] = {"name": "other.registry", "version": "9.9.9"}
        self.assertEqual([], canonical.validate_envelope(env))

    def test_supersedes_cycle_and_revision_monotonicity(self):
        a = assessment("asm-a", CONTROL, "fail", ["ev-a"], supersedes="asm-b")
        b = assessment("asm-b", CONTROL, "fail", ["ev-a"], supersedes="asm-a")
        env = mini_envelope(
            evidence=[evidence("ev-a", CONTROL, "refutes")],
            assessments=[a, b])
        self.assert_problem(env, "supersedes cycle")
        env2 = mini_envelope()
        env2["supersedes_revision"] = 1
        self.assert_problem(env2, "supersedes_revision")

    def test_supersedes_assessment_stays_within_one_control(self):
        old = assessment("asm-old", CONTROL, "not_tested", [])
        new = assessment("asm-new", MEDIUM_CONTROL, "not_tested", [],
                         supersedes="asm-old")
        env = mini_envelope(assessments=[old, new])
        self.assert_problem(env, "same control_id")

    def test_r3_pass_needs_current_supporting_evidence(self):
        # neutral (NO_SIGNAL-class) evidence never supports a pass
        env = mini_envelope(
            evidence=[evidence("ev-n", CONTROL, "neutral")],
            assessments=[assessment("asm-p", CONTROL, "pass", ["ev-n"])])
        self.assert_problem(env, "R3")
        # expired supporting evidence never supports a pass
        env = mini_envelope(
            evidence=[evidence("ev-s", CONTROL, "supports",
                               observed_at="2026-01-01T00:00:00Z",
                               valid_until="2026-02-01T00:00:00Z")],
            assessments=[assessment("asm-p", CONTROL, "pass", ["ev-s"])])
        self.assert_problem(env, "R3")
        # current supporting evidence is fine
        env = mini_envelope(
            evidence=[evidence("ev-s", CONTROL, "supports")],
            assessments=[assessment("asm-p", CONTROL, "pass", ["ev-s"])])
        self.assertEqual([], canonical.validate_envelope(env))

    def test_r3_evidence_expiry_compares_actual_instants(self):
        # 01:00+02:00 is 23:00Z on the previous day, so this evidence is
        # already expired at the assessment despite its lexically later hour.
        supporting = evidence(
            "ev-s", CONTROL, "supports",
            observed_at="2026-08-15T22:00:00Z",
            valid_until="2026-08-16T01:00:00+02:00")
        passed = assessment(
            "asm-p", CONTROL, "pass", ["ev-s"],
            assessed_at="2026-08-16T00:00:00Z")
        self.assert_problem(
            mini_envelope(evidence=[supporting], assessments=[passed]),
            "R3")

    def test_r3_recovery_support_must_postdate_refutation(self):
        refuting = evidence(
            "ev-r", CONTROL, "refutes",
            observed_at="2026-08-16T10:00:00Z", strength="decisive")
        stale_support = evidence(
            "ev-s", CONTROL, "supports",
            observed_at="2026-08-16T09:00:00Z")
        old = assessment(
            "asm-old", CONTROL, "fail", ["ev-r"],
            assessed_at="2026-08-16T10:30:00Z")
        for status in ("partial", "pass"):
            with self.subTest(status=status):
                new = assessment(
                    "asm-new", CONTROL, status, ["ev-s"],
                    supersedes="asm-old",
                    conflicts=[{
                        "evidence_ref": "ev-r",
                        "resolution": "the affected behavior was re-tested",
                    }])
                env = mini_envelope(
                    evidence=[refuting, stale_support],
                    assessments=[old, new])
                self.assert_problem(env, "post-date")

        fresh_support = copy.deepcopy(stale_support)
        fresh_support["observed_at"] = "2026-08-16T11:00:00Z"
        recovered = assessment(
            "asm-new", CONTROL, "partial", ["ev-s"],
            supersedes="asm-old",
            conflicts=[{
                "evidence_ref": "ev-r",
                "resolution": "the affected behavior was re-tested",
            }])
        env = mini_envelope(
            evidence=[refuting, fresh_support], assessments=[old, recovered])
        self.assertEqual([], canonical.validate_envelope(env))

    def test_r4_unresolved_refutation_blocks_pass(self):
        refuting = evidence("ev-r", CONTROL, "refutes")
        supporting = evidence("ev-s", CONTROL, "supports")
        env = mini_envelope(
            evidence=[refuting, supporting],
            assessments=[assessment("asm-p", CONTROL, "pass", ["ev-s"])])
        self.assert_problem(env, "R4")
        env["assessments"][0]["conflicts"] = [
            {"evidence_ref": "ev-r", "resolution": "false positive, verified"}]
        self.assertEqual([], canonical.validate_envelope(env))

    def test_r5_screening_statuses_and_critical_acceptance(self):
        env = mini_envelope(assessments=[
            assessment("asm-a", CONTROL, "answered", [])])
        self.assert_problem(env, "R5")
        ok = mini_envelope(assessments=[
            assessment("asm-a", SCREENING, "answered", [])])
        self.assertEqual([], canonical.validate_envelope(ok))
        env = mini_envelope(assessments=[
            assessment("asm-a", CONTROL, "risk_accepted", [],
                       acceptance={"accepted_by": "x", "reason": "y",
                                   "review_by": NOW})])
        self.assert_problem(env, "R5")
        ok = mini_envelope(assessments=[
            assessment("asm-a", MEDIUM_CONTROL, "risk_accepted", [],
                       acceptance={"accepted_by": "x", "reason": "y",
                                   "review_by": NOW})])
        self.assertEqual([], canonical.validate_envelope(ok))

    def test_r6_level_follows_matrix(self):
        # matrix(major, plausible) = high
        self.assertEqual([], canonical.validate_envelope(
            mini_envelope(risks=[risk("rsk-a", "major", "plausible", "high")])))
        # raising above the matrix needs no ceremony
        self.assertEqual([], canonical.validate_envelope(
            mini_envelope(risks=[risk("rsk-a", "major", "plausible", "critical")])))
        # below the matrix without a downgrade record fails
        self.assert_problem(
            mini_envelope(risks=[risk("rsk-a", "major", "plausible", "low")]),
            "R6")

    def test_r6_unknown_in_unknown_out(self):
        self.assert_problem(
            mini_envelope(risks=[risk("rsk-a", "unknown", "plausible", "low")]),
            "unknown")
        self.assertEqual([], canonical.validate_envelope(
            mini_envelope(risks=[risk("rsk-a", "unknown", "plausible", "unknown")])))

    def test_r6_downgrade_at_most_one_step(self):
        downgrade = {"from_level": "high", "rationale": "compensating control",
                     "evidence_refs": ["ev-s"], "approved_by": "reviewer:test"}
        base = mini_envelope(evidence=[evidence("ev-s", CONTROL, "supports")])
        one = copy.deepcopy(base)
        one["risks"] = [risk("rsk-a", "major", "plausible", "moderate",
                             downgrade=downgrade)]
        self.assertEqual([], canonical.validate_envelope(one))
        two = copy.deepcopy(base)
        two["risks"] = [risk("rsk-a", "major", "plausible", "low",
                             downgrade=downgrade)]
        self.assert_problem(two, "one level")

    def test_major_version_mismatch_is_flagged(self):
        env = mini_envelope()
        env["schema_version"] = "2.0.0"
        self.assert_problem(env, "migrate")


class TestSerializationAndMigration(unittest.TestCase):
    def test_dumps_is_deterministic_regardless_of_insertion_order(self):
        a = mini_envelope(evidence=[evidence("ev-a", CONTROL, "neutral")])
        b = json.loads(json.dumps(a))  # fresh objects
        b["context"] = dict(reversed(list(b["context"].items())))
        self.assertEqual(canonical.dumps(a), canonical.dumps(b))

    def test_round_trip_preserves_unknown_fields(self):
        env = mini_envelope()
        env["x_future_field"] = {"nested": [1, 2, 3]}
        env["evidence"] = [evidence("ev-a", CONTROL, "neutral",
                                    x_unknown="preserved")]
        back = canonical.loads(canonical.dumps(env))
        self.assertEqual(env, back)
        self.assertEqual("preserved", back["evidence"][0]["x_unknown"])

    def test_unknown_and_conflicting_evidence_survive_serialization(self):
        refuting = evidence("ev-r", CONTROL, "refutes")
        supporting = evidence("ev-s", CONTROL, "supports")
        unknown_risk = risk("rsk-u", "unknown", "plausible", "unknown")
        env = mini_envelope(
            evidence=[refuting, supporting],
            assessments=[assessment(
                "asm-p", CONTROL, "partial", ["ev-s"],
                conflicts=[{"evidence_ref": "ev-r",
                            "resolution": "aspect re-verified"}])],
            risks=[unknown_risk])
        back = canonical.loads(canonical.dumps(env))
        self.assertEqual([], canonical.validate_envelope(back))
        directions = {e["evidence_id"]: e["direction"] for e in back["evidence"]}
        self.assertEqual({"ev-r": "refutes", "ev-s": "supports"}, directions)
        self.assertEqual("unknown", back["risks"][0]["level"])
        self.assertEqual("ev-r",
                         back["assessments"][0]["conflicts"][0]["evidence_ref"])

    def test_migrate_same_major_is_identity(self):
        env = mini_envelope()
        self.assertIs(env, canonical.migrate(env, "1.4.2"))

    def test_migrate_without_hook_raises(self):
        env = mini_envelope()
        env["schema_version"] = "2.0.0"
        with self.assertRaises(canonical.MigrationError):
            canonical.migrate(env, "1.0.0")

    def test_registered_hook_is_applied(self):
        def down(doc):
            doc = dict(doc)
            doc["schema_version"] = "1.0.0"
            return doc
        canonical.register_migration(2, 1, down)
        try:
            env = mini_envelope()
            env["schema_version"] = "2.0.0"
            migrated = canonical.migrate(env, "1.0.0")
            self.assertEqual("1.0.0", migrated["schema_version"])
        finally:
            canonical.MIGRATIONS.pop((2, 1), None)


class TestRedactionBounds(unittest.TestCase):
    def test_credential_shapes_are_redacted(self):
        secret = "sk_live_" + "a1b2c3d4" * 3
        out = canonical.bound_raw("const key = %r" % secret)
        self.assertNotIn(secret, out)
        self.assertIn("[REDACTED", out)

    def test_high_entropy_runs_are_redacted(self):
        blob = "A" * 60
        out = canonical.bound_raw("data: " + blob)
        self.assertNotIn(blob, out)

    def test_length_is_bounded(self):
        out = canonical.bound_raw("x. " * 4000, limit=100)
        self.assertLessEqual(len(out), 100 + len(" ...[truncated]"))
        self.assertTrue(out.endswith("...[truncated]"))


# ----------------------------------------------------------- scanner adapters

HEADER = '{"scanner":"vibecheck","version":"0.5.0"}'
WARN_LINE = ('{"check":"secrets.hardcoded","checklist_items":[7],"status":"WARN",'
             '"title":"Secret-like literals assigned in source",'
             '"evidence":"src/api.ts:12: const apiKey = \\"sk_li...[REDACTED]\\""}')
NO_SIGNAL_LINE = ('{"check":"inject.sql","checklist_items":[29],'
                  '"status":"NO_SIGNAL","title":"No string-built SQL found",'
                  '"evidence":""}')
MANUAL_LINE = ('{"check":"cost.budget_caps","checklist_items":[24],'
               '"status":"MANUAL","title":"Budget caps cannot be seen from '
               'source","evidence":""}')
ERROR_LINE = '{"scanner":"vibecheck","error":"SQL analysis failed"}'
FOOTER = '{"scanner":"vibecheck","done":true,"online_audit":false}'
STREAM = "\n".join([HEADER, WARN_LINE, NO_SIGNAL_LINE, MANUAL_LINE,
                    ERROR_LINE, FOOTER]) + "\n"


class TestScannerImportSynthetic(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.env = adapters.import_scanner_jsonl(STREAM, app_name="demo", now=NOW)

    def test_envelope_is_valid(self):
        self.assertEqual([], canonical.validate_envelope(self.env))

    def test_every_line_is_archived_as_a_signal(self):
        self.assertEqual(6, len(self.env["signals"]))
        self.assertEqual([HEADER, WARN_LINE, NO_SIGNAL_LINE, MANUAL_LINE,
                          ERROR_LINE, FOOTER],
                         [s["raw_ref"]["value"] for s in self.env["signals"]])
        for s in self.env["signals"]:
            for forbidden in ("status", "verdict", "direction", "control_status"):
                self.assertNotIn(forbidden, s)

    def test_warn_maps_to_refuting_indicative_evidence(self):
        (ev,) = [e for e in self.env["evidence"]
                 if e["claim"]["control_ids"] == [controls.CONTROL_IDS[7]]]
        self.assertEqual("refutes", ev["direction"])
        self.assertEqual("indicative", ev["strength"],
                         "a regex hit is never decisive")

    def test_no_signal_maps_to_neutral_evidence_and_never_pass(self):
        (ev,) = [e for e in self.env["evidence"]
                 if e["claim"]["control_ids"] == [controls.CONTROL_IDS[29]]]
        self.assertEqual("neutral", ev["direction"])
        self.assertNotIn("assessments", self.env)

    def test_manual_maps_to_open_verify_action_without_evidence(self):
        (act,) = self.env["actions"]
        self.assertEqual("verify", act["kind"])
        self.assertEqual("open", act["state"])
        self.assertIn("cost.budget_caps", act["reason"])
        self.assertEqual([controls.CONTROL_IDS[24]], act["control_refs"])
        self.assertEqual([], [e for e in self.env["evidence"]
                              if controls.CONTROL_IDS[24]
                              in e["claim"]["control_ids"]])

    def test_scanner_error_becomes_a_coverage_gap_signal(self):
        (sig,) = [s for s in self.env["signals"]
                  if s["raw_ref"]["value"] == ERROR_LINE]
        self.assertIn("Coverage gap", sig["notes"])

    def test_import_is_deterministic(self):
        again = adapters.import_scanner_jsonl(STREAM, app_name="demo", now=NOW)
        self.assertEqual(canonical.dumps(self.env), canonical.dumps(again))

    def test_export_is_byte_compatible(self):
        self.assertEqual(STREAM, adapters.export_scanner_jsonl(self.env))

    def test_context_defaults_to_draft_confirmation(self):
        self.assertEqual("draft", self.env["context"]["confirmation"]["state"])

    def test_unredacted_credential_in_input_is_redacted_on_import(self):
        secret = "sk_live_" + "z9y8x7w6" * 3
        leaky = ('{"check":"secrets.hardcoded","checklist_items":[7],'
                 '"status":"WARN","title":"t","evidence":"key = %s"}' % secret)
        env = adapters.import_scanner_jsonl([leaky], now=NOW)
        self.assertNotIn(secret, canonical.dumps(env))

    def test_invalid_json_line_is_rejected(self):
        with self.assertRaises(ValueError):
            adapters.import_scanner_jsonl(["not json"], now=NOW)


class TestScannerImportFixture(unittest.TestCase):
    """Acceptance: existing scanner fixtures import into a valid artifact."""

    @classmethod
    def setUpClass(cls):
        tmp = tempfile.mkdtemp(prefix="vibecheck-canonical-")
        try:
            work = os.path.join(tmp, "vulnerable-app")
            shutil.copytree(os.path.join(REPO, "tests", "fixtures",
                                         "vulnerable-app"), work)
            proc = subprocess.run(
                ["bash", os.path.join(REPO, "scripts", "vibecheck.sh"), work],
                capture_output=True, text=True, timeout=180)
            cls.stdout = proc.stdout
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        cls.env = adapters.import_scanner_jsonl(cls.stdout,
                                                app_name="vulnerable-app",
                                                now=NOW)

    def test_fixture_imports_into_a_valid_artifact(self):
        self.assertEqual([], canonical.validate_envelope(self.env))

    def test_no_signal_is_never_pass(self):
        neutral = [e for e in self.env["evidence"] if e["direction"] == "neutral"]
        self.assertTrue(neutral, "fixture run must include NO_SIGNAL results")
        self.assertNotIn("assessments", self.env)

    def test_every_finding_line_is_mapped(self):
        findings = [json.loads(line) for line in self.stdout.splitlines()
                    if line.strip() and '"check"' in line]
        findings = [f for f in findings if "check" in f]
        with_signal = [s for s in self.env["signals"]
                       if s["source"].get("check_id")]
        self.assertEqual(len(findings), len(with_signal))
        statuses = {}
        for f in findings:
            statuses[f["status"]] = statuses.get(f["status"], 0) + 1
        self.assertEqual(statuses.get("WARN", 0) + statuses.get("NO_SIGNAL", 0),
                         len(self.env["evidence"]))
        self.assertEqual(statuses.get("MANUAL", 0), len(self.env["actions"]))

    def test_export_reproduces_the_scanner_stream_byte_for_byte(self):
        self.assertEqual(self.stdout, adapters.export_scanner_jsonl(self.env))


# ------------------------------------------------------------- probe adapters

PROBE = {
    "supabase_probe": True,
    "url": "https://demo.supabase.co",
    "anon_key": "eyJh...[masked]",
    "write_probe_enabled": True,
    "tables_probed": ["orders", "profiles"],
    "confirmed_failures": 2,
    "exposures_needing_intent_review": 1,
    "unknown_results": 1,
    "not_tested": 1,
    "probe_complete": False,
    "findings": [
        {"check": "discovery", "status": "INFO", "http": 200,
         "detail": "root status 200; discovered 2 table definitions"},
        {"check": "anon_select", "table": "orders", "http": 200,
         "verdict": "REVIEW_rows_readable_by_anon", "rows_visible_to_anon": 3,
         "note": "3 row(s) visible to an unauthenticated caller"},
        {"check": "anon_select", "table": "profiles", "http": 200,
         "verdict": "NO_ROWS_VISIBLE_UNCONFIRMED", "rows_visible_to_anon": 0,
         "note": "no rows returned to anon"},
        {"check": "anon_select", "table": "legacy", "http": 500,
         "verdict": "UNKNOWN_500", "rows_visible_to_anon": None, "note": "boom"},
        {"check": "anon_select", "table": "internal", "http": 404,
         "verdict": "INFO_not_exposed", "rows_visible_to_anon": None,
         "note": "not exposed through PostgREST"},
        {"check": "anon_insert_probe", "table": "orders", "http": 201,
         "verdict": "FAIL_anon_write_succeeded", "note": ""},
        {"check": "anon_insert_probe", "table": "profiles", "http": 422,
         "verdict": "WARN_write_reached_validation", "note": ""},
        {"check": "idor", "table": "orders", "record_id": "42", "http": 200,
         "verdict": "FAIL_cross_account_read", "rows_visible_to_b": 1,
         "note": "account B could read the known A-owned record"},
        {"check": "idor", "verdict": "NOT_TESTED",
         "note": "IDOR (#13) needs two authenticated test accounts"},
    ],
}


class TestProbeImport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.env = adapters.import_supabase_probe(
            PROBE, "private_test", now=NOW, authorized_by="owner:demo")
        cls.by_direction = {}
        for e in cls.env["evidence"]:
            cls.by_direction.setdefault(e["direction"], []).append(e)

    def evidence_for(self, table, operation):
        return [e for e in self.env["evidence"]
                if e["subject"]["locator"] == table
                and e["operation"] == operation]

    def test_envelope_is_valid(self):
        self.assertEqual([], canonical.validate_envelope(self.env))

    def test_results_are_scoped_evidence_not_conclusions(self):
        # every evidence names one table (or record) subject and a
        # scope statement; none carries a status, and no assessments exist
        self.assertNotIn("assessments", self.env)
        for e in self.env["evidence"]:
            self.assertEqual("table", e["subject"]["kind"])
            self.assertTrue(e["scope"])
            self.assertIn("aspect", e["claim"])
            for forbidden in ("status", "verdict", "control_status"):
                self.assertNotIn(forbidden, e)

    def test_claims_stay_on_the_probe_controls(self):
        allowed = {controls.CONTROL_IDS[13], controls.CONTROL_IDS[14]}
        for e in self.env["evidence"]:
            self.assertTrue(set(e["claim"]["control_ids"]) <= allowed)

    def test_review_verdict_maps_to_refuting_evidence_plus_decide_action(self):
        (ev,) = self.evidence_for("orders", "http_select_anon_head")
        self.assertEqual(("refutes", "decisive"), (ev["direction"], ev["strength"]))
        self.assertIn("unestablished", ev["scope"])
        (decide,) = [a for a in self.env["actions"] if a["kind"] == "decide"]
        self.assertEqual("founder", decide["owner"]["role"])
        self.assertIn("orders", decide["outcome"])

    def test_no_rows_unconfirmed_is_neutral(self):
        (ev,) = self.evidence_for("profiles", "http_select_anon_head")
        self.assertEqual("neutral", ev["direction"])
        self.assertIn("empty", ev["scope"])

    def test_unknown_and_not_exposed_stay_neutral(self):
        for table in ("legacy", "internal"):
            (ev,) = self.evidence_for(table, "http_select_anon_head")
            self.assertEqual("neutral", ev["direction"])

    def test_anon_write_success_is_decisive_with_side_effects(self):
        (ev,) = self.evidence_for("orders", "http_insert_anon")
        self.assertEqual(("refutes", "decisive"), (ev["direction"], ev["strength"]))
        self.assertTrue(ev["side_effects"]["writes"])
        self.assertEqual("owner:demo", ev["authorization"]["authorized_by"])

    def test_write_reached_validation_is_indicative(self):
        (ev,) = self.evidence_for("profiles", "http_insert_anon")
        self.assertEqual(("refutes", "indicative"),
                         (ev["direction"], ev["strength"]))
        self.assertFalse(ev["side_effects"]["writes"])

    def test_cross_account_read_refutes_object_level_control(self):
        (ev,) = self.evidence_for("orders",
                                  "http_select_authenticated_cross_account")
        self.assertEqual(("refutes", "decisive"), (ev["direction"], ev["strength"]))
        self.assertEqual([controls.CONTROL_IDS[13]], ev["claim"]["control_ids"])

    def test_not_tested_becomes_open_verify_action(self):
        verifies = [a for a in self.env["actions"] if a["kind"] == "verify"]
        self.assertEqual(1, len(verifies))
        self.assertEqual("open", verifies[0]["state"])
        self.assertEqual([controls.CONTROL_IDS[13]], verifies[0]["control_refs"])

    def test_derivable_summary_block_is_dropped(self):
        text = canonical.dumps(self.env)
        for key in ("probe_complete", "confirmed_failures",
                    "exposures_needing_intent_review", "tables_probed"):
            self.assertNotIn(key, text)

    def test_import_is_deterministic(self):
        again = adapters.import_supabase_probe(
            PROBE, "private_test", now=NOW, authorized_by="owner:demo")
        self.assertEqual(canonical.dumps(self.env), canonical.dumps(again))

    @unittest.skipUnless(HAVE_JSONSCHEMA, "jsonschema not installed")
    def test_envelope_validates_against_json_schema(self):
        validator = Draft202012Validator(canonical.load_schema())
        self.assertEqual([], [e.message for e in validator.iter_errors(self.env)])


class TestPassVerdictIsScoped(unittest.TestCase):
    def test_idor_pass_verdict_is_supporting_but_bounded(self):
        probe = {"url": "https://demo.supabase.co", "findings": [
            {"check": "idor", "table": "orders", "record_id": "42",
             "http": 200,
             "verdict": "PASS_no_cross_account_read_of_known_private_record",
             "rows_visible_to_b": 0, "note": "account B could not read it"}]}
        env = adapters.import_supabase_probe(probe, "private_test", now=NOW)
        (ev,) = env["evidence"]
        self.assertEqual(("supports", "decisive"),
                         (ev["direction"], ev["strength"]))
        self.assertIn("not proof", ev["scope"])
        self.assertNotIn("assessments", env,
                         "a probe PASS proposes evidence, never an assessment")


# ------------------------------------------------------------ workbook export

class TestWorkbookExport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sup = evidence("ev-s", CONTROL, "supports")
        cls.env = mini_envelope(
            evidence=[sup],
            assessments=[
                assessment("asm-old", CONTROL, "fail", ["ev-s"]),
                assessment("asm-new", CONTROL, "partial", ["ev-s"],
                           supersedes="asm-old"),
                assessment("asm-acc", MEDIUM_CONTROL, "risk_accepted", [],
                           acceptance={"accepted_by": "founder:demo",
                                       "reason": "single-tenant for pilot",
                                       "review_by": "2026-12-01T00:00:00Z"}),
            ])

    def test_current_assessment_wins_over_superseded(self):
        rows = adapters.export_workbook_rows(self.env)
        self.assertEqual("Partial", rows[14]["status"])

    def test_acceptance_record_lands_in_notes(self):
        rows = adapters.export_workbook_rows(self.env)
        self.assertEqual("Accepted risk", rows[33]["status"])
        self.assertIn("founder:demo", rows[33]["notes"])
        self.assertIn("review by", rows[33]["notes"])

    def test_unassessed_items_stay_blank(self):
        rows = adapters.export_workbook_rows(self.env)
        self.assertEqual(89, len(rows))
        self.assertEqual("", rows[1]["status"],
                         "blank means not reviewed — distinct from Not tested")

    def test_estonian_wording(self):
        rows = adapters.export_workbook_rows(self.env, lang="et")
        self.assertEqual("Osaline", rows[14]["status"])
        self.assertEqual("Aktsepteeritud risk", rows[33]["status"])


if __name__ == "__main__":
    unittest.main()
