# -*- coding: utf-8 -*-
"""External specialist tool adapters (gh issue #9, Increment 7).

The acceptance criteria this file stands for:

  * every adapter has a deterministic fixture/parser test and at least one
    failure or unknown case;
  * tool unavailable, parse failure, timeout and incomplete coverage stay
    explicit rather than turning into silence or into a pass;
  * a green tool result never becomes a control-wide pass (rule R3);
  * a claim never exceeds the provider's declared capability (rule R24);
  * secrets and raw output are redacted and bounded, never copied;
  * several providers contribute evidence to one assessment without
    overwriting each other.
"""
import io
import json
import os
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "scripts"))

import adapters  # noqa: E402
import authz  # noqa: E402
import canonical  # noqa: E402
import external_adapters as ext  # noqa: E402
import providers  # noqa: E402

NOW = "2026-08-17T12:00:00Z"
TARGET = "https://staging.example.test"

try:
    from jsonschema import Draft202012Validator
    HAVE_JSONSCHEMA = True
except ImportError:  # pragma: no cover - exercised only without the dep
    HAVE_JSONSCHEMA = False


def validate(envelope):
    """Schema errors plus R24 problems for one envelope."""
    problems = list(providers.validate_providers(envelope))
    if HAVE_JSONSCHEMA:
        validator = Draft202012Validator(canonical.load_schema())
        problems.extend("%s: %s" % ("/".join(str(part)
                                             for part in error.absolute_path),
                                    error.message)
                        for error in validator.iter_errors(envelope))
    return problems


def action_reasons(envelope):
    return " ".join(action["reason"] for action in envelope["actions"])


class EnvelopeAssertions(unittest.TestCase):
    def assertValid(self, envelope):
        self.assertEqual([], validate(envelope))

    def assertNoPassPossible(self, envelope):
        """R3: nothing a clean run produces may support a pass."""
        self.assertTrue(envelope["evidence"], "expected neutral evidence")
        for item in envelope["evidence"]:
            self.assertEqual("neutral", item["direction"])
            self.assertIn("Absence of a signal is not evidence of absence",
                          item["scope"])


# --------------------------------------------------------------- Gitleaks

GITLEAKS_FINDING = {
    "RuleID": "aws-access-token",
    "Description": "AWS Access Key",
    "File": "src/config.ts",
    "StartLine": 12,
    "Commit": "abc1234",
    "Secret": "AKIAIOSFODNN7EXAMPLE",
    "Match": "const key = 'AKIAIOSFODNN7EXAMPLE'",
}


class TestGitleaks(EnvelopeAssertions):
    def test_a_finding_becomes_scoped_refuting_evidence(self):
        env = ext.import_gitleaks_json(json.dumps([GITLEAKS_FINDING]), now=NOW)
        self.assertValid(env)
        self.assertEqual(1, len(env["evidence"]))
        item = env["evidence"][0]
        self.assertEqual("refutes", item["direction"])
        self.assertEqual("indicative", item["strength"])
        self.assertEqual("git_history_scan", item["operation"])
        self.assertEqual("prov-gitleaks", item["provider"]["provider_ref"])
        self.assertEqual({"kind": "file", "locator": "src/config.ts"},
                         item["subject"])
        self.assertIn("abc1234", item["scope"])

    def test_the_secret_itself_never_enters_the_envelope(self):
        env = ext.import_gitleaks_json(json.dumps([GITLEAKS_FINDING]), now=NOW)
        serialized = json.dumps(env)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", serialized)
        self.assertNotIn("Secret", serialized)
        self.assertIn("aws-access-token", serialized)

    def test_a_history_hit_claims_history_and_a_frontend_path_adds_the_bundle(self):
        history_only = ext.import_gitleaks_json(
            json.dumps([{"RuleID": "generic-passphrase",
                         "File": "ops/notes.txt", "StartLine": 3}]), now=NOW)
        self.assertEqual(["vibecheck.control.secrets.no_repo_history_leaks"],
                         history_only["evidence"][0]["claim"]["control_ids"])
        frontend = ext.import_gitleaks_json(json.dumps([GITLEAKS_FINDING]),
                                            now=NOW)
        self.assertEqual(
            ["vibecheck.control.secrets.no_client_provider_keys",
             "vibecheck.control.secrets.no_frontend_literals",
             "vibecheck.control.secrets.no_repo_history_leaks"],
            sorted(frontend["evidence"][0]["claim"]["control_ids"]))

    def test_a_clean_run_is_neutral_and_can_never_support_a_pass(self):
        env = ext.import_gitleaks_json("[]", now=NOW)
        self.assertValid(env)
        self.assertNoPassPossible(env)
        self.assertEqual([], env["actions"])

    def test_unparseable_output_produces_no_evidence_and_an_open_action(self):
        env = ext.import_gitleaks_json("not json at all{{{", now=NOW)
        self.assertValid(env)
        self.assertEqual([], env["evidence"])
        self.assertEqual(1, len(env["actions"]))
        action = env["actions"][0]
        self.assertEqual("open", action["state"])
        self.assertEqual("verify", action["kind"])
        self.assertIn("not valid JSON", action["reason"])
        self.assertIn("vibecheck.control.secrets.no_repo_history_leaks",
                      action["control_refs"])

    def test_a_timeout_keeps_its_partial_findings_and_the_gap(self):
        env = ext.import_gitleaks_json(
            json.dumps([GITLEAKS_FINDING]), now=NOW,
            run=ext.run_record(command=["gitleaks", "detect"], timed_out=True))
        self.assertValid(env)
        self.assertEqual(1, len(env["evidence"]))
        self.assertEqual(1, len(env["actions"]))
        reason = env["actions"][0]["reason"]
        self.assertIn("timed out", reason)
        self.assertIn("1 finding(s)", reason)
        self.assertIn("gitleaks detect", reason)

    def test_the_command_travels_with_the_evidence(self):
        env = ext.import_gitleaks_json(
            "[]", now=NOW,
            run=ext.run_record(command=["gitleaks", "detect", "--log-opts",
                                        "--all"]))
        self.assertIn("gitleaks detect --log-opts --all",
                      env["evidence"][0]["scope"])


# ------------------------------------------------------------- TruffleHog

class TestTruffleHog(EnvelopeAssertions):
    def test_a_verified_hit_says_so_in_its_scope(self):
        line = json.dumps({
            "DetectorName": "AWS",
            "Verified": True,
            "SourceMetadata": {"Data": {"Git": {"commit": "c0ffee",
                                                "file": "deploy/keys.env"}}},
            "Raw": "AKIA1234567890ABCDEF",
        })
        env = ext.import_trufflehog_json(line, now=NOW)
        self.assertValid(env)
        self.assertEqual("refutes", env["evidence"][0]["direction"])
        self.assertIn("verified against the provider: yes",
                      env["evidence"][0]["scope"])
        self.assertNotIn("AKIA1234567890ABCDEF", json.dumps(env))

    def test_several_json_lines_become_several_findings(self):
        stream = "\n".join(json.dumps({"DetectorName": name,
                                       "SourceMetadata": {}})
                           for name in ("AWS", "Stripe", "Slack"))
        env = ext.import_trufflehog_json(stream, now=NOW)
        self.assertValid(env)
        self.assertEqual(3, len(env["evidence"]))

    def test_empty_output_is_the_clean_run(self):
        env = ext.import_trufflehog_json("", now=NOW)
        self.assertValid(env)
        self.assertNoPassPossible(env)

    def test_lines_that_do_not_parse_are_counted_not_dropped(self):
        stream = json.dumps({"DetectorName": "AWS", "SourceMetadata": {}}) \
            + "\nthis line is not json\n"
        env = ext.import_trufflehog_json(stream, now=NOW)
        self.assertValid(env)
        self.assertEqual(1, len(env["evidence"]))
        self.assertIn("1 line(s) of the output did not parse",
                      action_reasons(env))

    def test_a_cancelled_run_is_reported_as_cancelled(self):
        env = ext.import_trufflehog_json(
            "", now=NOW, run=ext.run_record(cancelled=True))
        self.assertValid(env)
        self.assertEqual([], env["evidence"])
        self.assertIn("was cancelled", action_reasons(env))


# ------------------------------------------------------------ OSV-Scanner

OSV_REPORT = {
    "results": [{
        "source": {"path": "package-lock.json"},
        "packages": [{
            "package": {"name": "lodash", "version": "4.17.15"},
            "vulnerabilities": [{"id": "GHSA-p6mc-m468-83gw",
                                 "summary": "Prototype pollution"}],
        }],
    }]
}


class TestOSVScanner(EnvelopeAssertions):
    def test_an_advisory_becomes_evidence_about_the_package(self):
        env = ext.import_osv_scanner_json(json.dumps(OSV_REPORT), now=NOW)
        self.assertValid(env)
        item = env["evidence"][0]
        self.assertEqual("refutes", item["direction"])
        self.assertEqual({"kind": "dependency", "locator": "lodash@4.17.15"},
                         item["subject"])
        self.assertEqual(["vibecheck.control.deps.vuln_scanning"],
                         item["claim"]["control_ids"])
        self.assertIn("reaches the vulnerable code", item["scope"])
        self.assertTrue(item["side_effects"]["data_egress"])

    def test_an_advisory_is_not_a_statement_about_dependency_trust(self):
        env = ext.import_osv_scanner_json(json.dumps(OSV_REPORT), now=NOW)
        claimed = {control
                   for item in env["evidence"]
                   for control in item["claim"]["control_ids"]}
        self.assertNotIn("vibecheck.control.deps.dependency_trust", claimed)

    def test_a_clean_audit_is_neutral(self):
        env = ext.import_osv_scanner_json('{"results": []}', now=NOW)
        self.assertValid(env)
        self.assertNoPassPossible(env)

    def test_a_reported_error_produces_no_evidence(self):
        env = ext.import_osv_scanner_json(
            '{"error": "failed to read lockfile"}', now=NOW)
        self.assertValid(env)
        self.assertEqual([], env["evidence"])
        self.assertIn("failed to read lockfile", action_reasons(env))


# ------------------------------------------------------------------ Trivy

class TestTrivy(EnvelopeAssertions):
    def test_vulnerabilities_and_licences_are_kept_apart(self):
        report = {"Results": [{
            "Target": "package-lock.json",
            "Vulnerabilities": [{"VulnerabilityID": "CVE-2021-23337",
                                 "PkgName": "lodash",
                                 "InstalledVersion": "4.17.15",
                                 "Severity": "HIGH",
                                 "Title": "Command injection"}],
            "Licenses": [{"Name": "GPL-3.0", "PkgName": "some-lib",
                          "Severity": "HIGH"}],
        }]}
        env = ext.import_trivy_json(json.dumps(report), now=NOW)
        self.assertValid(env)
        claims = [item["claim"]["control_ids"] for item in env["evidence"]]
        self.assertIn(["vibecheck.control.deps.vuln_scanning"], claims)
        self.assertIn(["vibecheck.control.deps.license_compatibility"], claims)

    def test_a_clean_scan_is_neutral(self):
        env = ext.import_trivy_json('{"Results": []}', now=NOW)
        self.assertValid(env)
        self.assertNoPassPossible(env)

    def test_no_output_at_all_is_a_failure_not_a_clean_scan(self):
        env = ext.import_trivy_json("", now=NOW)
        self.assertValid(env)
        self.assertEqual([], env["evidence"])
        self.assertIn("no output", action_reasons(env))


# ---------------------------------------------------------------- Semgrep

class TestSemgrep(EnvelopeAssertions):
    def test_a_rule_is_mapped_to_the_control_it_is_about(self):
        report = {"results": [
            {"check_id": "javascript.express.security.sqli.express-sqli",
             "path": "src/db.js",
             "extra": {"message": "Detected SQL statement built from user "
                                  "input", "severity": "ERROR"}},
            {"check_id": "javascript.browser.security.raw-html-format",
             "path": "src/render.js",
             "extra": {"message": "Detected XSS via innerHTML"}},
        ]}
        env = ext.import_semgrep_json(json.dumps(report), now=NOW)
        self.assertValid(env)
        self.assertEqual(
            [["vibecheck.control.input.sql_parameterized"],
             ["vibecheck.control.input.output_encoding"]],
            [item["claim"]["control_ids"] for item in env["evidence"]])

    def test_static_analysis_never_carries_a_coverage_cell(self):
        report = {"results": [{"check_id": "sqli", "path": "src/db.js",
                               "extra": {"message": "sql injection"}}]}
        env = ext.import_semgrep_json(json.dumps(report), now=NOW)
        self.assertValid(env)
        for item in env["evidence"]:
            self.assertNotIn("coverage", item)
            self.assertIn("fills no authorization coverage cell", item["scope"])

    def test_an_unmappable_rule_becomes_a_triage_action_not_a_claim(self):
        report = {"results": [{"check_id": "python.lang.best-practice.pointless-"
                                           "string-statement",
                               "path": "app/util.py",
                               "extra": {"message": "Pointless string"}}]}
        env = ext.import_semgrep_json(json.dumps(report), now=NOW)
        self.assertValid(env)
        self.assertEqual([], env["evidence"])
        self.assertEqual(1, len(env["actions"]))
        self.assertIn("cannot map that rule to a control",
                      env["actions"][0]["reason"])

    def test_a_clean_scan_is_neutral(self):
        env = ext.import_semgrep_json('{"results": []}', now=NOW)
        self.assertValid(env)
        self.assertNoPassPossible(env)

    def test_a_nonzero_exit_with_findings_is_not_a_failure(self):
        report = {"results": [{"check_id": "sqli", "path": "a.js",
                               "extra": {"message": "sql injection"}}]}
        env = ext.import_semgrep_json(json.dumps(report), now=NOW,
                                      run=ext.run_record(exit_code=1))
        self.assertValid(env)
        self.assertEqual(1, len(env["evidence"]))
        self.assertEqual([], env["actions"])


# ----------------------------------------------------------------- CodeQL

class TestCodeQL(EnvelopeAssertions):
    def test_a_sarif_result_becomes_evidence_about_its_file(self):
        sarif = {"version": "2.1.0", "runs": [{"results": [{
            "ruleId": "js/sql-injection",
            "message": {"text": "This query depends on a user-provided value."},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "api/query.js"}}}],
        }]}]}
        env = ext.import_codeql_sarif(json.dumps(sarif), now=NOW)
        self.assertValid(env)
        item = env["evidence"][0]
        self.assertEqual("refutes", item["direction"])
        self.assertEqual({"kind": "file", "locator": "api/query.js"},
                         item["subject"])
        self.assertEqual(["vibecheck.control.input.sql_parameterized"],
                         item["claim"]["control_ids"])

    def test_codeql_cannot_claim_a_control_semgrep_declares_and_it_does_not(self):
        # The debug-flag control is Semgrep's, not CodeQL's. A rule whose text
        # matches it must not become a claim this provider never declared.
        sarif = {"version": "2.1.0", "runs": [{"results": [
            {"ruleId": "js/debug-mode-enabled",
             "message": {"text": "Debug logging is enabled"}}]}]}
        env = ext.import_codeql_sarif(json.dumps(sarif), now=NOW)
        self.assertValid(env)
        self.assertEqual([], env["evidence"])
        self.assertIn("cannot map that rule", action_reasons(env))

    def test_a_clean_sarif_is_neutral(self):
        env = ext.import_codeql_sarif(
            '{"version": "2.1.0", "runs": [{"results": []}]}', now=NOW)
        self.assertValid(env)
        self.assertNoPassPossible(env)

    def test_a_failed_build_is_a_gap(self):
        env = ext.import_codeql_sarif(
            "", now=NOW,
            run=ext.run_record(command=["codeql", "database", "create"],
                               exit_code=32, error="build failed"))
        self.assertValid(env)
        self.assertEqual([], env["evidence"])
        self.assertIn("build failed", action_reasons(env))


# -------------------------------------------------------------- OWASP ZAP

ZAP_REPORT = {"site": [{
    "@name": TARGET,
    "alerts": [{"pluginid": "10098", "alert": "Cross-Domain Misconfiguration",
                "riskdesc": "Medium", "confidence": "Medium"}],
}]}


class TestOwaspZap(EnvelopeAssertions):
    def test_an_alert_becomes_evidence_naming_its_target_and_authorization(self):
        env = ext.import_owasp_zap_json(json.dumps(ZAP_REPORT), TARGET,
                                        "security-lead", now=NOW)
        self.assertValid(env)
        item = env["evidence"][0]
        self.assertEqual("dast_web_scan", item["operation"])
        self.assertEqual("security-lead", item["authorization"]["authorized_by"])
        self.assertIn(TARGET, item["authorization"]["scope"])
        self.assertEqual(["vibecheck.control.deploy.cors_restricted"],
                         item["claim"]["control_ids"])

    def test_a_scan_with_no_named_target_is_refused(self):
        with self.assertRaises(ValueError):
            ext.import_owasp_zap_json(json.dumps(ZAP_REPORT), "",
                                      "security-lead", now=NOW)

    def test_a_scan_with_no_recorded_authorization_is_refused(self):
        with self.assertRaises(ValueError):
            ext.import_owasp_zap_json(json.dumps(ZAP_REPORT), TARGET, None,
                                      now=NOW)

    def test_a_dast_alert_never_fills_an_authorization_cell(self):
        report = {"site": [{"alerts": [
            {"pluginid": "10038", "alert": "Directory Browsing",
             "riskdesc": "Medium"}]}]}
        env = ext.import_owasp_zap_json(json.dumps(report), TARGET, "sec",
                                        now=NOW)
        self.assertValid(env)
        item = env["evidence"][0]
        self.assertEqual(["vibecheck.control.authz.anon_data_access"],
                         item["claim"]["control_ids"])
        self.assertNotIn("coverage", item)

    def test_a_quiet_baseline_scan_is_neutral_and_says_what_it_missed(self):
        env = ext.import_owasp_zap_json('{"site": []}', TARGET, "sec", now=NOW)
        self.assertValid(env)
        self.assertNoPassPossible(env)

    def test_an_unreachable_target_produces_no_evidence(self):
        env = ext.import_owasp_zap_json(
            "", TARGET, "sec", now=NOW,
            run=ext.run_record(command=["zap-baseline.py", "-t", TARGET],
                               error="connection refused"))
        self.assertValid(env)
        self.assertEqual([], env["evidence"])
        self.assertIn("connection refused", action_reasons(env))


# -------------------------------------------------------------- Playwright

def spec(**overrides):
    case = {"title": "account B cannot read account A's order",
            "status": "passed",
            "actor": "other_account",
            "operation": "read",
            "object_ref": "/api/orders/A-1001",
            "object_class": "user_owned_record"}
    case.update(overrides)
    return case


class TestPlaywright(EnvelopeAssertions):
    def test_a_passing_refusal_assertion_covers_exactly_one_cell(self):
        env = ext.import_playwright_json(json.dumps([spec()]), TARGET,
                                         "qa-lead", now=NOW)
        self.assertValid(env)
        item = env["evidence"][0]
        self.assertEqual("supports", item["direction"])
        self.assertEqual("decisive", item["strength"])
        self.assertEqual("browser_two_account_flow", item["operation"])
        self.assertEqual(1, len(item["coverage"]))
        self.assertEqual(
            {"object_ref": "/api/orders/A-1001", "actor": "other_account",
             "operation": "read", "observed": "denied",
             "object_class": "user_owned_record",
             "environment": "private_test"},
            {key: value for key, value in item["coverage"][0].items()
             if key != "note"})

    def test_a_failing_refusal_assertion_refutes_and_records_allowed(self):
        env = ext.import_playwright_json(json.dumps([spec(status="failed")]),
                                         TARGET, "qa-lead", now=NOW)
        self.assertValid(env)
        item = env["evidence"][0]
        self.assertEqual("refutes", item["direction"])
        self.assertEqual("allowed", item["coverage"][0]["observed"])

    def test_a_timed_out_assertion_is_inconclusive_never_denied(self):
        env = ext.import_playwright_json(json.dumps([spec(status="timedOut")]),
                                         TARGET, "qa-lead", now=NOW)
        self.assertValid(env)
        item = env["evidence"][0]
        self.assertEqual("neutral", item["direction"])
        self.assertEqual("indicative", item["strength"])
        self.assertNotIn("coverage", item)
        self.assertIn("the observation was inconclusive", item["scope"])

    def test_an_assertion_that_names_no_object_fills_no_cell(self):
        env = ext.import_playwright_json(
            json.dumps([spec(object_ref=None)]), TARGET, "qa-lead", now=NOW)
        self.assertValid(env)
        item = env["evidence"][0]
        self.assertNotIn("coverage", item)
        self.assertEqual("indicative", item["strength"])
        self.assertIn("does not name the object it touched", item["scope"])

    def test_an_expected_allowed_assertion_is_read_the_other_way_round(self):
        env = ext.import_playwright_json(
            json.dumps([spec(title="the owner can read their own order",
                             actor="other_account", expects="allowed")]),
            TARGET, "qa-lead", now=NOW)
        self.assertValid(env)
        self.assertEqual("allowed", env["evidence"][0]["coverage"][0]["observed"])
        self.assertEqual("refutes", env["evidence"][0]["direction"])

    def test_an_assertion_with_no_actor_is_a_core_flow_test(self):
        env = ext.import_playwright_json(
            json.dumps([{"title": "checkout completes", "status": "passed"}]),
            TARGET, "qa-lead", now=NOW)
        self.assertValid(env)
        item = env["evidence"][0]
        self.assertEqual(["vibecheck.control.testing.core_flow_tests"],
                         item["claim"]["control_ids"])
        self.assertNotIn("coverage", item)

    def test_the_playwright_json_reporter_shape_is_accepted(self):
        report = {"suites": [{"title": "authz", "suites": [{
            "title": "orders",
            "specs": [{"title": "cross-account read is refused",
                       "actor": "other_account", "operation": "read",
                       "object_ref": "public.orders",
                       "object_class": "user_owned_record",
                       "tests": [{"status": "expected"}]}],
        }]}]}
        env = ext.import_playwright_json(json.dumps(report), TARGET, "qa-lead",
                                         now=NOW)
        self.assertValid(env)
        self.assertEqual(1, len(env["evidence"]))
        self.assertEqual("denied", env["evidence"][0]["coverage"][0]["observed"])

    def test_a_write_assertion_records_the_effect_it_had(self):
        env = ext.import_playwright_json(
            json.dumps([spec(operation="delete", status="passed")]), TARGET,
            "qa-lead", now=NOW)
        self.assertValid(env)
        effects = env["evidence"][0]["side_effects"]
        self.assertTrue(effects["writes"])
        self.assertTrue(effects["destructive"])

    def test_the_cell_it_fills_reaches_the_coverage_model_as_one_cell(self):
        objects = [{"object_id": "obj-orders", "locator": "public.orders",
                    "object_class": "user_owned_record", "intent": "private",
                    "description": "One customer's order.",
                    "source": "founder:mari", "state": "confirmed"}]
        env = ext.import_playwright_json(
            json.dumps([spec(object_ref="public.orders",
                             object_id="obj-orders")]),
            TARGET, "qa-lead", now=NOW, authorization_objects=objects)
        self.assertValid(env)
        self.assertEqual([], authz.validate_coverage(env))
        state = authz.coverage_state(
            env, "vibecheck.control.authz.object_level", "private_test")
        # One denied read is one cell out of four, so the strongest available
        # status is partial and the other three operations stay named gaps.
        self.assertEqual("partial", state["state"])
        self.assertEqual(1, state["satisfied_count"])
        self.assertEqual(4, state["required_count"])
        self.assertEqual({"create", "update", "delete"},
                         {gap["operation"] for gap in state["gaps"]})

    def test_a_static_adapter_carrying_a_cell_would_be_refused_by_r20(self):
        # The structural half of "source analysis fills no cell": the three
        # operations these adapters use are the ones authz refuses outright.
        for operation in ("git_history_scan", "dependency_audit",
                          "sast_code_scan"):
            self.assertIn(operation, authz.STATIC_OPERATIONS)

    def test_a_run_against_an_unnamed_target_is_refused(self):
        with self.assertRaises(ValueError):
            ext.import_playwright_json("[]", None, "qa-lead", now=NOW)
        with self.assertRaises(ValueError):
            ext.import_playwright_json("[]", TARGET, None, now=NOW)

    def test_a_browser_that_will_not_launch_produces_no_evidence(self):
        env = ext.import_playwright_json(
            "", TARGET, "qa-lead", now=NOW,
            run=ext.run_record(error="browser launch failed"))
        self.assertValid(env)
        self.assertEqual([], env["evidence"])
        self.assertIn("browser launch failed", action_reasons(env))


# ---------------------------------------------------- availability of tools

class TestAvailability(unittest.TestCase):
    def test_availability_is_read_from_the_registry_not_guessed(self):
        self.assertEqual(["gitleaks"], ext.required_tools(ext.GITLEAKS_PROVIDER))
        self.assertEqual(["zap.sh"], ext.required_tools(ext.ZAP_PROVIDER))

    def test_a_missing_tool_is_reported_as_missing(self):
        status = ext.tool_availability(ext.SEMGREP_PROVIDER,
                                       path_lookup=lambda name: None)
        self.assertFalse(status["available"])
        self.assertEqual(["semgrep"], status["missing_tools"])

    def test_an_installed_tool_is_reported_as_available(self):
        status = ext.tool_availability(ext.SEMGREP_PROVIDER,
                                       path_lookup=lambda name: "/usr/bin/" + name)
        self.assertTrue(status["available"])
        self.assertEqual([], status["missing_tools"])

    def test_every_external_provider_is_in_the_report(self):
        report = ext.availability_report(path_lookup=lambda name: None)
        self.assertEqual(8, len(report))
        self.assertTrue(all(entry["detect"] for entry in report))

    def test_an_unavailable_tool_is_a_recorded_gap_with_no_evidence(self):
        env = ext.import_tool_unavailable(ext.GITLEAKS_PROVIDER, now=NOW,
                                          missing_tools=["gitleaks"])
        self.assertEqual([], validate(env))
        self.assertEqual([], env["evidence"])
        self.assertEqual([], env["signals"])
        self.assertEqual(1, len(env["actions"]))
        action = env["actions"][0]
        self.assertEqual("open", action["state"])
        self.assertIn("not installed", action["reason"])
        self.assertIn("does not install tools", action["reason"])
        self.assertIn("vibecheck.control.secrets.no_repo_history_leaks",
                      action["control_refs"])
        self.assertEqual(["prov-gitleaks"],
                         [record["provider_id"] for record in env["providers"]])


# ------------------------------------------------------ capability boundary

class TestCapabilityBoundary(unittest.TestCase):
    """R24: an adapter cannot claim what its provider never declared."""

    def test_a_claim_is_intersected_with_the_declared_coverage(self):
        self.assertIsNone(ext._claim_within(ext.CODEQL_PROVIDER, [42]))
        claim = ext._claim_within(ext.CODEQL_PROVIDER, [29, 42])
        self.assertEqual(["vibecheck.control.input.sql_parameterized"],
                         claim["control_ids"])

    def test_every_adapter_stamps_the_capability_it_exercised(self):
        envelopes = [
            ext.import_gitleaks_json(json.dumps([GITLEAKS_FINDING]), now=NOW),
            ext.import_trufflehog_json(
                json.dumps({"DetectorName": "AWS", "SourceMetadata": {}}),
                now=NOW),
            ext.import_osv_scanner_json(json.dumps(OSV_REPORT), now=NOW),
            ext.import_trivy_json('{"Results": []}', now=NOW),
            ext.import_semgrep_json(
                '{"results": [{"check_id": "sqli", "path": "a.js",'
                ' "extra": {"message": "sql injection"}}]}', now=NOW),
            ext.import_codeql_sarif(
                '{"version": "2.1.0", "runs": [{"results": []}]}', now=NOW),
            ext.import_owasp_zap_json(json.dumps(ZAP_REPORT), TARGET, "sec",
                                      now=NOW),
            ext.import_playwright_json(json.dumps([spec()]), TARGET, "qa",
                                       now=NOW),
        ]
        for env in envelopes:
            with self.subTest(assessment=env["assessment_id"]):
                self.assertEqual([], validate(env))
                self.assertTrue(env.get("providers"))

    def test_no_adapter_ever_produces_an_assessment(self):
        env = ext.import_playwright_json(json.dumps([spec()]), TARGET, "qa",
                                         now=NOW)
        self.assertNotIn("assessments", env)

    def test_raw_values_are_bounded(self):
        long_message = "x" * 9000
        env = ext.import_semgrep_json(json.dumps({"results": [
            {"check_id": "sqli", "path": "a.js",
             "extra": {"message": "sql injection " + long_message}}]}), now=NOW)
        self.assertEqual([], validate(env))
        for item in env["evidence"]:
            self.assertLessEqual(len(item["raw_result_ref"]["value"]),
                                 canonical.MAX_RAW_EVIDENCE + 32)
        for signal in env["signals"]:
            self.assertLessEqual(len(signal["raw_ref"]["value"]),
                                 canonical.MAX_RAW_SIGNAL + 32)


# ------------------------------------------------------ selection interplay

class TestSelectionSeesTheAdapters(unittest.TestCase):
    """Acceptance: selection compares the adapters on coverage, authorization,
    environment, cost, egress and side effects."""

    def _offer(self, **overrides):
        base = dict(environment="developer_only", targets=["source_tree"],
                    tools=["semgrep", "codeql", "gitleaks"],
                    authorized_providers="all")
        base.update(overrides)
        return providers.offer(**base)

    def test_an_installed_specialist_tool_outranks_the_human_review(self):
        plan = providers.select(
            providers.requirement("vibecheck.control.secrets."
                                  "no_repo_history_leaks", "developer_only"),
            self._offer())
        self.assertEqual(["prov-gitleaks"], plan["selected"])

    def test_an_uninstalled_specialist_tool_is_a_gap_naming_the_install(self):
        plan = providers.select(
            providers.requirement("vibecheck.control.secrets."
                                  "no_repo_history_leaks", "developer_only"),
            self._offer(tools=[]))
        self.assertEqual(["prov-code-policy-review"], plan["selected"])
        gap = next(gap for gap in plan["gaps"]
                   if gap["provider_id"] == "prov-gitleaks")
        self.assertEqual(["tool_unavailable"],
                         [c["kind"] for c in gap["constraints"]])
        self.assertEqual("install gitleaks", gap["constraints"][0]["grant"])

    def test_compute_cost_excludes_the_expensive_analyzer(self):
        plan = providers.select(
            providers.requirement("vibecheck.control.input.sql_parameterized",
                                  "developer_only"),
            self._offer())
        self.assertEqual(["prov-semgrep-ce"], plan["selected"])
        gap = next(gap for gap in plan["gaps"]
                   if gap["provider_id"] == "prov-codeql")
        self.assertIn("compute", json.dumps(gap["constraints"]))

    def test_unauthorized_egress_excludes_the_dependency_auditor(self):
        plan = providers.select(
            providers.requirement("vibecheck.control.deps.vuln_scanning",
                                  "developer_only"),
            self._offer(tools=["osv-scanner"]))
        self.assertNotIn("prov-osv-scanner", plan["selected"])
        gap = next(gap for gap in plan["gaps"]
                   if gap["provider_id"] == "prov-osv-scanner")
        self.assertIn("egress", json.dumps(gap))

    def test_a_dast_scanner_is_inapplicable_without_a_deployment(self):
        plan = providers.select(
            providers.requirement("vibecheck.control.deploy.cors_restricted",
                                  "developer_only"),
            self._offer())
        summary = next(entry for entry in plan["ranking"]
                       if entry["provider_id"] == "prov-owasp-zap")
        self.assertFalse(summary["applicable"])


# --------------------------------------------------------------- end to end

class TestMultiProviderAssessment(unittest.TestCase):
    """Acceptance: several providers contribute to one assessment without
    overwriting each other."""

    def setUp(self):
        self.envelope = adapters.import_scanner_jsonl(
            ['{"check": "SCAN01", "status": "WARN", '
             '"title": "possible hardcoded secret", "checklist_items": [7]}'],
            now=NOW)
        parts = [
            ext.import_gitleaks_json(json.dumps([GITLEAKS_FINDING]), now=NOW),
            ext.import_osv_scanner_json(json.dumps(OSV_REPORT), now=NOW),
            ext.import_semgrep_json(json.dumps({"results": [
                {"check_id": "js.sqli", "path": "src/db.js",
                 "extra": {"message": "SQL injection"}}]}), now=NOW),
            ext.import_owasp_zap_json(json.dumps(ZAP_REPORT), TARGET, "sec",
                                      environment="developer_only", now=NOW),
            ext.import_playwright_json(json.dumps([spec()]), TARGET, "qa-lead",
                                       environment="developer_only", now=NOW),
            ext.import_tool_unavailable(ext.TRIVY_PROVIDER, now=NOW,
                                        missing_tools=["trivy"]),
        ]
        for part in parts:
            self.envelope["signals"].extend(part["signals"])
            self.envelope["evidence"].extend(part["evidence"])
            self.envelope["actions"].extend(part["actions"])
            known = {record["provider_id"]
                     for record in self.envelope.get("providers") or []}
            for record in part.get("providers") or []:
                if record["provider_id"] not in known:
                    self.envelope.setdefault("providers", []).append(record)

    def test_every_provider_keeps_its_own_evidence(self):
        by_provider = {}
        for item in self.envelope["evidence"]:
            by_provider.setdefault(item["provider"]["provider_ref"],
                                   []).append(item)
        self.assertEqual(
            {"prov-static-scanner", "prov-gitleaks", "prov-osv-scanner",
             "prov-semgrep-ce", "prov-owasp-zap",
             "prov-playwright-two-account"},
            set(by_provider))
        self.assertTrue(all(len(items) == 1 for items in by_provider.values()))

    def test_identifiers_do_not_collide_across_providers(self):
        for key, field in (("evidence", "evidence_id"), ("signals", "signal_id"),
                           ("actions", "action_id")):
            ids = [obj[field] for obj in self.envelope[key]]
            self.assertEqual(len(ids), len(set(ids)), key)

    def test_the_combined_assessment_validates_and_stays_in_capability(self):
        self.assertEqual([], validate(self.envelope))

    def test_the_missing_tool_stays_visible_next_to_the_results(self):
        reasons = action_reasons(self.envelope)
        self.assertIn("trivy is not installed", reasons)

    def test_nothing_in_the_combined_assessment_supports_a_pass_by_itself(self):
        # Only the Playwright refusal supports anything, and only for the one
        # cell it names — everything else is refuting or neutral.
        supporting = [item for item in self.envelope["evidence"]
                      if item["direction"] == "supports"]
        self.assertEqual(1, len(supporting))
        self.assertEqual(1, len(supporting[0]["coverage"]))

# -------------------------------------------------------------------- CLI

class TestCli(unittest.TestCase):
    """The CLI must not invent an invocation from the report filename."""

    def _import(self, extra_argv):
        handle = tempfile.NamedTemporaryFile(
            "w", suffix=".json", delete=False, encoding="utf-8")
        try:
            handle.write("[]")
            handle.close()
            captured = io.StringIO()
            argv = ["--import", "gitleaks", handle.name] + extra_argv
            old = sys.stdout
            try:
                sys.stdout = captured
                code = ext._cli(argv)
            finally:
                sys.stdout = old
            self.assertEqual(0, code)
            env = json.loads(captured.getvalue())
            return env, os.path.basename(handle.name)
        finally:
            os.unlink(handle.name)

    def test_omitted_command_does_not_invent_provenance_from_the_filename(self):
        env, filename = self._import([])
        scope = env["evidence"][0]["scope"]
        self.assertIn("command not recorded", scope)
        self.assertNotIn(filename, scope)

    def test_provided_command_still_travels_in_the_evidence_scope(self):
        command = ("gitleaks detect --source . --log-opts --all "
                   "--report-format json --redact")
        env, _filename = self._import(["--command", command])
        self.assertIn(command, env["evidence"][0]["scope"])



if __name__ == "__main__":
    unittest.main()
