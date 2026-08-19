#!/usr/bin/env python3
"""Tests for scripts/sarif.py — SARIF 2.1.0 output for the scanner.

Acceptance criteria this file stands for:

  * the log is valid SARIF 2.1.0 with a rules table and results;
  * NO_SIGNAL lines never become SARIF results (absent signals are not findings);
  * severity maps to SARIF level from the canonical control mapping;
  * a WARN finding with a file:line evidence prefix gets a physical location;
  * --withhold-evidence keeps a hard-coded credential line out of machine output.
"""
import json
import os
import subprocess
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SARIF = os.path.join(REPO, "scripts", "sarif.py")
SCANNER = os.path.join(REPO, "scripts", "vibecheck.sh")

import scripts.sarif as sarif  # noqa: E402


def render(lines, **kwargs):
    out = subprocess.run([sys.executable, SARIF, "--repo", "repo"] +
                         (["--withhold-evidence"] if kwargs.get("withhold") else []),
                         input="\n".join(lines) + "\n",
                         capture_output=True, text=True, check=True)
    return json.loads(out.stdout)


class TestSarif(unittest.TestCase):
    def test_version_and_tool(self):
        log = render([])
        self.assertEqual(log["version"], "2.1.0")
        driver = log["runs"][0]["tool"]["driver"]
        self.assertEqual(driver["name"], "Vibecheck static scanner")

    def test_no_signal_never_becomes_a_result(self):
        log = render([
            '{"check":"rls.missing","checklist_items":[12],"status":"NO_SIGNAL","title":"clean","evidence":""}',
        ])
        self.assertEqual(log["runs"][0]["results"], [])

    def test_warn_severity_maps_to_level_and_location(self):
        log = render([
            '{"check":"arch.handrolled_auth","checklist_items":[3],"status":"WARN",'
            '"title":"Weak primitive","evidence":"./api/db.js:12:md5"}',
        ])
        results = log["runs"][0]["results"]
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["ruleId"], "vibecheck/arch.handrolled_auth")
        self.assertEqual(results[0]["level"], "error")  # item #3 is High
        loc = results[0]["locations"][0]["physicalLocation"]
        self.assertEqual(loc["artifactLocation"]["uri"], "api/db.js")
        self.assertEqual(loc["region"]["startLine"], 12)

    def test_high_in_checklist_becomes_error(self):
        log = render([
            '{"check":"secrets.hardcoded","checklist_items":[7],"status":"WARN","title":"hardcoded","evidence":""}',
        ])
        self.assertEqual(log["runs"][0]["results"][0]["level"], "error")

    def test_severity_uses_worst_of_all_checklist_items_not_just_the_first(self):
        # config.console maps to [38, 57]: item 38 is Medium, item 57 is High.
        # The level must reflect the worst covered item, not whichever the
        # scanner happened to list first.
        log = render([
            '{"check":"config.console","checklist_items":[38,57],"status":"WARN",'
            '"title":"console logging","evidence":""}',
        ])
        self.assertEqual(log["runs"][0]["results"][0]["level"], "error")

    def test_manual_is_note(self):
        log = render([
            '{"check":"cost.budget_caps","checklist_items":[24],"status":"MANUAL","title":"budget","evidence":""}',
        ])
        self.assertEqual(log["runs"][0]["results"][0]["level"], "note")

    def test_withhold_credential_evidence(self):
        msg = '"Secret-like literals","evidence":"./src/config.ts:4:DB_PASSWORD = \\"sk-ant-FAKEVALUE\\""'
        log = render([
            '{"check":"secrets.hardcoded","checklist_items":[7],"status":"WARN","title":%s}' % msg,
        ], withhold=True)
        text = log["runs"][0]["results"][0]["message"]["text"]
        self.assertNotIn("sk-ant-", text)
        self.assertIn("withheld", text)
        # file/line still locate it
        loc = log["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        self.assertEqual(loc["artifactLocation"]["uri"], "src/config.ts")

    def test_no_withhold_leaves_redacted_evidence(self):
        log = render([
            '{"check":"rls.permissive","checklist_items":[13],"status":"WARN",'
            '"title":"perm","evidence":"./migrations/1.sql:4:using (true)"}',
        ])
        text = log["runs"][0]["results"][0]["message"]["text"]
        self.assertIn("using (true)", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
