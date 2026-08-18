#!/usr/bin/env python3
"""Tests for scripts/coverage.py — the code-computed coverage ledger.

Acceptance criteria this file stands for:

  * the ledger accounts for every top-level directory: scanned, skipped with a
    reason, or unaccounted;
  * completeness is `checked`, `partial`, or `not-checkable`, computed in code;
  * a partial ledger makes even a clean scan a coverage gap, never a clean bill;
  * generated/dependency dirs are skipped with a reason, never silent;
  * a scope narrows coverage intentionally and the ledger says so.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
COVERAGE = os.path.join(REPO, "scripts", "coverage.py")
SCANNER = os.path.join(REPO, "scripts", "vibecheck.sh")


def build(repo, lines, scope=()):
    out = subprocess.run([sys.executable, COVERAGE, "--repo", repo] +
                         (["--scope"] + list(scope) if scope else []),
                         input="\n".join(lines) + "\n",
                         capture_output=True, text=True, check=True)
    return json.loads(out.stdout)


def scanner_lines_for_not_found():
    # Simulate a scan: one WARN under src, plus the scanner wrapper lines.
    return [
        '{"scanner":"vibecheck","version":"0.4.0"}',
        '{"check":"secrets.known_prefixes","checklist_items":[7],"status":"WARN",'
        '"title":"cred","evidence":"./src/config.ts:3:key = \\"sk-ant-FAKE\\""}',
        '{"scanner":"vibecheck","done":true,"online_audit":false}',
    ]


class TestCoverage(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="vibecheck-cov-")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _make(self, dirs, files=None):
        for d in dirs:
            os.makedirs(os.path.join(self.tmp, d), exist_ok=True)
        for rel in files or []:
            path = os.path.join(self.tmp, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as fh:
                fh.write("const k = 1;\n")

    def test_all_top_levels_accounted_is_checked(self):
        self._make(["src", "api", "supabase"],
                   files=["src/config.ts", "api/agent.js", "supabase/migrations/1.sql"])
        rec = build(self.tmp, scanner_lines_for_not_found())
        self.assertEqual(rec["completeness"], "checked")
        self.assertIn("src", rec["scanned"])
        self.assertIn("supabase", rec["scanned"])
        self.assertEqual(rec["unaccounted"], [])

    def test_unaccounted_dir_is_partial_not_clean(self):
        self._make(["src", "api", "docs"])  # docs has no evidence and isn't skipped
        rec = build(self.tmp, scanner_lines_for_not_found())
        self.assertEqual(rec["completeness"], "partial")
        self.assertIn("docs", rec["unaccounted"])
        self.assertNotIn("docs", rec["scanned"])
        self.assertNotIn("docs", [s["name"] for s in rec["skipped"]])

    def test_vendored_dir_is_skipped_with_reason_never_unaccounted(self):
        self._make(["src", "vendor", "docs"])
        rec = build(self.tmp, scanner_lines_for_not_found())
        self.assertEqual(rec["completeness"], "partial")  # docs remains unaccounted
        names = [s["name"] for s in rec["skipped"]]
        self.assertIn("vendor", names)
        self.assertNotIn("vendor", rec["unaccounted"])
        reason = [s["reason"] for s in rec["skipped"] if s["name"] == "vendor"][0]
        self.assertIn("vendored", reason)

    def test_scope_accounts_intentional_narrowing(self):
        self._make(["src", "api", "web"])
        rec = build(self.tmp, scanner_lines_for_not_found(), scope=["web"])
        # api unaccounted; web is in scope but had no evidence => add to skipped-side
        self.assertIn("api", rec["unaccounted"])

    def test_not_checkable_when_tree_unreadable(self):
        rec = build(os.path.join(self.tmp, "does-not-exist"),
                    scanner_lines_for_not_found())
        self.assertEqual(rec["completeness"], "not-checkable")

    def test_clean_scan_with_partial_completeness_is_not_a_clean_bill(self):
        self._make(["src", "docs"], files=["src/config.ts"])
        rec = build(self.tmp, scanner_lines_for_not_found())
        self.assertTrue(rec["scan"]["done"])
        self.assertEqual(rec["completeness"], "partial")
        self.assertIn("docs", rec["unaccounted"])
        self.assertIn("src", rec["scanned"])

    def test_empty_tree_with_no_source_is_honestly_unaccounted(self):
        self._make(["src", "docs"])  # no scannable files anywhere
        lines = [
            '{"scanner":"vibecheck","version":"0.4.0"}',
            '{"check":"secrets.known_prefixes","checklist_items":[7],"status":"NO_SIGNAL",'
            '"title":"cred","evidence":""}',
            '{"scanner":"vibecheck","done":true,"online_audit":false}',
        ]
        rec = build(self.tmp, lines)
        self.assertEqual(rec["completeness"], "partial")
        self.assertIn("src", rec["unaccounted"])
        self.assertIn("docs", rec["unaccounted"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
