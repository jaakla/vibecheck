#!/usr/bin/env python3
"""Workbook generation and gate-regression tests."""
import os
import subprocess
import sys
import tempfile
import unittest

try:
    import openpyxl
except ImportError:  # normal stdlib-only scanner test runs may omit workbook deps
    openpyxl = None


REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILDER = os.path.join(REPO, "scripts", "build_workbook.py")


@unittest.skipUnless(openpyxl, "openpyxl is required for workbook tests")
class TestWorkbookGates(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="vibecheck-workbook-")
        cls.path = os.path.join(cls.tmp.name, "reviewer.xlsx")
        subprocess.run([sys.executable, BUILDER, "--profile", "reviewer",
                        "--lang", "en", "--out", cls.path], check=True,
                       capture_output=True, text=True)
        cls.wb = openpyxl.load_workbook(cls.path, data_only=False)

    @classmethod
    def tearDownClass(cls):
        cls.wb.close()
        cls.tmp.cleanup()

    def _cells(self, sheet):
        return [cell.value for row in sheet.iter_rows() for cell in row
                if cell.value is not None]

    def test_verdict_has_no_arbitrary_percentage_release_gate(self):
        values = self._cells(self.wb["Summary"])
        verdict = next(v for v in values if isinstance(v, str)
                       and v.startswith("=IF(")
                       and "REVIEW COMPLETE - NO OPEN FAIL/PARTIAL" in v)
        self.assertNotIn("0.9", verdict)
        self.assertIn("SUMPRODUCT", verdict,
                      "unsupported Critical/High Passes must keep review incomplete")
        self.assertIn("FIX BEFORE RELEASE", verdict)

    def test_unsupported_critical_high_pass_is_visible_metric(self):
        values = self._cells(self.wb["Summary"])
        self.assertIn("Critical/High Pass without evidence", values)

    def test_workbook_requests_recalculation(self):
        self.assertEqual(self.wb.calculation.calcMode, "auto")
        self.assertTrue(self.wb.calculation.fullCalcOnLoad)
        self.assertTrue(self.wb.calculation.forceFullCalc)

    def test_verification_guide_prefers_mature_free_tools(self):
        text = "\n".join(str(v) for v in self._cells(self.wb["Verification guide"]))
        for tool in ("Gitleaks", "Semgrep Community", "OSV-Scanner",
                     "OWASP ZAP", "Playwright"):
            self.assertIn(tool, text)
        self.assertNotIn("Aikido", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
