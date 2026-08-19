# -*- coding: utf-8 -*-
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import fault_probe
import gen_playwright_suite


class TestFaultProbe(unittest.TestCase):

    def test_capability_record(self):
        cap = fault_probe.capability_record()
        self.assertEqual("prov-fault-probe", cap["provider_id"])
        self.assertTrue(cap["availability"]["bundled"])
        control_ids = [c["control_id"] for c in cap["coverage"]]
        self.assertIn("vibecheck.control.obs.no_stack_traces", control_ids)
        self.assertIn("vibecheck.control.obs.error_tracking", control_ids)

    def test_leak_detection_node_stack(self):
        body = """
        Error: Cannot find module './missing'
            at Function.Module._resolveFilename (internal/modules/cjs/loader.js:880:15)
            at Function.Module._load (internal/modules/cjs/loader.js:725:27)
        """
        leaks = fault_probe.analyze_response_for_leaks(500, body)
        self.assertTrue(len(leaks) > 0)
        self.assertIn("stack trace", leaks[0]["type"].lower())

    def test_leak_detection_python_traceback(self):
        body = """
        Traceback (most recent call last):
          File "/app/server.py", line 42, in handle_request
            raise ValueError("bad input")
        ValueError: bad input
        """
        leaks = fault_probe.analyze_response_for_leaks(500, body)
        self.assertTrue(len(leaks) > 0)
        types = [l["type"] for l in leaks]
        self.assertTrue(any("Python traceback" in t for t in types))

    def test_leak_detection_sql_syntax(self):
        body = '{"error": "syntax error at or near \\"SELECT\\": pg_catalog.tables"}'
        leaks = fault_probe.analyze_response_for_leaks(500, body)
        self.assertTrue(len(leaks) > 0)
        self.assertTrue(any("database error" in l["type"].lower() for l in leaks))

    def test_clean_error_response_has_no_leaks(self):
        body = '{"error": "Invalid request payload", "code": 400}'
        leaks = fault_probe.analyze_response_for_leaks(400, body)
        self.assertEqual([], leaks)


class TestPlaywrightSuiteGenerator(unittest.TestCase):

    def test_generate_suite(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = os.path.join(tmpdir, "smoke.spec.ts")
            result = gen_playwright_suite.generate_suite(
                repo_dir=tmpdir,
                out_file=out_file,
                base_url="http://localhost:3000"
            )
            self.assertEqual(out_file, result)
            self.assertTrue(os.path.exists(out_file))
            with open(out_file, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("http://localhost:3000", content)
            self.assertIn("Vibecheck E2E Product Correctness & Security Suite", content)
            self.assertIn("Item #17", content)
            self.assertIn("Item #50", content)
            self.assertIn("Item #65", content)


if __name__ == "__main__":
    unittest.main()
