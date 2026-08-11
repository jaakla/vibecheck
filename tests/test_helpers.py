#!/usr/bin/env python3
"""Tests for the redactor, the safe-fix helper, and the Supabase probe's logic.

The probe's network paths are not exercised; its pure functions are, because
that is where the interpretation bugs live (a 200 with zero rows is not an
exposure, and an empty table is indistinguishable from a protected one).
"""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(REPO, "scripts")
REDACT = os.path.join(SCRIPTS, "_redact.py")
SAFE_FIXES = os.path.join(SCRIPTS, "apply_safe_fixes.sh")

_spec = importlib.util.spec_from_file_location(
    "supabase_probe", os.path.join(SCRIPTS, "supabase_probe.py"))
probe = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(probe)


def redact(text, *args):
    out = subprocess.run([sys.executable, REDACT] + list(args), input=text,
                         capture_output=True, text=True, check=True)
    return json.loads(out.stdout)


def git(cwd, *args):
    subprocess.run(["git"] + list(args), cwd=cwd, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


class TestRedactor(unittest.TestCase):
    def test_known_prefixes_are_cut_to_eight_chars(self):
        out = redact('key = "sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"')
        self.assertIn("sk-ant-a", out)
        self.assertIn("REDACTED", out)
        self.assertNotIn("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345", out)

    def test_aws_and_github_and_jwt(self):
        for secret in ("AKIAIOSFODNN7EXAMPLE",
                       "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
                       "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.c2lnbmF0dXJl"):
            out = redact("token: " + secret)
            self.assertNotIn(secret, out, f"{secret[:10]}... survived redaction")

    def test_file_paths_survive(self):
        line = "./src/components/very/deeply/nested/AdminPanel.tsx:12:const x = 1;"
        self.assertEqual(redact(line), line)

    def test_long_lines_are_truncated(self):
        out = redact("x" * 5000)
        self.assertLessEqual(max(len(l) for l in out.splitlines()), 220)

    def test_line_count_is_capped(self):
        out = redact("\n".join("line %d" % i for i in range(500)))
        self.assertLessEqual(len(out.splitlines()), 41)
        self.assertIn("suppressed", out)

    def test_strings_mode_redacts_low_entropy_passphrases(self):
        line = 'const DB_PASSWORD = "correcthorsebatterystaple";'
        self.assertEqual(redact(line), line)              # default: left alone
        out = redact(line, "--strings")
        self.assertNotIn("correcthorsebatterystaple", out)
        self.assertIn("REDACTED", out)

    def test_output_is_valid_json_for_awkward_input(self):
        for raw in ('quote " backslash \\ newline\n', "unicode ✓ ő", ""):
            subprocess.run([sys.executable, REDACT], input=raw,
                           capture_output=True, text=True, check=True)


class TestSafeFixes(unittest.TestCase):
    def _repo(self):
        tmp = tempfile.mkdtemp(prefix="vibecheck-fixes-")
        git(tmp, "init", "-q")
        git(tmp, "config", "user.email", "t@example.invalid")
        git(tmp, "config", "user.name", "t")
        return tmp

    def _write(self, root, rel, body="SECRET=x\n"):
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            fh.write(body)
        return path

    def test_untracks_env_including_paths_with_spaces(self):
        root = self._repo()
        self._write(root, ".env")
        self._write(root, "my config/.env")
        self._write(root, ".env.example", "SECRET=\n")
        git(root, "add", "-A", "-f")
        git(root, "commit", "-q", "-m", "init")

        subprocess.run(["bash", SAFE_FIXES, root], capture_output=True, check=True)
        tracked = subprocess.run(["git", "ls-files"], cwd=root, capture_output=True,
                                 text=True).stdout.split()
        self.assertNotIn(".env", tracked)
        self.assertNotIn("my config/.env", tracked)
        self.assertIn(".env.example", tracked, "the example file must be kept")
        self.assertTrue(os.path.exists(os.path.join(root, ".env")),
                        "the local file must stay on disk")

    def test_dry_run_writes_nothing(self):
        root = self._repo()
        self._write(root, ".env")
        git(root, "add", "-A", "-f")
        git(root, "commit", "-q", "-m", "init")

        out = subprocess.run(["bash", SAFE_FIXES, root, "--dry-run"],
                             capture_output=True, text=True, check=True).stdout
        self.assertIn("DRY RUN", out)
        self.assertFalse(os.path.exists(os.path.join(root, ".gitignore")))
        tracked = subprocess.run(["git", "ls-files"], cwd=root, capture_output=True,
                                 text=True).stdout.split()
        self.assertIn(".env", tracked, "dry run must not touch the index")

    def test_is_idempotent(self):
        root = self._repo()
        subprocess.run(["bash", SAFE_FIXES, root], capture_output=True, check=True)
        second = subprocess.run(["bash", SAFE_FIXES, root], capture_output=True,
                                text=True, check=True).stdout
        self.assertIn("nothing safe to auto-fix", second)


class TestSupabaseProbeLogic(unittest.TestCase):
    def test_mask_hides_the_body_of_the_key(self):
        self.assertEqual(probe.mask("eyJhbGciOiJIUzI1NiJ9xxxx"), "eyJhbG...xxxx")
        self.assertEqual(probe.mask("short"), "***")
        self.assertEqual(probe.mask(""), "")

    def test_visible_count_prefers_content_range_total(self):
        self.assertEqual(probe.visible_count({"Content-Range": "0-0/42"}, "[{}]"), 42)
        self.assertEqual(probe.visible_count({"content-range": "*/0"}, "[]"), 0)

    def test_visible_count_falls_back_to_body_length(self):
        self.assertEqual(probe.visible_count({}, "[{},{}]"), 2)
        self.assertEqual(probe.visible_count({}, "[]"), 0)
        self.assertIsNone(probe.visible_count({}, "not json"))

    def test_jwt_role_extraction(self):
        import base64

        def token(role):
            payload = base64.urlsafe_b64encode(
                json.dumps({"role": role}).encode()).decode().rstrip("=")
            return "eyJhbGciOiJIUzI1NiJ9." + payload + ".sig"

        self.assertEqual(probe._jwt_role(token("service_role")), "service_role")
        self.assertEqual(probe._jwt_role(token("anon")), "anon")
        self.assertEqual(probe._jwt_role("not-a-jwt"), "")

    def test_service_role_key_is_refused(self):
        import base64
        payload = base64.urlsafe_b64encode(
            json.dumps({"role": "service_role"}).encode()).decode().rstrip("=")
        token = "eyJhbGciOiJIUzI1NiJ9." + payload + ".sig"
        out = subprocess.run(
            [sys.executable, os.path.join(SCRIPTS, "supabase_probe.py"),
             "--url", "https://example.invalid", "--anon", token],
            capture_output=True, text=True)
        self.assertEqual(out.returncode, 2)
        self.assertIn("refusing to run", out.stdout)

    def test_untested_probes_are_reported_not_silently_skipped(self):
        """Without --write-probe / --jwt-a/--jwt-b the report must say NOT_TESTED
        rather than leaving the reader to assume those checks passed."""
        out = subprocess.run(
            [sys.executable, os.path.join(SCRIPTS, "supabase_probe.py"),
             "--url", "https://example.invalid", "--anon", "anon-key-value",
             "--tables", "", "--timeout", "1"],
            capture_output=True, text=True, timeout=60)
        data = json.loads(out.stdout)
        self.assertFalse(data["write_probe_enabled"])
        verdicts = {(f.get("check"), f.get("verdict")) for f in data["findings"]}
        self.assertIn(("anon_insert_probe", "NOT_TESTED"), verdicts)
        self.assertIn(("idor", "NOT_TESTED"), verdicts)

    def test_anon_key_is_masked_in_output(self):
        out = subprocess.run(
            [sys.executable, os.path.join(SCRIPTS, "supabase_probe.py"),
             "--url", "https://example.invalid", "--anon", "supersecretanonvalue123",
             "--timeout", "1"],
            capture_output=True, text=True, timeout=60)
        self.assertNotIn("supersecretanonvalue123", out.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
