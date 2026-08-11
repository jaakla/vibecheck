#!/usr/bin/env python3
"""Scanner behaviour tests — stdlib only, no pytest required.

    python3 tests/test_scanner.py          (or: python3 -m unittest discover tests)

Each fixture repo is copied into a throwaway git repo first, so git-history
checks are scoped to the fixture instead of to whatever repo the tests happen
to be sitting inside.
"""
import json
import os
import shutil
import subprocess
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCANNER = os.path.join(REPO, "scripts", "vibecheck.sh")
FIXTURES = os.path.join(REPO, "tests", "fixtures")


def git(cwd, *args):
    subprocess.run(["git"] + list(args), cwd=cwd, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def scan(fixture, as_git_repo=True, extra_setup=None):
    """Copy a fixture to a temp dir, optionally git-init it, and scan it."""
    tmp = tempfile.mkdtemp(prefix="vibecheck-test-")
    try:
        work = os.path.join(tmp, fixture)
        shutil.copytree(os.path.join(FIXTURES, fixture), work)
        if as_git_repo:
            git(work, "init", "-q")
            git(work, "config", "user.email", "test@example.invalid")
            git(work, "config", "user.name", "vibecheck tests")
            git(work, "add", "-A")
            git(work, "commit", "-q", "-m", "fixture")
        if extra_setup:
            extra_setup(work)
        out = subprocess.run(["bash", SCANNER, work], capture_output=True,
                             text=True, timeout=180)
        findings = {}
        for line in out.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)   # raises if the scanner emitted invalid JSON
            if "check" in obj:
                findings[obj["check"]] = obj
        return findings, out
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


class ScannerTestCase(unittest.TestCase):
    def assertStatus(self, findings, check, expected):
        self.assertIn(check, findings, f"check {check!r} was not emitted at all")
        self.assertEqual(
            findings[check]["status"], expected,
            f"{check}: expected {expected}, got {findings[check]['status']} "
            f"— {findings[check]['title']}")


class TestVulnerableApp(ScannerTestCase):
    """Everything the scanner claims to detect must actually fire."""

    @classmethod
    def setUpClass(cls):
        cls.f, cls.proc = scan("vulnerable-app")

    def test_emits_valid_json_and_completes(self):
        self.assertIn('"done":true', self.proc.stdout)
        self.assertEqual(self.proc.returncode, 0)

    def test_hardcoded_secrets(self):
        self.assertStatus(self.f, "secrets.hardcoded", "FAIL")
        self.assertStatus(self.f, "secrets.known_prefixes", "FAIL")

    def test_service_role_in_client_code_is_fail_not_warn(self):
        self.assertStatus(self.f, "secrets.service_role", "FAIL")

    def test_rls(self):
        self.assertStatus(self.f, "rls.missing", "FAIL")      # profiles has no RLS
        self.assertStatus(self.f, "rls.permissive", "FAIL")   # using (true)
        self.assertStatus(self.f, "rls.anon_write", "WARN")

    def test_sql_injection(self):
        self.assertStatus(self.f, "inject.sql", "FAIL")

    def test_llm_cost_and_injection_chain(self):
        self.assertStatus(self.f, "cost.client_llm", "FAIL")
        self.assertStatus(self.f, "cost.no_ratelimit", "FAIL")
        self.assertStatus(self.f, "inject.llm_to_exec", "FAIL")
        self.assertStatus(self.f, "inject.prompt_interpolation", "WARN")

    def test_webhook_without_signature(self):
        self.assertStatus(self.f, "integ.webhook_sig", "FAIL")

    def test_architecture(self):
        self.assertStatus(self.f, "arch.datastore", "FAIL")        # sqlite + vercel
        self.assertStatus(self.f, "arch.handrolled_auth", "FAIL")  # md5 + Math.random
        self.assertStatus(self.f, "arch.mixed_stack", "WARN")      # pg + mongoose + prisma

    def test_lockfile_and_hygiene(self):
        self.assertStatus(self.f, "deps.lockfile", "FAIL")
        self.assertStatus(self.f, "errors.swallowed", "WARN")
        self.assertStatus(self.f, "inject.xss", "WARN")
        self.assertStatus(self.f, "authz.client_admin", "WARN")

    def test_console_threshold_is_reachable(self):
        """Regression: the count came from a head-capped pipeline, so a >50
        threshold could never be crossed and this check always passed."""
        self.assertStatus(self.f, "config.console", "WARN")
        self.assertIn("6", self.f["config.console"]["title"])  # ~60 statements

    def test_secrets_are_redacted_in_evidence(self):
        """Full secret values must never reach stdout."""
        self.assertNotIn("sk-ant-FAKEFAKEFAKEFAKEFAKEFAKE", self.proc.stdout)
        self.assertNotIn("AKIAFAKEFAKEFAKEFAKE", self.proc.stdout)
        self.assertIn("REDACTED", self.proc.stdout)

    def test_evidence_lines_are_length_capped(self):
        for check, obj in self.f.items():
            for line in obj["evidence"].splitlines():
                self.assertLessEqual(len(line), 220, f"{check}: unbounded evidence line")


class TestCleanApp(ScannerTestCase):
    """The same shapes, done right, must produce no FAIL."""

    @classmethod
    def setUpClass(cls):
        cls.f, cls.proc = scan("clean-app")

    def test_no_failures_at_all(self):
        fails = {k: v["title"] for k, v in self.f.items() if v["status"] == "FAIL"}
        self.assertEqual(fails, {}, f"false positives on a clean app: {fails}")

    def test_positive_detections(self):
        self.assertStatus(self.f, "rls.missing", "PASS")
        self.assertStatus(self.f, "rls.permissive", "PASS")
        self.assertStatus(self.f, "inject.sql", "PASS")
        self.assertStatus(self.f, "integ.webhook_sig", "PASS")
        self.assertStatus(self.f, "deps.lockfile", "PASS")
        self.assertStatus(self.f, "secrets.gitignore", "PASS")
        self.assertStatus(self.f, "arch.handrolled_auth", "PASS")

    def test_library_detection_uses_imports_not_bare_words(self):
        self.assertStatus(self.f, "inject.validation", "PASS")   # zod imported
        self.assertStatus(self.f, "errors.tracking", "PASS")     # @sentry/node imported
        self.assertStatus(self.f, "cost.no_ratelimit", "PASS")   # @upstash/ratelimit

    def test_ai_disclosure_found_in_ui(self):
        self.assertStatus(self.f, "aiact.transparency", "PASS")

    def test_server_side_llm_not_flagged_as_client(self):
        self.assertStatus(self.f, "cost.client_llm", "PASS")


class TestDocsOnly(ScannerTestCase):
    """Regression: prose *about* security must not be read as insecure code."""

    @classmethod
    def setUpClass(cls):
        cls.f, cls.proc = scan("docs-only")

    def test_no_failures_on_prose(self):
        fails = {k: v["title"] for k, v in self.f.items() if v["status"] == "FAIL"}
        self.assertEqual(fails, {}, f"prose triggered FAILs: {fails}")

    def test_specific_historical_false_positives(self):
        # "md5/sha1 password hashes, Math.random tokens" in a docstring
        self.assertStatus(self.f, "arch.handrolled_auth", "WARN")
        self.assertNotEqual(self.f["arch.handrolled_auth"]["status"], "FAIL")
        # the word "webhook" in prose is not a webhook handler
        self.assertStatus(self.f, "integ.webhook_sig", "PASS")
        self.assertIn("No webhook handlers", self.f["integ.webhook_sig"]["title"])

    def test_no_false_passes_from_prose(self):
        """'joi' inside 'join', 'PostHog' in a sentence — these used to be
        read as evidence that a library was present."""
        self.assertStatus(self.f, "inject.validation", "WARN")
        self.assertStatus(self.f, "errors.tracking", "WARN")


class TestGitHistory(ScannerTestCase):
    def test_env_in_history_is_detected_after_deletion(self):
        """A .env deleted from the tree is still a leak in history."""
        def commit_then_delete_env(work):
            with open(os.path.join(work, ".env"), "w") as fh:
                fh.write("ANTHROPIC_API_KEY=sk-ant-FAKEHISTORYFAKEHISTORY\n")
            git(work, "add", "-f", ".env")
            git(work, "commit", "-q", "-m", "oops")
            os.remove(os.path.join(work, ".env"))
            git(work, "rm", "-q", "--cached", ".env")
            git(work, "commit", "-q", "-m", "remove env")

        f, proc = scan("clean-app", extra_setup=commit_then_delete_env)
        self.assertStatus(f, "secrets.env_tracked", "PASS")     # gone from the tree
        self.assertStatus(f, "secrets.env_history", "FAIL")     # still in history
        self.assertStatus(f, "secrets.history_content", "FAIL")
        self.assertNotIn("sk-ant-FAKEHISTORYFAKEHISTORY", proc.stdout)

    def test_non_git_directory_degrades_gracefully(self):
        f, proc = scan("clean-app", as_git_repo=False)
        self.assertStatus(f, "secrets.env_tracked", "MANUAL")
        self.assertIn('"done":true', proc.stdout)


class TestPathsWithSpaces(ScannerTestCase):
    def test_filenames_with_spaces_are_scanned(self):
        """Word-splitting on the file list used to drop these silently."""
        def add_spacey_file(work):
            d = os.path.join(work, "src", "my components")
            os.makedirs(d, exist_ok=True)
            with open(os.path.join(d, "Leaky Panel.tsx"), "w") as fh:
                fh.write('const k = "sk-ant-SPACEYFAKEFAKEFAKE";\n')

        f, _ = scan("clean-app", extra_setup=add_spacey_file)
        self.assertStatus(f, "secrets.known_prefixes", "FAIL")


if __name__ == "__main__":
    unittest.main(verbosity=2)
