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
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCANNER = os.path.join(REPO, "scripts", "vibecheck.sh")
FIXTURES = os.path.join(REPO, "tests", "fixtures")
sys.path.insert(0, os.path.join(REPO, "scripts"))
import items


def git(cwd, *args):
    subprocess.run(["git"] + list(args), cwd=cwd, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def scan(fixture, as_git_repo=True, extra_setup=None, scanner_args=None):
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
        out = subprocess.run(["bash", SCANNER] + list(scanner_args or []) + [work], capture_output=True,
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
    """Every intentionally planted risky pattern must produce a warning."""

    @classmethod
    def setUpClass(cls):
        cls.f, cls.proc = scan("vulnerable-app")

    def test_emits_valid_json_and_completes(self):
        self.assertIn('"done":true', self.proc.stdout)
        self.assertEqual(self.proc.returncode, 0)

    def test_hardcoded_secrets(self):
        self.assertStatus(self.f, "secrets.hardcoded", "WARN")
        self.assertStatus(self.f, "secrets.known_prefixes", "WARN")

    def test_service_role_in_client_code_is_warning_requiring_confirmation(self):
        self.assertStatus(self.f, "secrets.service_role", "WARN")

    def test_rls(self):
        self.assertStatus(self.f, "rls.missing", "WARN")      # profiles has no RLS
        self.assertStatus(self.f, "rls.permissive", "WARN")   # using (true)
        self.assertStatus(self.f, "rls.anon_write", "WARN")

    def test_sql_injection(self):
        self.assertStatus(self.f, "inject.sql", "WARN")

    def test_llm_cost_and_injection_chain(self):
        self.assertStatus(self.f, "cost.client_llm", "WARN")
        self.assertStatus(self.f, "cost.no_ratelimit", "WARN")
        self.assertStatus(self.f, "inject.llm_to_exec", "WARN")
        self.assertStatus(self.f, "inject.prompt_interpolation", "WARN")

    def test_webhook_without_signature(self):
        self.assertStatus(self.f, "integ.webhook_sig", "WARN")

    def test_architecture(self):
        self.assertStatus(self.f, "arch.datastore", "WARN")        # sqlite + vercel
        self.assertStatus(self.f, "arch.handrolled_auth", "WARN")  # md5 + Math.random
        self.assertStatus(self.f, "arch.mixed_stack", "WARN")      # pg + mongoose + prisma

    def test_lockfile_and_hygiene(self):
        self.assertStatus(self.f, "deps.lockfile", "WARN")
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
    """The same shapes, done right, must produce no warnings for those checks."""

    @classmethod
    def setUpClass(cls):
        cls.f, cls.proc = scan("clean-app")

    def test_no_failures_at_all(self):
        fails = {k: v["title"] for k, v in self.f.items() if v["status"] == "FAIL"}
        self.assertEqual(fails, {}, f"false positives on a clean app: {fails}")

    def test_every_declared_check_emits_a_result(self):
        self.assertEqual(set(self.f), set(items.SCANNER_CHECKS))

    def test_positive_detections(self):
        self.assertStatus(self.f, "rls.missing", "NO_SIGNAL")
        self.assertStatus(self.f, "rls.permissive", "NO_SIGNAL")
        self.assertStatus(self.f, "inject.sql", "NO_SIGNAL")
        self.assertStatus(self.f, "integ.webhook_sig", "NO_SIGNAL")
        self.assertStatus(self.f, "deps.lockfile", "NO_SIGNAL")
        self.assertStatus(self.f, "secrets.gitignore", "NO_SIGNAL")
        self.assertStatus(self.f, "arch.handrolled_auth", "NO_SIGNAL")

    def test_library_detection_uses_imports_not_bare_words(self):
        self.assertStatus(self.f, "inject.validation", "NO_SIGNAL")   # zod imported
        self.assertStatus(self.f, "errors.tracking", "NO_SIGNAL")     # @sentry/node imported
        self.assertStatus(self.f, "cost.no_ratelimit", "NO_SIGNAL")   # @upstash/ratelimit

    def test_ai_disclosure_found_in_ui(self):
        self.assertStatus(self.f, "aiact.transparency", "NO_SIGNAL")

    def test_server_side_llm_not_flagged_as_client(self):
        self.assertStatus(self.f, "cost.client_llm", "NO_SIGNAL")

    def test_direct_provider_fetch_is_not_called_indirect_injection(self):
        self.assertStatus(self.f, "inject.indirect", "NO_SIGNAL")

    def test_dependency_audit_is_offline_by_default(self):
        self.assertStatus(self.f, "deps.audit", "MANUAL")
        self.assertIn("not run by default", self.f["deps.audit"]["title"])


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
        self.assertStatus(self.f, "integ.webhook_sig", "NO_SIGNAL")
        self.assertIn("No webhook-handler signal", self.f["integ.webhook_sig"]["title"])

    def test_no_false_passes_from_prose(self):
        """'joi' inside 'join', 'PostHog' in a sentence — these used to be
        read as evidence that a library was present."""
        self.assertStatus(self.f, "inject.validation", "WARN")
        self.assertStatus(self.f, "errors.tracking", "WARN")


class TestPlatformBackendTarget(ScannerTestCase):
    """The live authorization surface must be locatable, not asked for.

    Platform builders (Lovable Cloud, Bolt, v0) commit the project URL and the
    publishable key, because both are public by construction. Finding them is
    what lets #13/#14 be tested against the deployment instead of guessed from
    migrations, so the check is a to-do with a target, never a leak report.
    """

    ANON_JWT = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                + "a" * 44 + "." + "b" * 43)

    def test_lovable_style_tree_locates_url_key_and_client(self):
        def add_lovable_backend(work):
            with open(os.path.join(work, ".env"), "w") as fh:
                fh.write('SUPABASE_PROJECT_ID="abcdefghijklmnopqrst"\n'
                         'VITE_SUPABASE_URL='
                         '"https://abcdefghijklmnopqrst.supabase.co"\n'
                         'VITE_SUPABASE_PUBLISHABLE_KEY="%s"\n' % self.ANON_JWT)
            path = os.path.join(work, "src", "integrations", "supabase", "client.ts")
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as fh:
                fh.write("export const supabase = createClient(\n"
                         "  import.meta.env.VITE_SUPABASE_URL,\n"
                         "  import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY);\n")

        findings, proc = scan("clean-app", extra_setup=add_lovable_backend)
        self.assertStatus(findings, "authz.backend_target", "MANUAL")
        evidence = findings["authz.backend_target"]["evidence"]
        self.assertIn("abcdefghijklmnopqrst.supabase.co", evidence)
        self.assertIn("integrations/supabase/client.ts", evidence)
        # public by design, still not pasted into a report at full length
        self.assertNotIn(self.ANON_JWT, proc.stdout)
        self.assertIn("REDACTED", evidence)

    def test_a_bare_env_example_is_still_a_target(self):
        findings, _ = scan("clean-app")
        self.assertStatus(findings, "authz.backend_target", "MANUAL")
        self.assertIn("SUPABASE_URL", findings["authz.backend_target"]["evidence"])

    def test_no_backend_in_the_tree_says_so_instead_of_staying_silent(self):
        findings, _ = scan("docs-only")
        self.assertStatus(findings, "authz.backend_target", "MANUAL")
        self.assertIn("No Supabase project URL",
                      findings["authz.backend_target"]["title"])


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
        self.assertStatus(f, "secrets.env_tracked", "NO_SIGNAL")  # gone from tree
        self.assertStatus(f, "secrets.env_history", "WARN")       # still in history
        self.assertStatus(f, "secrets.history_content", "WARN")
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
        self.assertStatus(f, "secrets.known_prefixes", "WARN")


class TestAdversarialScannerCases(ScannerTestCase):
    def test_modern_supabase_secret_is_detected_and_redacted(self):
        secret = "sb_secret_FAKEFAKEFAKEFAKEFAKEFAKE"

        def add_secret(work):
            with open(os.path.join(work, "src", "secret.ts"), "w") as fh:
                fh.write('const key = "%s";\n' % secret)

        f, proc = scan("clean-app", extra_setup=add_secret)
        self.assertStatus(f, "secrets.known_prefixes", "WARN")
        self.assertNotIn(secret, proc.stdout)
        self.assertIn("REDACTED", proc.stdout)

    def test_multiline_create_table_without_rls_is_found(self):
        def add_sql(work):
            path = os.path.join(work, "db", "multiline.sql")
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as fh:
                fh.write("CREATE\n TABLE IF NOT EXISTS private_notes (id uuid);\n")

        f, _ = scan("clean-app", extra_setup=add_sql)
        self.assertStatus(f, "rls.missing", "WARN")
        self.assertIn("private_notes", f["rls.missing"]["evidence"])

    def test_rls_in_another_schema_does_not_mask_missing_rls(self):
        def add_sql(work):
            path = os.path.join(work, "db", "schemas.sql")
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as fh:
                fh.write("CREATE TABLE tenant.accounts (id uuid);\n"
                         "ALTER TABLE public.accounts ENABLE ROW LEVEL SECURITY;\n")

        f, _ = scan("clean-app", extra_setup=add_sql)
        self.assertStatus(f, "rls.missing", "WARN")
        self.assertIn("tenant.accounts", f["rls.missing"]["evidence"])

    def test_untracked_lockfile_is_not_treated_as_reproducible(self):
        def replace_after_commit(work):
            os.remove(os.path.join(work, "package-lock.json"))
            with open(os.path.join(work, "bun.lock"), "w") as fh:
                fh.write("lockfileVersion = 1\n")

        f, _ = scan("clean-app", extra_setup=replace_after_commit)
        self.assertStatus(f, "deps.lockfile", "WARN")
        self.assertIn("not tracked", f["deps.lockfile"]["title"])

    def test_typescript_client_candidate_is_scanned(self):
        def add_client_ts(work):
            with open(os.path.join(work, "src", "browser.ts"), "w") as fh:
                fh.write('const role = "service_role";\n')

        f, _ = scan("clean-app", extra_setup=add_client_ts)
        self.assertStatus(f, "secrets.service_role", "WARN")
        self.assertIn("client-reachable candidate", f["secrets.service_role"]["title"])

    def test_server_tsx_is_not_labeled_client_reachable(self):
        def add_server_tsx(work):
            path = os.path.join(work, "src", "server", "render.tsx")
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as fh:
                fh.write('const role = "service_role";\n')

        f, _ = scan("clean-app", extra_setup=add_server_tsx)
        self.assertStatus(f, "secrets.service_role", "WARN")
        self.assertNotIn("client-reachable candidate", f["secrets.service_role"]["title"])

    def test_nonexistent_repo_is_scanner_failure(self):
        proc = subprocess.run(["bash", SCANNER, "/definitely/not/a/vibecheck/repo"],
                              capture_output=True, text=True)
        self.assertEqual(proc.returncode, 2)
        self.assertIn('"error"', proc.stdout)
        self.assertNotIn('"done":true', proc.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
