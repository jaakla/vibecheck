#!/usr/bin/env python3
"""Tests for the precheck source-state fingerprint."""
import importlib.util
import os
import subprocess
import tempfile
import unittest


REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(REPO, "scripts", "precheck_fingerprint.py")

_spec = importlib.util.spec_from_file_location("precheck_fingerprint", SCRIPT)
precheck = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(precheck)


def git(cwd, *args):
    subprocess.run(["git"] + list(args), cwd=cwd, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def write(root, rel, body):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(body)
    return path


class TestPrecheckFingerprint(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="vibecheck-precheck-")
        self.root = self.tmp.name
        git(self.root, "init", "-q")
        git(self.root, "config", "user.email", "test@example.invalid")
        git(self.root, "config", "user.name", "test")
        write(self.root, "src/app.js", "export const value = 1;\n")
        git(self.root, "add", "-A")
        git(self.root, "commit", "-q", "-m", "initial")

    def tearDown(self):
        self.tmp.cleanup()

    def fp(self, scope=None):
        return precheck.fingerprint(scope or self.root)["workspace_fingerprint"]

    def test_overview_creation_and_edits_do_not_invalidate_fingerprint(self):
        before = self.fp()
        write(self.root, "TECHNICAL_OVERVIEW.md", "Review status: DRAFT\n")
        self.assertEqual(self.fp(), before)
        write(self.root, "TECHNICAL_OVERVIEW.md", "Review status: HUMAN-REVIEWED\n")
        self.assertEqual(self.fp(), before)

    def test_tracked_content_change_invalidates_fingerprint(self):
        before = self.fp()
        write(self.root, "src/app.js", "export const value = 2;\n")
        self.assertNotEqual(self.fp(), before)

    def test_untracked_content_change_invalidates_fingerprint(self):
        write(self.root, "docs/notes.md", "first\n")
        before = self.fp()
        write(self.root, "docs/notes.md", "second\n")
        self.assertNotEqual(self.fp(), before)

    def test_nested_scope_ignores_sibling_changes(self):
        write(self.root, "other/service.js", "one\n")
        git(self.root, "add", "-A")
        git(self.root, "commit", "-q", "-m", "add sibling")
        scope = os.path.join(self.root, "src")
        before = self.fp(scope)
        write(self.root, "other/service.js", "two\n")
        self.assertEqual(self.fp(scope), before)

    def test_non_git_directory_is_supported(self):
        with tempfile.TemporaryDirectory(prefix="vibecheck-no-git-") as root:
            write(root, "main.py", "print('one')\n")
            first = precheck.fingerprint(root)
            self.assertEqual(first["mode"], "filesystem")
            write(root, "main.py", "print('two')\n")
            self.assertNotEqual(
                first["workspace_fingerprint"],
                precheck.fingerprint(root)["workspace_fingerprint"],
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
