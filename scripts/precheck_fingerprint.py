#!/usr/bin/env python3
"""Fingerprint a review scope without executing code from the reviewed repository.

For Git worktrees, hash tracked and unignored untracked files within the requested
scope. For non-Git directories, walk the scope while excluding common generated and
dependency directories. The generated Vibecheck overview is always excluded so a
human can review or edit it without invalidating its own source fingerprint.
"""
import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys


OVERVIEW_NAMES = {
    "technical_overview.md",
    "technical_overview.vibecheck-draft.md",
}

IGNORED_DIRS = {
    ".git", ".hg", ".svn", ".venv", "venv", "env", "node_modules",
    "vendor", "dist", "build", ".next", ".nuxt", ".svelte-kit", "coverage",
    "htmlcov", "__pycache__", ".pytest_cache", ".mypy_cache", ".tox",
}


def _run_git(scope, *args):
    return subprocess.run(
        ["git", "-C", scope] + list(args),
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=True,
    ).stdout


def _git_context(scope):
    try:
        root = os.fsdecode(_run_git(scope, "rev-parse", "--show-toplevel")).strip()
        commit = os.fsdecode(_run_git(scope, "rev-parse", "HEAD")).strip()
    except (OSError, subprocess.CalledProcessError):
        return None

    root = os.path.realpath(root)
    try:
        scoped_path = os.path.relpath(scope, root)
    except ValueError:
        return None
    if scoped_path == os.pardir or scoped_path.startswith(os.pardir + os.sep):
        return None
    return root, commit, scoped_path


def _is_overview(scope, path):
    try:
        rel = os.path.relpath(path, scope)
    except ValueError:
        return False
    return os.sep not in rel and rel.lower() in OVERVIEW_NAMES


def _git_files(scope, root, scoped_path):
    raw = _run_git(root, "ls-files", "-co", "--exclude-standard", "-z", "--", scoped_path)
    paths = []
    for encoded in raw.split(b"\0"):
        if not encoded:
            continue
        path = os.path.join(root, os.fsdecode(encoded))
        if not _is_overview(scope, path):
            paths.append(path)
    return sorted(set(paths), key=os.fsencode)


def _filesystem_files(scope):
    paths = []
    for current, dirs, files in os.walk(scope, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in IGNORED_DIRS)
        for name in sorted(files):
            path = os.path.join(current, name)
            if not _is_overview(scope, path):
                paths.append(path)
    return paths


def _hash_file(digest, scope, path):
    rel = os.path.relpath(path, scope)
    encoded_rel = os.fsencode(rel)
    digest.update(len(encoded_rel).to_bytes(8, "big"))
    digest.update(encoded_rel)

    try:
        info = os.lstat(path)
    except FileNotFoundError:
        digest.update(b"MISSING")
        return

    digest.update(stat.S_IMODE(info.st_mode).to_bytes(4, "big"))
    if stat.S_ISLNK(info.st_mode):
        digest.update(b"SYMLINK\0")
        digest.update(os.fsencode(os.readlink(path)))
        return
    if not stat.S_ISREG(info.st_mode):
        digest.update(b"SPECIAL\0")
        digest.update(str(stat.S_IFMT(info.st_mode)).encode("ascii"))
        return

    digest.update(b"FILE\0")
    before = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    current = os.lstat(path)
    after = (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns)
    if after != before:
        raise RuntimeError("file changed while fingerprinting: %s" % rel)


def fingerprint(scope):
    scope = os.path.realpath(scope)
    if not os.path.isdir(scope):
        raise ValueError("review scope is not a directory: %s" % scope)

    context = _git_context(scope)
    if context:
        root, commit, scoped_path = context
        paths = _git_files(scope, root, scoped_path)
        mode = "git"
    else:
        commit = None
        paths = _filesystem_files(scope)
        mode = "filesystem"

    digest = hashlib.sha256(b"vibecheck-precheck-fingerprint-v1\0")
    for path in paths:
        _hash_file(digest, scope, path)

    return {
        "scope": scope,
        "mode": mode,
        "git_commit": commit,
        "workspace_fingerprint": "sha256:" + digest.hexdigest(),
        "files_hashed": len(paths),
        "excluded_overviews": sorted(OVERVIEW_NAMES),
    }


def main():
    parser = argparse.ArgumentParser(
        description="Fingerprint a repository scope for Vibecheck precheck staleness detection")
    parser.add_argument("repo_dir", help="repository or directory to fingerprint")
    args = parser.parse_args()
    try:
        result = fingerprint(args.repo_dir)
    except (OSError, RuntimeError, ValueError, subprocess.CalledProcessError) as exc:
        print(json.dumps({"error": str(exc)}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
