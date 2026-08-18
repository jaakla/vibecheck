#!/usr/bin/env python3
"""Code-computed coverage ledger for a `vibecheck.sh` scan.

    bash scripts/vibecheck.sh <repo> | python3 scripts/coverage.py \
        --repo <repo> [--scope a:web b:api] [--out coverage.json]

The bundled scanner is a grep plus a handful of MANUAL reviewer to-dos; it is
not a guarantee that anything was `covered`. This ledger makes that honest and
checkable instead of assumed. It recomputes, with no model in the loop:

  * every top-level directory of the scanned tree, from the tree itself;
  * which of them the scanner's own checks touched (a `scanner_checks` counts
    a directory as touched when a finding's evidence names a path under it),
    which are explicitly skipped with a reason, and which are neither — those
    are `unaccounted` and make completeness `partial`, not `checked`;
  * a `completeness` status: `checked` (every top-level dir is either scanned
    or explicitly skipped), `partial` (some dirs are unaccounted), or
    `not-checkable` (the tree's directory list could not be read);
  * `verify` metadata: what the scanner does and does not claim, so the scan
    skill says it plainly instead of implying coverage it did not have.

A clean scan (`done:true`) whose completeness is `partial` is reported as an
open coverage gap, never as a clean bill of health. Skipped directories are
disclosure, not failure: each entry carries the reason the scan skill gave
(vendored, generated, documentation, tests, and the like) and appears in the
ledger so a reader can calibrate what was not examined.

Stdlib only; reading nothing of the reviewed repository except its directory
names and evidence paths passed on stdin as scanning data under review.
"""
import argparse
import json
import os
import sys

# Source extensions the bundled scanner reads (mirrors scripts/vibecheck.sh SRC_FIND).
SRC_EXTENSIONS = (
    ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py", ".vue", ".svelte",
    ".html", ".sql", ".toml", ".yaml", ".yml", ".json", ".env",
)
# Sub-paths the scanner excludes from source enumeration.
EXCLUDED_SUB = (
    "node_modules", ".git", "dist", "build", ".next", ".venv", "venv",
    "vendor", "__pycache__",
)

SKIPPABLE = {
    "node_modules": "vendored third-party code not scanned by the bundled ruleset",
    "vendor": "vendored third-party code not scanned by the bundled ruleset",
    "dist": "generated build output",
    "build": "generated build output",
    ".next": "generated build output",
    ".nuxt": "generated build output",
    ".svelte-kit": "generated build output",
    ".venv": "a virtual environment, not application source",
    "venv": "a virtual environment, not application source",
    "__pycache__": "Python bytecode cache",
    ".pytest_cache": "test cache",
    ".mypy_cache": "type-checker cache",
    ".tox": "test/build matrix cache",
    ".git": "version-control metadata",
    ".hg": "version-control metadata",
    ".svn": "version-control metadata",
    "coverage": "coverage-reporter output",
    "htmlcov": "coverage-reporter output",
}


def _top_level_dirs(repo):
    """Direct top-level directories of `repo`, from the tree itself."""
    out = []
    try:
        with os.scandir(repo) as it:
            for entry in it:
                if entry.is_dir():
                    out.append(entry.name)
    except OSError:
        return None
    return sorted(out)


def _evidence_paths(findings):
    """Repository-relative paths the scanner's evidence names (best effort)."""
    import re
    paths = []
    pat = re.compile(r'((?:[A-Za-z0-9_.@-]+/)+[A-Za-z0-9_.@-]+)')
    for finding in findings:
        for line in finding.get("evidence", "").splitlines():
            m = pat.search(line)
            if m:
                paths.append(m.group(1).lstrip("./"))
    return paths


def _top_dir_of(path):
    parts = [p for p in path.split("/") if p]
    return parts[0] if parts else None


def _resolve(repo, top):
    """Whether a top-level dir is (including) a file the scanner actually read."""
    return os.path.exists(os.path.join(repo, top))


def _is_scannable_source(repo, rel):
    """Whether `rel` (repo-relative, may be dir or file prefix) contains source
    the scanner's file globs would read. Mirrors vibecheck.sh's SRC_FIND."""
    path = os.path.join(repo, rel)
    try:
        if os.path.isfile(path):
            name = os.path.basename(path)
            if name.startswith(".env"):
                return True
            dots = name.rfind(".")
            if dots == -1:
                return False
            return name[dots:] in SRC_EXTENSIONS
        if os.path.isdir(path):
            for part in rel.split(os.sep):
                if part in EXCLUDED_SUB:
                    return False
            return True
        return False
    except OSError:
        return False


def _dir_has_source(repo, top):
    """Whether any scannable source file exists under `repo/<top>`, recursing
    (the scanner globs whole trees, so a file nested several levels still counts
    the top-level directory it lives under as scanned)."""
    base = os.path.join(repo, top)
    for root, dirnames, files in os.walk(base):
        # prune excluded sub-paths as the scanner does
        rel_root = os.path.relpath(root, repo)
        dirnames[:] = [d for d in dirnames
                       if os.path.join(rel_root, d) not in EXCLUDED_SUB]
        for name in files:
            rel = os.path.join(rel_root, name)
            if _is_scannable_source(repo, rel):
                return True
    return False


def build(repo, findings, skipped=None, scope=None):
    dirs = _top_level_dirs(repo)
    if dirs is None:
        return {
            "version": 1,
            "completeness": "not-checkable",
            "top_level_count": None,
            "reason": "the tree's directory list could not be read",
            "scanned": [],
            "skipped": [],
            "unaccounted": [],
        }
    touched = set(_top_dir_of(p) for p in _evidence_paths(findings))
    touched.discard(None)
    skipped = dict(skipped or {})
    # Always-recognisable generated/dependency dirs default to skipped-diagonly
    # rather than unaccounted, but never silently: they appear in the ledger.
    for d in dirs:
        if d in SKIPPABLE and d not in skipped:
            skipped[d] = SKIPPABLE[d]
    scanned = []
    for d in dirs:
        # A dir is scanned if it holds scannable source (the scanner read it even
        # if it produced no WARN) OR a finding's evidence named a path under it.
        if (d in touched or _dir_has_source(repo, d)) and d not in skipped:
            scanned.append(d)
    accounted_skipped = [{"name": d, "reason": r}
                         for d, r in skipped.items() if d in dirs]
    unaccounted = [d for d in dirs
                   if d not in scanned and d not in skipped]
    if scope:
        # The user narrowed the scan; that is intentional coverage, not a gap,
        # but the ledger must say so explicitly rather than claiming whole-tree.
        unaccounted = [d for d in unaccounted if d not in scope]
        scope_skipped = [{"name": d, "reason": "outside the requested scan scope"}
                         for d in dirs if d in scope and d not in scanned and d not in skipped]
        accounted_skipped.extend(scope_skipped)
    if unaccounted:
        completeness = "partial"
    else:
        completeness = "checked"
    return {
        "version": 1,
        "completeness": completeness,
        "top_level_count": len(dirs),
        "completeness_outcome": (
            "checked" if completeness == "checked"
            else "partial (top-level directories in neither ledger: %s)" % ", ".join(unaccounted)
        ),
        "scanned": sorted(scanned),
        "skipped": accounted_skipped,
        "unaccounted": sorted(unaccounted),
        "verify": "The scanner reads source files by extension; a directory holding "
                  "scannable source is scanned whether or not a finding named a path in "
                  "it, and a directory with neither scannable source nor an explicit "
                  "skip reason is unaccounted. This ledger reports coverage honestly; "
                  "it is not a clean bill of health.",
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", default=".", help="scanned repository path")
    ap.add_argument("--scope", nargs="*", default=[],
                    help="top-level directories intentionally in scope")
    ap.add_argument("--out", help="write coverage.json here (default: stdout)")
    ap.add_argument("--skip", action="append", default=[],
                    help="NAME=reason to explicitly skip a directory")
    args = ap.parse_args(argv)

    skipped = {}
    for item in args.skip:
        name, _, reason = item.partition("=")
        if name:
            skipped[name] = reason or "explicitly skipped"

    findings = []
    meta = {}
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if obj.get("scanner") == "vibecheck":
            meta["done"] = obj.get("done", True)
            meta["version"] = obj.get("version", meta.get("version"))
            continue
        if "check" in obj:
            findings.append(obj)

    record = build(args.repo, findings, skipped, scope=args.scope or None)
    record["scan"] = meta
    text = json.dumps(record, indent=2, ensure_ascii=False)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        sys.stdout.write(json.dumps({"coverage": "written", "path": args.out}) + "\n")
    else:
        sys.stdout.write(text + "\n")


if __name__ == "__main__":
    main()
