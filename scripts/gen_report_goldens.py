#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Regenerate the founder/reviewer markdown golden reports.

The selected cases jointly pin the report edge cases: more than five
scenarios, conflicting evidence, an incomplete context, current private versus
future public risk, and both report profiles and languages.
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import canonical
import gen_goldens
import report

REPO_ROOT = canonical.REPO_ROOT
OUTPUT_DIR = os.path.join(REPO_ROOT, "tests", "golden", "reports")

CASES = (
    ("tests/golden/report-inputs/many-scenarios-conflicting-evidence.json",
     "founder", "en"),
    ("tests/golden/report-inputs/many-scenarios-conflicting-evidence.json",
     "reviewer", "et"),
    ("tests/golden/inputs/sensitive-high-impact-unknowns.json",
     "founder", "et"),
)


def _load(relative_path):
    with open(os.path.join(REPO_ROOT, relative_path), encoding="utf-8") as fh:
        return json.load(fh)


def artifacts():
    rendered = {}
    for source, profile, language in CASES:
        spec = _load(source)
        envelope = gen_goldens.build_case(spec)
        derived = report.derive_into(
            envelope, audience=profile, language=language, now=spec["now"])
        problems = canonical.validate_envelope(derived)
        if problems:
            raise SystemExit("report case %s does not validate:\n  %s"
                             % (spec["case_id"], "\n  ".join(problems)))
        name = "%s.%s.%s.md" % (spec["case_id"], profile, language)
        rendered[os.path.join(OUTPUT_DIR, name)] = report.render(
            derived, profile=profile, language=language, now=spec["now"])
    return rendered


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true",
                        help="fail if a committed report differs; do not write")
    args = parser.parse_args(argv)
    stale = []
    for path, body in sorted(artifacts().items()):
        relative = os.path.relpath(path, REPO_ROOT)
        if args.check:
            try:
                with open(path, encoding="utf-8") as fh:
                    current = fh.read()
            except OSError:
                current = ""
            if current != body:
                stale.append(relative)
            else:
                print("current: %s" % relative)
            continue
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(body)
        print("wrote: %s" % relative)
    if stale:
        for relative in stale:
            print("stale: %s" % relative, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
