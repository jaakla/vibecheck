#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Regenerate the canonical control registry and vibecheck_v1 framework mapping.

Outputs (both derived from scripts/items.py + scripts/controls.py):

  schema/vibecheck.controls.v1.json   stable control registry
  schema/mappings/vibecheck_v1.json   full 89-entry lossless framework mapping

Usage: python3 scripts/gen_canonical.py [--check]   (run from anywhere)

--check fails when a committed artifact differs from the regenerated one,
mirroring gen_map.py; tests/test_canonical.py enforces the same.
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import controls

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REGISTRY_OUT = os.path.join(REPO_ROOT, "schema", "vibecheck.controls.v1.json")
MAPPING_OUT = os.path.join(REPO_ROOT, "schema", "mappings", "vibecheck_v1.json")


def render(doc):
    return json.dumps(doc, ensure_ascii=False, indent=2) + "\n"


def artifacts():
    return {
        REGISTRY_OUT: render(controls.build_registry()),
        MAPPING_OUT: render(controls.build_framework_mapping()),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true",
                        help="fail if a committed artifact differs; do not modify it")
    args = parser.parse_args()
    stale = []
    for path, rendered in artifacts().items():
        rel = os.path.relpath(path, REPO_ROOT)
        if args.check:
            try:
                with open(path, encoding="utf-8") as fh:
                    current = fh.read()
            except OSError:
                current = ""
            if current != rendered:
                stale.append(rel)
            else:
                print("current: %s" % rel)
        else:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(rendered)
            print("wrote %s" % rel)
    if stale:
        for rel in stale:
            print("stale: %s (run python3 scripts/gen_canonical.py)" % rel,
                  file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
