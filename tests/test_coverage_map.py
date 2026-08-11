#!/usr/bin/env python3
"""Consistency tests across the item bank, the scanner, and the generated map.

These exist because the three drifted apart: the README advertised nine
deterministic items, the generated map said four, and the hardcoded set in
gen_map.py listed items the scanner only ever reports as MANUAL.
"""
import os
import re
import subprocess
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "scripts"))

import items  # noqa: E402

SCANNER = os.path.join(REPO, "scripts", "vibecheck.sh")
MAP = os.path.join(REPO, "references", "checklist-map.md")

# emit "check.id" "[1,2]" "STATUS" ...
EMIT = re.compile(r'^\s*(?:\|\|\s*)?emit\s+"([a-z0-9_.]+)"\s+"\[([0-9,\s]*)\]"', re.M)


def scanner_emits():
    """check id -> set of checklist item numbers, as written in vibecheck.sh."""
    with open(SCANNER) as fh:
        source = fh.read()
    found = {}
    for check, nums in EMIT.findall(source):
        parsed = {int(n) for n in nums.split(",") if n.strip()}
        found.setdefault(check, set()).update(parsed)
    return found


class TestItemBank(unittest.TestCase):
    def test_item_count_is_89(self):
        self.assertEqual(items.item_count(), 89)

    def test_every_item_has_all_wordings(self):
        n = 0
        for cat in items.CATEGORIES:
            for it in cat["items"]:
                n += 1
                self.assertEqual(len(it), 7, f"item {n} has {len(it)} fields, expected 7")
                for i, field in enumerate(it):
                    self.assertTrue(str(field).strip(), f"item {n} field {i} is empty")

    def test_every_item_has_verification_metadata(self):
        for n in range(1, items.item_count() + 1):
            self.assertIn(n, items.VERIFICATION, f"item {n} missing from VERIFICATION")
            codes, tools = items.VERIFICATION[n]
            self.assertTrue(codes and tools, f"item {n} has empty verification metadata")
            for c in codes:
                self.assertIn(c, {"AUTO", "AI", "MAN", "E2E", "SPEC"})

    def test_verification_has_no_extra_items(self):
        extra = set(items.VERIFICATION) - set(range(1, items.item_count() + 1))
        self.assertEqual(extra, set(), f"VERIFICATION has entries for missing items: {extra}")

    def test_severities_are_known(self):
        for cat in items.CATEGORIES:
            for it in cat["items"]:
                self.assertIn(it[0], items.WEIGHT)


class TestScannerCoverageMap(unittest.TestCase):
    """items.SCANNER_CHECKS must describe exactly what vibecheck.sh emits."""

    @classmethod
    def setUpClass(cls):
        cls.emitted = scanner_emits()

    def test_scanner_parse_found_checks(self):
        self.assertGreater(len(self.emitted), 30,
                           "emit() parser found almost nothing — has the syntax changed?")

    def test_no_check_missing_from_items_py(self):
        missing = sorted(set(self.emitted) - set(items.SCANNER_CHECKS))
        self.assertEqual(missing, [],
                         f"vibecheck.sh emits checks absent from items.SCANNER_CHECKS: {missing}")

    def test_no_stale_checks_in_items_py(self):
        stale = sorted(set(items.SCANNER_CHECKS) - set(self.emitted))
        self.assertEqual(stale, [],
                         f"items.SCANNER_CHECKS lists checks the scanner no longer emits: {stale}")

    def test_item_numbers_agree(self):
        for check, nums in sorted(self.emitted.items()):
            declared = set(items.SCANNER_CHECKS[check][0])
            self.assertEqual(nums, declared,
                             f"{check}: scanner maps to {sorted(nums)}, "
                             f"items.py declares {sorted(declared)}")

    def test_all_mapped_items_exist(self):
        for check, (nums, _tier) in items.SCANNER_CHECKS.items():
            for n in nums:
                self.assertTrue(1 <= n <= items.item_count(),
                                f"{check} maps to out-of-range item {n}")

    def test_tiers_are_valid(self):
        for check, (_nums, tier) in items.SCANNER_CHECKS.items():
            self.assertIn(tier, items.TIER_ORDER, f"{check} has unknown tier {tier!r}")

    def test_manual_tier_checks_never_claim_automation(self):
        """A MANUAL-tier check must be a reviewer to-do, not a real detection."""
        with open(SCANNER) as fh:
            source = fh.read()
        for check, (_nums, tier) in items.SCANNER_CHECKS.items():
            if tier != "MANUAL":
                continue
            for line in re.findall(r'^\s*emit\s+"%s".*$' % re.escape(check), source, re.M):
                self.assertIn('"MANUAL"', line,
                              f"{check} is tiered MANUAL but emits a non-MANUAL status")


class TestGeneratedMapIsCurrent(unittest.TestCase):
    def test_checklist_map_matches_generator(self):
        """references/checklist-map.md must be the committed output of gen_map.py."""
        with open(MAP) as fh:
            before = fh.read()
        subprocess.run([sys.executable, os.path.join(REPO, "scripts", "gen_map.py")],
                       check=True, capture_output=True)
        with open(MAP) as fh:
            after = fh.read()
        self.assertEqual(before, after,
                         "checklist-map.md is stale — run: python3 scripts/gen_map.py")

    def test_map_reports_the_real_tier_counts(self):
        with open(MAP) as fh:
            text = fh.read()
        cov = items.coverage_by_item()
        for tier in items.TIER_ORDER:
            count = sum(1 for t in cov.values() if t == tier)
            self.assertIn("- %s: %d items" % (tier, count), text,
                          f"map does not report {count} {tier} items")


class TestDocsAgree(unittest.TestCase):
    """Counts stated in prose must match the item bank."""

    def _read(self, *parts):
        with open(os.path.join(REPO, *parts)) as fh:
            return fh.read()

    def test_no_stale_item_counts_anywhere(self):
        n = items.item_count()
        targets = [
            ("README.md",),
            (".claude-plugin", "plugin.json"),
            ("skills", "vibecheck-scan", "SKILL.md"),
            ("skills", "vibecheck-report", "SKILL.md"),
        ]
        for parts in targets:
            text = self._read(*parts)
            for stale in re.findall(r'\b(\d{2})-item\b', text):
                self.assertEqual(int(stale), n,
                                 f"{'/'.join(parts)} says {stale}-item, bank has {n}")

    def test_readme_does_not_contradict_tier_counts(self):
        readme = self._read("README.md")
        cov = items.coverage_by_item()
        for tier in items.TIER_ORDER:
            count = sum(1 for t in cov.values() if t == tier)
            self.assertIn("%d items" % count, readme,
                          f"README does not state the real {tier} count ({count})")


if __name__ == "__main__":
    unittest.main(verbosity=2)
