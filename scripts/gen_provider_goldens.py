#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Regenerate the golden provider-selection cases (gh issue #8).

Each case states one requirement and one offer — what this review has, and
what its owner has actually authorized — and the script writes the plan the
selection policy produces for it: which provider was chosen, which stronger
ones were refused and why, what is still uncovered, and the exact grant that
would close the difference.

The plans are committed so that:

  * the fallback chain is reviewable as English prose rather than only as code;
  * the same requirement and the same capabilities demonstrably produce the
    same plan (--check fails on any drift, in CI and in the tests);
  * the cases that matter are pinned side by side — a review with nothing
    authorized, the same review once the probe is allowed to run, the same
    review once it may write, and one where the strongest method is missing
    for a reason the user could fix.

Usage: python3 scripts/gen_provider_goldens.py [--check]   (run from anywhere)
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import providers as providers_mod

REPO_ROOT = providers_mod.REPO_ROOT
OUTPUT_PATH = os.path.join(REPO_ROOT, "tests", "golden", "providers",
                           "selection.md")

ANON = "vibecheck.control.authz.anon_data_access"
IDOR = "vibecheck.control.authz.object_level"

PROBE_INPUTS = ["supabase_url", "supabase_anon_key", "test_account_a_token",
                "test_account_b_token", "known_private_record_id"]
BROWSER_INPUTS = ["deployment_base_url", "test_account_a_login",
                  "test_account_b_login", "known_private_record_url",
                  "two_account_flow_spec"]
LIVE_EFFECTS = ["network", "data_egress", "credentials"]


def _cells(actor, object_class, object_ref, operations):
    return [{"actor": actor, "object_class": object_class,
             "object_ref": object_ref, "operation": operation}
            for operation in operations]


CASES = [
    {
        "id": "nothing-authorized",
        "title": "A review that has been given the source and nothing else",
        "why": "The safe default. Every live method needs a grant nobody has "
               "given yet, so the plan falls all the way to reading the "
               "source — and says so, instead of implying the reading settled "
               "anything.",
        "requirement": providers_mod.requirement(
            IDOR, "private_test",
            cells=_cells("other_account", "user_owned_record", "public.orders",
                         ["read", "create", "update", "delete"])),
        "offer": providers_mod.offer(environment="private_test",
                                     targets=["source_tree"]),
    },
    {
        "id": "probe-authorized-read-only",
        "title": "The Supabase probe is authorized, read-only",
        "why": "The strongest applicable method runs, and covers exactly one "
               "of the four requested cells. The other three are not quietly "
               "dropped: they are gaps with the grant that would reach them.",
        "requirement": providers_mod.requirement(
            IDOR, "private_test",
            cells=_cells("other_account", "user_owned_record", "public.orders",
                         ["read", "create", "update", "delete"])),
        "offer": providers_mod.offer(
            environment="private_test",
            targets=["source_tree", "supabase_project", "deployed_web_app"],
            inputs=PROBE_INPUTS + BROWSER_INPUTS,
            authorized_providers=["prov-supabase-probe",
                                  "prov-guided-browser-test"],
            authorized_effects=LIVE_EFFECTS),
    },
    {
        "id": "anon-matrix-write-withheld",
        "title": "The anonymous matrix, with writing withheld",
        "why": "The same provider covers the read cell and is refused the "
               "create cell, because covering it means inserting a row. A "
               "side effect excludes the aspect that needs it, not the "
               "provider.",
        "requirement": providers_mod.requirement(
            ANON, "private_test",
            cells=_cells("anonymous", "user_owned_record", "public.orders",
                         ["read", "create"])),
        "offer": providers_mod.offer(
            environment="private_test",
            targets=["source_tree", "supabase_project"],
            inputs=PROBE_INPUTS,
            authorized_providers=["prov-supabase-probe"],
            authorized_effects=LIVE_EFFECTS),
    },
    {
        "id": "anon-matrix-write-authorized",
        "title": "The anonymous matrix, with writing authorized",
        "why": "The same requirement and the same provider, one grant later. "
               "This is the whole point of recording effects: the difference "
               "between the two plans is a decision somebody made, and it is "
               "visible.",
        "requirement": providers_mod.requirement(
            ANON, "private_test",
            cells=_cells("anonymous", "user_owned_record", "public.orders",
                         ["read", "create"])),
        "offer": providers_mod.offer(
            environment="private_test",
            targets=["source_tree", "supabase_project"],
            inputs=PROBE_INPUTS,
            authorized_providers=["prov-supabase-probe"],
            authorized_effects=LIVE_EFFECTS + ["write"]),
    },
    {
        "id": "authorized-for-a-different-environment",
        "title": "Authorized for the pilot, asked about production",
        "why": "The probe is installed, credentialed and authorized — for the "
               "pilot. The question is about production. Permission does not "
               "stretch to a scope nobody approved, and an observation made "
               "in the pilot would not have answered the question anyway, so "
               "the plan falls back and asks for the grant it actually needs.",
        "requirement": providers_mod.requirement(
            ANON, "public_release",
            cells=_cells("anonymous", "user_owned_record", "public.orders",
                         ["read"])),
        "offer": providers_mod.offer(
            environment="private_test",
            targets=["source_tree", "supabase_project"],
            inputs=PROBE_INPUTS,
            authorized_providers=["prov-supabase-probe"],
            authorized_effects=LIVE_EFFECTS),
    },
    {
        "id": "no-supabase-guided-fallback",
        "title": "No Supabase project, no Playwright, one available person",
        "why": "The two automated methods are gone for different reasons — "
               "one has nothing to observe, the other is not installed — and "
               "only the second is a gap. A person with a browser is what is "
               "left, and it is a real observation, not a consolation.",
        "requirement": providers_mod.requirement(
            IDOR, "public_release",
            cells=_cells("other_account", "user_owned_record",
                         "/orders/{id}", ["read"])),
        "offer": providers_mod.offer(
            environment="public_release",
            targets=["source_tree", "deployed_web_app"],
            inputs=BROWSER_INPUTS,
            authorized_providers=["prov-guided-browser-test",
                                  "prov-playwright-two-account"],
            authorized_effects=LIVE_EFFECTS),
    },
    {
        "id": "playwright-installed",
        "title": "Playwright is installed and authorized",
        "why": "The declared fallback order decides between two methods of "
               "equal strength, and the cheapest one still goes first. What "
               "Playwright adds is the cells the probe cannot reach at all.",
        "requirement": providers_mod.requirement(
            IDOR, "private_test",
            cells=_cells("other_account", "user_owned_record", "public.orders",
                         ["read", "create", "update", "delete"])),
        "offer": providers_mod.offer(
            environment="private_test",
            targets=["source_tree", "supabase_project", "deployed_web_app"],
            tools=["node", "playwright"],
            inputs=PROBE_INPUTS + BROWSER_INPUTS,
            authorized_providers=["prov-supabase-probe",
                                  "prov-playwright-two-account"],
            authorized_effects=LIVE_EFFECTS + ["write"]),
    },
]


def render():
    lines = [
        "# Provider selection, worked cases",
        "",
        "Generated by `scripts/gen_provider_goldens.py`; do not edit by hand.",
        "",
        "Each case is one requirement and one offer. The plan under it is what "
        "`scripts/providers.py` selects, in the order it ranks them, with "
        "every refusal named. Registry: `%s` %s."
        % (providers_mod.registry_ref()["name"],
           providers_mod.registry_ref()["version"]),
        "",
    ]
    for case in CASES:
        plan = providers_mod.select(case["requirement"], case["offer"])
        lines.append("## %s" % case["title"])
        lines.append("")
        lines.append(case["why"])
        lines.append("")
        lines.append("```text")
        lines.extend(providers_mod.explain(plan))
        lines.append("```")
        lines.append("")
        requests = plan["authorization_requests"]
        if requests:
            lines.append("Authorization:")
            lines.append("")
            for request in requests:
                lines.append("- **%s** — %s"
                             % (request["reason"], request["prompt_en"]))
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true",
                        help="fail if the committed golden is stale")
    args = parser.parse_args()

    rendered = render()
    if args.check:
        if not os.path.exists(OUTPUT_PATH):
            print("missing golden: %s" % OUTPUT_PATH)
            return 1
        with open(OUTPUT_PATH, encoding="utf-8") as fh:
            if fh.read() != rendered:
                print("stale golden: %s — run "
                      "python3 scripts/gen_provider_goldens.py" % OUTPUT_PATH)
                return 1
        print("provider selection goldens are current")
        return 0

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w", encoding="utf-8") as fh:
        fh.write(rendered)
    print("wrote %s" % os.path.relpath(OUTPUT_PATH, REPO_ROOT))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
