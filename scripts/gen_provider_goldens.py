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
    review once it may write, one where the strongest method is missing for a
    reason the user could fix, and the specialist tools being compared on
    install, cost, egress and target rather than on reputation.

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
SECRETS_HISTORY = "vibecheck.control.secrets.no_repo_history_leaks"

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
    {
        "id": "specialist-secret-scanner-installed",
        "title": "A specialist secret scanner is installed",
        "why": "Gitleaks is free, unattended and written by people who do only "
               "this, so it goes ahead of a person reading the repository by "
               "hand and ahead of the bundled grep. TruffleHog is the same "
               "strength and loses on the declared order, which is what the "
               "order is for. Note the last line: covering the requirement is "
               "not closing the control, and a scanner that found nothing has "
               "not established that there is nothing.",
        "requirement": providers_mod.requirement(
            SECRETS_HISTORY, "developer_only"),
        "offer": providers_mod.offer(
            environment="developer_only", targets=["source_tree"],
            tools=["gitleaks", "trufflehog"], authorized_providers="all"),
    },
    {
        "id": "specialist-secret-scanner-missing",
        "title": "The same review, without the scanner installed",
        "why": "The plan falls back to a person reading the source, and the "
               "uninstalled tool does not disappear: it is a gap whose grant "
               "is one install command. vibecheck never runs that command "
               "itself — what executes on the user's machine is the user's "
               "decision.",
        "requirement": providers_mod.requirement(
            SECRETS_HISTORY, "developer_only"),
        "offer": providers_mod.offer(
            environment="developer_only", targets=["source_tree"],
            authorized_providers="all"),
    },
    {
        "id": "sast-cost-comparison",
        "title": "Two SAST tools, one compute budget",
        "why": "Semgrep and CodeQL both claim the SQL control at the same "
               "strength. CodeQL finds more and declares high compute, which "
               "this offer did not accept, so it is excluded on cost and "
               "reported as a gap rather than silently skipped. Cost is a "
               "selection input exactly like authorization is.",
        "requirement": providers_mod.requirement(
            "vibecheck.control.input.sql_parameterized", "developer_only"),
        "offer": providers_mod.offer(
            environment="developer_only", targets=["source_tree"],
            tools=["semgrep", "codeql"], authorized_providers="all"),
    },
    {
        "id": "codex-security-send-gated",
        "title": "Codex Security joins the SAST comparison",
        "why": "Codex Security claims the same SQL control at the same "
               "indicative strength as Semgrep and ranks between Semgrep and "
               "CodeQL on the declared order. Its local tree scan needs no "
               "grant, so under this offer it is selected; opening the opt-in "
               "send mode for model validation is a network + egress "
               "decision, so a send-enabled run must say where the source "
               "excerpts go, exactly as the dependency auditors must.",
        "requirement": providers_mod.requirement(
            "vibecheck.control.input.sql_parameterized", "developer_only"),
        "offer": providers_mod.offer(
            environment="developer_only", targets=["source_tree"],
            tools=["semgrep", "codex-security", "codeql"],
            authorized_providers="all"),
    },
    {
        "id": "dependency-audit-egress",
        "title": "A dependency audit that has to phone home",
        "why": "Both dependency auditors send the project's package names and "
               "versions to a remote database. With no egress grant they are "
               "excluded and the plan says which destination each one would "
               "have reached — a supply-chain inventory leaving the machine is "
               "a decision, not an implementation detail.",
        "requirement": providers_mod.requirement(
            "vibecheck.control.deps.vuln_scanning", "developer_only"),
        "offer": providers_mod.offer(
            environment="developer_only", targets=["source_tree"],
            tools=["osv-scanner", "trivy"], authorized_providers="all"),
    },
    {
        "id": "dast-authorized-against-staging",
        "title": "A DAST scan of an authorized staging deployment",
        "why": "ZAP needs the target URL, the owner's authorization and a "
               "network grant before it is selectable at all, and the plan "
               "states all three as a request rather than an instruction. Its "
               "closure threshold is the honest part: a baseline scan reports "
               "on the routes its crawler reached, and a quiet report mostly "
               "means the crawler never got past the login.",
        "requirement": providers_mod.requirement(
            "vibecheck.control.deploy.cors_restricted", "private_test"),
        "offer": providers_mod.offer(
            environment="private_test",
            targets=["source_tree", "deployed_web_app"],
            tools=["zap.sh"], inputs=["target_url", "scan_authorization"],
            authorized_providers="all", authorized_effects=LIVE_EFFECTS),
    },
    {
        "id": "dast-without-a-deployment",
        "title": "The same DAST requirement with no deployment to point at",
        "why": "A scanner with nothing to observe is inapplicable, not a gap: "
               "there is no work to schedule and no grant that would change "
               "that. The distinction matters, because a gap is a to-do and an "
               "inapplicable provider is not.",
        "requirement": providers_mod.requirement(
            "vibecheck.control.deploy.cors_restricted", "private_test"),
        "offer": providers_mod.offer(
            environment="private_test", targets=["source_tree"],
            tools=["zap.sh"], authorized_providers="all",
            authorized_effects=LIVE_EFFECTS),
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
