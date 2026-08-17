#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Regenerate the Supabase authorization lifecycle fixture (gh issue #7).

One envelope walks the whole vertical slice for a real Supabase authorization
problem, in the order it actually happens:

    static migration signal
        -> authorized read-only probe: anon reads an order row, account B
           reads account A's order, the invitations table returns nothing and
           stays inconclusive because empty is not denied
        -> failed controls, contextual risk per scope, founder scenario
        -> one remediation Action with three checkpoints:
             repository_patch  (diff-first, branch-first, approved before it ran)
             deployment        (its own consent, its own target and revision)
             live_verification (a fresh probe, after the deploy, by a provider
                                independent of whoever wrote and deployed it)
        -> reassessment: partial, not pass. The read cell is denied; create,
           update and delete on two representative object types are untested,
           and one observation never closes a control.
        -> an authorized, opt-in write probe then finds anon INSERT open,
           records what it created and that the row was deleted, and drops the
           control back to fail with a new blocking remediation Action.

Everything except the coverage requirement is deliberately ordinary: what makes
the fixture worth committing is that removing the deployment attempt, or
reading one denied request as a closed control, makes it invalid.

Risks, readiness, scenarios, the coverage Actions and the report are derived,
not written by hand, so the committed file also pins that derivation.

Usage: python3 scripts/gen_authz_fixture.py [--check]   (run from anywhere)
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import actions as actions_mod
import authz as authz_mod
import canonical
import context as ctx
import controls
import providers as providers_mod
import report as report_mod

REPO_ROOT = canonical.REPO_ROOT
OUTPUT_PATH = os.path.join(REPO_ROOT, "schema", "examples",
                           "supabase-authz-lifecycle.json")

NOW = "2026-08-16T12:00:00Z"
VALID_UNTIL = "2026-09-13T00:00:00Z"
PROJECT_URL = "https://acme-orders-pilot.supabase.co"

ANON = "vibecheck.control.authz.anon_data_access"
IDOR = "vibecheck.control.authz.object_level"
DEFAULT_DENY = "vibecheck.control.authz.server_side_default_deny"

PILOT = {"environment": "private_test", "intended_use": "invite_only_pilot"}
PUBLIC = {"environment": "public_release", "intended_use": "public_product"}


def _title(control_id):
    registry = {c["control_id"]: c for c in canonical.load_registry()["controls"]}
    return registry[control_id]["title"]["en"]


def _claim(control_ids, aspect):
    return {
        "control_ids": list(control_ids),
        "statement": "; ".join("The requirement of %s is met" % _title(c)
                               for c in control_ids),
        "aspect": aspect,
    }


def _read_only_side_effects(egress=True):
    return {"writes": False, "destructive": False, "external_accounts": False,
            "data_egress": egress,
            **({"details": "HTTP requests to the probed project URL only."}
               if egress else {})}


# --------------------------------------------------------------------- context

def build_context():
    return ctx.build_context(
        context_id="ctx-acme-orders-authz",
        application={
            "name": "Acme Orders",
            "description": "Lovable + Supabase order tracker piloted with "
                           "twelve named testers before a public launch decision.",
            "repo_ref": "github.com/acme/orders",
            "platform": "lovable+supabase",
        },
        target_scopes=[PILOT, PUBLIC],
        current_scope=PILOT,
        profile=ctx.profile({
            "lifecycle": "piloting",
            "audience_scale": "named_handful",
            "network_exposure": "unlisted_public_url",
            "authentication": "invite_only_accounts",
            "tenancy": "multi_tenant_shared_store",
            "data_sensitivity": "personal_data",
            "financial_operations": "none",
            "privileged_operations": "internal_admin_actions",
            "business_criticality": "supporting",
        }, source="founder:mari"),
        data_summary="Customer names, emails, delivery addresses, order lines, "
                     "and the invitation tokens that let a tester create an "
                     "account. No card data (hosted checkout).",
        assumptions=["The pilot stays limited to the twelve named testers.",
                     "No public marketing before the launch decision."],
        confirmation={
            "state": "human_reviewed",
            "confirmed_by": "founder:mari",
            "confirmed_at": "2026-08-12T10:00:00Z",
            "source_fingerprint": "sha256:2f7c1a44b0e9d3aa61c5f0b8e2d94c7a"
                                  "913e5b6f8d0a2c4e6b8d0f2a4c6e8b0d",
        },
        valid_until="2026-11-12T00:00:00Z",
        # The representative private object types. This inventory is what makes
        # coverage measurable: plan tiers are excluded only because someone
        # decided they are public, and that decision is recorded here.
        authorization_objects=[
            {"object_id": "obj-orders", "object_class": "user_owned_record",
             "locator": "public.orders", "intent": "private",
             "state": "confirmed", "source": "founder:mari",
             "description": "One customer's order with their delivery address."},
            {"object_id": "obj-invitations",
             "object_class": "credential_or_token_record",
             "locator": "public.invitations", "intent": "private",
             "state": "confirmed", "source": "founder:mari",
             "description": "Single-use invitation tokens; reading one is "
                            "enough to join the pilot as someone else."},
            {"object_id": "obj-plan-tiers", "object_class": "reference_data",
             "locator": "public.plan_tiers", "intent": "intended_public",
             "state": "confirmed", "source": "founder:mari",
             "description": "Published price tiers the marketing page reads."},
        ],
        reassess_triggers=[{"kind": "before_environment", "value": "public_release"},
                           {"kind": "context_change"}],
    )


# ------------------------------------------------------------------- providers

#: The capability records come from the bundled registry rather than being
#: restated here: a fixture that describes what the probe can do in its own
#: words is a second source of truth, and the one that drifts. Only the parts
#: the registry cannot know — this project's URL — are filled in.
def providers():
    return [
        providers_mod.instantiate("prov-migration-analysis",
                                  control_ids=[ANON, DEFAULT_DENY]),
        providers_mod.instantiate("prov-supabase-probe",
                                  control_ids=[ANON, IDOR],
                                  egress_destinations=[PROJECT_URL],
                                  network_targets=[PROJECT_URL]),
    ]


# ------------------------------------------------------------------ the record

def build_records():
    """Signals, evidence, assessments, actions, procedures and attempts."""
    signals, evidence, assessments = [], [], []

    def signal(signal_id, tool, check, subject, environment, observed_at, raw):
        signals.append({
            "signal_id": signal_id,
            "source": {"tool": tool, "check_id": check,
                       "provider_ref": ("prov-migration-analysis"
                                        if tool == "analyze_sql.py"
                                        else "prov-supabase-probe")},
            "subject": subject,
            "environment": environment,
            "observed_at": observed_at,
            "raw_ref": {"kind": "inline", "value": canonical.bound_raw(raw)},
        })

    # 1. Static signal: the source says no RLS. It is material, and it is not
    #    an observation of the deployed project, so it fills no coverage cell.
    signal("sig-rls-static-1", "analyze_sql.py", "missing_rls",
           {"kind": "file", "locator": "supabase/migrations/20260801_orders.sql"},
           "developer_only", "2026-08-12T11:02:14Z",
           '{"missing_rls":["public.orders"],"created":["public.orders",'
           '"public.invitations"],"rls_enabled":["public.invitations"]}')
    evidence.append({
        "evidence_id": "ev-rls-static-missing",
        "provider": {"name": "vibecheck SQL migration analysis", "version": "0.4.0",
                     "provider_ref": "prov-migration-analysis"},
        "subject": {"kind": "file",
                    "locator": "supabase/migrations/20260801_orders.sql"},
        "environment": "developer_only",
        "operation": "migration_analysis",
        "scope": "Recognized statements in the committed migrations only. The "
                 "migration creating public.orders has no matching ENABLE ROW "
                 "LEVEL SECURITY. This is a statement about the source tree; "
                 "the deployed project may differ in either direction.",
        "claim": _claim([ANON, DEFAULT_DENY],
                        "row level security enabled in the creating migration"),
        "direction": "refutes",
        "strength": "indicative",
        "observed_at": "2026-08-12T11:02:14Z",
        "valid_until": VALID_UNTIL,
        "signal_refs": ["sig-rls-static-1"],
        "raw_result_ref": {"kind": "inline",
                           "value": "create table public.orders without a "
                                    "matching enable row level security"},
        "side_effects": {"writes": False, "destructive": False,
                         "external_accounts": False, "data_egress": False},
    })

    # 2. The authorized read-only probe. Three requests, three cells.
    probe_authorization = {
        "authorized_by": "founder:mari",
        "granted_at": "2026-08-12T11:30:00Z",
        "scope": "read-only anon and two-account probe of the pilot project",
    }
    signal("sig-probe-orders-read-1", "supabase_probe.py", "anon_select",
           {"kind": "table", "locator": "public.orders"}, "private_test",
           "2026-08-12T11:40:31Z",
           '{"check":"anon_select","table":"public.orders","http":200,'
           '"verdict":"REVIEW_rows_readable_by_anon","rows_visible_to_anon":1}')
    evidence.append({
        "evidence_id": "ev-anon-read-orders-open",
        "provider": {"name": "supabase_probe.py", "version": "0.5.0",
                     "provider_ref": "prov-supabase-probe"},
        "subject": {"kind": "table", "locator": "public.orders"},
        "environment": "private_test",
        "operation": "http_select_anon_head",
        "scope": "One HEAD request with the public key against the pilot "
                 "project. Covers reading public.orders as an anonymous "
                 "caller: not writing it, not another table, not another actor.",
        "claim": _claim([ANON], "anonymous read of public.orders"),
        "direction": "refutes",
        "strength": "decisive",
        "observed_at": "2026-08-12T11:40:31Z",
        "valid_until": VALID_UNTIL,
        "signal_refs": ["sig-probe-orders-read-1"],
        "raw_result_ref": {"kind": "inline",
                           "value": "HTTP 200, one order row visible to the "
                                    "anon role; the founder confirms orders "
                                    "are private"},
        "authorization": probe_authorization,
        "side_effects": _read_only_side_effects(),
        "coverage": [{"object_ref": "public.orders", "object_id": "obj-orders",
                      "object_class": "user_owned_record", "actor": "anonymous",
                      "operation": "read", "observed": "allowed",
                      "environment": "private_test"}],
    })

    signal("sig-probe-invitations-read-1", "supabase_probe.py", "anon_select",
           {"kind": "table", "locator": "public.invitations"}, "private_test",
           "2026-08-12T11:41:02Z",
           '{"check":"anon_select","table":"public.invitations","http":200,'
           '"verdict":"NO_ROWS_VISIBLE_UNCONFIRMED","rows_visible_to_anon":0}')
    evidence.append({
        "evidence_id": "ev-anon-read-invitations-empty",
        "provider": {"name": "supabase_probe.py", "version": "0.5.0",
                     "provider_ref": "prov-supabase-probe"},
        "subject": {"kind": "table", "locator": "public.invitations"},
        "environment": "private_test",
        "operation": "http_select_anon_head",
        "scope": "Zero rows returned to the anon role, and no test account "
                 "read of the same window to establish that the table holds "
                 "anything. Empty and filtered are indistinguishable here, so "
                 "this settles nothing.",
        "claim": _claim([ANON], "anonymous read of public.invitations"),
        "direction": "neutral",
        "strength": "indicative",
        "observed_at": "2026-08-12T11:41:02Z",
        "valid_until": VALID_UNTIL,
        "signal_refs": ["sig-probe-invitations-read-1"],
        "raw_result_ref": {"kind": "inline",
                           "value": "HTTP 200, zero rows in the response window"},
        "authorization": probe_authorization,
        "side_effects": _read_only_side_effects(),
        "coverage": [{"object_ref": "public.invitations",
                      "object_id": "obj-invitations",
                      "object_class": "credential_or_token_record",
                      "actor": "anonymous", "operation": "read",
                      "observed": "inconclusive", "environment": "private_test",
                      "note": "an empty response is not a denial"}],
    })

    signal("sig-probe-idor-1", "supabase_probe.py", "idor",
           {"kind": "table", "locator": "public.orders"}, "private_test",
           "2026-08-12T11:44:10Z",
           '{"check":"idor","table":"public.orders","record_id":"ord-7c1a",'
           '"http":200,"verdict":"FAIL_cross_account_read","rows_visible_to_b":1}')
    evidence.append({
        "evidence_id": "ev-idor-orders-open",
        "provider": {"name": "supabase_probe.py", "version": "0.5.0",
                     "provider_ref": "prov-supabase-probe"},
        "subject": {"kind": "table", "locator": "public.orders (record ord-7c1a)"},
        "environment": "private_test",
        "operation": "http_select_authenticated_cross_account",
        "scope": "Test account B requested one order owned by test account A "
                 "and received it. Covers reading that one record as an "
                 "unrelated account.",
        "claim": _claim([IDOR], "cross-account read of one order record"),
        "direction": "refutes",
        "strength": "decisive",
        "observed_at": "2026-08-12T11:44:10Z",
        "valid_until": VALID_UNTIL,
        "signal_refs": ["sig-probe-idor-1"],
        "raw_result_ref": {"kind": "inline",
                           "value": "account B read order ord-7c1a owned by "
                                    "account A"},
        "authorization": probe_authorization,
        "side_effects": _read_only_side_effects(),
        "coverage": [{"object_ref": "public.orders", "object_id": "obj-orders",
                      "object_class": "user_owned_record",
                      "actor": "other_account", "operation": "read",
                      "observed": "allowed", "environment": "private_test",
                      "instance": "ord-7c1a"}],
    })

    # 3. The failed controls.
    assessments.append({
        "assessment_id": "asm-anon-access-1",
        "control_id": ANON,
        "status": "fail",
        "assessor": {"kind": "human", "id": "reviewer:jaak"},
        "assessed_at": "2026-08-12T12:05:00Z",
        "basis": {
            "rationale": "An unauthenticated caller read an order row with the "
                         "public key, and the founder confirms orders are "
                         "private. The migration signal agrees.",
            "evidence_refs": ["ev-rls-static-missing", "ev-anon-read-orders-open"],
        },
    })
    assessments.append({
        "assessment_id": "asm-object-level-1",
        "control_id": IDOR,
        "status": "fail",
        "assessor": {"kind": "human", "id": "reviewer:jaak"},
        "assessed_at": "2026-08-12T12:06:00Z",
        "basis": {
            "rationale": "Account B read an order owned by account A.",
            "evidence_refs": ["ev-idor-orders-open"],
        },
    })

    # 4. Remediation, one checkpoint at a time.
    procedures = [
        {
            "procedure_id": "prc-orders-rls-migration-v1",
            "procedure_key": "orders-rls-migration",
            "revision": 1,
            "created_at": "2026-08-12T12:20:00Z",
            "title": "Enable RLS with owner-only policies in a committed migration",
            "executor_role": "developer",
            "execution_mode": "guided",
            "mechanism": "sql_migration",
            "stage": "repository_patch",
            "prerequisites": ["The ownership column of each private table is "
                              "agreed with the founder."],
            "required_inputs": ["Table list and ownership column (user_id)"],
            "effects": {
                "targets": ["supabase/migrations"],
                "write": True, "destructive": False, "deployment": False,
                "data": False, "external_accounts": False,
                "reversibility": "reversible",
            },
            "authorization": {
                "consent": "explicit_consent",
                "scope": "Write one migration file on a branch. Nothing is "
                         "deployed and no data is touched by this step.",
                "notes": "The diff is shown before the consent is asked for.",
            },
            "method": {
                "tool": "editor + git",
                "steps": [
                    "Write the migration: enable row level security on "
                    "public.orders, add owner-only select/insert/update "
                    "policies keyed on auth.uid() = user_id.",
                    "Open a branch and show the diff.",
                    "Commit only after the diff is approved.",
                ],
            },
            "cost": {"monetary": "none"},
            "network": {"required": False},
            "data_egress": {"occurs": False},
            "failure_behavior": {
                "on_failure": "Nothing outside the branch changes.",
                "rollback": "Delete the branch; the pilot project is untouched "
                            "because this step never reaches it.",
            },
            "success_evidence": "The reviewed diff on the approved branch. It is "
                                "evidence about the repository, not about the "
                                "running project.",
            "verification": {"provider": "reviewer reading the diff",
                             "independent_from_executor": True},
        },
        {
            "procedure_id": "prc-pilot-migration-deploy-v1",
            "procedure_key": "pilot-migration-deploy",
            "revision": 1,
            "created_at": "2026-08-12T12:20:00Z",
            "title": "Apply the approved migration to the pilot project",
            "executor_role": "developer",
            "execution_mode": "manual",
            "mechanism": "deployment",
            "stage": "deployment",
            "prerequisites": ["The migration is approved and committed.",
                              "The Supabase CLI is linked to the pilot project."],
            "required_inputs": ["The approved migration revision"],
            "effects": {
                "targets": ["pilot Supabase project"],
                "write": False, "destructive": False, "deployment": True,
                "data": False, "external_accounts": False,
                "reversibility": "reversible",
            },
            "authorization": {
                "consent": "explicit_consent_per_run",
                "scope": "Apply one named migration revision to the pilot "
                         "project only. Production is not linked and is not "
                         "part of this consent.",
                "notes": "Approving a diff is not approving a deploy; this is "
                         "asked for separately, per run.",
            },
            "method": {
                "tool": "supabase db push",
                "steps": ["Confirm the linked project is the pilot.",
                          "Push the approved migration revision.",
                          "Record the revision that is now live."],
            },
            "cost": {"monetary": "none"},
            "network": {"required": True,
                        "destinations": ["api.supabase.com",
                                         "db.acme-orders-pilot.supabase.co"],
                        "purpose": "Apply the migration to the linked project."},
            "data_egress": {"occurs": False},
            "failure_behavior": {
                "on_failure": "The migration fails closed: enabling row level "
                              "security without policies denies access rather "
                              "than exposing data, and pilot testers see errors.",
                "rollback": "Push the down migration and record that the "
                            "previous revision is live again.",
            },
            "success_evidence": "A deployment record naming the pilot project "
                                "and the exact revision now live.",
            "verification": {"provider": "supabase project migration history",
                             "independent_from_executor": True},
        },
        {
            "procedure_id": "prc-anon-read-reprobe-v1",
            "procedure_key": "anon-read-reprobe",
            "revision": 1,
            "created_at": "2026-08-12T12:20:00Z",
            "title": "Re-probe anonymous and cross-account reads after the deploy",
            "executor_role": "vibecheck_agent",
            "execution_mode": "automated",
            "mechanism": "live_probe",
            "stage": "live_verification",
            "prerequisites": ["The migration is deployed.",
                              "Two test account tokens exist so an empty "
                              "response can be told apart from a filtered one."],
            "required_inputs": ["SUPABASE_URL", "anon key", "test account tokens"],
            "effects": {
                "targets": ["pilot Supabase project:public.orders"],
                "write": False, "destructive": False, "deployment": False,
                "data": False, "external_accounts": False,
                "reversibility": "reversible",
            },
            "authorization": {
                "consent": "explicit_consent",
                "scope": "Read-only requests against the pilot project. No "
                         "write probe is included in this consent.",
            },
            "method": {
                "tool": "python3 scripts/supabase_probe.py",
                "reference": "skills/vibecheck-supabase/SKILL.md",
                "steps": ["Read public.orders as the anon role.",
                          "Read the same window as test account A to establish "
                          "the table is not empty.",
                          "Request account A's order as account B."],
            },
            "cost": {"monetary": "none"},
            "network": {"required": True, "destinations": [PROJECT_URL],
                        "purpose": "Send the probe requests."},
            "data_egress": {"occurs": True, "destinations": [PROJECT_URL]},
            "failure_behavior": {
                "on_failure": "The cells stay inconclusive and the control "
                              "stays unverified; no retry without fresh consent.",
                "rollback": "Nothing to roll back: no request in this procedure "
                            "changes state.",
            },
            "success_evidence": "One evidence record per observed cell, each "
                                "naming its object, actor, operation and "
                                "environment.",
            "verification": {"provider": "supabase_probe.py",
                             "independent_from_executor": True,
                             "provider_ref": "prov-supabase-probe"},
        },
        {
            "procedure_id": "prc-anon-write-probe-v1",
            "procedure_key": "anon-write-probe",
            "revision": 1,
            "created_at": "2026-08-14T09:30:00Z",
            "title": "Authorized anon write probe, with cleanup",
            "executor_role": "vibecheck_agent",
            "execution_mode": "automated",
            "mechanism": "live_probe",
            "stage": "live_verification",
            "prerequisites": [
                "The founder owns the target project.",
                "Explicit per-run consent: PostgREST has no dry-run insert, so "
                "this can create a real row and fire triggers.",
            ],
            "required_inputs": ["SUPABASE_URL", "anon key", "table list",
                                "target environment", "who authorized the run"],
            "effects": {
                "targets": ["pilot Supabase project:public.orders"],
                "write": True, "destructive": False, "deployment": False,
                "data": True, "external_accounts": False,
                "reversibility": "reversible",
            },
            "authorization": {
                "consent": "explicit_consent_per_run",
                "scope": "One anon INSERT attempt against public.orders in the "
                         "pilot project. Any row it creates is deleted by the "
                         "owner and the deletion is recorded.",
                "notes": "Never run against a project the user does not own.",
            },
            "method": {
                "tool": "python3 scripts/supabase_probe.py --write-probe",
                "reference": "skills/vibecheck-supabase/SKILL.md",
                "steps": ["Attempt one anon INSERT.",
                          "Record the created row identifier from the response.",
                          "Delete the row as the owner and record that it is gone."],
            },
            "cost": {"monetary": "none"},
            "network": {"required": True, "destinations": [PROJECT_URL],
                        "purpose": "Send the insert attempt."},
            "data_egress": {"occurs": True, "destinations": [PROJECT_URL]},
            "failure_behavior": {
                "on_failure": "The create cell stays inconclusive rather than "
                              "reading as denied.",
                "rollback": "Delete the created row by the identifier the "
                            "response returned, and record the deletion.",
            },
            "success_evidence": "The observed result of the insert attempt, "
                                "plus the recorded cleanup state.",
            "verification": {"provider": "supabase_probe.py",
                             "independent_from_executor": True,
                             "provider_ref": "prov-supabase-probe"},
        },
        {
            "procedure_id": "prc-anon-write-policy-migration-v1",
            "procedure_key": "anon-write-policy-migration",
            "revision": 1,
            "created_at": "2026-08-15T11:00:00Z",
            "title": "Remove the anon insert grant in a committed migration",
            "executor_role": "developer",
            "execution_mode": "guided",
            "mechanism": "sql_migration",
            "stage": "repository_patch",
            "prerequisites": ["The intended writers of public.orders are "
                              "agreed with the founder."],
            "required_inputs": ["The role each write path runs as"],
            "effects": {
                "targets": ["supabase/migrations"],
                "write": True, "destructive": False, "deployment": False,
                "data": False, "external_accounts": False,
                "reversibility": "reversible",
            },
            "authorization": {
                "consent": "explicit_consent",
                "scope": "Write one migration file on a branch; nothing is "
                         "deployed by this step.",
            },
            "method": {
                "tool": "editor + git",
                "steps": ["Revoke insert on public.orders from anon.",
                          "Restrict the insert policy to auth.uid() = user_id.",
                          "Show the diff before asking for consent."],
            },
            "cost": {"monetary": "none"},
            "network": {"required": False},
            "data_egress": {"occurs": False},
            "failure_behavior": {
                "on_failure": "Nothing outside the branch changes.",
                "rollback": "Delete the branch.",
            },
            "success_evidence": "The reviewed diff on the approved branch.",
            "verification": {"provider": "reviewer reading the diff",
                             "independent_from_executor": True},
        },
    ]

    actions = [
        {
            "action_id": "act-enforce-order-read-access-v1",
            "action_key": "enforce-order-read-access",
            "revision": 1,
            "created_at": "2026-08-12T12:15:00Z",
            "kind": "remediate",
            "outcome": "Anonymous and cross-account reads of public.orders are "
                       "denied in the deployed pilot project, observed after "
                       "the change is live.",
            "reason": "An anonymous caller read an order row and account B read "
                      "account A's order (asm-anon-access-1, asm-object-level-1).",
            "priority": "critical",
            "urgency": "immediate",
            "deadline": {
                "kind": "before_environment",
                "value": "public_release",
                "rationale": "Anonymous access to customer orders at public "
                             "launch is a critical contextual risk; during the "
                             "pilot it is already high.",
                "reassess_trigger": {"kind": "before_environment",
                                     "value": "public_release"},
            },
            "blocking_scope": [PUBLIC],
            "owner": {"role": "developer", "name": "dev:priit"},
            "state": "done",
            "state_history": [
                {"state": "open", "at": "2026-08-12T12:15:00Z", "by": "reviewer:jaak"},
                {"state": "in_progress", "at": "2026-08-13T14:50:00Z", "by": "dev:priit"},
                {"state": "done", "at": "2026-08-14T09:10:00Z", "by": "reviewer:jaak",
                 "note": "Patch, deploy and an independent re-probe each have "
                         "their own attempt and evidence. The read cells are "
                         "denied; the write cells were never part of this "
                         "outcome and stay open."},
            ],
            "control_refs": [ANON, IDOR],
            "procedure_refs": ["prc-orders-rls-migration-v1",
                               "prc-pilot-migration-deploy-v1",
                               "prc-anon-read-reprobe-v1"],
            "required_stages": ["repository_patch", "deployment",
                                "live_verification"],
            "success_evidence": "A re-probe after the deploy showing anon reads "
                                "denied on a table established as non-empty, "
                                "and account B refused account A's order. The "
                                "original warning disappearing is not evidence.",
            "reassess_control_ids": [ANON, IDOR],
        },
        {
            "action_id": "act-probe-anon-write-v1",
            "action_key": "probe-anon-write",
            "revision": 1,
            "created_at": "2026-08-14T09:30:00Z",
            "kind": "verify",
            "outcome": "What an anonymous caller can insert into public.orders "
                       "is observed and recorded, with any created row removed.",
            "reason": "The read cells are denied and the write cells were never "
                      "observed. An untested operation is not a denied one "
                      "(asm-anon-access-2).",
            "priority": "high",
            "urgency": "immediate",
            "deadline": {
                "kind": "before_environment",
                "value": "public_release",
                "rationale": "An anon-writable orders table would let anyone "
                             "forge orders at launch.",
                "reassess_trigger": {"kind": "before_environment",
                                     "value": "public_release"},
            },
            "blocking_scope": [PUBLIC],
            "owner": {"role": "founder", "name": "founder:mari"},
            "state": "done",
            "state_history": [
                {"state": "open", "at": "2026-08-14T09:30:00Z", "by": "reviewer:jaak"},
                {"state": "in_progress", "at": "2026-08-15T09:55:00Z", "by": "founder:mari"},
                {"state": "done", "at": "2026-08-15T10:30:00Z", "by": "reviewer:jaak",
                 "note": "Observed: the insert succeeded. The probe row was "
                         "deleted and the control went back to fail."},
            ],
            "control_refs": [ANON],
            "procedure_refs": ["prc-anon-write-probe-v1"],
            "required_stages": ["live_verification"],
            "success_evidence": "A recorded observation of the anon insert "
                                "attempt, whichever way it went, plus the "
                                "cleanup state of anything it created.",
            "reassess_control_ids": [ANON],
        },
        {
            "action_id": "act-deny-anon-order-writes-v1",
            "action_key": "deny-anon-order-writes",
            "revision": 1,
            "created_at": "2026-08-15T10:35:00Z",
            "kind": "remediate",
            "outcome": "Anonymous inserts into public.orders are denied in the "
                       "deployed project, observed by a re-run of the write "
                       "probe after the change is live.",
            "reason": "The authorized write probe created a row in public.orders "
                      "with nothing but the public key (asm-anon-access-3).",
            "priority": "critical",
            "urgency": "immediate",
            "deadline": {
                "kind": "immediate",
                "rationale": "The pilot is live with real testers and anyone "
                             "holding the public key can write to it now.",
                "reassess_trigger": {"kind": "context_change"},
            },
            "blocking_scope": [PILOT, PUBLIC],
            "owner": {"role": "developer", "name": "dev:priit"},
            "state": "open",
            "state_history": [
                {"state": "open", "at": "2026-08-15T10:35:00Z", "by": "reviewer:jaak"},
            ],
            "control_refs": [ANON],
            "risk_refs": [],
            "procedure_refs": ["prc-anon-write-policy-migration-v1",
                               "prc-pilot-migration-deploy-v1",
                               "prc-anon-write-probe-v1"],
            "required_stages": ["repository_patch", "deployment",
                                "live_verification"],
            "success_evidence": "The write probe re-run after the deploy, "
                                "observing the insert refused. The committed "
                                "migration on its own is not the fix.",
            "reassess_control_ids": [ANON],
        },
    ]

    attempts = [
        {
            "attempt_id": "att-orders-rls-patch-1",
            "procedure_ref": "prc-orders-rls-migration-v1",
            "action_ref": "act-enforce-order-read-access-v1",
            "authorization": {
                "authorization_id": "auth-orders-rls-patch-1",
                "attempt_ref": "att-orders-rls-patch-1",
                "authorized_by": "founder:mari",
                "granted_at": "2026-08-13T14:45:00Z",
                "expires_at": "2026-08-13T20:00:00Z",
                "scope": "Write the RLS migration on branch fix/orders-rls. "
                         "Nothing is deployed under this consent.",
                "mode": "explicit_consent",
                "record": "PR #14, approval comment",
                "effects": {
                    "targets": ["supabase/migrations/20260813_orders_rls.sql"],
                    "write": True, "destructive": False, "deployment": False,
                    "data": False, "external_accounts": False,
                    "data_egress": False, "data_egress_destinations": [],
                },
            },
            "executor": {"kind": "human", "id": "dev:priit"},
            "execution_environment": "developer_only",
            "execution_context": {
                "kind": "local", "locator": "workstation dev:priit",
                "source_ref": "branch fix/orders-rls @ 3f9c1ab",
                "tool_versions": {"git": "2.45.2"},
            },
            "input_refs": [
                {"name": "ownership column", "kind": "record",
                 "locator": "PR #14 description"},
            ],
            "started_at": "2026-08-13T15:00:00Z",
            "finished_at": "2026-08-13T15:40:00Z",
            "result": "succeeded",
            "side_effects_observed": {
                "targets": ["supabase/migrations/20260813_orders_rls.sql"],
                "write": True, "destructive": False, "deployment": False,
                "data": False, "external_accounts": False,
                "data_egress": False, "data_egress_destinations": [],
                "details": ["One migration file added on branch fix/orders-rls.",
                            "No running system was touched by this attempt."],
            },
            "change_control": {
                "diff_ref": {"kind": "file",
                             "value": "supabase/migrations/20260813_orders_rls.sql"},
                "branch": "fix/orders-rls",
                "base_ref": "main @ 91e77c0",
                "approved_by": "founder:mari",
                "approved_at": "2026-08-13T14:45:00Z",
                "review_record": "PR #14",
            },
            "rollback": {"state": "not_needed",
                         "notes": "The branch is the change; deleting it undoes "
                                  "everything this attempt did."},
            "evidence_refs": ["ev-rls-migration-diff"],
            "notes": "The diff was shown and approved before the file was "
                     "committed.",
        },
        {
            "attempt_id": "att-orders-rls-deploy-1",
            "procedure_ref": "prc-pilot-migration-deploy-v1",
            "action_ref": "act-enforce-order-read-access-v1",
            "authorization": {
                "authorization_id": "auth-orders-rls-deploy-1",
                "attempt_ref": "att-orders-rls-deploy-1",
                "authorized_by": "founder:mari",
                "granted_at": "2026-08-13T16:00:00Z",
                "expires_at": "2026-08-13T18:00:00Z",
                "scope": "Apply migration 20260813_orders_rls to the pilot "
                         "project. This is a second decision, asked for after "
                         "the diff was approved.",
                "mode": "explicit_consent",
                "record": "chat approval 2026-08-13 16:00, quoted in PR #14",
                "effects": {
                    "targets": ["pilot Supabase project:public.orders policies"],
                    "write": False, "destructive": False, "deployment": True,
                    "data": False, "external_accounts": False,
                    "data_egress": False, "data_egress_destinations": [],
                },
            },
            "executor": {"kind": "human", "id": "dev:priit"},
            "execution_environment": "private_test",
            "execution_context": {
                "kind": "staging", "locator": "supabase project acme-orders-pilot",
                "source_ref": "migration 20260813_orders_rls (merge commit 7d20fe1)",
                "tool_versions": {"supabase-cli": "1.192.5"},
            },
            "input_refs": [
                {"name": "approved migration", "kind": "file",
                 "locator": "supabase/migrations/20260813_orders_rls.sql"},
                {"name": "project access token", "kind": "secret_store",
                 "locator": "1password://acme/supabase-cli", "sensitive": True},
            ],
            "started_at": "2026-08-13T16:10:00Z",
            "finished_at": "2026-08-13T16:20:00Z",
            "result": "succeeded",
            "side_effects_observed": {
                "targets": ["pilot Supabase project:public.orders policies"],
                "write": False, "destructive": False, "deployment": True,
                "data": False, "external_accounts": False,
                "data_egress": False, "data_egress_destinations": [],
                "details": ["Migration 20260813_orders_rls applied to the pilot "
                            "project; no rows were modified."],
            },
            "rollback": {"state": "not_needed",
                         "notes": "The deploy succeeded; the down migration is "
                                  "ready if the pilot reports access errors."},
            "evidence_refs": ["ev-rls-deployment-record"],
            "notes": "Production is not linked to this CLI session and was not "
                     "part of the consent.",
        },
        {
            "attempt_id": "att-orders-rls-verify-1",
            "procedure_ref": "prc-anon-read-reprobe-v1",
            "action_ref": "act-enforce-order-read-access-v1",
            "authorization": {
                "authorization_id": "auth-orders-rls-verify-1",
                "attempt_ref": "att-orders-rls-verify-1",
                "authorized_by": "founder:mari",
                "granted_at": "2026-08-14T08:45:00Z",
                "expires_at": "2026-08-14T12:00:00Z",
                "scope": "Read-only re-probe of the pilot project: anon read of "
                         "public.orders, the same window as account A, and one "
                         "cross-account read.",
                "mode": "explicit_consent",
                "record": "chat approval 2026-08-14 08:45",
                "effects": {
                    "targets": ["pilot Supabase project:public.orders"],
                    "write": False, "destructive": False, "deployment": False,
                    "data": False, "external_accounts": False,
                    "data_egress": True, "data_egress_destinations": [PROJECT_URL],
                },
            },
            "executor": {"kind": "agent", "id": "vibecheck:supabase-probe"},
            "execution_environment": "private_test",
            "execution_context": {
                "kind": "sandbox", "locator": "vibecheck runner",
                "source_ref": "supabase_probe.py 0.5.0",
                "tool_versions": {"supabase_probe.py": "0.5.0"},
            },
            "input_refs": [
                {"name": "SUPABASE_URL", "kind": "environment_variable",
                 "locator": "SUPABASE_URL"},
                {"name": "anon key", "kind": "environment_variable",
                 "locator": "SUPABASE_ANON_KEY", "sensitive": True},
                {"name": "test account tokens", "kind": "environment_variable",
                 "locator": "SUPABASE_JWT_A / SUPABASE_JWT_B", "sensitive": True},
            ],
            "started_at": "2026-08-14T08:50:00Z",
            "finished_at": "2026-08-14T09:00:00Z",
            "result": "succeeded",
            "side_effects_observed": {
                "targets": ["pilot Supabase project:public.orders"],
                "write": False, "destructive": False, "deployment": False,
                "data": False, "external_accounts": False,
                "data_egress": True, "data_egress_destinations": [PROJECT_URL],
                "details": ["Read-only requests to the pilot project."],
            },
            "rollback": {"state": "not_needed",
                         "notes": "No request in this attempt changed state."},
            "evidence_refs": ["ev-anon-read-orders-denied", "ev-idor-orders-denied"],
            "reassessment_refs": ["asm-anon-access-2", "asm-object-level-2"],
            "notes": "Run by the probe rather than by the developer who wrote "
                     "and deployed the migration.",
        },
        {
            "attempt_id": "att-anon-write-probe-1",
            "procedure_ref": "prc-anon-write-probe-v1",
            "action_ref": "act-probe-anon-write-v1",
            "authorization": {
                "authorization_id": "auth-anon-write-probe-1",
                "attempt_ref": "att-anon-write-probe-1",
                "authorized_by": "founder:mari",
                "granted_at": "2026-08-15T09:50:00Z",
                "expires_at": "2026-08-15T11:00:00Z",
                "scope": "One anon INSERT attempt against public.orders in the "
                         "pilot project, on the understanding that it may "
                         "create a real row which the founder then deletes.",
                "mode": "explicit_consent",
                "record": "chat approval 2026-08-15 09:50, quoting the warning "
                          "that a row may be created",
                "effects": {
                    "targets": ["pilot Supabase project:public.orders"],
                    "write": True, "destructive": False, "deployment": False,
                    "data": True, "external_accounts": False,
                    "data_egress": True, "data_egress_destinations": [PROJECT_URL],
                },
            },
            "executor": {"kind": "agent", "id": "vibecheck:supabase-probe"},
            "execution_environment": "private_test",
            "execution_context": {
                "kind": "sandbox", "locator": "vibecheck runner",
                "source_ref": "supabase_probe.py 0.5.0 --write-probe",
                "tool_versions": {"supabase_probe.py": "0.5.0"},
            },
            "input_refs": [
                {"name": "SUPABASE_URL", "kind": "environment_variable",
                 "locator": "SUPABASE_URL"},
                {"name": "anon key", "kind": "environment_variable",
                 "locator": "SUPABASE_ANON_KEY", "sensitive": True},
            ],
            "started_at": "2026-08-15T10:00:00Z",
            "finished_at": "2026-08-15T10:05:00Z",
            "result": "succeeded",
            "side_effects_observed": {
                "targets": ["pilot Supabase project:public.orders"],
                "write": True, "destructive": False, "deployment": False,
                "data": True, "external_accounts": False,
                "data_egress": True, "data_egress_destinations": [PROJECT_URL],
                "details": ["The insert returned 201 and created row "
                            "public.orders?id=eq.90ab41c2.",
                            "No other table was touched."],
            },
            "rollback": {
                "state": "succeeded",
                "notes": "Row public.orders?id=eq.90ab41c2 was deleted by "
                         "founder:mari as the owner and a follow-up read "
                         "confirmed it is gone.",
                "finished_at": "2026-08-15T10:12:00Z",
            },
            "evidence_refs": ["ev-anon-write-orders-open"],
            "reassessment_refs": ["asm-anon-access-3"],
            "notes": "The attempt succeeded in the sense that the probe ran and "
                     "settled the cell. What it observed is a failure of the "
                     "control, which is a different question.",
        },
    ]

    # Evidence produced by the attempts, in the order it was produced.
    evidence.append({
        "evidence_id": "ev-rls-migration-diff",
        "provider": {"name": "human reviewer", "version": "n/a"},
        "subject": {"kind": "file",
                    "locator": "supabase/migrations/20260813_orders_rls.sql"},
        "environment": "developer_only",
        "operation": "code_review_of_diff",
        "scope": "The remediation migration on branch fix/orders-rls: row level "
                 "security enabled plus owner-only policies on public.orders. "
                 "Evidence about the repository; it says nothing about which "
                 "revision the pilot project is running.",
        "claim": _claim([ANON, IDOR, DEFAULT_DENY],
                        "owner-only policies present in the source"),
        "direction": "supports",
        "strength": "indicative",
        "observed_at": "2026-08-13T15:35:00Z",
        "valid_until": VALID_UNTIL,
        "raw_result_ref": {"kind": "file",
                           "value": "supabase/migrations/20260813_orders_rls.sql"},
        "side_effects": {"writes": False, "destructive": False,
                         "external_accounts": False, "data_egress": False},
    })
    evidence.append({
        "evidence_id": "ev-rls-deployment-record",
        "provider": {"name": "supabase project migration history", "version": "n/a"},
        "subject": {"kind": "deployment", "locator": PROJECT_URL},
        "environment": "private_test",
        "operation": "deployment_record",
        "scope": "The pilot project's migration history after the push: "
                 "20260813_orders_rls is the current revision. Establishes what "
                 "is deployed, not how it behaves.",
        "claim": _claim([ANON, IDOR], "the reviewed migration is live in the pilot"),
        "direction": "supports",
        "strength": "indicative",
        "observed_at": "2026-08-13T16:22:00Z",
        "valid_until": VALID_UNTIL,
        "raw_result_ref": {"kind": "inline",
                           "value": "acme-orders-pilot: applied "
                                    "20260813_orders_rls at 2026-08-13T16:19Z"},
        "authorization": {
            "authorized_by": "founder:mari",
            "granted_at": "2026-08-13T16:00:00Z",
            "scope": "read the pilot project's migration history",
        },
        "side_effects": {"writes": False, "destructive": False,
                         "external_accounts": False, "data_egress": True,
                         "details": "Read of the project API only."},
    })

    signal("sig-probe-orders-read-2", "supabase_probe.py", "anon_select",
           {"kind": "table", "locator": "public.orders"}, "private_test",
           "2026-08-14T08:55:10Z",
           '{"check":"anon_select","table":"public.orders","http":200,'
           '"verdict":"PASS_no_anon_rows_on_non_empty_table",'
           '"rows_visible_to_anon":0,"rows_visible_to_test_account":3}')
    evidence.append({
        "evidence_id": "ev-anon-read-orders-denied",
        "provider": {"name": "supabase_probe.py", "version": "0.5.0",
                     "provider_ref": "prov-supabase-probe"},
        "subject": {"kind": "table", "locator": "public.orders"},
        "environment": "private_test",
        "operation": "http_select_anon_head",
        "scope": "After the deploy: nothing returned to the anon role while "
                 "test account A saw three rows in the same window, so the "
                 "table is not empty and the filtering is real. Covers reading "
                 "public.orders as an anonymous caller in the pilot project, "
                 "and nothing else.",
        "claim": _claim([ANON], "anonymous read of public.orders"),
        "direction": "supports",
        "strength": "decisive",
        "observed_at": "2026-08-14T08:55:10Z",
        "valid_until": VALID_UNTIL,
        "signal_refs": ["sig-probe-orders-read-2"],
        "raw_result_ref": {"kind": "inline",
                           "value": "anon: 0 rows; test account A: 3 rows; "
                                    "deployed revision 20260813_orders_rls"},
        "authorization": {
            "authorized_by": "founder:mari",
            "granted_at": "2026-08-14T08:45:00Z",
            "scope": "read-only anon re-probe of the pilot project",
        },
        "side_effects": _read_only_side_effects(),
        "coverage": [{"object_ref": "public.orders", "object_id": "obj-orders",
                      "object_class": "user_owned_record", "actor": "anonymous",
                      "operation": "read", "observed": "denied",
                      "environment": "private_test"}],
    })

    signal("sig-probe-idor-2", "supabase_probe.py", "idor",
           {"kind": "table", "locator": "public.orders"}, "private_test",
           "2026-08-14T08:57:40Z",
           '{"check":"idor","table":"public.orders","record_id":"ord-7c1a",'
           '"http":200,"verdict":"PASS_no_cross_account_read_of_known_private_'
           'record","rows_visible_to_b":0}')
    evidence.append({
        "evidence_id": "ev-idor-orders-denied",
        "provider": {"name": "supabase_probe.py", "version": "0.5.0",
                     "provider_ref": "prov-supabase-probe"},
        "subject": {"kind": "table", "locator": "public.orders (record ord-7c1a)"},
        "environment": "private_test",
        "operation": "http_select_authenticated_cross_account",
        "scope": "After the deploy: account B asked for account A's order "
                 "ord-7c1a and received nothing, while account A still sees it. "
                 "Covers reading that one record as an unrelated account. It is "
                 "not evidence about updating or deleting it, about the "
                 "invitations table, or about any other record.",
        "claim": _claim([IDOR], "cross-account read of one order record"),
        "direction": "supports",
        "strength": "decisive",
        "observed_at": "2026-08-14T08:57:40Z",
        "valid_until": VALID_UNTIL,
        "signal_refs": ["sig-probe-idor-2"],
        "raw_result_ref": {"kind": "inline",
                           "value": "account B: 0 rows for ord-7c1a; account A "
                                    "still reads it"},
        "authorization": {
            "authorized_by": "founder:mari",
            "granted_at": "2026-08-14T08:45:00Z",
            "scope": "read-only two-account re-probe of the pilot project",
        },
        "side_effects": _read_only_side_effects(),
        "coverage": [{"object_ref": "public.orders", "object_id": "obj-orders",
                      "object_class": "user_owned_record",
                      "actor": "other_account", "operation": "read",
                      "observed": "denied", "environment": "private_test",
                      "instance": "ord-7c1a"}],
    })

    assessments.append({
        "assessment_id": "asm-anon-access-2",
        "control_id": ANON,
        "status": "partial",
        "assessor": {"kind": "human", "id": "reviewer:jaak"},
        "assessed_at": "2026-08-14T09:05:00Z",
        "supersedes": "asm-anon-access-1",
        "basis": {
            "rationale": "The read path is fixed and independently re-observed "
                         "after the deploy on a table established as non-empty. "
                         "Partial, not pass: anonymous create, update and "
                         "delete were never attempted, and public.invitations "
                         "returned an empty response that settles nothing. One "
                         "denied request covers one cell.",
            "evidence_refs": ["ev-rls-migration-diff", "ev-rls-deployment-record",
                              "ev-anon-read-orders-denied"],
        },
        "conflicts": [{
            "evidence_ref": "ev-anon-read-orders-open",
            "resolution": "Superseded by ev-anon-read-orders-denied: same "
                          "provider and operation, observed after the "
                          "deployment finished at 2026-08-13T16:20Z.",
        }],
    })
    assessments.append({
        "assessment_id": "asm-object-level-2",
        "control_id": IDOR,
        "status": "partial",
        "assessor": {"kind": "human", "id": "reviewer:jaak"},
        "assessed_at": "2026-08-14T09:06:00Z",
        "supersedes": "asm-object-level-1",
        "basis": {
            "rationale": "One known private order is no longer readable by an "
                         "unrelated account. That is one cell of the matrix: "
                         "cross-account update and delete, and the invitations "
                         "table, remain untested.",
            "evidence_refs": ["ev-rls-migration-diff", "ev-idor-orders-denied"],
        },
        "conflicts": [{
            "evidence_ref": "ev-idor-orders-open",
            "resolution": "Superseded by ev-idor-orders-denied: same record, "
                          "same operation, observed after the deployment.",
        }],
    })

    signal("sig-probe-orders-write-1", "supabase_probe.py", "anon_insert_probe",
           {"kind": "table", "locator": "public.orders"}, "private_test",
           "2026-08-15T10:02:00Z",
           '{"check":"anon_insert_probe","table":"public.orders","http":201,'
           '"verdict":"FAIL_anon_write_succeeded","target_environment":'
           '"private_test","created_row_hint":"/orders?id=eq.90ab41c2",'
           '"cleanup":{"state":"pending"}}')
    evidence.append({
        "evidence_id": "ev-anon-write-orders-open",
        "provider": {"name": "supabase_probe.py", "version": "0.5.0",
                     "provider_ref": "prov-supabase-probe"},
        "subject": {"kind": "table", "locator": "public.orders"},
        "environment": "private_test",
        "operation": "http_insert_anon",
        "scope": "One authorized anon INSERT against public.orders in the pilot "
                 "project. Covers creating a row as an anonymous caller; it "
                 "says nothing about update or delete, or about any other table.",
        "claim": _claim([ANON], "anonymous create in public.orders"),
        "direction": "refutes",
        "strength": "decisive",
        "observed_at": "2026-08-15T10:02:00Z",
        "valid_until": VALID_UNTIL,
        "signal_refs": ["sig-probe-orders-write-1"],
        "raw_result_ref": {"kind": "inline",
                           "value": "HTTP 201; row public.orders?id=eq.90ab41c2 "
                                    "created with the public key alone"},
        "authorization": {
            "authorized_by": "founder:mari",
            "granted_at": "2026-08-15T09:50:00Z",
            "scope": "one opt-in anon write probe of public.orders in the pilot "
                     "project",
        },
        "side_effects": {
            "writes": True, "destructive": False, "external_accounts": False,
            "data_egress": True,
            "details": "Created row public.orders?id=eq.90ab41c2 in the pilot "
                       "project; deleted by founder:mari at 2026-08-15T10:12Z "
                       "and confirmed gone (see att-anon-write-probe-1).",
        },
        "coverage": [{"object_ref": "public.orders", "object_id": "obj-orders",
                      "object_class": "user_owned_record", "actor": "anonymous",
                      "operation": "create", "observed": "allowed",
                      "environment": "private_test",
                      "instance": "probe row 90ab41c2, since deleted"}],
    })

    assessments.append({
        "assessment_id": "asm-anon-access-3",
        "control_id": ANON,
        "status": "fail",
        "assessor": {"kind": "human", "id": "reviewer:jaak"},
        "assessed_at": "2026-08-15T10:20:00Z",
        "supersedes": "asm-anon-access-2",
        "basis": {
            "rationale": "The authorized write probe created a row in "
                         "public.orders with nothing but the public key. The "
                         "read path being fixed does not make the control met: "
                         "the requirement covers reading and writing.",
            "evidence_refs": ["ev-anon-write-orders-open"],
        },
    })

    return signals, evidence, assessments, actions, procedures, attempts


def build_envelope():
    signals, evidence, assessments, actions, procedures, attempts = build_records()
    return {
        "schema": canonical.SCHEMA_NAME,
        "schema_version": canonical.SCHEMA_VERSION,
        "assessment_id": "va-acme-orders-authz",
        "revision": 3,
        "supersedes_revision": 2,
        "created_at": NOW,
        "context": build_context(),
        "control_registry": {"name": controls.REGISTRY_NAME,
                             "version": controls.REGISTRY_VERSION},
        "action_registry": actions_mod.registry_ref(),
        "coverage_model": authz_mod.model_ref(),
        "providers": providers(),
        "signals": signals,
        "evidence": evidence,
        "assessments": assessments,
        "actions": actions,
        "procedures": procedures,
        "attempts": attempts,
    }


def build_fixture():
    """The envelope with risk, readiness, coverage actions and report derived."""
    derived = report_mod.derive_into(build_envelope(), "founder", "en", NOW)
    problems = canonical.validate_envelope(derived)
    if problems:
        raise SystemExit("the authorization lifecycle fixture does not "
                         "validate:\n  %s" % "\n  ".join(problems))
    return derived


# ------------------------------------------ the intended public write (issue #7)

INTENDED_PATH = os.path.join(REPO_ROOT, "schema", "examples",
                             "intended-anon-write.json")
INTENDED_NOW = "2026-08-16T12:00:00Z"
SITE_URL = "https://example-consultancy.supabase.co"
BOUNDED_WRITE = "vibecheck.control.cost.expensive_endpoints_auth"
LIVE = {"environment": "public_release", "intended_use": "public_product"}


def build_intended_write_envelope():
    """A published site whose contact form must accept anonymous inserts.

    The common shape of a vibecoded marketing site: a public form writes
    straight to the database from the browser. The write is the product working,
    so the owner confirms it — and the confirmation is where the review starts
    rather than stops, because the same path is reachable by automation.
    """
    context = ctx.build_context(
        context_id="ctx-example-consultancy",
        application={
            "name": "Example Consultancy site",
            "description": "Published marketing site with a booking form that "
                           "writes enquiries to the database from the browser "
                           "and emails the owner.",
            "platform": "lovable-cloud+supabase",
        },
        target_scopes=[LIVE],
        current_scope=LIVE,
        profile=ctx.profile({
            "lifecycle": "live",
            "audience_scale": "open_large",
            "network_exposure": "public_internet",
            "authentication": "none",
            "tenancy": "single_tenant",
            "data_sensitivity": "personal_data",
            "financial_operations": "none",
            "privileged_operations": "external_side_effects",
            "business_criticality": "supporting",
        }, source="founder:mari"),
        data_summary="Names, emails, company names and free-text messages from "
                     "enquiry forms, plus the unsubscribe tokens the mailer uses.",
        confirmation={
            "state": "human_reviewed",
            "confirmed_by": "founder:mari",
            "confirmed_at": "2026-08-16T09:00:00Z",
            "source_fingerprint": "sha256:9a1c77e2b4d0f6a8c2e4b6d8f0a2c4e6"
                                  "b8d0f2a4c6e8b0d2f4a6c8e0b2d4f6a8c0",
        },
        authorization_objects=[
            {
                "object_id": "obj-bookings",
                "object_class": "admin_or_privileged_record",
                "locator": "public.bookings",
                "intent": "private",
                "state": "confirmed",
                "source": "founder:mari",
                "description": "Enquiries: name, email, company, message. Only "
                               "the owner reads them; anyone may submit one.",
                "intended_operations": [{
                    "actor": "anonymous",
                    "operation": "create",
                    "state": "confirmed",
                    "source": "founder:mari",
                    "rationale": "The public booking form submits enquiries "
                                 "directly from the browser. Requiring an "
                                 "account first would defeat the form.",
                    "decided_at": "2026-08-16T09:30:00Z",
                }],
            },
            {
                "object_id": "obj-unsubscribe-tokens",
                "object_class": "credential_or_token_record",
                "locator": "public.email_unsubscribe_tokens",
                "intent": "private",
                "state": "confirmed",
                "source": "founder:mari",
                "description": "Single-use unsubscribe tokens; reading one lets "
                               "anyone act as that recipient.",
            },
        ],
        reassess_triggers=[{"kind": "context_change"}],
    )

    probe_authorization = {
        "authorized_by": "founder:mari",
        "granted_at": "2026-08-16T10:00:00Z",
        "scope": "read-only anon probe of the published project, plus one "
                 "authorized insert into public.bookings",
    }
    read_only = {"writes": False, "destructive": False,
                 "external_accounts": False, "data_egress": True,
                 "details": "HTTP requests to the project URL only."}

    signals = [
        {
            "signal_id": "sig-bookings-read",
            "source": {"tool": "supabase_probe.py", "check_id": "anon_select"},
            "subject": {"kind": "table", "locator": "public.bookings"},
            "environment": "public_release",
            "observed_at": "2026-08-16T10:05:00Z",
            "raw_ref": {"kind": "inline", "value": canonical.bound_raw(
                '{"check":"anon_select","table":"public.bookings","http":200,'
                '"verdict":"PASS_no_anon_rows_on_non_empty_table",'
                '"rows_visible_to_anon":0,"rows_visible_to_test_account":41}')},
        },
        {
            "signal_id": "sig-bookings-create",
            "source": {"tool": "supabase_probe.py",
                       "check_id": "anon_insert_probe"},
            "subject": {"kind": "table", "locator": "public.bookings"},
            "environment": "public_release",
            "observed_at": "2026-08-16T10:08:00Z",
            "raw_ref": {"kind": "inline", "value": canonical.bound_raw(
                '{"check":"anon_insert_probe","table":"public.bookings",'
                '"http":201,"verdict":"FAIL_anon_write_succeeded",'
                '"target_environment":"public_release",'
                '"created_row_hint":"/bookings?id=eq.51f0",'
                '"cleanup":{"state":"pending"}}')},
        },
    ]

    evidence = [
        {
            "evidence_id": "ev-bookings-read-denied",
            "provider": {"name": "supabase_probe.py", "version": "0.5.0"},
            "subject": {"kind": "table", "locator": "public.bookings"},
            "environment": "public_release",
            "operation": "http_select_anon_head",
            "scope": "Nothing returned to the anon role while a test account saw "
                     "41 rows in the same window, so the table is not empty and "
                     "the filtering is real. Covers reading public.bookings as "
                     "an anonymous caller.",
            "claim": _claim([ANON], "anonymous read of public.bookings"),
            "direction": "supports",
            "strength": "decisive",
            "observed_at": "2026-08-16T10:05:00Z",
            "valid_until": "2026-09-13T00:00:00Z",
            "signal_refs": ["sig-bookings-read"],
            "raw_result_ref": {"kind": "inline",
                               "value": "anon: 0 rows; test account: 41 rows"},
            "authorization": probe_authorization,
            "side_effects": read_only,
            "coverage": [{"object_ref": "public.bookings",
                          "object_id": "obj-bookings",
                          "object_class": "admin_or_privileged_record",
                          "actor": "anonymous", "operation": "read",
                          "observed": "denied",
                          "environment": "public_release"}],
        },
        {
            "evidence_id": "ev-bookings-create-open",
            "provider": {"name": "supabase_probe.py", "version": "0.5.0"},
            "subject": {"kind": "table", "locator": "public.bookings"},
            "environment": "public_release",
            "operation": "http_insert_anon",
            "scope": "One authorized anon INSERT into public.bookings on the "
                     "published project. The insert is the form working; this "
                     "observation says the path is open, and nothing about "
                     "whether anything limits how often it can be used.",
            "claim": _claim([ANON], "anonymous create in public.bookings"),
            "direction": "neutral",
            "strength": "decisive",
            "observed_at": "2026-08-16T10:08:00Z",
            "valid_until": "2026-09-13T00:00:00Z",
            "signal_refs": ["sig-bookings-create"],
            "raw_result_ref": {"kind": "inline",
                               "value": "HTTP 201; row public.bookings?id=eq.51f0 "
                                        "created with the public key alone"},
            "authorization": probe_authorization,
            "side_effects": {
                "writes": True, "destructive": False,
                "external_accounts": False, "data_egress": True,
                "details": "Created enquiry row public.bookings?id=eq.51f0 on "
                           "the live site; deleted by founder:mari at "
                           "2026-08-16T10:15Z and confirmed gone. The insert "
                           "also sent the owner one notification email.",
            },
            "coverage": [{"object_ref": "public.bookings",
                          "object_id": "obj-bookings",
                          "object_class": "admin_or_privileged_record",
                          "actor": "anonymous", "operation": "create",
                          "observed": "allowed",
                          "environment": "public_release",
                          "instance": "probe enquiry 51f0, since deleted",
                          "note": "confirmed as intended: this is the booking "
                                  "form"}],
        },
    ]

    assessments = [{
        "assessment_id": "asm-anon-access-live",
        "control_id": ANON,
        "status": "partial",
        "assessor": {"kind": "human", "id": "reviewer:jaak"},
        "assessed_at": "2026-08-16T11:00:00Z",
        "basis": {
            "rationale": "Anonymous reads of public.bookings are denied on a "
                         "non-empty table. The anonymous insert is confirmed as "
                         "intended — it is the booking form — so it is not a "
                         "violation, but nothing bounds it: there is no "
                         "assessment of the unauthenticated write path being "
                         "limited, and the unsubscribe-token table has not been "
                         "probed at all. Partial, and it stays partial until "
                         "the form is bounded.",
            "evidence_refs": ["ev-bookings-read-denied", "ev-bookings-create-open"],
        },
    }]

    return {
        "schema": canonical.SCHEMA_NAME,
        "schema_version": canonical.SCHEMA_VERSION,
        "assessment_id": "va-example-consultancy-form",
        "revision": 1,
        "created_at": INTENDED_NOW,
        "context": context,
        "control_registry": {"name": controls.REGISTRY_NAME,
                             "version": controls.REGISTRY_VERSION},
        "action_registry": actions_mod.registry_ref(),
        "coverage_model": authz_mod.model_ref(),
        "signals": signals,
        "evidence": evidence,
        "assessments": assessments,
        "actions": [],
        "procedures": [],
        "attempts": [],
    }


def build_intended_write_fixture():
    derived = report_mod.derive_into(
        build_intended_write_envelope(), "founder", "en", INTENDED_NOW)
    problems = canonical.validate_envelope(derived)
    if problems:
        raise SystemExit("the intended-write fixture does not validate:\\n  %s"
                         % "\\n  ".join(problems))
    return derived


def artifacts():
    return {OUTPUT_PATH: canonical.dumps(build_fixture()),
            INTENDED_PATH: canonical.dumps(build_intended_write_fixture())}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true",
                        help="fail if a committed fixture differs")
    args = parser.parse_args()
    stale = []
    for path, rendered in sorted(artifacts().items()):
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
            continue
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(rendered)
        print("wrote %s" % rel)
    if stale:
        for rel in stale:
            print("stale: %s (run python3 scripts/gen_authz_fixture.py)" % rel,
                  file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
