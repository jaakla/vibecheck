# -*- coding: utf-8 -*-
"""Stable control IDs and the vibecheck_v1 framework mapping (RFC 0001 §3.3-3.4).

Controls get semantic IDs independent of checklist row numbers and wording:

    vibecheck.control.<namespace>.<slug>

The slug table below is hand-reviewed, not derived from wording: IDs are never
reused and never renamed, so a wording change in items.py must never move a
control's identity. Renumbering the workbook must never move it either — that
is why row numbers may not leak into slugs (tests/test_canonical.py pins it).

items.py remains the authoring source for wording, severity, verification and
scanner coverage until cutover (Increment 8). This module derives from it:

  build_registry()           -> schema/vibecheck.controls.v1.json
  build_framework_mapping()  -> schema/mappings/vibecheck_v1.json

Regenerate with scripts/gen_canonical.py; tests fail when the committed
artifacts drift from items.py.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from items import CATEGORIES, WEIGHT, VERIFICATION, SCANNER_CHECKS, item_count

REGISTRY_NAME = "vibecheck.controls"
REGISTRY_VERSION = "1.0.0"
FRAMEWORK = "vibecheck_v1"
FRAMEWORK_VERSION = "2026.08"

# RFC 0001 §3.3: one stable namespace token per concern, decoupled from the
# numbered workbook categories. Index = category number (1-18).
NAMESPACE_BY_CATEGORY = {
    1: "arch", 2: "secrets", 3: "authz", 4: "product", 5: "cost",
    6: "input", 7: "data", 8: "obs", 9: "deploy", 10: "integ",
    11: "deps", 12: "privacy", 13: "aiact", 14: "logic", 15: "testing",
    16: "perf", 17: "llm", 18: "continuity",
}

# item number (1-89) -> slug. Hand-reviewed; append-only. Slugs already pinned
# by RFC examples: 7, 13, 14, 15, 24, 29.
CONTROL_SLUGS = {
    # 1. Architecture reasonableness
    1: "mainstream_stack",
    2: "datastore_fit",
    3: "proven_auth_provider",
    4: "proportional_complexity",
    5: "consistent_patterns",
    6: "hosting_runtime_fit",
    # 2. Secrets & credentials
    7: "no_frontend_literals",
    8: "no_client_provider_keys",
    9: "no_repo_history_leaks",
    10: "secure_runtime_injection",
    11: "leak_incident_response",
    # 3. Authorization & access control
    12: "server_side_default_deny",
    13: "object_level",
    14: "anon_data_access",
    15: "tenant_isolation",
    16: "admin_actions_server_side",
    # 4. Product readiness - is it real?
    17: "data_persistence",
    18: "no_mocked_output",
    19: "email_delivery",
    20: "payment_mode_match",
    21: "upload_storage",
    22: "backend_search",
    # 5. Cost & abuse blast radius
    23: "usage_quotas",
    24: "budget_caps",
    25: "bounded_agent_loops",
    26: "expensive_endpoints_auth",
    27: "abuse_limits",
    # 6. Input handling & injection
    28: "server_side_validation",
    29: "sql_parameterized",
    30: "output_encoding",
    31: "upload_validation",
    32: "other_injection_classes",
    # 7. Data, migrations, backups
    33: "versioned_migrations",
    34: "tested_backups",
    35: "safe_prod_migrations",
    36: "deletion_semantics",
    # 8. Errors, logging & observability
    37: "no_swallowed_errors",
    38: "error_tracking",
    39: "no_leaked_internals",
    40: "event_logging",
    41: "health_alerting",
    # 9. Config & deployment pipeline
    42: "debug_disabled",
    43: "env_separation",
    44: "cors_restricted",
    45: "transport_security",
    46: "change_control",
    # 10. Third-party integrations
    47: "webhook_signatures",
    48: "oauth_hardening",
    49: "least_privilege_scopes",
    50: "idempotent_handlers",
    # 11. Dependencies & supply chain
    51: "vuln_scanning",
    52: "dependency_trust",
    53: "reproducible_builds",
    54: "license_compatibility",
    # 12. Privacy & GDPR
    55: "data_minimisation",
    56: "password_hashing",
    57: "no_pii_leakage",
    58: "data_residency",
    59: "subject_rights",
    # 13. EU AI Act screening
    60: "high_risk_screen",
    61: "transparency_screen",
    62: "prohibited_practice_screen",
    63: "specialist_escalation",
    # 14. Correctness & business logic
    64: "invariant_enforcement",
    65: "concurrency_safety",
    66: "money_math",
    67: "time_handling",
    68: "permission_revocation",
    # 15. Product readiness - testing
    69: "core_flow_tests",
    70: "authz_tests",
    71: "payment_deploy_tests",
    72: "calculation_tests",
    # 16. Performance
    73: "pagination_limits",
    74: "query_performance",
    75: "graceful_degradation",
    76: "bundle_cold_start",
    # 17. AI security (prompt injection & agents)
    77: "no_output_to_exec",
    78: "untrusted_content_isolation",
    79: "tool_call_authorization",
    80: "rag_acl_propagation",
    81: "output_rendering",
    # 18. Ownership, continuity & usability
    82: "bus_factor",
    83: "account_ownership",
    84: "data_export",
    85: "failure_recovery",
    86: "support_path",
    87: "product_analytics",
    88: "cross_device_testing",
    89: "accessibility_basics",
}

# Canonical status -> workbook display wording. Must match build_workbook.STR;
# tests/test_rfc_schema.py and tests/test_canonical.py pin both directions.
STATUS_MAP = {
    "pass": {"en": "Pass", "et": "Korras"},
    "partial": {"en": "Partial", "et": "Osaline"},
    "fail": {"en": "Fail", "et": "Puudulik"},
    "not_tested": {"en": "Not tested", "et": "Testimata"},
    "not_applicable": {"en": "N/A", "et": "Ei kohaldu"},
    "risk_accepted": {"en": "Accepted risk", "et": "Aktsepteeritud risk"},
    "answered": {"en": "Answered", "et": "Vastatud"},
    "needs_specialist": {"en": "Needs specialist", "et": "Vajab spetsialisti"},
}


def _bank():
    """item number -> (category_number, category, item tuple), workbook numbering."""
    bank = {}
    n = 0
    for category_number, cat in enumerate(CATEGORIES, 1):
        for tup in cat["items"]:
            n += 1
            bank[n] = (category_number, cat, tup)
    return bank


def control_id(item_number):
    category_number = _bank()[item_number][0]
    return "vibecheck.control.%s.%s" % (
        NAMESPACE_BY_CATEGORY[category_number], CONTROL_SLUGS[item_number])


# item number -> stable control ID, and the reverse.
CONTROL_IDS = {n: control_id(n) for n in range(1, item_count() + 1)}
ITEM_NUMBERS = {cid: n for n, cid in CONTROL_IDS.items()}


def build_registry():
    """The stable control registry (intrinsic severity lives here, RFC §5)."""
    controls = []
    for n, (category_number, cat, tup) in sorted(_bank().items()):
        severity = tup[0]
        controls.append({
            "control_id": CONTROL_IDS[n],
            "status": "active",
            "kind": "screening" if severity == "Triage" else "control",
            "severity": severity,
            "weight": WEIGHT[severity],
            "title": {"en": tup[1], "et": tup[2]},
        })
    return {
        "registry": REGISTRY_NAME,
        "version": REGISTRY_VERSION,
        "description": (
            "Stable semantic control IDs for Vibecheck (RFC 0001 §3.3). IDs are "
            "never reused and never renamed; a control that stops making sense "
            "is deprecated with status=deprecated and superseded_by. Intrinsic "
            "severity lives here and in framework mappings only — no assessment "
            "or risk object may override it (rule R14). Generated from "
            "scripts/items.py by scripts/gen_canonical.py; do not edit by hand."),
        "controls": controls,
    }


def build_framework_mapping():
    """The lossless vibecheck_v1 mapping entry set (RFC §3.4), one per item."""
    entries = []
    for n, (category_number, cat, tup) in sorted(_bank().items()):
        severity, tech_en, tech_et, plain_en, plain_et, test_en, test_et = tup
        codes, tools = VERIFICATION[n]
        entries.append({
            "control_id": CONTROL_IDS[n],
            "item_number": n,
            "category": {"number": category_number, "en": cat["en"], "et": cat["et"]},
            "severity": severity,
            "weight": WEIGHT[severity],
            "kind": "screening" if severity == "Triage" else "control",
            "wording": {
                "tech_en": tech_en, "tech_et": tech_et,
                "plain_en": plain_en, "plain_et": plain_et,
                "test_en": test_en, "test_et": test_et,
            },
            "verification": {"codes": list(codes), "tools": tools},
            "scanner_checks": [
                {"check_id": check, "tier": tier}
                for check, (nums, tier) in SCANNER_CHECKS.items() if n in nums
            ],
            "workbook_profiles": ["reviewer", "founder"],
        })
    return {
        "framework": FRAMEWORK,
        "framework_version": FRAMEWORK_VERSION,
        "status_map": STATUS_MAP,
        "entries": entries,
    }
