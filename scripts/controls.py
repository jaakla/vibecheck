# -*- coding: utf-8 -*-
"""Stable control IDs and the vibecheck_v1 framework mapping (RFC 0001 §3.3-3.4).

Controls get semantic IDs independent of checklist row numbers and wording:

    vibecheck.control.<namespace>.<slug>

The slug table below is hand-reviewed, not derived from wording: IDs are never
reused and never renamed, so a wording change in items.py must never move a
control's identity. Renumbering the workbook must never move it either — that
is why row numbers may not leak into slugs (tests/test_canonical.py pins it).

items.py is the authoring input for wording, severity, verification and
scanner coverage (Increment 8 cut over the runtime consumers to the mapping;
items.py now feeds this module only, with a deprecation window documented in
RFC 0001 §11.4). This module derives from it:

  build_registry()             -> schema/vibecheck.controls.v1.json
  build_framework_mapping()    -> schema/mappings/vibecheck_v1.json
  build_focus_framework()      -> schema/mappings/founder_focus_v1.json

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


# How the vibecheck_v1 mapping was established and is maintained. A change to
# the mapping is a new framework_version; historical envelopes keep the version
# that was current at assessment time and are never re-mapped in place.
FRAMEWORK_PROVENANCE = {
    "source": "scripts/items.py positional 7-tuples + VERIFICATION + SCANNER_CHECKS (workbook v0.3, RFC 0001 section 11.4)",
    "established_at": "2026-08-16T00:00:00Z",
    "method": "generated by scripts/gen_canonical.py from scripts/controls.py; losslessness pinned by tests/test_canonical.py and tests/test_rfc_schema.py",
    "reviewed_by": "vibecheck maintainers (issue #10)",
    "change_policy": "append-only control IDs; item numbers, categories and wording may change only via a new framework_version. items.py remains the authoring source for vibecheck_v1 until its documented deprecation window (RFC 0001 section 11.4) closes.",
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


def scanner_tier(check_id):
    """Tier (DECISIVE/EVIDENCE/MANUAL) for a scanner check, read from the
    canonical vibecheck_v1 mapping entries (which carry the lossless
    SCANNER_CHECKS data). Returns None for an unknown check, matching the
    legacy `items.SCANNER_CHECKS.get(check, ...)` fallback behaviour at the
    call site. Consumers read tiers here so the assessment pipeline does not
    depend on items.py directly after cutover (issue #10)."""
    for entry in build_framework_mapping()["entries"]:
        for check in entry.get("scanner_checks") or []:
            if check["check_id"] == check_id:
                return check["tier"]
    return None


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
        "provenance": FRAMEWORK_PROVENANCE,
        "status_map": STATUS_MAP,
        "entries": entries,
    }



# ---------------------------------------------------------------------------
# Second sample framework: founder_focus (Increment 8, issue #10).
#
# Proves the mapping model is reusable: a completely different framework view —
# a short founder-side go/no-go list — reuses the same stable control records
# without duplicating any control. Framework items and controls are
# many-to-many:
#
#   * the same control serves several framework views (e.g. datastore_fit,
#     object_level, dependency_trust: each is already a vibecheck_v1 control and
#     appears again here only as a reference),
#   * one founder item can span several controls
#     (item 2 maps to object_level + tenant_isolation via related_control_ids),
#   * every entry records why the edge exists (per-entry provenance).
#
# The framework view owns its wording; the control owns its identity, intrinsic
# severity and weight. Item numbers in this framework are its own coordinates
# (1-N), not vibecheck_v1 numbers, which is why the schema no longer hard-caps
# item_number at 89.
FOCUS_FRAMEWORK = "founder_focus"
FOCUS_FRAMEWORK_VERSION = "2026.08"
FOCUS_FRAMEWORK_PROVENANCE = {
    "source": "curated subset of the vibecheck_v1 checklist for a non-technical owner go/no-go review (sample second framework, issue #10)",
    "established_at": "2026-08-16T00:00:00Z",
    "method": "hand-reviewed mapping onto existing stable control IDs; reuse is intentional and pinned by tests (no control record is duplicated)",
    "reviewed_by": "vibecheck maintainers (issue #10)",
    "change_policy": "sample only: illustrates control reuse across frameworks; not a compliance framework.",
}

# item_number -> dict(control_id, related, category, wording, verification, tools)
FOCUS_ITEM_SPECS = {
    1: {
        "control_id": "vibecheck.control.arch.datastore_fit",
        "related": [],
        "category": {"number": 1, "en": "Data durability", "et": "Andmete püsivus"},
        "wording": {
            "tech_en": "Primary data store is a managed persistent DB; no SQLite/JSON-file/localStorage as system of record.",
            "tech_et": "Põhihoidla on hallatud püsiv andmebaas; mitte SQLite/JSON-fail/localStorage põhihoidlana.",
            "plain_en": "Is user data stored in a durable database, not a file or browser storage?",
            "plain_et": "Kas kasutajaandmed on püsivas andmebaasis, mitte failis või brauseri mälus?",
            "test_en": "Ask where data lives; the scanner flags SQLite/JSON-file/localStorage on ephemeral hosting.",
            "test_et": "Küsi, kus andmed elavad; skanner märgib SQLite/JSON-faili ajutisel majutusel.",
        },
        "verification": ["AI"],
        "tools": "storage question, second pair of eyes",
    },
    2: {
        "control_id": "vibecheck.control.authz.object_level",
        "related": ["vibecheck.control.authz.tenant_isolation"],
        "category": {"number": 2, "en": "Other users' data", "et": "Teiste kasutajate andmed"},
        "wording": {
            "tech_en": "Object-level authorization and tenant isolation hold against a second account.",
            "tech_et": "Objektitaseme õigused ja rentniku eraldus peavad vastu teisele kontole.",
            "plain_en": "Could another customer see or change data that is not theirs?",
            "plain_et": "Kas keegi teine saaks näha või muuta andmed, mis ei ole tema omad?",
            "test_en": "Two test accounts; try to read/write the other account's records.",
            "test_et": "Kaks testkontot; proovi teise konto kirjeid lugeda või muuta.",
        },
        "verification": ["E2E"],
        "tools": "two-account test (Playwright)",
    },
    3: {
        "control_id": "vibecheck.control.arch.proven_auth_provider",
        "related": ["vibecheck.control.privacy.password_hashing"],
        "category": {"number": 3, "en": "Login & secrets", "et": "Sisselogimine ja saladused"},
        "wording": {
            "tech_en": "Authentication and handling of credentials use a proven provider/library, never hand-rolled crypto.",
            "tech_et": "Autentimine ja mandaadid kasutavad tõestatud teenust/teeki, mitte isetehtud krüptot.",
            "plain_en": "Are login and secrets handled by a proven provider or library?",
            "plain_et": "Kas sisselogimist ja saladusi haldab tõestatud teenus või teek?",
            "test_en": "Ask which auth provider handles login; the scanner flags home-made primitives.",
            "test_et": "Küsi, milline teenus sisselogimist haldab; skanner märgib isetehtud räsid.",
        },
        "verification": ["AI"],
        "tools": "auth review (provider/library check)",
    },
    6: {
        "control_id": "vibecheck.control.deps.dependency_trust",
        "related": ["vibecheck.control.deps.vuln_scanning"],
        "category": {"number": 6, "en": "Supply chain", "et": "Tarneahel"},
        "wording": {
            "tech_en": "Dependencies and the supply chain are reviewed for vulnerabilities and trust.",
            "tech_et": "Sõltuvused ja tarneahel on üle vaadatud haavatavuste ja usalduse osas.",
            "plain_en": "Are the libraries and packages the app is built on reviewed?",
            "plain_et": "Kas raamatukogud ja paketid, millel rakendus põhineb, on üle vaadatud?",
            "test_en": "Run a lockfile scan (OSV/Trivy) in CI and evaluate severity and reachability.",
            "test_et": "Käivita lukufaili skann (OSV/Trivy) ning hinda haavatavusi ja nende mõju.",
        },
        "verification": ["AUTO"],
        "tools": "OSV-Scanner / Trivy lockfile scan",
    },
    7: {
        "control_id": "vibecheck.control.data.versioned_migrations",
        "related": ["vibecheck.control.data.tested_backups", "vibecheck.control.deploy.change_control"],
        "category": {"number": 7, "en": "Data integrity", "et": "Andmete terviklikkus"},
        "wording": {
            "tech_en": "Versioned migrations, tested backups and safe production-change control are demonstrable.",
            "tech_et": "Versioonitud migratsioonid, testitud varukoopiad ja ohutu tootemuudatuste kontroll on tõendatud.",
            "plain_en": "Can you restore your data after a bad deployment or deletion?",
            "plain_et": "Kas saad pärast vigast juurutust või kustutamist andmed taastada?",
            "test_en": "Do a backup restore drill on a throwaway environment.",
            "test_et": "Proovi varukoopia taastamist kindlas testimiskeskkonnas.",
        },
        "verification": ["MAN"],
        "tools": "backup restore drill",
    },
    8: {
        "control_id": "vibecheck.control.continuity.account_ownership",
        "related": ["vibecheck.control.continuity.data_export", "vibecheck.control.continuity.failure_recovery"],
        "category": {"number": 8, "en": "Recovery", "et": "Taastumine"},
        "wording": {
            "tech_en": "Account ownership, data export and failure recovery are available and tested.",
            "tech_et": "Kontode omanik, andmete eksport ja rikkest taastumine on saadaval ja testitud.",
            "plain_en": "Can you get your users' data back out, and recover accounts if needed?",
            "plain_et": "Kas saad kasutajate andmed välja ja vigased kontod taastada?",
            "test_en": "Walk through export and account recovery with a real second user.",
            "test_et": "Käi eksport ja konto taastamine läbi teise reaalse kasutajaga.",
        },
        "verification": ["MAN"],
        "tools": "account recovery + export test",
    },
}


def _severity_for(control_ids):
    """Worst intrinsic severity across the reused controls (never re-stated)."""
    worst, worst_w = None, -1
    for cid in control_ids:
        sev = _registry_severity(cid)
        if WEIGHT.get(sev, 0) > worst_w:
            worst, worst_w = sev, WEIGHT.get(sev, 0)
    return worst


def _registry_severity(control_id):
    for entry in build_registry()["controls"]:
        if entry["control_id"] == control_id:
            return entry["severity"]
    raise KeyError("unknown control id %r" % control_id)


def build_focus_framework():
    """The founder_focus sample mapping: many-to-many reuse of existing controls."""
    entries = []
    for n in sorted(FOCUS_ITEM_SPECS):
        spec = FOCUS_ITEM_SPECS[n]
        control_ids = [spec["control_id"]] + list(spec.get("related", []))
        sev = _severity_for(control_ids)
        entries.append({
            "control_id": spec["control_id"],
            "related_control_ids": list(spec.get("related", [])),
            "item_number": n,
            "category": {"number": spec["category"]["number"],
                         "en": spec["category"]["en"],
                         "et": spec["category"]["et"]},
            "severity": sev,
            "weight": WEIGHT[sev],
            "kind": "control",
            "wording": spec["wording"],
            "verification": {"codes": list(spec["verification"]), "tools": spec["tools"]},
            "scanner_checks": [],
            "workbook_profiles": ["founder"],
            "provenance": {
                "rationale": (
                    "founder item %d reuses %s without duplicating any control"
                    % (n, ", ".join(control_ids))),
            },
        })
    return {
        "framework": FOCUS_FRAMEWORK,
        "framework_version": FOCUS_FRAMEWORK_VERSION,
        "provenance": FOCUS_FRAMEWORK_PROVENANCE,
        "status_map": STATUS_MAP,
        "entries": entries,
    }
