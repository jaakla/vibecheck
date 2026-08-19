# -*- coding: utf-8 -*-
"""EN/ET report vocabulary (RFC 0001 §9).

Every fixed string the founder and reviewer reports render comes from
schema/report-wording.v1.json through this module. Wording is data for one
reason: a translation must never be able to change what a control means. The
same envelope produces the same scenarios, the same disclosures and the same
control identities in either language and either profile — only the words
differ (RFC 0001 §9).

Control wording is deliberately *not* duplicated here. Plain-language and
technical phrasings live in the vibecheck_v1 framework mapping, so the report,
the workbook and the checklist map keep one source (`control_wording`).

Stdlib only.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import canonical

WORDING_PATH = os.path.join(canonical.REPO_ROOT, "schema", "report-wording.v1.json")

WORDING_NAME = "vibecheck.report_wording"
LANGUAGES = ("en", "et")
PROFILES = ("founder", "reviewer")

_cache = {}


def load_wording():
    if "wording" not in _cache:
        with open(WORDING_PATH, encoding="utf-8") as fh:
            _cache["wording"] = json.load(fh)
    return _cache["wording"]


def _pick(entry, lang, where):
    if not isinstance(entry, dict) or lang not in entry:
        raise KeyError("report wording %s has no %r translation" % (where, lang))
    return entry[lang]


def text(key, lang):
    """One fixed string, e.g. a heading or a note."""
    table = load_wording()["text"]
    if key not in table:
        raise KeyError("report wording has no text %r" % (key,))
    return _pick(table[key], lang, "text.%s" % key)


def label(group, key, lang, default=None):
    """One label from a labelled group (levels, domains, owner roles, ...).

    An unrecognised key is not silently blanked: it renders as the raw value,
    so an unmapped enum shows up in the output instead of disappearing from it.
    A key that is absent is a different thing from one that is unmapped: an
    optional field the envelope never set renders empty — which the table
    writer turns into an em-dash — never as the literal text "None".
    """
    table = load_wording()["labels"]
    if group not in table:
        raise KeyError("report wording has no label group %r" % (group,))
    entry = table[group].get(key)
    if entry is None:
        if default is not None:
            return default
        return "" if key is None else str(key)
    return _pick(entry, lang, "labels.%s.%s" % (group, key))


def group_wording(group_id, part, lang):
    """Scenario-group title or opener."""
    table = load_wording()["labels"]["scenario_groups"]
    if group_id not in table:
        raise KeyError("report wording has no scenario group %r" % (group_id,))
    return _pick(table[group_id][part], lang, "scenario_groups.%s.%s" % (group_id, part))


def template(key, lang, **values):
    """A template string with its placeholders filled."""
    table = load_wording()["templates"]
    if key not in table:
        raise KeyError("report wording has no template %r" % (key,))
    return _pick(table[key], lang, "templates.%s" % key).format(**values)


def disclaimers(lang):
    """The strings that are allowed to mention certification, security or
    shipping — because they deny all three. tests/test_report.py strips exactly
    these before checking that nothing else claims any of them."""
    return [text(key, lang) for key in load_wording()["disclaimer_keys"]]


# ----------------------------------------------------------- control wording

def _mapping_index():
    if "mapping" not in _cache:
        mapping = canonical.load_framework_mapping()
        _cache["mapping"] = {entry["control_id"]: entry for entry in mapping["entries"]}
    return _cache["mapping"]


def control_entry(control_id):
    return _mapping_index().get(control_id)


def control_wording(control_id, lang, profile="founder"):
    """What to call a control in this language and profile.

    The founder profile asks the plain question the workbook asks; the reviewer
    profile states the technical control. Both come from the vibecheck_v1
    mapping, so neither can drift from the checklist.
    """
    entry = control_entry(control_id)
    if entry is None:
        return control_id
    key = "%s_%s" % ("plain" if profile == "founder" else "tech", lang)
    return entry["wording"].get(key, control_id)


def control_category(control_id, lang):
    entry = control_entry(control_id)
    if entry is None:
        return ""
    return entry["category"].get(lang, entry["category"].get("en", ""))


def item_number(control_id):
    entry = control_entry(control_id)
    return entry["item_number"] if entry else None


def status_label(status, lang):
    """Canonical status -> the workbook's wording, from the framework mapping."""
    table = canonical.load_framework_mapping()["status_map"]
    entry = table.get(status)
    return _pick(entry, lang, "status_map.%s" % status) if entry else str(status)


def dimension_question(dimension_id, lang):
    """The founder-facing question behind a context dimension."""
    return label("dimensions", dimension_id, lang)


def dimension_value(dimension_id, value, lang):
    """The reader-facing wording of one captured context answer."""
    table = load_wording()["labels"]["dimension_values"]
    entry = (table.get(dimension_id) or {}).get(value)
    return _pick(entry, lang, "dimension_values.%s.%s" % (dimension_id, value)) \
        if entry else str(value)


def scope_label(scope, lang):
    """`environment + intended use` in reader-facing words."""
    return template(
        "scope_pair", lang,
        environment=label("environments", scope.get("environment"), lang),
        intended_use=label("intended_uses", scope.get("intended_use"), lang))
