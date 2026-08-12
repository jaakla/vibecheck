#!/usr/bin/env python3
"""Extract conservative RLS signals from SQL files listed as NUL-separated paths.

This is intentionally a signal extractor, not a SQL parser.  Unlike line-based
grep it handles normal multiline migrations and reports enough evidence for a
reviewer to confirm the result.
"""

import argparse
import json
import re


IDENT_PART = r'(?:"(?:[^"]|"")+"|[A-Za-z_][A-Za-z0-9_$]*)'
IDENT = IDENT_PART + r'(?:\s*\.\s*' + IDENT_PART + r')?'

CREATE_TABLE = re.compile(
    r'\bcreate\s+(?:unlogged\s+)?table\s+(?:if\s+not\s+exists\s+)?('
    + IDENT + r')', re.I)
ENABLE_RLS = re.compile(
    r'\balter\s+table\s+(?:only\s+)?(' + IDENT
    + r')\s+enable\s+row\s+level\s+security\b', re.I)
PERMISSIVE = re.compile(
    r'\b(?:using|with\s+check)\s*\(\s*true\s*\)', re.I)
POLICY_STMT = re.compile(r'\bcreate\s+policy\b.*?;', re.I | re.S)
ANON_ROLE = re.compile(
    r'\bto\b[^;]*?(?<![A-Za-z0-9_$])anon(?![A-Za-z0-9_$])', re.I)
WRITE_POLICY = re.compile(r'\bfor\s+(?:insert|update|delete|all)\b', re.I)
ANON_GRANT = re.compile(
    r'\bgrant\s+(?:all|insert|update|delete)(?:\s*,\s*(?:insert|update|delete))*'
    r'\s+on\b.*?\bto\s+anon\b.*?;', re.I | re.S)


def strip_comments(text):
    """Remove SQL comments while preserving newlines for evidence line numbers."""
    text = re.sub(r'/\*.*?\*/', lambda m: '\n' * m.group(0).count('\n'),
                  text, flags=re.S)
    return re.sub(r'--[^\n]*', '', text)


def canonical(identifier):
    parts = [p.strip() for p in re.split(r'\s*\.\s*', identifier)]
    normalized = []
    for part in parts:
        if part.startswith('"') and part.endswith('"'):
            normalized.append(part[1:-1].replace('""', '"'))
        else:
            normalized.append(part.lower())
    return '.'.join(normalized)


def line_evidence(path, text, match):
    line_no = text.count('\n', 0, match.start()) + 1
    excerpt = re.sub(r'\s+', ' ', match.group(0)).strip()[:180]
    return "%s:%d:%s" % (path, line_no, excerpt)


def rls_matches(created, enabled):
    # Do not collapse schemas by basename: public.accounts and tenant.accounts
    # are different tables. An imprecise match here creates a dangerous false
    # negative, so require the migration references to agree exactly.
    return created in enabled


def analyze(paths):
    created = set()
    enabled = set()
    permissive = []
    anon_write = []

    for path in paths:
        with open(path, encoding='utf-8', errors='replace') as handle:
            raw = handle.read()
        text = strip_comments(raw)
        created.update(canonical(m.group(1)) for m in CREATE_TABLE.finditer(text))
        enabled.update(canonical(m.group(1)) for m in ENABLE_RLS.finditer(text))
        permissive.extend(line_evidence(path, text, m)
                          for m in PERMISSIVE.finditer(text))
        for match in POLICY_STMT.finditer(text):
            stmt = match.group(0)
            if ANON_ROLE.search(stmt) and WRITE_POLICY.search(stmt):
                anon_write.append(line_evidence(path, text, match))
        anon_write.extend(line_evidence(path, text, m)
                          for m in ANON_GRANT.finditer(text))

    missing = sorted(t for t in created if not rls_matches(t, enabled))
    return {
        'created': sorted(created),
        'rls_enabled': sorted(enabled),
        'missing_rls': missing,
        'permissive': permissive[:40],
        'anon_write': anon_write[:40],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--files-from', required=True,
                        help='file containing NUL-separated SQL paths')
    args = parser.parse_args()
    with open(args.files_from, 'rb') as handle:
        paths = [p.decode('utf-8', 'surrogateescape')
                 for p in handle.read().split(b'\0') if p]
    print(json.dumps(analyze(paths)))


if __name__ == '__main__':
    main()
