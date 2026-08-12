#!/usr/bin/env python3
"""Redact, cap and JSON-encode scanner evidence read from stdin.

Kept as a file rather than an inline heredoc: `python3 - <<'PY'` feeds the
*script* on stdin, which silently leaves sys.stdin.read() empty and emits
evidence-free findings.

Rules, in order:
  1. Known credential shapes -> first 8 chars + a redaction marker.
  2. Any remaining high-entropy run (40+ chars) -> same treatment. '/' and '.'
     are excluded from the run so file paths survive intact.
  3. Lines capped at 200 chars, output capped at 40 lines (base64 blobs in git
     history used to arrive here 4 KB at a time).
"""
import json
import re
import sys

KNOWN = re.compile(
    r'(sk-ant-[A-Za-z0-9_\-]{6,}'
    r'|sk-proj-[A-Za-z0-9_\-]{6,}'
    r'|sk-[A-Za-z0-9]{20,}'
    r'|(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{6,}'
    r'|AKIA[0-9A-Z]{16}'
    r'|gh[pousr]_[A-Za-z0-9]{20,}'
    r'|xox[bapsr]-[A-Za-z0-9-]{10,}'
    r'|sb_secret_[A-Za-z0-9_\-]{10,}'
    r'|eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,})')

GENERIC = re.compile(r'[A-Za-z0-9+_\-]{40,}')

# --strings mode: any quoted literal of real length. Used for the hardcoded-secret
# check, where every evidence line is by construction `<secret-ish name> = "<value>"`
# and the value may be a low-entropy passphrase that KNOWN/GENERIC would miss.
QUOTED = re.compile(r'(["\'])([^"\']{10,})\1')

MAX_LINE = 200
MAX_LINES = 40
MAX_TOTAL = 4000


def cut(match):
    s = match.group(0)
    return s[:8] + '...[REDACTED %d chars]' % (len(s) - 8)


def cut_quoted(match):
    q, value = match.group(1), match.group(2)
    return '%s%s...[REDACTED %d chars]%s' % (q, value[:4], len(value) - 4, q)


def main():
    text = sys.stdin.read()
    text = KNOWN.sub(cut, text)
    text = GENERIC.sub(cut, text)
    if '--strings' in sys.argv[1:]:
        text = QUOTED.sub(cut_quoted, text)

    lines = []
    for line in text.splitlines():
        if len(lines) >= MAX_LINES:
            lines.append('...[more matches suppressed]')
            break
        lines.append(line if len(line) <= MAX_LINE
                     else line[:MAX_LINE] + ' ...[truncated]')

    rendered = '\n'.join(lines).strip()
    encoded = json.dumps(rendered)
    if len(encoded) > MAX_TOTAL:
        suffix = ' ...[truncated]'
        lo, hi = 0, len(rendered)
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if len(json.dumps(rendered[:mid] + suffix)) <= MAX_TOTAL:
                lo = mid
            else:
                hi = mid - 1
        encoded = json.dumps(rendered[:lo] + suffix)
    sys.stdout.write(encoded)


if __name__ == '__main__':
    main()
