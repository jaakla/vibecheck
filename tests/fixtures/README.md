# Scanner fixtures

Three miniature repos the test suite scans. They are **not** real applications and
must never be deployed or copied from.

| Fixture | Purpose |
|---|---|
| `vulnerable-app/` | Trips every FAIL-tier check. Asserts the scanner still detects what it claims to. |
| `clean-app/` | The same shapes done correctly. Asserts the scanner produces no FAIL — guards against false positives. |
| `docs-only/` | Source files whose *prose* mentions `md5`, `Math.random` tokens, webhooks and `service_role`. Asserts the scanner does not FAIL on documentation about security. This is a regression test: earlier versions FAILed on their own checklist text. |

All credentials in `vulnerable-app/` are fake strings chosen to match the scanner's
prefix regexes (`sk-ant-FAKE…`, `AKIAFAKEFAKEFAKEFAKE`). They authenticate nothing.
