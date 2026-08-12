# Scanner fixtures

Three miniature repos the test suite scans. They are **not** real applications and
must never be deployed or copied from.

| Fixture | Purpose |
|---|---|
| `vulnerable-app/` | Trips every planted warning signal. Asserts the scanner still detects what it claims to. |
| `clean-app/` | The same shapes done correctly. Asserts the relevant checks return NO_SIGNAL — guards against false warnings. |
| `docs-only/` | Source files whose *prose* mentions `md5`, `Math.random` tokens, webhooks and `service_role`. Asserts documentation is not mistaken for a conclusive finding. |

All credentials in `vulnerable-app/` are fake strings chosen to match the scanner's
prefix regexes (`sk-ant-FAKE…`, `AKIAFAKEFAKEFAKEFAKE`). They authenticate nothing.
