# Confidentiality review

Use this guide to verify that data is disclosed only to authorized people and services. Start from
the project reconnaissance data map. Apply only relevant areas, but explicitly record skipped or
unresolved areas as Not tested/to-do.

## Contents

- Method
- Credentials and secret-bearing configuration
- Sessions, cookies, and authentication lifecycle
- Route protection, CSRF, CORS, and browser boundaries
- Data at rest, serialization, and response minimization
- Data in transit and proxy boundaries
- Outbound requests and SSRF
- Logs, analytics, prompts, and third-party disclosure
- Bootstrap, seed, and administrative recovery
- Finding content

## Method

1. Start with the configuration, entry point, route, service, persistence, and response/logging
   files identified during reconnaissance.
2. Trace every applicable path end to end. Expand the search when the initial files do not answer
   precedence, masking, authorization, serialization, redirect, retry, or error behavior, and keep
   an evidence trail of the additional files or runtime settings inspected.
3. Record a finding only when code, runtime evidence, or supplied configuration confirms the
   exposure mechanism. Treat ambiguous framework/provider behavior as a verification task.
4. Map confirmed findings to the existing 89-item checklist. Do not invent a parallel ID, status,
   severity, or verdict system.
5. For an applicable area with no confirmed issue, say that no finding was confirmed and name any
   remaining evidence gap. This does not establish a checklist Pass by itself.

For a confidentiality-only request, keep integrity and availability outside that targeted pass and
do not claim completion of the full Vibecheck review. In a full review, use this guide alongside the
other checklist areas.

## Review areas

### Credentials and secret-bearing configuration (#7-#11, #38, #43, #48-#49, #56-#57)

- Trace every source and consumer of API keys, signing keys, database credentials, integration
  tokens, and passwords. Establish precedence when the same secret can come from several sources.
- Verify that encryption/masking happens before serialization and cannot be bypassed by alternate
  routes, list endpoints, development branches, object spreading, or error handlers.
- Check whether credentials are logged, reflected to clients, placed in prompts/telemetry, stored
  reversibly without a need, or retained after an integration is disconnected.
- Distinguish intentional one-time secret display from ongoing retrieval; verify authorization and
  auditability for both.

### Sessions, cookies, and authentication lifecycle (#3, #12, #16, #39, #42-#45, #56, #68, #70)

- Identify session/token signing secrets, their source, rotation path, and any static fallback.
- Check cookie flags and token transport in every environment: `Secure`, `HttpOnly`, `SameSite`,
  domain/path scope, expiry, and HTTPS assumptions.
- For server-side sessions, check store isolation, TTL, logout destruction, fixation prevention,
  and invalidation after password or permission changes.
- Trace login, logout, password reset/change, bootstrap, refresh, impersonation, and admin flows.
  Confirm error responses and logs do not reveal credentials, tokens, or account existence beyond
  the intended policy.

### Route protection, CSRF, CORS, and browser boundaries (#12-#16, #28, #30, #44-#45, #70)

- Build the route/middleware registration order and identify every unauthenticated exemption.
- Verify server-side authentication and object/tenant authorization for all reads and mutations;
  UI hiding is not enforcement.
- For cookie-authenticated applications, check CSRF on all state-changing methods and exemptions.
  Verify token session binding and rotation across login/logout.
- Check CORS origins, credentials, methods, and headers together with cookie `SameSite` behavior.
  Look for route/proxy headers that override the global policy.
- Verify CSP, framing, MIME sniffing, referrer, permissions, and cache controls where sensitive
  responses make them relevant.

### Data at rest, serialization, and response minimization (#12-#16, #28, #34, #36, #55-#59)

- Trace sensitive columns, JSON/document fields, object storage, caches, queues, logs, backups, and
  search indexes. Confirm encryption and access restrictions rather than assuming provider defaults.
- Review select/include clauses and serializers for list, detail, export, admin, debug, and error
  endpoints. Avoid returning whole ORM records or JSON blobs when the client needs a subset.
- Check whether raw HTML, uploaded files, prompts, model responses, reset tokens, internal state,
  or integration configuration can reach unintended clients or tenants.
- Verify retention, deletion, backup handling, and third-party deletion for the stated lifecycle.

### Data in transit and proxy boundaries (#43-#45, #48, #55-#58)

- Verify plaintext-to-HTTPS redirects, HSTS, minimum TLS versions, and certificate handling at the
  actual public termination point.
- Inspect database, cache, queue, object-storage, and third-party connection configuration for TLS
  enforcement and certificate verification.
- Check reverse-proxy/app interactions for stripped, weakened, duplicated, or trusted-forwarded
  headers. Mark provider-managed settings as requiring deployment evidence when absent from code.

### Outbound requests and SSRF (#27-#28, #32, #73, #75)

- Allowlist required schemes and reject credentials, unexpected ports, private/loopback/link-local/
  multicast/reserved destinations for IPv4 and IPv6.
- Resolve and validate destination addresses at connection time; consider DNS rebinding, redirects,
  alternate IP encodings, and proxy behavior. Revalidate every redirect target.
- Bound connect/read/total time, redirects, response bytes, decompression, and accepted content
  types. Apply equivalent controls before storing fetched content.
- Confirm outbound requests cannot reach cloud metadata, internal admin services, or tenant-private
  resources through user-controlled URLs.

### Logs, analytics, prompts, and third-party disclosure (#10, #38-#40, #49, #55, #57-#59, #80-#81, #87)

- Inspect request/error logging for bodies, query parameters, headers, cookies, CSRF tokens,
  credentials, PII, customer content, and raw provider responses at every log level.
- Trace prompt and AI-usage records: included content, tenant/user association, access controls,
  redaction/truncation, retention, training/retention settings, and deletion.
- Inventory analytics, error tracking, email/SMS, payments, model providers, CDNs, and other runtime
  recipients. Compare transmitted data and scopes with the product need.
- Check that sensitive data is absent from URLs, metric labels, trace attributes, notifications,
  client telemetry, and support tooling.

### Bootstrap, seed, and administrative recovery (#9-#12, #16, #43, #56, #68, #82-#83)

- Trace initial admin creation and repeated seed behavior. Verify passwords are not printed,
  embedded, silently reset, or left at a shared default.
- Confirm a controlled password/credential rotation and account-recovery path exists after bootstrap.
- Review maintenance scripts and CLIs that access production data or infrastructure for authorization,
  secret handling, environment selection, and auditability.

## Finding content

For every confirmed issue, include the mapped checklist item, severity, reproducible evidence,
plain-language impact, exposure conditions, technical mechanism, and concrete remediation direction.
Keep remediation as guidance unless the user invokes `vibecheck-fix`; do not edit the reviewed
repository during a scan.
