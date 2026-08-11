#!/usr/bin/env bash
# vibecheck.sh — static scanner for vibecoded applications.
# Usage: vibecheck.sh [repo_dir]   (defaults to current directory)
# Output: JSON to stdout, one finding object per line-item, plus a summary.
# Exit code: 0 always (findings are data, not errors). Claude interprets results.
#
# Each finding maps to checklist item numbers (#1-#89) from the Goplex
# vibecoded-app review workbook. status: FAIL | WARN | PASS | MANUAL
# WARN = suspicious hit needing human/LLM judgment. MANUAL = cannot be automated.
#
# The check id -> checklist item mapping is mirrored in scripts/items.py
# (SCANNER_CHECKS); tests/test_coverage_map.py fails if the two drift apart.
#
# Compatible with bash 3.2 (macOS system bash): no mapfile, no associative arrays.

set -uo pipefail

VERSION="0.2.0"

case "${1:-}" in
  -h|--help)
    sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
    exit 0 ;;
  -v|--version)
    echo "$VERSION"; exit 0 ;;
esac

# Resolve helper paths before cd'ing into the target repo.
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd -P)
REDACT="$SCRIPT_DIR/_redact.py"

REPO="${1:-.}"
cd "$REPO" 2>/dev/null || { echo '{"error":"repo dir not found"}'; exit 0; }

TMPD=$(mktemp -d 2>/dev/null) || { echo '{"error":"cannot create temp dir"}'; exit 0; }
trap 'rm -rf "$TMPD"' EXIT INT TERM

IS_GIT=0
git rev-parse --git-dir >/dev/null 2>&1 && IS_GIT=1

# ---------------------------------------------------------------- file lists
# Source file globs to scan (skip node_modules, dist, build, .git, lockfiles).
SRC_FIND=(-type f \( -name '*.ts' -o -name '*.tsx' -o -name '*.js' -o -name '*.jsx' -o -name '*.mjs' -o -name '*.cjs' -o -name '*.py' -o -name '*.vue' -o -name '*.svelte' -o -name '*.html' -o -name '*.sql' -o -name '*.toml' -o -name '*.yaml' -o -name '*.yml' -o -name '*.json' -o -name '*.env*' \) \
  -not -path '*/node_modules/*' -not -path '*/.git/*' -not -path '*/dist/*' -not -path '*/build/*' -not -path '*/.next/*' -not -path '*/.venv/*' -not -path '*/venv/*' -not -path '*/vendor/*' -not -path '*/__pycache__/*' \
  -not -name 'package-lock.json' -not -name 'yarn.lock' -not -name 'pnpm-lock.yaml' -not -name 'bun.lockb')

ALL_Z="$TMPD/all.z"          # every scannable source file, NUL-separated
find . "${SRC_FIND[@]}" -print0 2>/dev/null > "$ALL_Z"

# subset_z <name> <extension-regex> — build a NUL list filtered by path regex.
subset_z() {
  local out="$TMPD/$1.z"
  tr '\0' '\n' < "$ALL_Z" | grep -Ei "$2" 2>/dev/null | tr '\n' '\0' > "$out"
  echo "$out"
}
CLIENT_Z=$(subset_z client '\.(tsx|jsx|vue|svelte|html)$')
JS_Z=$(subset_z js '\.(ts|tsx|js|jsx|mjs|cjs|vue|svelte)$')
CODE_Z=$(subset_z code '\.(ts|tsx|js|jsx|mjs|cjs|py|vue|svelte|html)$')
SQL_Z=$(subset_z sql '\.sql$')

has_files() { [ -s "$1" ]; }

# ------------------------------------------------------------------- output
# Evidence is redacted (secret-shaped strings truncated) and line-capped by
# scripts/_redact.py before it reaches stdout, so a scan can be pasted into a
# report or a ticket without leaking the credential it just found.
#
# Checks below use `[ -n "$HITS" ] && emit FAIL || emit PASS` (shellcheck
# SC2015). That is safe here only because emit() always succeeds — if you ever
# give emit a failing exit path, both branches will fire. Keep it returning 0.
emit() { # emit id items status title evidence [redact-flags]
  local id="$1" items="$2" status="$3" title="$4" evidence="$5" flags="${6:-}"
  local ev ti
  ev=$(printf '%s' "$evidence" | python3 "$REDACT" $flags 2>/dev/null) || ev='""'
  [ -n "$ev" ] || ev='""'
  ti=$(printf '%s' "$title" | python3 "$REDACT" 2>/dev/null) || ti='""'
  [ -n "$ti" ] || ti='""'
  printf '{"check":"%s","checklist_items":%s,"status":"%s","title":%s,"evidence":%s}\n' \
    "$id" "$items" "$status" "$ti" "$ev"
}

# --------------------------------------------------------------- grep helpers
# -H forces the filename prefix even when xargs' final batch holds one file
# (without it, evidence lines silently lose their path).
MAXHITS=40

grep_list() { # grep_list <nul-list> <pattern> [extra grep args...]
  local list="$1" pat="$2"; shift 2
  [ -s "$list" ] || return 0
  xargs -0 grep -nHEI "$@" -e "$pat" < "$list" 2>/dev/null | head -"$MAXHITS"
}
grep_src()    { local p="$1"; shift; grep_list "$ALL_Z"    "$p" "$@"; }
grep_client() { local p="$1"; shift; grep_list "$CLIENT_Z" "$p" "$@"; }
grep_js()     { local p="$1"; shift; grep_list "$JS_Z"     "$p" "$@"; }
grep_code()   { local p="$1"; shift; grep_list "$CODE_Z"   "$p" "$@"; }

# Uncapped count — grep_src truncates at MAXHITS, so any threshold above that
# is unreachable through it. Thresholded checks must use this instead.
count_src() {
  local pat="$1"; shift
  [ -s "$ALL_Z" ] || { echo 0; return; }
  xargs -0 grep -cHEI "$@" -e "$pat" < "$ALL_Z" 2>/dev/null \
    | awk -F: '{s+=$NF} END {print s+0}'
}

# package.json dependency lookup (deps + devDeps text, quoted names only)
pkg_dep() { # pkg_dep <name-regex>
  [ -f package.json ] || return 0
  grep -oE "\"($1)\"[[:space:]]*:" package.json 2>/dev/null | sed 's/[[:space:]]*:$//' | sort -u
}

echo "{\"scanner\":\"vibecheck\",\"version\":\"$VERSION\"}"

# ---------- 0. Scan scope ----------
if [ "$IS_GIT" = 1 ]; then
  GIT_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || echo "")
  SCAN_ROOT=$(pwd -P)
  if [ -n "$GIT_ROOT" ] && [ "$GIT_ROOT" != "$SCAN_ROOT" ]; then
    emit "scan.scope" "[9]" "WARN" "Scanned directory is nested inside a larger git repo — history checks are pathspec-scoped to this subtree, but repo-wide leaks elsewhere are not covered" "git root: $GIT_ROOT
scan root: $SCAN_ROOT"
  fi
fi

# ---------- 1. Secrets & credentials (#7-#11) ----------
# 1a. Hardcoded secret-looking strings in source (assignments with long values)
HITS=$(grep_src "(api[_-]?key|apikey|secret|password|token|private[_-]?key)['\"]?[[:space:]]*[:=][[:space:]]*['\"][A-Za-z0-9_\-\.\+/]{16,}['\"]" -i)
# filter obvious placeholders/env reads
HITS=$(echo "$HITS" | grep -vEi 'process\.env|import\.meta\.env|os\.environ|getenv|YOUR_|EXAMPLE|PLACEHOLDER|CHANGEME|xxx+|<[A-Z_]+>|\$\{' || true)
[ -n "$HITS" ] && emit "secrets.hardcoded" "[7]" "FAIL" "Secret-like literals assigned in source" "$HITS" "--strings" \
               || emit "secrets.hardcoded" "[7]" "PASS" "No hardcoded secret-like literals found" ""

# 1b. Known key prefixes (Anthropic/OpenAI/Stripe/AWS/GitHub/Slack).
# Each prefix requires a key body — a bare "sk-ant-" in prose is documentation,
# not a credential.
KEY_PREFIXES="(sk-ant-[A-Za-z0-9_\-]{12,}|sk-proj-[A-Za-z0-9_\-]{12,}|sk_live_[A-Za-z0-9]{12,}|rk_live_[A-Za-z0-9]{12,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|xox[bapsr]-[A-Za-z0-9-]{12,})"
HITS=$(grep_src "$KEY_PREFIXES")
[ -n "$HITS" ] && emit "secrets.known_prefixes" "[7,8]" "FAIL" "Provider key prefixes present in source" "$HITS" \
               || emit "secrets.known_prefixes" "[7,8]" "PASS" "No known provider key prefixes in source" ""

# 1c. service_role — critical in client-reachable code, worth confirming anywhere else
CLIENT_SR=$(grep_client "service_role")
ANY_SR=$(grep_code "service_role")
if [ -n "$CLIENT_SR" ]; then
  emit "secrets.service_role" "[8]" "FAIL" "service_role key referenced in client-side component code — this ships to the browser" "$CLIENT_SR"
elif [ -n "$ANY_SR" ]; then
  emit "secrets.service_role" "[8]" "WARN" "service_role referenced — verify every use is server-side only (edge function / API route)" "$ANY_SR"
else
  emit "secrets.service_role" "[8]" "PASS" "No service_role references in source" ""
fi

# 1d. .env committed / present in git history (pathspec-scoped to the scanned subtree)
if [ "$IS_GIT" = 1 ]; then
  TRACKED=$(git ls-files 2>/dev/null | grep -E '(^|/)\.env(\..+)?$' | grep -v '\.example' || true)
  [ -n "$TRACKED" ] && emit "secrets.env_tracked" "[9]" "FAIL" ".env file(s) tracked by git" "$TRACKED" \
                    || emit "secrets.env_tracked" "[9]" "PASS" "No .env files tracked" ""
  HIST=$(git log --all --name-only --pretty=format: -- . 2>/dev/null \
         | grep -E '(^|/)\.env(\..+)?$' | grep -v '\.example' | sort -u | head -20 || true)
  [ -n "$HIST" ] && emit "secrets.env_history" "[9,11]" "FAIL" ".env file(s) exist in git HISTORY — rotate all keys they held" "$HIST" \
                 || emit "secrets.env_history" "[9,11]" "PASS" "No .env files in git history" ""
  GI_OK=$(grep -hsE '^[[:space:]]*\.env' .gitignore 2>/dev/null || true)
  [ -z "$GI_OK" ] && emit "secrets.gitignore" "[9]" "WARN" ".env not listed in .gitignore" "" \
                  || emit "secrets.gitignore" "[9]" "PASS" ".env is gitignored" "$GI_OK"
  # Secrets in history content (sampled, bounded, scoped to this subtree).
  HSEC=$(git log --all -p --pretty=format: -- . 2>/dev/null | head -40000 \
         | grep -E '^\+' | grep -E "$KEY_PREFIXES" | head -10 || true)
  [ -n "$HSEC" ] && emit "secrets.history_content" "[9,11]" "FAIL" "Key-like strings found in git history (sampled) — rotate" "$HSEC" \
                 || emit "secrets.history_content" "[9,11]" "PASS" "No key prefixes in sampled git history" ""
else
  emit "secrets.env_tracked" "[9]" "MANUAL" "Not a git repo — tracked-file and history checks skipped" ""
fi

# ---------- 2. Authorization & access control (#12-#16) ----------
if has_files "$SQL_Z"; then
  # Table names created in migrations, matched against ENABLE ROW LEVEL SECURITY.
  CREATED=$(xargs -0 grep -hoiE 'create table (if not exists )?[a-zA-Z0-9_."]+' < "$SQL_Z" 2>/dev/null \
            | sed -E 's/create table (if not exists )?//I' | tr -d '"' | sed 's/.*\.//' | sort -u)
  RLSON=$(xargs -0 grep -hoiE 'alter table [a-zA-Z0-9_."]+ enable row level security' < "$SQL_Z" 2>/dev/null \
          | sed -E 's/alter table //I; s/ enable row level security//I' | tr -d '"' | sed 's/.*\.//' | sort -u)
  NORLS=""
  for t in $CREATED; do
    echo "$RLSON" | grep -qxF "$t" || NORLS="$NORLS $t"
  done
  if [ -n "$NORLS" ]; then
    emit "rls.missing" "[12,14]" "FAIL" "Tables created without a matching ENABLE ROW LEVEL SECURITY" "tables:$NORLS"
  else
    emit "rls.missing" "[12,14]" "PASS" "All created tables have RLS enabled in migrations" ""
  fi
  PERM=$(grep_list "$SQL_Z" 'using[[:space:]]*\([[:space:]]*true[[:space:]]*\)|with check[[:space:]]*\([[:space:]]*true[[:space:]]*\)' -i)
  [ -n "$PERM" ] && emit "rls.permissive" "[13,14]" "FAIL" "Permissive RLS policies: using(true)/with check(true)" "$PERM" \
                 || emit "rls.permissive" "[13,14]" "PASS" "No using(true) placeholder policies" ""
  ANONW=$(grep_list "$SQL_Z" 'to[[:space:]]+anon\b' -i | grep -iE 'insert|update|delete|all' | head -10 || true)
  [ -n "$ANONW" ] && emit "rls.anon_write" "[14]" "WARN" "Policies grant write to the anon role — verify intent" "$ANONW" \
                  || emit "rls.anon_write" "[14]" "PASS" "No anon write grants in policies" ""
else
  emit "rls.missing" "[12,14]" "MANUAL" "No SQL migrations found — run the vibecheck-supabase live probe" ""
fi
emit "authz.idor" "[13]" "MANUAL" "IDOR requires a live probe — use the vibecheck-supabase skill or two test accounts" ""

# Admin gating that exists only in UI components
HITS=$(grep_client "(isAdmin|is_admin|role[[:space:]]*===?[[:space:]]*['\"]admin)")
[ -n "$HITS" ] && emit "authz.client_admin" "[16]" "WARN" "Admin-role checks in UI components — verify server-side enforcement also exists" "$HITS" \
               || emit "authz.client_admin" "[16]" "PASS" "No client-side-only admin gating patterns found" ""

# ---------- 3. Product readiness — is it real? (#17-#22) ----------
HITS=$(grep_code "(mockData|MOCK_|dummyData|sampleData|fakeData|FIXME|TODO:)" \
       | grep -vEi '(^|/)(tests?|__tests__|__mocks__|spec|e2e|fixtures?|stories)/|\.(test|spec|stories)\.' | head -20 || true)
[ -n "$HITS" ] && emit "real.mocks" "[17,18,19,20,21,22]" "WARN" "Mock/stub/TODO markers in non-test code — verify these features are actually live" "$HITS" \
               || emit "real.mocks" "[17,18,19,20,21,22]" "PASS" "No mock/stub markers outside tests" ""

HITS=$(grep_code "(sk_test_|pk_test_)")
[ -n "$HITS" ] && emit "real.stripe_test" "[20]" "WARN" "Stripe TEST-mode keys referenced — confirm production uses live mode" "$HITS" \
               || emit "real.stripe_test" "[20]" "PASS" "No Stripe test-mode key references" ""

HITS=$(grep_js "localStorage\.(set|get)Item\(['\"](token|jwt|auth|session)" -i)
[ -n "$HITS" ] && emit "real.localstorage_auth" "[17]" "WARN" "Auth tokens in localStorage — check persistence model and XSS exposure" "$HITS" \
               || emit "real.localstorage_auth" "[17]" "PASS" "No auth tokens in localStorage" ""

# ---------- 4. Cost & abuse blast radius (#23-#27) ----------
LLM_ENDPOINT="(api\.anthropic\.com|api\.openai\.com|generativelanguage\.googleapis|openrouter\.ai)"
LLM_SDK="(\.messages\.create|chat\.completions|generateText|streamText|new Anthropic|new OpenAI|invokeModel|ChatOpenAI|ChatAnthropic|langchain)"
LLM_DEPS=$(pkg_dep "openai|@anthropic-ai/sdk|@ai-sdk/[a-z-]+|ai|langchain|@langchain/[a-z-]+|@google/generative-ai|ollama|replicate")
LLM=$(grep_code "$LLM_ENDPOINT|$LLM_SDK")

if [ -n "$LLM" ] || [ -n "$LLM_DEPS" ]; then
  RL=$(grep_code "(rateLimit|rate_limit|ratelimit|Ratelimit|@upstash/ratelimit|bottleneck|p-limit|pLimit|throttle|slowDown|express-rate-limit)")
  RL_DEPS=$(pkg_dep "@upstash/ratelimit|express-rate-limit|bottleneck|p-limit|rate-limiter-flexible|slowapi")
  if [ -z "$RL" ] && [ -z "$RL_DEPS" ]; then
    emit "cost.no_ratelimit" "[23]" "FAIL" "LLM/paid API usage present but no rate-limiting library or pattern found" "$LLM$LLM_DEPS"
  else
    emit "cost.no_ratelimit" "[23]" "PASS" "LLM usage and rate-limiting patterns both present — confirm the limiter actually wraps the expensive call" "$RL
$RL_DEPS"
  fi
  CLIENTLLM=$(grep_client "$LLM_ENDPOINT|$LLM_SDK")
  [ -n "$CLIENTLLM" ] && emit "cost.client_llm" "[8,26]" "FAIL" "LLM endpoints called from client-side code (key exposure + uncapped spend)" "$CLIENTLLM" \
                      || emit "cost.client_llm" "[8,26]" "PASS" "LLM calls appear server-side" ""
else
  emit "cost.no_ratelimit" "[23]" "PASS" "No LLM/paid API usage found in source" ""
  emit "cost.client_llm" "[8,26]" "PASS" "No LLM endpoints in client code" ""
fi
emit "cost.budget_caps" "[24]" "MANUAL" "Budget caps live in provider dashboards — verify manually" ""

# ---------- 5. Input handling & injection (#28-#32) ----------
HITS=$(grep_code "dangerouslySetInnerHTML|innerHTML[[:space:]]*=|v-html")
[ -n "$HITS" ] && emit "inject.xss" "[30]" "WARN" "Raw HTML injection sinks — verify inputs are sanitized (DOMPurify or equivalent)" "$HITS" \
               || emit "inject.xss" "[30]" "PASS" "No innerHTML/dangerouslySetInnerHTML/v-html sinks" ""

HITS=$(grep_code "(query|execute|raw)[[:space:]]*\([[:space:]]*[\`'\"].*(SELECT|INSERT|UPDATE|DELETE).*(\\\$\{|['\"][[:space:]]*\+)" -i)
[ -n "$HITS" ] && emit "inject.sql" "[29]" "FAIL" "String-built SQL detected" "$HITS" \
               || emit "inject.sql" "[29]" "PASS" "No string-concatenated SQL found" ""

# Validation libraries: imports and manifest entries only — a bare word match
# hits prose and substrings ("joi" inside "join").
VAL_IMPORT=$(grep_code "(from|require\(|import)[[:space:]]*['\"](zod|joi|@hapi/joi|yup|valibot|class-validator|superstruct|ajv)['\"]|^[[:space:]]*(import|from)[[:space:]]+pydantic|^[[:space:]]*import[[:space:]]+marshmallow")
VAL_DEPS=$(pkg_dep "zod|joi|@hapi/joi|yup|valibot|class-validator|superstruct|ajv|pydantic")
if [ -z "$VAL_IMPORT" ] && [ -z "$VAL_DEPS" ]; then
  emit "inject.validation" "[28]" "WARN" "No validation library detected — server-side input validation may be missing" ""
else
  emit "inject.validation" "[28]" "PASS" "Validation library present — confirm it is applied on server-side entry points" "$VAL_IMPORT
$VAL_DEPS"
fi

# ---------- 6. Prompt injection & agents (#77-#81) ----------
LLM_MARK="$LLM_ENDPOINT|$LLM_SDK"
LLM_FILES_Z="$TMPD/llmfiles.z"
: > "$LLM_FILES_Z"
if has_files "$CODE_Z"; then
  xargs -0 grep -lEI -i -e "$LLM_MARK" < "$CODE_Z" 2>/dev/null | tr '\n' '\0' > "$LLM_FILES_Z"
fi

if has_files "$LLM_FILES_Z"; then
  # #77: LLM call and a code/command/SQL execution sink in the same module
  EXEC_HITS=$(grep_list "$LLM_FILES_Z" "(\beval\(|new Function\(|child_process|execSync|\bexec\(|\bspawn\(|vm\.runIn|subprocess\.|os\.system)")
  [ -n "$EXEC_HITS" ] && emit "inject.llm_to_exec" "[77]" "FAIL" "LLM call and a code/command execution sink live in the same module — trace whether model output can reach it" "$EXEC_HITS" \
                      || emit "inject.llm_to_exec" "[77]" "PASS" "No exec/eval/shell sinks in LLM modules" ""

  # #78: variables interpolated raw into prompt strings
  INTERP=$(grep_list "$LLM_FILES_Z" "(content|prompt|system|messages)[^\`\"']{0,40}\`[^\`]*\\\$\{")
  [ -n "$INTERP" ] && emit "inject.prompt_interpolation" "[78]" "WARN" "Variables interpolated into prompt template literals — confirm user text cannot override instructions (delimiting / role separation)" "$INTERP" \
                   || emit "inject.prompt_interpolation" "[78]" "PASS" "No raw variable interpolation into prompt strings" ""

  # #79: tool/function-calling agents
  TOOLS=$(grep_list "$LLM_FILES_Z" "(tools[[:space:]]*:|functions[[:space:]]*:|tool_choice|function_call|tool_use|\.bindTools|StructuredTool)")
  [ -n "$TOOLS" ] && emit "inject.tool_agent" "[79]" "WARN" "Tool/function-calling detected — verify tools are allowlisted, args validated, and authorisation is based on the authenticated user rather than model output" "$TOOLS" \
                  || emit "inject.tool_agent" "[79]" "PASS" "No tool/function-calling agents detected" ""

  # #80: indirect injection — external/RAG content flowing into a model
  INDIRECT=$(grep_list "$LLM_FILES_Z" "(fetch\(|axios\.|http\.get|readFile|web_fetch|scrape|crawl|embeddings|vectorStore|retriever|\brag\b)" | cut -d: -f1 | sort -u | head -20)
  [ -n "$INDIRECT" ] && emit "inject.indirect" "[80]" "WARN" "External/retrieved content flows through LLM modules — treat fetched/RAG content as untrusted data, not instructions" "$INDIRECT" \
                     || emit "inject.indirect" "[80]" "PASS" "No external/retrieved content in LLM modules" ""

  # #81: model output rendered as raw HTML
  TOHTML=$(grep_list "$LLM_FILES_Z" "(dangerouslySetInnerHTML|innerHTML[[:space:]]*=|v-html)")
  [ -n "$TOHTML" ] && emit "inject.llm_to_html" "[81]" "WARN" "LLM module renders raw HTML — model output as HTML turns prompt injection into XSS; render as text or sanitize" "$TOHTML" \
                   || emit "inject.llm_to_html" "[81]" "PASS" "No raw-HTML rendering in LLM modules" ""
else
  emit "inject.llm_to_exec" "[77]" "PASS" "No LLM SDK/endpoint usage detected — prompt-injection surface not present" ""
  emit "inject.prompt_interpolation" "[78]" "PASS" "No LLM SDK/endpoint usage detected" ""
  emit "inject.tool_agent" "[79]" "PASS" "No LLM SDK/endpoint usage detected" ""
  emit "inject.indirect" "[80]" "PASS" "No LLM SDK/endpoint usage detected" ""
  emit "inject.llm_to_html" "[81]" "PASS" "No LLM SDK/endpoint usage detected" ""
fi

# ---------- 7. Errors, logging & observability (#37-#41) ----------
HITS=$(grep_code "catch[[:space:]]*(\([[:space:]]*[a-zA-Z_$]*[[:space:]]*\))?[[:space:]]*\{[[:space:]]*\}")
[ -n "$HITS" ] && emit "errors.swallowed" "[37]" "WARN" "Empty catch blocks — errors are silently swallowed" "$HITS" \
               || emit "errors.swallowed" "[37]" "PASS" "No empty catch blocks" ""

ET_IMPORT=$(grep_code "(from|require\(|import)[[:space:]]*['\"](@sentry/[a-z-]+|posthog-js|posthog-node|@bugsnag/[a-z-]+|rollbar|@highlight-run/[a-z-]+)['\"]|Sentry\.init\(|posthog\.init\(|Bugsnag\.start\(|^[[:space:]]*import[[:space:]]+sentry_sdk")
ET_DEPS=$(pkg_dep "@sentry/[a-z-]+|posthog-js|posthog-node|@bugsnag/[a-z-]+|rollbar|@highlight-run/[a-z-]+|sentry-sdk")
if [ -z "$ET_IMPORT" ] && [ -z "$ET_DEPS" ]; then
  emit "errors.tracking" "[38]" "WARN" "No error-tracking SDK detected on client or server" ""
else
  emit "errors.tracking" "[38]" "PASS" "Error tracking SDK present — confirm it is initialised on both client and server" "$ET_IMPORT
$ET_DEPS"
fi

# ---------- 8. Config & deployment (#42-#45) ----------
HITS=$(grep_src "Access-Control-Allow-Origin.*\*")
[ -n "$HITS" ] && emit "config.cors" "[44]" "WARN" "Wildcard CORS — a finding if the endpoint is authenticated or non-public" "$HITS" \
               || emit "config.cors" "[44]" "PASS" "No wildcard CORS headers in source" ""

HITS=$(grep_src "(DEBUG[[:space:]]*=[[:space:]]*[Tt]rue|debug:[[:space:]]*true)" | grep -vEi '(^|/)(tests?|__tests__|spec|e2e)/|\.(test|spec)\.' | head -10 || true)
[ -n "$HITS" ] && emit "config.debug" "[42]" "WARN" "Debug flags set true — verify they are off in production" "$HITS" \
               || emit "config.debug" "[42]" "PASS" "No debug=true flags" ""

# Uses count_src: grep_src caps at MAXHITS, which would make this threshold dead.
NLOG=$(count_src "console\.(log|debug|info)")
if [ "$NLOG" -gt 50 ]; then
  emit "config.console" "[38,57]" "WARN" "$NLOG console logging statements — review for PII/secret leakage and use a structured logger" ""
else
  emit "config.console" "[38,57]" "PASS" "console logging usage moderate ($NLOG statements)" ""
fi

# ---------- 9. Third-party integrations (#47) ----------
# Only route/handler context counts as "has webhooks" — a prose mention of the
# word does not (that produced false FAILs on any repo with security docs).
WH_FILES=$(tr '\0' '\n' < "$CODE_Z" 2>/dev/null | grep -Ei '(^|/)[^/]*webhook[^/]*\.(ts|tsx|js|jsx|mjs|cjs|py)$' | head -20 || true)
WH_ROUTES=$(grep_code "(app|router|server|api)\.(post|put|all|use)[[:space:]]*\([[:space:]]*['\"\`][^'\"\`]*webhook" -i)
WH_PATH=$(grep_code "(route|path|endpoint|url)[[:space:]]*[:=][[:space:]]*['\"\`][^'\"\`]*webhook" -i)
WEBHOOK="$WH_FILES
$WH_ROUTES
$WH_PATH"
if [ -n "$WH_FILES$WH_ROUTES$WH_PATH" ]; then
  SIG=$(grep_code "(constructEvent|verifyWebhook|svix|new Webhook\(|timingSafeEqual|compare_digest|createHmac|hmac\.new|X-Hub-Signature|stripe-signature|webhook_secret|WEBHOOK_SECRET)" -i)
  [ -z "$SIG" ] && emit "integ.webhook_sig" "[47]" "FAIL" "Webhook handlers present but no signature verification found" "$WEBHOOK" \
                || emit "integ.webhook_sig" "[47]" "PASS" "Webhook signature verification present — confirm it runs before any side effect and that timestamps are checked" "$SIG"
else
  emit "integ.webhook_sig" "[47]" "PASS" "No webhook handlers found" ""
fi

# ---------- 10. Dependencies & supply chain (#51,#53) ----------
if [ -f package.json ]; then
  if [ -f package-lock.json ] || [ -f yarn.lock ] || [ -f pnpm-lock.yaml ] || [ -f bun.lockb ]; then
    emit "deps.lockfile" "[53]" "PASS" "Lockfile present" ""
  else
    emit "deps.lockfile" "[53]" "FAIL" "No lockfile committed — builds are not reproducible" ""
  fi
  if command -v npm >/dev/null 2>&1 && [ -f package-lock.json ]; then
    AUDIT=$(npm audit --omit=dev --json 2>/dev/null | python3 -c 'import json,sys
try:
  d=json.load(sys.stdin); v=d.get("metadata",{}).get("vulnerabilities",{})
  print("critical=%d high=%d moderate=%d" % (v.get("critical",0), v.get("high",0), v.get("moderate",0)))
except Exception: print("audit-unavailable")' 2>/dev/null)
    case "$AUDIT" in
      critical=0\ high=0*) emit "deps.audit" "[51]" "PASS" "npm audit clean of critical/high" "$AUDIT" ;;
      audit-unavailable|"") emit "deps.audit" "[51]" "MANUAL" "npm audit unavailable (offline?) — run it manually" "" ;;
      *) emit "deps.audit" "[51]" "FAIL" "npm audit found critical/high vulnerabilities" "$AUDIT" ;;
    esac
  else
    emit "deps.audit" "[51]" "MANUAL" "Run npm audit / pip-audit manually" ""
  fi
else
  emit "deps.lockfile" "[53]" "MANUAL" "No package.json — check the lockfile/pinning story for this ecosystem manually" ""
  emit "deps.audit" "[51]" "MANUAL" "No package.json — run the ecosystem's audit tool manually" ""
fi

# ---------- 11. Privacy & GDPR (#57,#58) ----------
PII=$(grep_code "(console\.(log|info|debug)|logger\.(info|debug|warn|error)|print\()[^)]*(email|phone|address|birthdate|isikukood|ssn|passport)" -i)
[ -n "$PII" ] && emit "gdpr.pii_logs" "[57]" "WARN" "PII-adjacent fields inside log statements" "$PII" \
              || emit "gdpr.pii_logs" "[57]" "PASS" "No obvious PII in log statements" ""
emit "gdpr.residency" "[58]" "MANUAL" "Check DB region and LLM routing region in provider dashboards / DPA" ""

# ---------- 12. EU AI Act (#60,#61) ----------
if [ -n "$LLM" ] || [ -n "$LLM_DEPS" ]; then
  # Disclosure strings are user-facing: look in UI files, not in every .py docstring.
  DISCLOSE=$(grep_client "(AI-generated|generated by AI|AI assistant|powered by AI|tehisintellekt|AI-genereeritud|automated response)" -i)
  [ -z "$DISCLOSE" ] && emit "aiact.transparency" "[61]" "WARN" "AI features present but no user-facing AI disclosure string found in UI code (Art. 50)" "" \
                     || emit "aiact.transparency" "[61]" "PASS" "AI disclosure strings present in UI" "$DISCLOSE"
  emit "aiact.classification" "[60]" "MANUAL" "Annex III classification is a judgment call — document it (CV screening / credit / biometrics / essential services = high-risk)" ""
else
  emit "aiact.transparency" "[61]" "PASS" "No AI features detected in source" ""
  emit "aiact.classification" "[60]" "MANUAL" "Confirm no AI features exist before closing the Annex III screen" ""
fi

# ---------- 13. Architecture reasonableness (#1-#6) ----------
# Opinionated platforms (Lovable+Supabase, Bolt, v0) constrain these choices;
# freehand tools (Claude Code, Codex CLI) can pick anything — scrutinise harder.
SERVERLESS=""
for f in vercel.json netlify.toml serverless.yml wrangler.toml wrangler.jsonc; do
  [ -f "$f" ] && SERVERLESS="$SERVERLESS $f"
done

FILEDB=$(pkg_dep "better-sqlite3|sqlite3|lowdb|node-json-db|nedb" | tr '\n' ' ')
LSSTORE=$(count_src "localStorage\.setItem")
if [ -n "$FILEDB" ] && [ -n "$SERVERLESS" ]; then
  emit "arch.datastore" "[2]" "FAIL" "File-based DB ($FILEDB) on serverless hosting ($SERVERLESS) — data will not persist across invocations" ""
elif [ -n "$FILEDB" ]; then
  emit "arch.datastore" "[2]" "WARN" "File-based DB in dependencies ($FILEDB) — confirm the host has a persistent disk and this is the intended system of record" ""
elif [ "$LSSTORE" -gt 10 ]; then
  emit "arch.datastore" "[2]" "WARN" "$LSSTORE localStorage.setItem calls — verify browser storage is not the primary data store" ""
else
  emit "arch.datastore" "[2]" "PASS" "No file-based/browser-storage system-of-record patterns detected" ""
fi

AUTHLIB=$(pkg_dep "@supabase/supabase-js|firebase|next-auth|@auth/core|@clerk/[a-z-]+|auth0|@auth0/[a-z-]+|passport|lucia|better-auth" | tr '\n' ' ')
# Call syntax required — prose like "no md5 hashes, no Math.random tokens" must not match.
WEAKHASH=$(grep_code "createHash\([[:space:]]*['\"](md5|sha1)['\"]|hashlib\.(md5|sha1)\(")
RANDTOKEN=$(grep_js "Math\.random[[:space:]]*\(" | grep -iE 'token|session|auth|password|secret' | head -5 || true)
if [ -n "$WEAKHASH" ] || [ -n "$RANDTOKEN" ]; then
  emit "arch.handrolled_auth" "[3,56]" "FAIL" "Hand-rolled auth primitives: weak hash or Math.random-derived tokens" "$WEAKHASH
$RANDTOKEN"
elif [ -n "$AUTHLIB" ]; then
  emit "arch.handrolled_auth" "[3,56]" "PASS" "Recognised auth provider/library present: $AUTHLIB" ""
else
  emit "arch.handrolled_auth" "[3,56]" "WARN" "No recognised auth library detected — verify authentication uses a proven provider rather than custom code" ""
fi

if [ -f package.json ]; then
  ORMS=$(pkg_dep "prisma|@prisma/client|typeorm|sequelize|knex|drizzle-orm|mongoose|@supabase/supabase-js|pg|mysql2|mongodb")
  NORM=$(echo "$ORMS" | grep -c . || true)
  [ -z "$ORMS" ] && NORM=0
  if [ "$NORM" -gt 2 ]; then
    emit "arch.mixed_stack" "[5]" "WARN" "$NORM parallel data-access libraries in dependencies — vibecoded apps often accrete one per session; consolidate" "$(echo $ORMS | tr '\n' ' ')"
  else
    emit "arch.mixed_stack" "[5]" "PASS" "Data-access dependencies look consolidated" ""
  fi
else
  emit "arch.mixed_stack" "[5]" "MANUAL" "No package.json — inventory data-access layers manually" ""
fi

RUNTIME=$(pkg_dep "ws|socket\.io|node-cron|bull|bullmq|agenda" | tr '\n' ' ')
if [ -n "$RUNTIME" ] && [ -n "$SERVERLESS" ]; then
  emit "arch.hosting_fit" "[6]" "WARN" "Long-running/real-time dependencies ($RUNTIME) with serverless config ($SERVERLESS) — verify the platform supports persistent processes and cron" ""
else
  emit "arch.hosting_fit" "[6]" "PASS" "No runtime-vs-hosting mismatch signals" ""
fi

emit "arch.stack_mainstream" "[1]" "MANUAL" "Rate the stack: is the language/framework/DB mainstream, documented, hireable? Freehand tools (Claude Code) need this check most; platform apps (Lovable+Supabase) usually inherit a sane stack" ""
emit "arch.complexity" "[4]" "MANUAL" "Judge proportionality: no microservices/queues/k8s for an MVP; no god-module. Summarise the architecture in five sentences — if you cannot, that is the finding" ""

echo '{"scanner":"vibecheck","done":true}'
