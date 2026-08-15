#!/usr/bin/env bash
# vibecheck.sh — static scanner for vibecoded applications.
# Usage: vibecheck.sh [--online-audit] [repo_dir]   (defaults to current directory)
# Output: JSON to stdout, one finding object per line-item, plus a summary.
# Exit code: 0 for a completed scan; 2 for scanner/input failure.
#
# Each finding maps to checklist item numbers (#1-#89) from the Goplex
# vibecoded-app review workbook. status: WARN | NO_SIGNAL | MANUAL
# WARN = suspicious hit needing human/LLM judgment. NO_SIGNAL is never a Pass.
# MANUAL = cannot be automated.
#
# The check id -> checklist item mapping is mirrored in scripts/items.py
# (SCANNER_CHECKS); tests/test_coverage_map.py fails if the two drift apart.
#
# Compatible with bash 3.2 (macOS system bash): no mapfile, no associative arrays.

set -uo pipefail

VERSION="0.4.0"

REPO="."
ONLINE_AUDIT=0
POSITIONAL=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    -h|--help)
      sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    -v|--version)
      echo "$VERSION"; exit 0 ;;
    --online-audit)
      ONLINE_AUDIT=1 ;;
    --)
      shift
      [ "$#" -le 1 ] || { echo '{"scanner":"vibecheck","error":"too many repository paths"}'; exit 2; }
      [ "$#" -eq 0 ] || REPO="$1"
      break ;;
    -*)
      echo '{"scanner":"vibecheck","error":"unknown option"}'
      exit 2 ;;
    *)
      POSITIONAL=$((POSITIONAL + 1))
      [ "$POSITIONAL" -le 1 ] || { echo '{"scanner":"vibecheck","error":"too many repository paths"}'; exit 2; }
      REPO="$1" ;;
  esac
  shift
done

# Resolve helper paths before cd'ing into the target repo.
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd -P)
REDACT="$SCRIPT_DIR/_redact.py"
SQL_ANALYZER="$SCRIPT_DIR/analyze_sql.py"

for cmd in python3 find grep sed awk xargs head tr git; do
  command -v "$cmd" >/dev/null 2>&1 || {
    echo "{\"scanner\":\"vibecheck\",\"error\":\"required command not found: $cmd\"}"
    exit 2
  }
done
[ -f "$REDACT" ] && [ -f "$SQL_ANALYZER" ] || {
  echo '{"scanner":"vibecheck","error":"scanner helper file missing"}'
  exit 2
}

cd "$REPO" 2>/dev/null || { echo '{"scanner":"vibecheck","error":"repo dir not found"}'; exit 2; }

TMPD=$(mktemp -d 2>/dev/null) || { echo '{"scanner":"vibecheck","error":"cannot create temp dir"}'; exit 2; }
trap 'rm -rf "$TMPD"' EXIT INT TERM

IS_GIT=0
git rev-parse --git-dir >/dev/null 2>&1 && IS_GIT=1

# ---------------------------------------------------------------- file lists
# Source file globs to scan (skip node_modules, dist, build, .git, lockfiles).
SRC_FIND=(-type f \( -name '*.ts' -o -name '*.tsx' -o -name '*.js' -o -name '*.jsx' -o -name '*.mjs' -o -name '*.cjs' -o -name '*.py' -o -name '*.vue' -o -name '*.svelte' -o -name '*.html' -o -name '*.sql' -o -name '*.toml' -o -name '*.yaml' -o -name '*.yml' -o -name '*.json' -o -name '*.env*' \) \
  -not -path '*/node_modules/*' -not -path '*/.git/*' -not -path '*/dist/*' -not -path '*/build/*' -not -path '*/.next/*' -not -path '*/.venv/*' -not -path '*/venv/*' -not -path '*/vendor/*' -not -path '*/__pycache__/*' \
  -not -name 'package-lock.json' -not -name 'yarn.lock' -not -name 'pnpm-lock.yaml' -not -name 'bun.lockb')

ALL_Z="$TMPD/all.z"          # every scannable source file, NUL-separated
if ! find . "${SRC_FIND[@]}" -print0 > "$ALL_Z" 2> "$TMPD/find.err"; then
  FIND_ERR=$(head -5 "$TMPD/find.err" | tr '\n' ' ')
  FIND_ERR_JSON=$(printf '%s' "source enumeration failed: $FIND_ERR" | python3 "$REDACT")
  printf '{"scanner":"vibecheck","error":%s}\n' "$FIND_ERR_JSON"
  exit 2
fi
while IFS= read -r -d '' f; do
  if [ ! -r "$f" ]; then
    FILE_JSON=$(printf '%s' "unreadable source file: $f" | python3 "$REDACT")
    printf '{"scanner":"vibecheck","error":%s}\n' "$FILE_JSON"
    exit 2
  fi
done < "$ALL_Z"

# subset_z <name> <extension-regex> — build a NUL list filtered by path regex.
subset_z() {
  local out="$TMPD/$1.z"
  local regex="$2" f
  : > "$out"
  while IFS= read -r -d '' f; do
    if [[ "$f" =~ $regex ]]; then
      printf '%s\0' "$f" >> "$out"
    fi
  done < "$ALL_Z"
  echo "$out"
}
CLIENT_ALL_Z=$(subset_z client_all '\.(ts|tsx|js|jsx|mjs|cjs|vue|svelte|html)$')
CLIENT_Z="$TMPD/client.z"
: > "$CLIENT_Z"
while IFS= read -r -d '' f; do
  case "$f" in
    */server/*|*/servers/*|*/api/*|*/backend/*|*/functions/*|*/edge-functions/*|*/workers/*)
      ;;
    *) printf '%s\0' "$f" >> "$CLIENT_Z" ;;
  esac
done < "$CLIENT_ALL_Z"
JS_Z=$(subset_z js '\.(ts|tsx|js|jsx|mjs|cjs|vue|svelte)$')
CODE_Z=$(subset_z code '\.(ts|tsx|js|jsx|mjs|cjs|py|vue|svelte|html)$')
SQL_Z=$(subset_z sql '\.sql$')

has_files() { [ -s "$1" ]; }

# ------------------------------------------------------------------- output
# Evidence is redacted (secret-shaped strings truncated) and line-capped by
# scripts/_redact.py before it reaches stdout, so a scan can be pasted into a
# report or a ticket without leaking the credential it just found.
#
# Checks below use `[ -n "$HITS" ] && emit WARN || emit NO_SIGNAL` (shellcheck
# SC2015). That is safe here only because emit() always succeeds — if you ever
# give emit a failing exit path, both branches will fire. Keep it returning 0.
emit() { # emit id items status title evidence [redact-flags]
  local id="$1" items="$2" status="$3" title="$4" evidence="$5" flags="${6:-}"
  local ev ti
  if [ "$flags" = "--strings" ]; then
    ev=$(printf '%s' "$evidence" | python3 "$REDACT" --strings 2>/dev/null) || ev='""'
  else
    ev=$(printf '%s' "$evidence" | python3 "$REDACT" 2>/dev/null) || ev='""'
  fi
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
  if [ -z "$GIT_ROOT" ] || [ "$GIT_ROOT" = "$SCAN_ROOT" ]; then
    emit "scan.scope" "[9]" "NO_SIGNAL" "Scan root matches the git repository root" ""
  fi
else
  emit "scan.scope" "[9]" "MANUAL" "Not a git repository — repository-wide scope and history cannot be verified" ""
fi

# ---------- 1. Secrets & credentials (#7-#11) ----------
# 1a. Hardcoded secret-looking strings in source (assignments with long values)
HITS=$(grep_src "(api[_-]?key|apikey|secret|password|token|private[_-]?key)['\"]?[[:space:]]*[:=][[:space:]]*['\"][A-Za-z0-9_\-\.\+/]{16,}['\"]" -i)
# filter obvious placeholders/env reads
HITS=$(echo "$HITS" | grep -vEi 'process\.env|import\.meta\.env|os\.environ|getenv|YOUR_|EXAMPLE|PLACEHOLDER|CHANGEME|xxx+|<[A-Z_]+>|\$\{' || true)
[ -n "$HITS" ] && emit "secrets.hardcoded" "[7]" "WARN" "Secret-like literals assigned in source — confirm whether they are real credentials" "$HITS" "--strings" \
               || emit "secrets.hardcoded" "[7]" "NO_SIGNAL" "No hardcoded secret-like literals found by this ruleset" ""

# 1b. Known key prefixes (Anthropic/OpenAI/Stripe/AWS/GitHub/Slack/Supabase).
# Each prefix requires a key body — a bare "sk-ant-" in prose is documentation,
# not a credential.
KEY_PREFIXES="(sk-ant-[A-Za-z0-9_\-]{12,}|sk-proj-[A-Za-z0-9_\-]{12,}|sk_live_[A-Za-z0-9]{12,}|rk_live_[A-Za-z0-9]{12,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|xox[bapsr]-[A-Za-z0-9-]{12,}|sb_secret_[A-Za-z0-9_\-]{16,})"
HITS=$(grep_src "$KEY_PREFIXES")
[ -n "$HITS" ] && emit "secrets.known_prefixes" "[7,8]" "WARN" "Provider credential-shaped strings present — verify validity and placement" "$HITS" \
               || emit "secrets.known_prefixes" "[7,8]" "NO_SIGNAL" "No known provider credential prefixes found" ""

# 1c. service_role — candidate client reachability is a path heuristic, not proof.
CLIENT_SR=$(grep_client "service_role")
ANY_SR=$(grep_code "service_role")
if [ -n "$CLIENT_SR" ]; then
  emit "secrets.service_role" "[8]" "WARN" "service_role referenced in client-reachable candidate files — trace the actual build boundary" "$CLIENT_SR"
elif [ -n "$ANY_SR" ]; then
  emit "secrets.service_role" "[8]" "WARN" "service_role referenced — verify every use is server-side only (edge function / API route)" "$ANY_SR"
else
  emit "secrets.service_role" "[8]" "NO_SIGNAL" "No service_role references found in scanned source" ""
fi

# 1d. .env committed / present in git history (pathspec-scoped to the scanned subtree)
if [ "$IS_GIT" = 1 ]; then
  TRACKED=$(git ls-files 2>/dev/null | grep -E '(^|/)\.env(\..+)?$' | grep -v '\.example' || true)
  [ -n "$TRACKED" ] && emit "secrets.env_tracked" "[9]" "WARN" ".env file(s) tracked by git — inspect and rotate any credentials" "$TRACKED" \
                    || emit "secrets.env_tracked" "[9]" "NO_SIGNAL" "No .env files tracked" ""
  HIST=$(git log --all --name-only --pretty=format: -- . 2>/dev/null \
         | grep -E '(^|/)\.env(\..+)?$' | grep -v '\.example' | sort -u | head -20 || true)
  [ -n "$HIST" ] && emit "secrets.env_history" "[9,11]" "WARN" ".env file(s) exist in git history — inspect and rotate any keys they held" "$HIST" \
                 || emit "secrets.env_history" "[9,11]" "NO_SIGNAL" "No .env paths found in git history" ""
  GI_OK=$(grep -hsE '^[[:space:]]*\.env' .gitignore 2>/dev/null || true)
  [ -z "$GI_OK" ] && emit "secrets.gitignore" "[9]" "WARN" ".env not listed in .gitignore" "" \
                  || emit "secrets.gitignore" "[9]" "NO_SIGNAL" ".env is gitignored" "$GI_OK"
  # Secrets in history content (sampled, bounded, scoped to this subtree).
  HSEC=$(git log --all -p --pretty=format: -- . 2>/dev/null | head -40000 \
         | grep -E '^\+' | grep -E "$KEY_PREFIXES" | head -10 || true)
  [ -n "$HSEC" ] && emit "secrets.history_content" "[9,11]" "WARN" "Credential-shaped strings found in sampled git history — verify and rotate if real" "$HSEC" \
                 || emit "secrets.history_content" "[9,11]" "NO_SIGNAL" "No credential prefixes in sampled git history" ""
else
  emit "secrets.env_tracked" "[9]" "MANUAL" "Not a git repo — tracked-file and history checks skipped" ""
  emit "secrets.env_history" "[9,11]" "MANUAL" "Not a git repo — .env history check skipped" ""
  emit "secrets.gitignore" "[9]" "MANUAL" "Not a git repo — verify ignore rules in the actual source repository" ""
  emit "secrets.history_content" "[9,11]" "MANUAL" "Not a git repo — credential history scan skipped" ""
fi

# ---------- 2. Authorization & access control (#12-#16) ----------
if has_files "$SQL_Z"; then
  SQL_JSON="$TMPD/sql-analysis.json"
  python3 "$SQL_ANALYZER" --files-from "$SQL_Z" > "$SQL_JSON" || {
    echo '{"scanner":"vibecheck","error":"SQL analysis failed"}'
    exit 2
  }
  CREATED_COUNT=$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["created"]))' "$SQL_JSON")
  NORLS=$(python3 -c 'import json,sys; print("\n".join(json.load(open(sys.argv[1]))["missing_rls"]))' "$SQL_JSON")
  PERM=$(python3 -c 'import json,sys; print("\n".join(json.load(open(sys.argv[1]))["permissive"]))' "$SQL_JSON")
  ANONW=$(python3 -c 'import json,sys; print("\n".join(json.load(open(sys.argv[1]))["anon_write"]))' "$SQL_JSON")
  if [ -n "$NORLS" ]; then
    emit "rls.missing" "[12,14]" "WARN" "Tables appear to be created without matching ENABLE ROW LEVEL SECURITY — confirm schema and live state" "$NORLS"
  elif [ "$CREATED_COUNT" -eq 0 ]; then
    emit "rls.missing" "[12,14]" "NO_SIGNAL" "SQL files found, but no persistent CREATE TABLE statements were recognized" ""
  else
    emit "rls.missing" "[12,14]" "NO_SIGNAL" "Every recognized created table has a matching RLS-enable statement; verify live state" ""
  fi
  [ -n "$PERM" ] && emit "rls.permissive" "[13,14]" "WARN" "Permissive RLS expressions found — public read policies may be intentional; review each policy" "$PERM" \
                 || emit "rls.permissive" "[13,14]" "NO_SIGNAL" "No unconditional using(true)/with check(true) expressions found" ""
  [ -n "$ANONW" ] && emit "rls.anon_write" "[14]" "WARN" "Policies grant write to the anon role — verify intent" "$ANONW" \
                  || emit "rls.anon_write" "[14]" "NO_SIGNAL" "No anon write grants recognized in policies" ""
else
  emit "rls.missing" "[12,14]" "MANUAL" "No SQL migrations found — run the vibecheck-supabase live probe" ""
  emit "rls.permissive" "[13,14]" "MANUAL" "No SQL migrations found — inspect live RLS policies and infrastructure sources" ""
  emit "rls.anon_write" "[14]" "MANUAL" "No SQL migrations found — test anonymous writes against an authorized deployment" ""
fi
emit "authz.idor" "[13]" "MANUAL" "IDOR requires a live probe — use the vibecheck-supabase skill or two test accounts" ""

# Admin gating that exists only in UI components
HITS=$(grep_client "(isAdmin|is_admin|role[[:space:]]*===?[[:space:]]*['\"]admin)")
[ -n "$HITS" ] && emit "authz.client_admin" "[16]" "WARN" "Admin-role checks in UI components — verify server-side enforcement also exists" "$HITS" \
               || emit "authz.client_admin" "[16]" "NO_SIGNAL" "No client-side admin-role pattern found by this ruleset" ""

# ---------- 3. Product readiness — is it real? (#17-#22) ----------
HITS=$(grep_code "(mockData|MOCK_|dummyData|sampleData|fakeData|FIXME|TODO:)" \
       | grep -vEi '(^|/)(tests?|__tests__|__mocks__|spec|e2e|fixtures?|stories)/|\.(test|spec|stories)\.' | head -20 || true)
[ -n "$HITS" ] && emit "real.mocks" "[17,18,19,20,21,22]" "WARN" "Mock/stub/TODO markers in non-test code — verify these features are actually live" "$HITS" \
               || emit "real.mocks" "[17,18,19,20,21,22]" "NO_SIGNAL" "No mock/stub marker found outside tests" ""

HITS=$(grep_code "(sk_test_|pk_test_)")
[ -n "$HITS" ] && emit "real.stripe_test" "[20]" "WARN" "Stripe TEST-mode keys referenced — confirm production uses live mode" "$HITS" \
               || emit "real.stripe_test" "[20]" "NO_SIGNAL" "No Stripe test-mode key reference found" ""

HITS=$(grep_js "localStorage\.(set|get)Item\(['\"](token|jwt|auth|session)" -i)
[ -n "$HITS" ] && emit "real.localstorage_auth" "[17]" "WARN" "Auth tokens in localStorage — check persistence model and XSS exposure" "$HITS" \
               || emit "real.localstorage_auth" "[17]" "NO_SIGNAL" "No recognized auth-token localStorage call found" ""

# ---------- 4. Cost & abuse blast radius (#23-#27) ----------
LLM_ENDPOINT="(api\.anthropic\.com|api\.openai\.com|generativelanguage\.googleapis|openrouter\.ai)"
LLM_SDK="(\.messages\.create|chat\.completions|generateText|streamText|new Anthropic|new OpenAI|invokeModel|ChatOpenAI|ChatAnthropic|langchain)"
LLM_DEPS=$(pkg_dep "openai|@anthropic-ai/sdk|@ai-sdk/[a-z-]+|ai|langchain|@langchain/[a-z-]+|@google/generative-ai|ollama|replicate")
LLM=$(grep_code "$LLM_ENDPOINT|$LLM_SDK")

if [ -n "$LLM" ] || [ -n "$LLM_DEPS" ]; then
  RL=$(grep_code "(rateLimit|rate_limit|ratelimit|Ratelimit|@upstash/ratelimit|bottleneck|p-limit|pLimit|throttle|slowDown|express-rate-limit)")
  RL_DEPS=$(pkg_dep "@upstash/ratelimit|express-rate-limit|bottleneck|p-limit|rate-limiter-flexible|slowapi")
  if [ -z "$RL" ] && [ -z "$RL_DEPS" ]; then
    emit "cost.no_ratelimit" "[23]" "WARN" "LLM/paid API usage present but no rate-limiting signal found — trace the deployed request path" "$LLM$LLM_DEPS"
  else
    emit "cost.no_ratelimit" "[23]" "NO_SIGNAL" "A rate-limiting signal is present; confirm it actually wraps every expensive call" "$RL
$RL_DEPS"
  fi
  CLIENTLLM=$(grep_client "$LLM_ENDPOINT|$LLM_SDK")
  [ -n "$CLIENTLLM" ] && emit "cost.client_llm" "[8,26]" "WARN" "LLM calls appear in client-reachable candidate files — verify the build boundary and credential flow" "$CLIENTLLM" \
                      || emit "cost.client_llm" "[8,26]" "NO_SIGNAL" "No LLM call found in client-reachable candidate files" ""
else
  emit "cost.no_ratelimit" "[23]" "NO_SIGNAL" "No LLM/paid API usage found by this ruleset" ""
  emit "cost.client_llm" "[8,26]" "NO_SIGNAL" "No LLM call found in client-reachable candidate files" ""
fi
emit "cost.budget_caps" "[24]" "MANUAL" "Budget caps live in provider dashboards — verify manually" ""

# ---------- 5. Input handling & injection (#28-#32) ----------
HITS=$(grep_code "dangerouslySetInnerHTML|innerHTML[[:space:]]*=|v-html")
[ -n "$HITS" ] && emit "inject.xss" "[30]" "WARN" "Raw HTML injection sinks — verify inputs are sanitized (DOMPurify or equivalent)" "$HITS" \
               || emit "inject.xss" "[30]" "NO_SIGNAL" "No recognized raw-HTML sink found" ""

HITS=$(grep_code "(query|execute|raw)[[:space:]]*\([[:space:]]*[\`'\"].*(SELECT|INSERT|UPDATE|DELETE).*(\\\$\{|['\"][[:space:]]*\+)" -i)
[ -n "$HITS" ] && emit "inject.sql" "[29]" "WARN" "String-built SQL pattern detected — trace whether untrusted input reaches it" "$HITS" \
               || emit "inject.sql" "[29]" "NO_SIGNAL" "No string-built SQL pattern found by this ruleset" ""

# Validation libraries: imports and manifest entries only — a bare word match
# hits prose and substrings ("joi" inside "join").
VAL_IMPORT=$(grep_code "(from|require\(|import)[[:space:]]*['\"](zod|joi|@hapi/joi|yup|valibot|class-validator|superstruct|ajv)['\"]|^[[:space:]]*(import|from)[[:space:]]+pydantic|^[[:space:]]*import[[:space:]]+marshmallow")
VAL_DEPS=$(pkg_dep "zod|joi|@hapi/joi|yup|valibot|class-validator|superstruct|ajv|pydantic")
if [ -z "$VAL_IMPORT" ] && [ -z "$VAL_DEPS" ]; then
  emit "inject.validation" "[28]" "WARN" "No validation library detected — server-side input validation may be missing" ""
else
  emit "inject.validation" "[28]" "NO_SIGNAL" "Validation-library signal present — confirm it is applied on server-side entry points" "$VAL_IMPORT
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
  [ -n "$EXEC_HITS" ] && emit "inject.llm_to_exec" "[77]" "WARN" "LLM call and a code/command execution sink live in the same module — trace whether model output can reach it" "$EXEC_HITS" \
                      || emit "inject.llm_to_exec" "[77]" "NO_SIGNAL" "No recognized exec/eval/shell sink found in LLM modules" ""

  # #78: variables interpolated raw into prompt strings
  INTERP=$(grep_list "$LLM_FILES_Z" "(content|prompt|system|messages)[^\`\"']{0,40}\`[^\`]*\\\$\{")
  [ -n "$INTERP" ] && emit "inject.prompt_interpolation" "[78]" "WARN" "Variables interpolated into prompt template literals — confirm user text cannot override instructions (delimiting / role separation)" "$INTERP" \
                   || emit "inject.prompt_interpolation" "[78]" "NO_SIGNAL" "No raw prompt interpolation pattern found" ""

  # #79: tool/function-calling agents
  TOOLS=$(grep_list "$LLM_FILES_Z" "(tools[[:space:]]*:|functions[[:space:]]*:|tool_choice|function_call|tool_use|\.bindTools|StructuredTool)")
  [ -n "$TOOLS" ] && emit "inject.tool_agent" "[79]" "WARN" "Tool/function-calling detected — verify tools are allowlisted, args validated, and authorisation is based on the authenticated user rather than model output" "$TOOLS" \
                  || emit "inject.tool_agent" "[79]" "NO_SIGNAL" "No tool/function-calling signal found" ""

  # #80: indirect injection — external/RAG content flowing into a model
  INDIRECT=$(grep_list "$LLM_FILES_Z" "(fetch\(|axios\.|http\.get|readFile|web_fetch|scrape|crawl|embeddings|vectorStore|retriever|\brag\b)" \
             | grep -vEi "$LLM_ENDPOINT" | cut -d: -f1 | sort -u | head -20 || true)
  [ -n "$INDIRECT" ] && emit "inject.indirect" "[80]" "WARN" "External/retrieved content flows through LLM modules — treat fetched/RAG content as untrusted data, not instructions" "$INDIRECT" \
                     || emit "inject.indirect" "[80]" "NO_SIGNAL" "No retrieved-content signal found in LLM modules" ""

  # #81: model output rendered as raw HTML
  TOHTML=$(grep_list "$LLM_FILES_Z" "(dangerouslySetInnerHTML|innerHTML[[:space:]]*=|v-html)")
  [ -n "$TOHTML" ] && emit "inject.llm_to_html" "[81]" "WARN" "LLM module renders raw HTML — model output as HTML turns prompt injection into XSS; render as text or sanitize" "$TOHTML" \
                   || emit "inject.llm_to_html" "[81]" "NO_SIGNAL" "No raw-HTML rendering signal found in LLM modules" ""
else
  emit "inject.llm_to_exec" "[77]" "NO_SIGNAL" "No LLM usage found by this ruleset; prompt-injection surface not established" ""
  emit "inject.prompt_interpolation" "[78]" "NO_SIGNAL" "No LLM usage found by this ruleset" ""
  emit "inject.tool_agent" "[79]" "NO_SIGNAL" "No LLM usage found by this ruleset" ""
  emit "inject.indirect" "[80]" "NO_SIGNAL" "No LLM usage found by this ruleset" ""
  emit "inject.llm_to_html" "[81]" "NO_SIGNAL" "No LLM usage found by this ruleset" ""
fi

# ---------- 7. Errors, logging & observability (#37-#41) ----------
HITS=$(grep_code "catch[[:space:]]*(\([[:space:]]*[a-zA-Z_$]*[[:space:]]*\))?[[:space:]]*\{[[:space:]]*\}")
[ -n "$HITS" ] && emit "errors.swallowed" "[37]" "WARN" "Empty catch blocks — errors are silently swallowed" "$HITS" \
               || emit "errors.swallowed" "[37]" "NO_SIGNAL" "No empty catch block found by this ruleset" ""

ET_IMPORT=$(grep_code "(from|require\(|import)[[:space:]]*['\"](@sentry/[a-z-]+|posthog-js|posthog-node|@bugsnag/[a-z-]+|rollbar|@highlight-run/[a-z-]+)['\"]|Sentry\.init\(|posthog\.init\(|Bugsnag\.start\(|^[[:space:]]*import[[:space:]]+sentry_sdk")
ET_DEPS=$(pkg_dep "@sentry/[a-z-]+|posthog-js|posthog-node|@bugsnag/[a-z-]+|rollbar|@highlight-run/[a-z-]+|sentry-sdk")
if [ -z "$ET_IMPORT" ] && [ -z "$ET_DEPS" ]; then
  emit "errors.tracking" "[38]" "WARN" "No error-tracking SDK detected on client or server" ""
else
  emit "errors.tracking" "[38]" "NO_SIGNAL" "Error-tracking signal present — confirm it is initialized on both client and server" "$ET_IMPORT
$ET_DEPS"
fi

# ---------- 8. Config & deployment (#42-#45) ----------
HITS=$(grep_src "Access-Control-Allow-Origin.*\*")
[ -n "$HITS" ] && emit "config.cors" "[44]" "WARN" "Wildcard CORS — a finding if the endpoint is authenticated or non-public" "$HITS" \
               || emit "config.cors" "[44]" "NO_SIGNAL" "No wildcard CORS header found in scanned source" ""

HITS=$(grep_src "(DEBUG[[:space:]]*=[[:space:]]*[Tt]rue|debug:[[:space:]]*true)" | grep -vEi '(^|/)(tests?|__tests__|spec|e2e)/|\.(test|spec)\.' | head -10 || true)
[ -n "$HITS" ] && emit "config.debug" "[42]" "WARN" "Debug flags set true — verify they are off in production" "$HITS" \
               || emit "config.debug" "[42]" "NO_SIGNAL" "No debug=true flag found by this ruleset" ""

# Uses count_src: grep_src caps at MAXHITS, which would make this threshold dead.
NLOG=$(count_src "console\.(log|debug|info)")
if [ "$NLOG" -gt 50 ]; then
  emit "config.console" "[38,57]" "WARN" "$NLOG console logging statements — review for PII/secret leakage and use a structured logger" ""
else
  emit "config.console" "[38,57]" "NO_SIGNAL" "Console logging count is below this heuristic threshold ($NLOG statements)" ""
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
  [ -z "$SIG" ] && emit "integ.webhook_sig" "[47]" "WARN" "Webhook handler signal present but signature verification was not found — inspect the route and middleware" "$WEBHOOK" \
                || emit "integ.webhook_sig" "[47]" "NO_SIGNAL" "Signature-verification signal present — confirm it runs before side effects and checks timestamps" "$SIG"
else
  emit "integ.webhook_sig" "[47]" "NO_SIGNAL" "No webhook-handler signal found" ""
fi

# ---------- 10. Dependencies & supply chain (#51,#53) ----------
if [ -f package.json ]; then
  LOCKFILE=""
  for f in package-lock.json npm-shrinkwrap.json yarn.lock pnpm-lock.yaml bun.lock bun.lockb; do
    if [ -f "$f" ]; then LOCKFILE="$f"; break; fi
  done
  if [ -n "$LOCKFILE" ] && [ "$IS_GIT" = 1 ] \
      && git ls-files --error-unmatch -- "$LOCKFILE" >/dev/null 2>&1; then
    emit "deps.lockfile" "[53]" "NO_SIGNAL" "Tracked lockfile present" "$LOCKFILE"
  elif [ -n "$LOCKFILE" ]; then
    emit "deps.lockfile" "[53]" "WARN" "Lockfile exists but is not tracked by git — builds may not be reproducible elsewhere" "$LOCKFILE"
  else
    emit "deps.lockfile" "[53]" "WARN" "No recognized lockfile found — builds may not be reproducible" ""
  fi
  if [ "$ONLINE_AUDIT" = 1 ] && command -v npm >/dev/null 2>&1 \
      && { [ -f package-lock.json ] || [ -f npm-shrinkwrap.json ]; }; then
    AUDIT=$(npm audit --json 2>/dev/null | python3 -c 'import json,sys
try:
  d=json.load(sys.stdin); v=d.get("metadata",{}).get("vulnerabilities",{})
  print("critical=%d high=%d moderate=%d" % (v.get("critical",0), v.get("high",0), v.get("moderate",0)))
except Exception: print("audit-unavailable")' 2>/dev/null)
    case "$AUDIT" in
      critical=0\ high=0*) emit "deps.audit" "[51]" "NO_SIGNAL" "npm audit reported no critical/high advisories; triage moderate and reachability separately" "$AUDIT" ;;
      audit-unavailable|"") emit "deps.audit" "[51]" "MANUAL" "npm audit did not return usable results" "" ;;
      *) emit "deps.audit" "[51]" "WARN" "npm audit reported critical/high advisories — confirm affected paths and remediate or accept explicitly" "$AUDIT" ;;
    esac
  elif [ "$ONLINE_AUDIT" = 0 ]; then
    emit "deps.audit" "[51]" "MANUAL" "Online dependency audit not run by default; it sends dependency metadata to the configured npm registry. Re-run with --online-audit or use a local/CI scanner" ""
  else
    emit "deps.audit" "[51]" "MANUAL" "npm/lockfile unavailable — run the ecosystem's dependency scanner manually" ""
  fi
else
  emit "deps.lockfile" "[53]" "MANUAL" "No package.json — check the lockfile/pinning story for this ecosystem manually" ""
  emit "deps.audit" "[51]" "MANUAL" "No package.json — run the ecosystem's audit tool manually" ""
fi

WORKFLOW_Z=$(subset_z workflows '^\./\.github/workflows/.*\.(yml|yaml)$')
if has_files "$WORKFLOW_Z"; then
  ACTIONS=$(grep_list "$WORKFLOW_Z" 'uses:[[:space:]]*[^[:space:]#]+@[^[:space:]#]+' -i)
  MUTABLE_ACTIONS=$(printf '%s\n' "$ACTIONS" | grep -Ev 'uses:[[:space:]]*[^[:space:]#]+@[0-9a-fA-F]{40}([[:space:]#]|$)' || true)
  [ -n "$MUTABLE_ACTIONS" ] && emit "deps.ci_pins" "[53]" "WARN" "GitHub Actions use mutable tags/branches — pin third-party actions to full commit SHAs" "$MUTABLE_ACTIONS" \
                           || emit "deps.ci_pins" "[53]" "NO_SIGNAL" "All recognized GitHub Action uses are pinned to full commit SHAs" "$ACTIONS"
else
  emit "deps.ci_pins" "[53]" "MANUAL" "No GitHub Actions workflows found; review CI actions and container image pinning on the platform in use" ""
fi

# ---------- 11. Privacy & GDPR (#57,#58) ----------
PII=$(grep_code "(console\.(log|info|debug)|logger\.(info|debug|warn|error)|print\()[^)]*(email|phone|address|birthdate|isikukood|ssn|passport)" -i)
[ -n "$PII" ] && emit "gdpr.pii_logs" "[57]" "WARN" "PII-adjacent fields inside log statements" "$PII" \
              || emit "gdpr.pii_logs" "[57]" "NO_SIGNAL" "No obvious PII-in-logging pattern found by this ruleset" ""
emit "gdpr.residency" "[58]" "MANUAL" "Check DB region and LLM routing region in provider dashboards / DPA" ""

# ---------- 12. EU AI Act (#60,#61) ----------
if [ -n "$LLM" ] || [ -n "$LLM_DEPS" ]; then
  # Disclosure strings are user-facing: look in UI files, not in every .py docstring.
  DISCLOSE=$(grep_client "(AI-generated|generated by AI|AI assistant|powered by AI|tehisintellekt|AI-genereeritud|automated response)" -i)
  [ -z "$DISCLOSE" ] && emit "aiact.transparency" "[61]" "WARN" "AI features present but no user-facing AI disclosure string found in UI code (Art. 50)" "" \
                     || emit "aiact.transparency" "[61]" "NO_SIGNAL" "AI-disclosure string present in UI; confirm it is visible at the required interaction" "$DISCLOSE"
  emit "aiact.classification" "[60]" "MANUAL" "Annex III classification is a judgment call — document it (CV screening / credit / biometrics / essential services = high-risk)" ""
else
  emit "aiact.transparency" "[61]" "NO_SIGNAL" "No AI feature found by this ruleset; confirm the product scope manually" ""
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
  emit "arch.datastore" "[2]" "WARN" "File-based DB ($FILEDB) plus serverless config ($SERVERLESS) — verify persistence semantics for the actual deployment" ""
elif [ -n "$FILEDB" ]; then
  emit "arch.datastore" "[2]" "WARN" "File-based DB in dependencies ($FILEDB) — confirm the host has a persistent disk and this is the intended system of record" ""
elif [ "$LSSTORE" -gt 10 ]; then
  emit "arch.datastore" "[2]" "WARN" "$LSSTORE localStorage.setItem calls — verify browser storage is not the primary data store" ""
else
  emit "arch.datastore" "[2]" "NO_SIGNAL" "No file-based/browser-storage system-of-record pattern found" ""
fi

AUTHLIB=$(pkg_dep "@supabase/supabase-js|firebase|next-auth|@auth/core|@clerk/[a-z-]+|auth0|@auth0/[a-z-]+|passport|lucia|better-auth" | tr '\n' ' ')
# Call syntax required — prose like "no md5 hashes, no Math.random tokens" must not match.
WEAKHASH=$(grep_code "createHash\([[:space:]]*['\"](md5|sha1)['\"]|hashlib\.(md5|sha1)\(")
RANDTOKEN=$(grep_js "Math\.random[[:space:]]*\(" | grep -iE 'token|session|auth|password|secret' | head -5 || true)
if [ -n "$WEAKHASH" ] || [ -n "$RANDTOKEN" ]; then
  emit "arch.handrolled_auth" "[3,56]" "WARN" "Weak hash or Math.random-derived token primitive found — determine whether it is used for authentication/security" "$WEAKHASH
$RANDTOKEN"
elif [ -n "$AUTHLIB" ]; then
  emit "arch.handrolled_auth" "[3,56]" "NO_SIGNAL" "Recognized auth provider/library present; verify the application uses it correctly" "$AUTHLIB"
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
    emit "arch.mixed_stack" "[5]" "NO_SIGNAL" "No excess parallel data-access dependency signal found" ""
  fi
else
  emit "arch.mixed_stack" "[5]" "MANUAL" "No package.json — inventory data-access layers manually" ""
fi

RUNTIME=$(pkg_dep "ws|socket\.io|node-cron|bull|bullmq|agenda" | tr '\n' ' ')
if [ -n "$RUNTIME" ] && [ -n "$SERVERLESS" ]; then
  emit "arch.hosting_fit" "[6]" "WARN" "Long-running/real-time dependencies ($RUNTIME) with serverless config ($SERVERLESS) — verify the platform supports persistent processes and cron" ""
else
  emit "arch.hosting_fit" "[6]" "NO_SIGNAL" "No runtime-vs-hosting mismatch signal found" ""
fi

emit "arch.stack_mainstream" "[1]" "MANUAL" "Rate the stack: is the language/framework/DB mainstream, documented, hireable? Freehand tools (Claude Code) need this check most; platform apps (Lovable+Supabase) usually inherit a sane stack" ""
emit "arch.complexity" "[4]" "MANUAL" "Judge proportionality: no microservices/queues/k8s for an MVP; no god-module. Summarise the architecture in five sentences — if you cannot, that is the finding" ""

if [ "$ONLINE_AUDIT" = 1 ]; then
  echo '{"scanner":"vibecheck","done":true,"online_audit":true}'
else
  echo '{"scanner":"vibecheck","done":true,"online_audit":false}'
fi
