#!/usr/bin/env bash
# apply_safe_fixes.sh — ONLY scoped, reversible hygiene fixes.
# Never rewrites git history, never rotates keys, never edits application code.
#
# Usage: apply_safe_fixes.sh [repo_dir] [--dry-run] [--allow-network-lockfile]
set -uo pipefail

REPO="."
DRY=0
ALLOW_NETWORK_LOCKFILE=0
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY=1 ;;
    --allow-network-lockfile) ALLOW_NETWORK_LOCKFILE=1 ;;
    -h|--help) sed -n '2,6p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) REPO="$arg" ;;
  esac
done

cd "$REPO" 2>/dev/null || { echo "repo dir not found: $REPO"; exit 1; }

CHANGED=()
note() { CHANGED+=("$1"); }
act()  { [ "$DRY" = 1 ] && return 0; return 1; }   # act || <do the thing>

# 1. Ensure .gitignore covers common secret/build artifacts.
GI=".gitignore"
if [ ! -f "$GI" ]; then
  if act; then
    note "would create .gitignore"
  elif : > "$GI"; then
    note "created .gitignore"
  else
    echo "failed to create $GI" >&2
    exit 1
  fi
fi
for pat in ".env" ".env.*" "!.env.example" "node_modules/" "dist/" ".DS_Store"; do
  if ! grep -qxF "$pat" "$GI" 2>/dev/null; then
    if act; then
      note "would add to gitignore: $pat"
    elif printf '%s\n' "$pat" >> "$GI"; then
      note "gitignore += $pat"
    else
      echo "failed to update $GI" >&2
      exit 1
    fi
  fi
done

# 2. Untrack any committed .env (keeps the local file; removes it from the index only).
if git rev-parse --git-dir >/dev/null 2>&1; then
  # -z / read -d '' so paths containing spaces survive.
  while IFS= read -r -d '' f; do
    case "$f" in *.example) continue ;; esac
    if act; then
      note "would untrack $f (file would remain on disk)"
    elif git rm --cached -q -- "$f"; then
      note "untracked $f (still on disk; ROTATE its keys and purge history separately)"
    else
      echo "failed to untrack $f" >&2
      exit 1
    fi
  done < <(git ls-files -z -- '*.env' '.env' '.env.*' '**/.env' '**/.env.*' 2>/dev/null)
fi

# 3. Generate a lockfile if one is missing (npm projects).
if [ -f package.json ] \
   && [ ! -f package-lock.json ] && [ ! -f npm-shrinkwrap.json ] \
   && [ ! -f yarn.lock ] && [ ! -f pnpm-lock.yaml ] \
   && [ ! -f bun.lock ] && [ ! -f bun.lockb ]; then
  if [ "$ALLOW_NETWORK_LOCKFILE" = 0 ]; then
    note "skipped lockfile generation (networked dependency resolution requires --allow-network-lockfile)"
  elif command -v npm >/dev/null 2>&1; then
    if act; then
      note "would generate package-lock.json"
    # A reviewed repository is still untrusted input. Never run its lifecycle
    # scripts, and do not submit a second implicit audit request while creating
    # the lockfile.
    elif npm install --package-lock-only --ignore-scripts --no-audit --fund=false \
             >/dev/null 2>&1; then
      note "generated package-lock.json"
    else
      echo "failed to generate package-lock.json; inspect npm output and retry with --ignore-scripts --no-audit" >&2
      exit 1
    fi
  else
    echo "no lockfile and npm is unavailable; no lockfile was generated" >&2
    exit 1
  fi
fi

if [ "$DRY" = 1 ]; then
  echo "=== apply_safe_fixes (DRY RUN — nothing written) ==="
else
  echo "=== apply_safe_fixes: actions/results ==="
fi
if [ ${#CHANGED[@]} -eq 0 ]; then
  echo "(none — nothing safe to auto-fix)"
else
  printf ' - %s\n' "${CHANGED[@]}"
fi
echo ""
echo "NOTE: This helper does NOT rotate secrets or purge git history."
echo "If any secret was ever committed, rotate it at the provider and purge history"
echo "with git filter-repo / BFG. Untracking a file does not undo the leak."
