#!/usr/bin/env bash
# apply_safe_fixes.sh — ONLY non-destructive, reversible hygiene fixes.
# Never rewrites git history, never rotates keys, never edits application code.
#
# Usage: apply_safe_fixes.sh [repo_dir] [--dry-run]
set -uo pipefail

REPO="."
DRY=0
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY=1 ;;
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
[ -f "$GI" ] || { act || : > "$GI"; note "created .gitignore"; }
for pat in ".env" ".env.*" "!.env.example" "node_modules/" "dist/" ".DS_Store"; do
  if ! grep -qxF "$pat" "$GI" 2>/dev/null; then
    act || echo "$pat" >> "$GI"
    note "gitignore += $pat"
  fi
done

# 2. Untrack any committed .env (keeps the local file; removes it from the index only).
if git rev-parse --git-dir >/dev/null 2>&1; then
  # -z / read -d '' so paths containing spaces survive.
  while IFS= read -r -d '' f; do
    case "$f" in *.example) continue ;; esac
    act || git rm --cached -q -- "$f"
    note "untracked $f (still on disk; ROTATE its keys and purge history separately)"
  done < <(git ls-files -z -- '*.env' '.env' '.env.*' '**/.env' '**/.env.*' 2>/dev/null)
fi

# 3. Generate a lockfile if one is missing (npm projects).
if [ -f package.json ] \
   && [ ! -f package-lock.json ] && [ ! -f yarn.lock ] \
   && [ ! -f pnpm-lock.yaml ] && [ ! -f bun.lockb ]; then
  if command -v npm >/dev/null 2>&1; then
    if act; then
      note "would generate package-lock.json"
    elif npm install --package-lock-only >/dev/null 2>&1; then
      note "generated package-lock.json"
    else
      note "FAILED to generate package-lock.json (npm error — run 'npm install --package-lock-only' manually)"
    fi
  else
    note "no lockfile and npm is unavailable — generate one manually"
  fi
fi

if [ "$DRY" = 1 ]; then
  echo "=== apply_safe_fixes (DRY RUN — nothing written) ==="
else
  echo "=== apply_safe_fixes: changes made ==="
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
