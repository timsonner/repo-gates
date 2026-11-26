#!/bin/sh
set -eu

require_base_sha() {
  base=${BASE_SHA-}
  if [ "${#base}" -ne 40 ] || ! printf '%s' "$base" | grep -Eq '^[0-9a-f]{40}$'; then
    echo 'error: BASE_SHA must match ^[0-9a-f]{40}$' >&2
    exit 1
  fi
  if [ "$(git cat-file -t "$base" 2>/dev/null)" = "commit" ]; then
    :
  else
    echo 'error: BASE_SHA does not name a commit' >&2
    exit 1
  fi
}

require_base_sha

if [ "${1-}" = "--check" ]; then
  exit 0
fi

dest="${RUNNER_TEMP}/repo-gates.json"
if git cat-file -e "$BASE_SHA:.github/repo-gates.json" >/dev/null 2>&1; then
  git show "$BASE_SHA:.github/repo-gates.json" > "$dest"
  printf 'path=%s\n' "$dest" >> "$GITHUB_OUTPUT"
else
  printf 'path=\n' >> "$GITHUB_OUTPUT"
fi
