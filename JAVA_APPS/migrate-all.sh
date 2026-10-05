#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

shopt -s nullglob
env_files=("$SCRIPT_DIR"/env/node-*.env)
shopt -u nullglob

if [[ ${#env_files[@]} -eq 0 ]]; then
  echo "No node env files found (expected env/node-*.env)" >&2
  exit 1
fi

for env_file in "${env_files[@]}"; do
  echo "==> $env_file"
  "$SCRIPT_DIR/migrate.sh" "$env_file"
done
