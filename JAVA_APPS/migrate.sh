#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

ENV_FILE="${1:-.env}"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "Env file not found: $ENV_FILE" >&2
  exit 1
fi

set -a
# shellcheck source=/dev/null
source <(tr -d '\r' < "$ENV_FILE")
set +a

# Ensure SQLite parent directory exists before Flyway opens the file.
if [[ "${DB_URL:-}" == jdbc:sqlite:* ]]; then
  db_path="${DB_URL#jdbc:sqlite:}"
  db_path="${db_path#file:}"
  db_path="${db_path%%\?*}"
  if [[ -n "$db_path" && "$db_path" != ":memory:" ]]; then
    mkdir -p "$(dirname -- "$db_path")"
  fi
fi

mvn -pl :sae-node flyway:migrate
