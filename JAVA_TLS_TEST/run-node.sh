#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

ENV_FILE="${1:-.env}"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "Usage: $0 [env-file]   (default: .env)" >&2
  echo "  e.g. $0 env/node-1.env" >&2
  exit 1
fi

set -a
# shellcheck source=/dev/null
source <(tr -d '\r' < "$ENV_FILE")
set +a

exec mvn -q exec:java \
  -Dexec.mainClass=fel.cvut.node.Node \
  -Dexec.cleanupDaemonThreads=false
