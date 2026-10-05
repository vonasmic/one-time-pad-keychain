# shellcheck shell=bash
# Sourced by scripts in this directory. ROOT is the repo root.
SCRIPTS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPTS/.." && pwd)"
JAVA_DIR="$ROOT/JAVA_APPS"
SE_DIR="$ROOT/stm32u535-trustzone-usb"

log() { printf '==> %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing command: $1"
}

ensure_unix_text() {
  local f="$1"
  [[ -f "$f" ]] || die "file not found: $f"
  if grep -q $'\r' "$f"; then
    log "converting CRLF to LF: $f"
    sed -i 's/\r$//' "$f"
  fi
}

source_env() {
  local file="$1"
  [[ -f "$file" ]] || die "env file not found: $file"
  set -a
  # shellcheck disable=SC1090
  source <(tr -d '\r' < "$file")
  set +a
}

env_get() {
  local file="$1" key="$2" default="${3:-}"
  local value
  value="$(tr -d '\r' < "$file" | awk -F= -v k="$key" '
    $1 == k { sub(/^[^=]+=/, ""); print; exit }
  ')"
  if [[ -n "$value" ]]; then
    printf '%s\n' "$value"
  else
    printf '%s\n' "$default"
  fi
}
