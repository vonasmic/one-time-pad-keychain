#!/usr/bin/env bash
# Java SAE apps: certgen, migrate, node, terminal, userapp.
# lab-terminal / lab-userapp wrap those apps for the run-all tmux panes.
set -euo pipefail
# shellcheck source=common.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

compile() {
  log "mvn compile (JAVA_TLS_TEST)"
  cd "$JAVA_DIR"
  mvn -q compile
}

ensure_env_files() {
  [[ -f "$JAVA_DIR/env/hsm.env" ]] || die "missing $JAVA_DIR/env/hsm.env"
  [[ -f "$JAVA_DIR/env/node-1.env" ]] || die "missing $JAVA_DIR/env/node-1.env"
  [[ -f "$JAVA_DIR/env/node-2.env" ]] || die "missing $JAVA_DIR/env/node-2.env"
  if [[ ! -f "$JAVA_DIR/env/terminal-1.env" ]]; then
    log "creating env/terminal-1.env from example"
    cp "$JAVA_DIR/env/example/terminal.env.example" "$JAVA_DIR/env/terminal-1.env"
  fi
  if [[ ! -f "$JAVA_DIR/env/userapp.env" ]]; then
    log "creating env/userapp.env from example"
    cp "$JAVA_DIR/env/example/userapp.env.example" "$JAVA_DIR/env/userapp.env"
  fi
}

certgen() {
  ensure_env_files
  log "CertGenerator"
  cd "$JAVA_DIR"
  source_env env/hsm.env
  mvn exec:java -Dexec.mainClass=fel.cvut.certGen.CertGenerator
}

migrate() {
  ensure_env_files
  log "Flyway migrate node-1 / node-2"
  "$JAVA_DIR/migrate.sh" env/node-1.env
  "$JAVA_DIR/migrate.sh" env/node-2.env
}

node() {
  local env_file="${1:-}"
  [[ -n "$env_file" ]] || die "usage: java.sh node env/node-N.env"
  compile
  source_env env/hsm.env
  source_env "$env_file"
  exec mvn exec:java -Dexec.mainClass=fel.cvut.node.Node
}

terminal() {
  compile
  source_env env/hsm.env
  source_env env/terminal-1.env
  unset USB_LAB_FILE
  exec mvn exec:java -Dexec.mainClass=fel.cvut.terminalapp.TerminalApp
}

userapp() {
  compile
  source_env env/userapp.env
  unset USB_LAB_FILE
  exec mvn exec:java -Dexec.mainClass=fel.cvut.userapp.UserApplication
}

lab_file() {
  printf '%s\n' "${USB_LAB_FILE:-/tmp/otp-keychain-lab.json}"
}

lab_terminal() {
  compile
  source_env env/hsm.env
  source_env env/terminal-1.env
  local file
  file="$(lab_file)"
  unset USB_LAB_FILE
  exec python3 -u "$SCRIPTS/lab-run.py" --lab "$file" --role terminal -- \
    mvn exec:java -Dexec.mainClass=fel.cvut.terminalapp.TerminalApp
}

lab_userapp() {
  compile
  source_env env/userapp.env
  local file
  file="$(lab_file)"
  unset USB_LAB_FILE
  exec python3 -u "$SCRIPTS/lab-run.py" --lab "$file" --role userapp -- \
    mvn exec:java -Dexec.mainClass=fel.cvut.userapp.UserApplication
}

lab() {
  compile
  USB_LAB_FILE="$(lab_file)"
  export USB_LAB_FILE
  if [[ $# -gt 0 ]]; then
    exec mvn exec:java -Dexec.mainClass=fel.cvut.lab.LabSwitchApp -Dexec.args="$*"
  fi
  exec mvn exec:java -Dexec.mainClass=fel.cvut.lab.LabSwitchApp
}

case "${1:-}" in
  compile) compile ;;
  certgen) certgen ;;
  migrate) migrate ;;
  node) shift; node "${1:-}" ;;
  terminal) terminal ;;
  userapp) userapp ;;
  lab-terminal) lab_terminal ;;
  lab-userapp) lab_userapp ;;
  lab) shift; lab "$@" ;;
  -h|--help|"")
    cat <<EOF
Usage: $(basename "$0") compile|certgen|migrate|node ENV|terminal|userapp|lab-terminal|lab-userapp|lab [CMD]
EOF
    [[ -n "${1:-}" ]] || exit 1
    ;;
  *) die "unknown command: $1 (try --help)" ;;
esac
