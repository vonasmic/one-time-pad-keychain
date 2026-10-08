#!/usr/bin/env bash
# Java SAE apps: certgen, migrate, node, terminal, userapp.
# lab-terminal / lab-userapp wrap those apps for the run-all tmux panes.
set -euo pipefail
# shellcheck source=common.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

compile() {
  log "mvn install (JAVA_APPS)"
  cd "$JAVA_DIR"
  mvn -q install -DskipTests
}

# Sibling modules are not on Maven Central; install the module subgraph into ~/.m2.
# Do not pass -am to exec:java — that also binds exec to java-tls-parent (no mainClass).
install_module_deps() {
  local module="$1"
  cd "$JAVA_DIR"
  mvn -q -pl ":${module}" -am install -DskipTests
}

run_module() {
  local module="$1"
  shift
  cd "$JAVA_DIR"
  exec mvn -q -pl ":${module}" "$@" exec:java
}

ensure_env_files() {
  [[ -f "$JAVA_DIR/env/hsm.env" ]] || die "missing $JAVA_DIR/env/hsm.env"
  [[ -f "$JAVA_DIR/env/node-1.env" ]] || die "missing $JAVA_DIR/env/node-1.env"
  [[ -f "$JAVA_DIR/env/node-2.env" ]] || die "missing $JAVA_DIR/env/node-2.env"
  if [[ ! -f "$JAVA_DIR/env/terminal-1.env" ]]; then
    log "creating env/terminal-1.env from example"
    cp "$JAVA_DIR/env/example/terminal.env.example" "$JAVA_DIR/env/terminal-1.env"
  fi
  if [[ ! -f "$JAVA_DIR/env/terminal-2.env" ]]; then
    log "creating env/terminal-2.env for SAE 2"
    cat >"$JAVA_DIR/env/terminal-2.env" <<'EOF'
# Terminal 2 — operates SAE 2 (node-2). See src/TerminalBridge/README.md.
TLS_NODE_ID=Terminal
NODE_HOSTNAME=127.0.0.1
NODE_TERMINAL_PORT=11113
NODE_NATIVE_PORT=5020
USB_SERIAL_PORT=/tmp/ttyACM-se2
EOF
  fi
  if [[ ! -f "$JAVA_DIR/env/userapp-1.env" ]]; then
    if [[ -f "$JAVA_DIR/env/userapp.env" ]]; then
      log "creating env/userapp-1.env from env/userapp.env"
      cp "$JAVA_DIR/env/userapp.env" "$JAVA_DIR/env/userapp-1.env"
    else
      log "creating env/userapp-1.env from example"
      cp "$JAVA_DIR/env/example/userapp.env.example" "$JAVA_DIR/env/userapp-1.env"
    fi
  fi
  if [[ ! -f "$JAVA_DIR/env/userapp-2.env" ]]; then
    log "creating env/userapp-2.env for client-2"
    cat >"$JAVA_DIR/env/userapp-2.env" <<'EOF'
# UserApp 2 — keychain /tmp/ttyACM-se2. See src/UserApp/README.md.
USB_SERIAL_PORT=/tmp/ttyACM-se2
USERAPP_OWNER_P12=user/user.p12
USERAPP_OWNER_P12_PASSWORD=password
USERAPP_OWNER_CERT=user/user-cert.pem
USERAPP_OWNER_KEY=user/user-key.pem
USERAPP_DEVICE_CERT=client2/client-cert.pem
USERAPP_CLIENT_CA_P12=ca/client_ca.p12
USERAPP_CLIENT_CA_P12_PASSWORD=password
USERAPP_SAE_CA=ca/root-ca.pem
EOF
  fi
}

certgen() {
  ensure_env_files
  log "CertGenerator"
  cd "$JAVA_DIR"
  source_env env/hsm.env
  source_env env/certgen.env
  install_module_deps cert-generator
  run_module cert-generator
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
  cd "$JAVA_DIR"
  source_env env/hsm.env
  source_env "$env_file"
  run_module sae-node
}

terminal() {
  local env_file="${1:-env/terminal-1.env}"
  cd "$JAVA_DIR"
  source_env env/hsm.env
  source_env "$env_file"
  unset USB_LAB_FILE
  run_module terminal-bridge
}

userapp() {
  local env_file="${1:-}"
  if [[ -z "$env_file" ]]; then
    if [[ -f "$JAVA_DIR/env/userapp-1.env" ]]; then
      env_file=env/userapp-1.env
    elif [[ -f "$JAVA_DIR/env/userapp.env" ]]; then
      env_file=env/userapp.env
    else
      die "missing env/userapp-1.env (or env/userapp.env)"
    fi
  fi
  cd "$JAVA_DIR"
  source_env "$env_file"
  unset USB_LAB_FILE
  run_module user-app
}

lab_file() {
  printf '%s\n' "${USB_LAB_FILE:-/tmp/otp-keychain-lab.json}"
}

# Lab panes: 1 → client-1 / SAE 1, 2 → client-2 / SAE 2. USER/SAE toggles USB owner
# for both clients at once (no CL switch).
lab_terminal() {
  local which="${1:-1}"
  case "$which" in
    1|2) ;;
    *) die "usage: java.sh lab-terminal 1|2" ;;
  esac
  cd "$JAVA_DIR"
  source_env env/hsm.env
  source_env "env/terminal-${which}.env"
  local file client
  file="$(lab_file)"
  client="client-${which}"
  unset USB_LAB_FILE
  exec python3 -u "$SCRIPTS/lab-run.py" --lab "$file" --role terminal \
    --fixed-client "$client" -- \
    mvn -pl :terminal-bridge exec:java
}

lab_userapp() {
  local which="${1:-1}"
  case "$which" in
    1|2) ;;
    *) die "usage: java.sh lab-userapp 1|2" ;;
  esac
  cd "$JAVA_DIR"
  local env_file="env/userapp-${which}.env"
  if [[ ! -f "$env_file" && "$which" == "1" && -f env/userapp.env ]]; then
    env_file=env/userapp.env
  fi
  source_env "$env_file"
  local file client
  file="$(lab_file)"
  client="client-${which}"
  unset USB_LAB_FILE
  exec python3 -u "$SCRIPTS/lab-run.py" --lab "$file" --role userapp \
    --fixed-client "$client" -- \
    mvn -pl :user-app exec:java
}

lab() {
  USB_LAB_FILE="$(lab_file)"
  export USB_LAB_FILE
  if [[ $# -gt 0 ]]; then
    run_module lab-switch -Dexec.args="$*"
  fi
  run_module lab-switch
}

# TSV: name, row, then arguments to this script. run-all.sh selects names.
list_panes() {
  printf '%s\n' \
    $'node-1\tsaes\tnode\tenv/node-1.env' \
    $'node-2\tsaes\tnode\tenv/node-2.env' \
    $'terminal-1\tterminals\tlab-terminal\t1' \
    $'terminal-2\tterminals\tlab-terminal\t2' \
    $'userapp-1\tuserapps\tlab-userapp\t1' \
    $'userapp-2\tuserapps\tlab-userapp\t2' \
    $'lab\tlab\tlab'
}

case "${1:-}" in
  compile) compile ;;
  certgen) certgen ;;
  migrate) migrate ;;
  node) shift; node "${1:-}" ;;
  terminal) shift; terminal "${1:-}" ;;
  userapp) shift; userapp "${1:-}" ;;
  lab-terminal) shift; lab_terminal "${1:-}" ;;
  lab-userapp) shift; lab_userapp "${1:-}" ;;
  lab) shift; lab "$@" ;;
  list-panes) list_panes ;;
  -h|--help|"")
    cat <<EOF
Usage: $(basename "$0") compile|certgen|migrate|node ENV|terminal [ENV]|userapp [ENV]|lab-terminal 1|2|lab-userapp 1|2|lab [CMD]|list-panes
EOF
    [[ -n "${1:-}" ]] || exit 1
    ;;
  *) die "unknown command: $1 (try --help)" ;;
esac
