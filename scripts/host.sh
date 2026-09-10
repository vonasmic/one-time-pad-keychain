#!/usr/bin/env bash
# SE host: build se_host, tropic model_server, se_host console.
set -euo pipefail
# shellcheck source=common.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

ensure_libtropic() {
  if [[ ! -f "$SE_DIR/libtropic/scripts/tropic01_model/model_cfg.yml" ]]; then
    log "initializing nested libtropic submodule"
    git -C "$SE_DIR" submodule update --init --recursive
  fi
  [[ -f "$SE_DIR/libtropic/scripts/tropic01_model/model_cfg.yml" ]] \
    || die "libtropic model config missing after submodule init"
}

prepare() {
  ensure_libtropic
  local venv="$SE_DIR/libtropic/scripts/tropic01_model/.venv"
  local deps="$SE_DIR/host/tropic_model/_deps/wolfssl"
  if [[ ! -x "$venv/bin/python" && ! -x "$venv/bin/python3" ]]; then
    log "installing tropic model venv"
    ensure_unix_text "$SE_DIR/libtropic/scripts/tropic01_model/install_linux.sh"
    bash "$SE_DIR/libtropic/scripts/tropic01_model/install_linux.sh"
  fi
  if [[ ! -d "$deps" ]]; then
    log "downloading se_host deps (wolfSSL / ed25519)"
    ensure_unix_text "$SE_DIR/host/tropic_model/download_deps.sh"
    bash "$SE_DIR/host/tropic_model/download_deps.sh"
  fi
  log "building se_host / se_host_2"
  mkdir -p "$SE_DIR/host/tropic_model/build"
  (
    cd "$SE_DIR/host/tropic_model/build"
    cmake ..
    make -j"$(nproc)" se_host
    cp se_host se_host_2
  )
  [[ -x "$SE_DIR/host/tropic_model/build/se_host" ]] || die "se_host did not build"
  [[ -x "$SE_DIR/host/tropic_model/build/se_host_2" ]] || die "se_host_2 did not build"
}

model() {
  local port="${1:-28992}"
  cd "$SE_DIR"
  # shellcheck disable=SC1091
  source libtropic/scripts/tropic01_model/.venv/bin/activate
  exec model_server tcp -c libtropic/scripts/tropic01_model/model_cfg.yml -p "$port"
}

se_host() {
  local tty="${1:-/tmp/ttyACM-se1}"
  local tropic="${2:-28992}"
  local bin="${3:-se_host}"
  cd "$SE_DIR/host/tropic_model/build"
  exec ./"$bin" --tty "$tty" --tty-sae none --tropic-port "$tropic"
}

case "${1:-}" in
  prepare) prepare ;;
  model) shift; model "${1:-28992}" ;;
  se-host) shift; se_host "${1:-/tmp/ttyACM-se1}" "${2:-28992}" "${3:-se_host}" ;;
  -h|--help|"")
    cat <<EOF
Usage: $(basename "$0") prepare|model [PORT]|se-host [TTY] [TROPIC_PORT] [BIN]
EOF
    [[ -n "${1:-}" ]] || exit 1
    ;;
  *) die "unknown command: $1 (try --help)" ;;
esac
