#!/usr/bin/env bash
# Private host SE simulator for se-bench: TROPIC01 model_server + se_host on a PTY.
# Uses its own port/PTY (default 28997, /tmp/ttyACM-bench) so the lab simulators
# (28992/28993, /tmp/ttyACM-se1/se2) are never touched. Every (re)start is a fresh chip.
#   sim.sh start | stop | restart
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SE_DIR="$(cd "$HERE/../../../stm32u535-trustzone-usb" && pwd)"
PORT="${SEBENCH_SIM_PORT:-28997}"
TTY="${SEBENCH_SIM_TTY:-/tmp/ttyACM-bench}"
RUN="${SEBENCH_SIM_DIR:-/tmp/se-bench-sim}"
mkdir -p "$RUN"

stop() {
  for f in se_host model; do
    if [[ -f "$RUN/$f.pid" ]]; then
      pkill -P "$(cat "$RUN/$f.pid")" 2>/dev/null || true
      kill "$(cat "$RUN/$f.pid")" 2>/dev/null || true
      for _ in $(seq 50); do kill -0 "$(cat "$RUN/$f.pid")" 2>/dev/null || break; sleep 0.1; done
      kill -9 "$(cat "$RUN/$f.pid")" 2>/dev/null || true
      rm -f "$RUN/$f.pid"
    fi
  done
  rm -f "$TTY"
}

start() {
  ( cd "$SE_DIR"
    # shellcheck disable=SC1091
    source libtropic/scripts/tropic01_model/.venv/bin/activate
    setsid model_server tcp -c libtropic/scripts/tropic01_model/model_cfg.yml -p "$PORT" \
      >"$RUN/model.log" 2>&1 < /dev/null & echo $! >"$RUN/model.pid" )
  for _ in $(seq 100); do ss -ltn | grep -q ":$PORT " && break; sleep 0.1; done
  ( cd "$SE_DIR/host/tropic_model/build"
    # keep stdin open (se_host mirrors stdin when no slave is attached)
    setsid bash -c 'sleep infinity | ./se_host --tty "$0" --tty-sae none --tropic-port "$1"; echo "se_host exit=$?" >&2' \
      "$TTY" "$PORT" >"$RUN/se_host.log" 2>&1 < /dev/null & echo $! >"$RUN/se_host.pid" )
  for _ in $(seq 100); do [[ -e "$TTY" ]] && break; sleep 0.1; done
  [[ -e "$TTY" ]] || { echo "se_host did not create $TTY" >&2; tail -20 "$RUN/se_host.log" >&2; exit 1; }
  sleep 0.5
}

case "${1:-}" in
  start) stop; start ;;
  stop) stop ;;
  restart) stop; start ;;
  *) echo "usage: $0 start|stop|restart" >&2; exit 2 ;;
esac