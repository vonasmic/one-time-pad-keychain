#!/usr/bin/env bash
# Orchestrator: HSM check, Java provision, host build, then tmux stack.
set -euo pipefail
# shellcheck source=common.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

SESSION="${OTP_TMUX_SESSION:-otp-keychain}"
LOG_DIR="${OTP_TMUX_LOG_DIR:-$SCRIPTS/logs}"

# lab-run.py puts Maven in a new session so pane SIGHUP does not reach the JVM.
# Reap those leftovers when the tmux session goes away (and before a new start).
reap_lab_jvms() {
  pkill -TERM -f '[e]xec.mainClass=fel.cvut.terminalapp.TerminalApp' 2>/dev/null || true
  pkill -TERM -f '[e]xec.mainClass=fel.cvut.userapp.UserApplication' 2>/dev/null || true
}

kill_session() {
  tmux kill-session -t "$SESSION" 2>/dev/null || true
  reap_lab_jvms
}

start_stack() {
  if tmux has-session -t "$SESSION" 2>/dev/null; then
    die "tmux session '$SESSION' already exists. Kill it with: tmux kill-session -t $SESSION"
  fi
  trap kill_session EXIT INT TERM
  reap_lab_jvms
  mkdir -p "$LOG_DIR"
  log "starting tmux session $SESSION (logs: $LOG_DIR)"
  python3 -u "$SCRIPTS/lab-run.py" --lab "${USB_LAB_FILE:-/tmp/otp-keychain-lab.json}" --set-owner USER
  tmux new-session -d -s "$SESSION" -n stack -c "$ROOT"
  tmux set-option -t "$SESSION" remain-on-exit on
  tmux set-option -t "$SESSION" allow-rename off
  tmux set-option -t "$SESSION" mouse on
  tmux set-option -w -t "$SESSION:stack" automatic-rename off
  tmux set-option -w -t "$SESSION:stack" pane-border-status top
  tmux set-option -w -t "$SESSION:stack" pane-border-format " #{pane_title} "
  tmux bind-key -n M-Left select-pane -L
  tmux bind-key -n M-Right select-pane -R
  tmux bind-key -n M-Up select-pane -U
  tmux bind-key -n M-Down select-pane -D
  tmux set-hook -t "$SESSION" session-closed \
    "unbind-key -n M-Left ; unbind-key -n M-Right ; unbind-key -n M-Up ; unbind-key -n M-Down ; run-shell 'pkill -TERM -f \"[e]xec.mainClass=fel.cvut.terminalapp.TerminalApp\" || true; pkill -TERM -f \"[e]xec.mainClass=fel.cvut.userapp.UserApplication\" || true'"

  tmux split-window -v -t "$SESSION:stack"
  tmux split-window -v -t "$SESSION:stack"
  tmux select-layout -t "$SESSION:stack" even-vertical

  local rows=() pane
  mapfile -t rows < <(tmux list-panes -t "$SESSION:stack" -F '#{pane_id}')
  for pane in "${rows[@]}"; do
    tmux split-window -h -t "$pane"
  done

  local panes=()
  mapfile -t panes < <(
    tmux list-panes -t "$SESSION:stack" -F '#{pane_top} #{pane_left} #{pane_id}' \
      | sort -n -k1,1 -k2,2 \
      | awk '{print $3}'
  )
  [[ ${#panes[@]} -eq 6 ]] || die "expected 6 tmux panes, got ${#panes[@]}"

  pane() {
    local target="$1" title="$2"
    shift 2
    local logfile="$LOG_DIR/${title}.log"
    {
      printf '# %s  pane %s\n' "$(date -Iseconds)" "$title"
    } >"$logfile"
    tmux pipe-pane -t "$target" "exec stdbuf -oL cat >>$(printf '%q' "$logfile")"
    tmux respawn-pane -k -t "$target" "exec $(printf '%q ' "$@")"
    tmux select-pane -t "$target" -T "$title"
  }

  pane "${panes[0]}" "tropic-1" "$SCRIPTS/host.sh" model 28992
  pane "${panes[2]}" "node-1" "$SCRIPTS/java.sh" node env/node-1.env
  pane "${panes[4]}" "node-2" "$SCRIPTS/java.sh" node env/node-2.env
  pane "${panes[1]}" "terminal" "$SCRIPTS/java.sh" lab-terminal
  pane "${panes[3]}" "userapp" "$SCRIPTS/java.sh" lab-userapp
  pane "${panes[5]}" "se-host-1" "$SCRIPTS/host.sh" se-host /tmp/ttyACM-se1 28992

  # Second Tropic model + se_host (CL 2). Lab starts at USER so bring-up is free.
  local tropic2 se2 lab_pane
  tropic2="$(tmux split-window -v -t "${panes[0]}" -P -F '#{pane_id}')"
  pane "$tropic2" "tropic-2" "$SCRIPTS/host.sh" model 28993
  se2="$(tmux split-window -v -t "${panes[5]}" -P -F '#{pane_id}')"
  pane "$se2" "se-host-2" "$SCRIPTS/host.sh" se-host /tmp/ttyACM-se2 28993 se_host_2
  lab_pane="$(tmux split-window -v -t "${panes[3]}" -P -F '#{pane_id}')"
  pane "$lab_pane" "lab" "$SCRIPTS/java.sh" lab

  tmux select-pane -t "${panes[0]}"
  if [[ -n "${TMUX:-}" ]]; then
    trap - EXIT INT TERM
    tmux switch-client -t "$SESSION"
  else
    tmux attach -t "$SESSION" || true
  fi
}

main() {
  need_cmd git
  need_cmd python3
  need_cmd mvn
  need_cmd cmake
  need_cmd make
  need_cmd tmux
  need_cmd stdbuf
  [[ -d "$JAVA_DIR" ]] || die "JAVA_TLS_TEST not found"
  [[ -d "$SE_DIR" ]] || die "stm32u535-trustzone-usb not found"

  "$SCRIPTS/hsm.sh"
  "$SCRIPTS/java.sh" compile
  "$SCRIPTS/java.sh" certgen
  "$SCRIPTS/host.sh" prepare
  "$SCRIPTS/java.sh" migrate
  start_stack
}

case "${1:-}" in
  -h|--help)
    cat <<EOF
Usage: $(basename "$0")

Start the HSM simulator first. Then:

  scripts/hsm.sh           csadm setup if needed
  scripts/java.sh compile  mvn install (local reactor jars)
  scripts/java.sh certgen  CertGenerator
  scripts/host.sh prepare  embed certs + build se_host
  scripts/java.sh migrate  Flyway node-1 / node-2
  tmux session '$SESSION'  panes (2 tropic models, 2 nodes, terminal, userapp, lab, 2 se_host)
  each pane is logged to $LOG_DIR/<pane>.log

Or from the repo root: ./run-all.sh
Detach or Ctrl-C tears down session '$SESSION'.
If a leftover session exists: tmux kill-session -t $SESSION
See RUN_ALL.md.
EOF
    ;;
  "")
    main
    ;;
  *)
    die "unknown argument: $1 (try --help)"
    ;;
esac
