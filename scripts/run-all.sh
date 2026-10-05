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
  # Detached create often uses a tiny default size; build rows at a tall
  # temporary height, then shrink to the calling terminal so everything fits.
  local term_cols term_lines
  if read -r term_lines term_cols < <(stty size 2>/dev/null); then
    :
  else
    term_cols=$(tput cols 2>/dev/null || echo 80)
    term_lines=$(tput lines 2>/dev/null || echo 40)
  fi
  # pane-border-status top needs ~1 line per pane; keep a usable floor.
  (( term_lines >= 24 )) || term_lines=24
  (( term_cols >= 40 )) || term_cols=40

  tmux set-option -w -t "$SESSION:stack" window-size manual
  tmux resize-window -t "$SESSION:stack" -x "$term_cols" -y 60
  tmux bind-key -n M-Left select-pane -L
  tmux bind-key -n M-Right select-pane -R
  tmux bind-key -n M-Up select-pane -U
  tmux bind-key -n M-Down select-pane -D
  tmux set-hook -t "$SESSION" session-closed \
    "unbind-key -n M-Left ; unbind-key -n M-Right ; unbind-key -n M-Up ; unbind-key -n M-Down ; run-shell 'pkill -TERM -f \"[e]xec.mainClass=fel.cvut.terminalapp.TerminalApp\" || true; pkill -TERM -f \"[e]xec.mainClass=fel.cvut.userapp.UserApplication\" || true'"

  # Six rows top→bottom: tropics | hosts | SAEs | terminals | userapps | lab.
  # -f makes each split a full-width band (works with the temporary height).
  local i
  for ((i = 1; i < 6; i++)); do
    tmux split-window -v -f -t "$SESSION:stack"
  done
  tmux select-layout -t "$SESSION:stack" even-vertical

  local rows=()
  mapfile -t rows < <(
    tmux list-panes -t "$SESSION:stack" -F '#{pane_top} #{pane_id}' \
      | sort -n -k1,1 \
      | awk '{print $2}'
  )
  [[ ${#rows[@]} -eq 6 ]] || die "expected 6 tmux rows, got ${#rows[@]}"

  local lefts=() rights=() half
  half=$(( term_cols / 2 ))
  for i in 0 1 2 3 4; do
    lefts[i]="${rows[i]}"
    rights[i]="$(tmux split-window -h -t "${rows[i]}" -P -F '#{pane_id}')"
    tmux resize-pane -t "${lefts[i]}" -x "$half"
  done
  local lab_pane="${rows[5]}"

  # Shrink to the real terminal; columns stay half-width (rows scale with the window).
  tmux resize-window -t "$SESSION:stack" -x "$term_cols" -y "$term_lines"
  half=$(( term_cols / 2 ))
  for i in 0 1 2 3 4; do
    tmux resize-pane -t "${lefts[i]}" -x "$half"
  done

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

  pane "${lefts[0]}" "tropic-1" "$SCRIPTS/host.sh" model 28992
  pane "${rights[0]}" "tropic-2" "$SCRIPTS/host.sh" model 28993
  pane "${lefts[1]}" "se-host-1" "$SCRIPTS/host.sh" se-host /tmp/ttyACM-se1 28992
  pane "${rights[1]}" "se-host-2" "$SCRIPTS/host.sh" se-host /tmp/ttyACM-se2 28993 se_host_2
  pane "${lefts[2]}" "node-1" "$SCRIPTS/java.sh" node env/node-1.env
  pane "${rights[2]}" "node-2" "$SCRIPTS/java.sh" node env/node-2.env
  pane "${lefts[3]}" "terminal-1" "$SCRIPTS/java.sh" lab-terminal 1
  pane "${rights[3]}" "terminal-2" "$SCRIPTS/java.sh" lab-terminal 2
  pane "${lefts[4]}" "userapp-1" "$SCRIPTS/java.sh" lab-userapp 1
  pane "${rights[4]}" "userapp-2" "$SCRIPTS/java.sh" lab-userapp 2
  pane "$lab_pane" "lab" "$SCRIPTS/java.sh" lab

  # Fit the attaching client so both columns stay visible and even.
  tmux set-option -w -t "$SESSION:stack" window-size latest
  tmux select-pane -t "${lefts[0]}"
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
  [[ -d "$JAVA_DIR" ]] || die "JAVA_APPS not found"
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
  tmux session '$SESSION'  rows: tropics | hosts | SAEs | terminals | userapps | lab

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
