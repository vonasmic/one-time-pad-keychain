#!/usr/bin/env bash
# Orchestrator: HSM check, Java provision, host build, then tmux stack.
# host.sh and java.sh define panes (list-panes). A config selects which to open.
set -euo pipefail
# shellcheck source=common.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

SESSION="${OTP_TMUX_SESSION:-otp-keychain}"
LOG_DIR="${OTP_TMUX_LOG_DIR:-$SCRIPTS/logs}"
CONFIG_DIR="$SCRIPTS/configs"

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

usage() {
  cat <<EOF
Usage: $(basename "$0") [CONFIG]

Start the HSM simulator first. CONFIG is a file in scripts/configs/
(default: run-all). The file lists pane names; it does not define commands.

  scripts/host.sh list-panes   tropic / se_host panes
  scripts/java.sh list-panes   SAE, terminal, userapp, lab panes
  scripts/hsm.sh               csadm setup if needed
  scripts/java.sh compile      mvn install (local reactor jars)
  scripts/java.sh certgen      CertGenerator
  scripts/host.sh prepare      embed certs + build se_host
  scripts/java.sh migrate      Flyway node-1 / node-2
  tmux session '$SESSION'      one row per selected group; pairs split left|right

  each pane is logged to $LOG_DIR/<pane>.log

Configurations:
EOF
  local f base
  for f in "$CONFIG_DIR"/*; do
    [[ -f "$f" ]] || continue
    base="$(basename "$f")"
    printf '  %-20s %s\n' "$base" "$f"
  done
  cat <<EOF

  ./run-all.sh
  ./run-all-with-hw.sh

run-all-with-hw.sh keeps client-1 on the simulator and points client-2 at
auto (no second tropic model or se_host). terminal-2 / userapp-2 scan for the
keychain CDC device (0483:5710) when they own USB. Pin a node with
serial client-2 /dev/ttyACM1 in the config if several boards are plugged in.

Or from the repo root: ./run-all.sh
Detach or Ctrl-C tears down session '$SESSION'.
If a leftover session exists: tmux kill-session -t $SESSION
See RUN_ALL.md.
EOF
}

load_catalog() {
  declare -g -a C_NAME=() C_ROW=() C_SCRIPT=() C_ARG=()
  declare -gA C_INDEX=()
  local script line name row i
  local -a fields=()
  for script in "$SCRIPTS/host.sh" "$SCRIPTS/java.sh"; do
    while IFS= read -r line; do
      [[ -n "$line" ]] || continue
      IFS=$'\t' read -r -a fields <<< "$line"
      [[ ${#fields[@]} -ge 3 ]] || die "bad pane from $script: $line"
      name="${fields[0]}"
      row="${fields[1]}"
      [[ "$name" =~ ^[A-Za-z0-9_-]+$ ]] || die "bad pane name from $script: $name"
      [[ -z "${C_INDEX[$name]:-}" ]] || die "duplicate pane name: $name"
      i=${#C_NAME[@]}
      C_INDEX["$name"]=$i
      C_NAME+=("$name")
      C_ROW+=("$row")
      C_SCRIPT+=("$script")
      C_ARG+=("$(printf '%q ' "${fields[@]:2}")")
    done < <("$script" list-panes)
  done
  [[ ${#C_NAME[@]} -gt 0 ]] || die "no panes from host.sh / java.sh list-panes"
}

resolve_config() {
  local name="$1"
  if [[ "$name" == */* || "$name" == .* ]]; then
    [[ -f "$name" ]] || die "configuration file not found: $name"
    printf '%s\n' "$name"
    return
  fi
  [[ -f "$CONFIG_DIR/$name" ]] || die "unknown configuration '$name' (see $CONFIG_DIR)"
  printf '%s\n' "$CONFIG_DIR/$name"
}

trim_line() {
  local s="$1"
  s="${s%%#*}"
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf '%s' "$s"
}

parse_config() {
  local file="$1" line token
  local -a tokens=()
  declare -g -a SEL=() SERIAL_CLIENT=() SERIAL_PATH=()
  declare -gA SEL_SEEN=()
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="$(trim_line "$line")"
    [[ -n "$line" ]] || continue
    read -r -a tokens <<< "$line"
    if [[ "${tokens[0]}" == "serial" ]]; then
      [[ ${#tokens[@]} -eq 3 ]] || die "$file: usage: serial client-1|client-2 PATH"
      case "${tokens[1]}" in
        client-1|client-2) ;;
        *) die "$file: serial client must be client-1 or client-2" ;;
      esac
      SERIAL_CLIENT+=("${tokens[1]}")
      SERIAL_PATH+=("${tokens[2]}")
      continue
    fi
    for token in "${tokens[@]}"; do
      [[ -n "${C_INDEX[$token]:-}" ]] || die "$file: unknown pane '$token'"
      [[ -z "${SEL_SEEN[$token]:-}" ]] || die "$file: pane listed twice: $token"
      SEL_SEEN["$token"]=1
      SEL+=("$token")
    done
  done < "$file"
  [[ ${#SEL[@]} -gt 0 ]] || die "$file: configuration selects no panes"
}

build_rows() {
  declare -g -a ROW_ORDER=() ACTIVE_ROWS=()
  declare -gA ROW_PANES=() ROW_SEEN=()
  local i row name count member
  for i in "${!C_NAME[@]}"; do
    row="${C_ROW[i]}"
    if [[ -z "${ROW_SEEN[$row]:-}" ]]; then
      ROW_SEEN["$row"]=1
      ROW_ORDER+=("$row")
    fi
  done
  for name in "${SEL[@]}"; do
    i="${C_INDEX[$name]}"
    row="${C_ROW[i]}"
    ROW_PANES["$row"]+="$name"$'\n'
  done
  for row in "${ROW_ORDER[@]}"; do
    [[ -n "${ROW_PANES[$row]:-}" ]] || continue
    count=0
    while IFS= read -r member; do
      [[ -n "$member" ]] || continue
      count=$((count + 1))
    done <<< "${ROW_PANES[$row]}"
    (( count >= 1 && count <= 2 )) || die "row $row has $count panes (max 2)"
    ACTIVE_ROWS+=("$row")
  done
  [[ ${#ACTIVE_ROWS[@]} -gt 0 ]] || die "configuration produced no rows"
}

pane_args() {
  local i="$1"
  declare -g -a PANE_ARGV=()
  # shellcheck disable=SC2294
  eval "PANE_ARGV=( ${C_ARG[i]} )"
}

apply_lab() {
  local lab="${USB_LAB_FILE:-/tmp/otp-keychain-lab.json}"
  local -a cmd=(python3 -u "$SCRIPTS/lab-run.py" --lab "$lab" --set-owner USER)
  local i
  for i in "${!SERIAL_CLIENT[@]}"; do
    cmd+=(--serial "${SERIAL_CLIENT[i]}=${SERIAL_PATH[i]}")
  done
  "${cmd[@]}"
}

start_stack() {
  if tmux has-session -t "$SESSION" 2>/dev/null; then
    die "tmux session '$SESSION' already exists. Kill it with: tmux kill-session -t $SESSION"
  fi
  trap kill_session EXIT INT TERM
  reap_lab_jvms
  mkdir -p "$LOG_DIR"
  log "starting tmux session $SESSION (config: $(basename "$CONFIG_FILE"), logs: $LOG_DIR)"
  apply_lab
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

  local n=${#ACTIVE_ROWS[@]}
  local i
  for ((i = 1; i < n; i++)); do
    tmux split-window -v -f -t "$SESSION:stack"
  done
  tmux select-layout -t "$SESSION:stack" even-vertical

  local -a band=()
  mapfile -t band < <(
    tmux list-panes -t "$SESSION:stack" -F '#{pane_top} #{pane_id}' \
      | sort -n -k1,1 \
      | awk '{print $2}'
  )
  [[ ${#band[@]} -eq $n ]] || die "expected $n tmux rows, got ${#band[@]}"

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

  launch() {
    local target="$1" name="$2"
    local i="${C_INDEX[$name]}"
    pane_args "$i"
    pane "$target" "$name" "${C_SCRIPT[i]}" "${PANE_ARGV[@]}"
  }

  local half=$(( term_cols / 2 ))
  local -a split_left=() members=()
  local row ri=0 left right name
  for row in "${ACTIVE_ROWS[@]}"; do
    members=()
    while IFS= read -r name; do
      [[ -n "$name" ]] || continue
      members+=("$name")
    done <<< "${ROW_PANES[$row]}"
    left="${band[ri]}"
    if [[ ${#members[@]} -eq 1 ]]; then
      launch "$left" "${members[0]}"
    else
      right="$(tmux split-window -h -t "$left" -P -F '#{pane_id}')"
      tmux resize-pane -t "$left" -x "$half"
      split_left+=("$left")
      launch "$left" "${members[0]}"
      launch "$right" "${members[1]}"
    fi
    ri=$((ri + 1))
  done

  # Shrink to the real terminal; split rows stay half-width.
  tmux resize-window -t "$SESSION:stack" -x "$term_cols" -y "$term_lines"
  half=$(( term_cols / 2 ))
  for left in "${split_left[@]}"; do
    tmux resize-pane -t "$left" -x "$half"
  done

  tmux set-option -w -t "$SESSION:stack" window-size latest
  tmux select-pane -t "${band[0]}"
  if [[ -n "${TMUX:-}" ]]; then
    trap - EXIT INT TERM
    tmux switch-client -t "$SESSION"
  else
    tmux attach -t "$SESSION" || true
  fi
}

CONFIG_NAME=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --config)
      shift
      [[ $# -gt 0 ]] || die "--config needs a name or path"
      [[ -z "$CONFIG_NAME" ]] || die "configuration given twice"
      CONFIG_NAME="$1"
      shift
      ;;
    --)
      shift
      break
      ;;
    -*)
      die "unknown option: $1 (try --help)"
      ;;
    *)
      [[ -z "$CONFIG_NAME" ]] || die "configuration given twice"
      CONFIG_NAME="$1"
      shift
      ;;
  esac
done
[[ $# -eq 0 ]] || die "unexpected arguments: $* (try --help)"
CONFIG_NAME="${CONFIG_NAME:-run-all}"

main() {
  load_catalog
  CONFIG_FILE="$(resolve_config "$CONFIG_NAME")"
  parse_config "$CONFIG_FILE"
  build_rows

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

main
