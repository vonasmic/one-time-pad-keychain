#!/usr/bin/env bash
# Resource usage of a running process (SAE node, UserApp, ...) for the thesis benchmarks.
#
#   procmon.sh --pid PID | --match PATTERN [--interval SEC] [--out FILE.csv] [--label NAME] [--no-jstat]
#   procmon.sh jfr-summary FILE.jfr
#
# Sampling mode reads /proc/PID every interval until the process exits or Ctrl-C, writes a CSV and
# prints a summary. --match waits for a java process whose command line matches PATTERN (pgrep -f).
# jfr-summary prints process CPU, heap after GC and RSS from a Flight Recorder file (JDK `jfr` tool).
# Only bash, awk and coreutils are needed; jstat (JDK) adds heap columns when it is on PATH.
set -uo pipefail

die() { printf 'procmon: %s\n' "$*" >&2; exit 1; }

usage() {
  sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

# ---- jfr-summary -------------------------------------------------------------------------------

# Prints "name value" lines; sizes converted to kB, percentages without "%".
jfr_values() {
  awk '
    function kb(v, u) {
      if (u == "bytes" || u == "byte") return v / 1024
      if (u == "kB") return v
      if (u == "MB") return v * 1024
      if (u == "GB") return v * 1024 * 1024
      return v
    }
    /^jdk\.[A-Za-z]+ \{/ { ev = $1; when = ""; depth = 0 }
    /\{$/ { depth++ }
    /^ *\}$/ { depth-- }
    ev == "jdk.CPULoad" && $1 == "jvmUser"   { gsub(/%/, "", $3); u = $3 }
    ev == "jdk.CPULoad" && $1 == "jvmSystem" { gsub(/%/, "", $3); print "cpu", u + $3 }
    ev == "jdk.CPULoad" && $1 == "machineTotal" { gsub(/%/, "", $3); print "machine", $3 }
    ev == "jdk.GCHeapSummary" && $1 == "when" { when = $3 }
    ev == "jdk.GCHeapSummary" && $1 == "committedSize" { committed = kb($3, $4) }
    ev == "jdk.GCHeapSummary" && $1 == "heapUsed" {
      if (when ~ /After/) { print "heap_after", kb($3, $4); print "heap_committed", committed }
      else print "heap_before", kb($3, $4)
    }
    ev == "jdk.ResidentSetSize" && $1 == "size" { print "rss", kb($3, $4) }
    ev == "jdk.ResidentSetSize" && $1 == "peak" { print "rss_peak", kb($3, $4) }
    ev == "jdk.PhysicalMemory" && $1 == "totalSize" { print "phys_total", kb($3, $4) }
  '
}

jfr_summary() {
  local f="${1:-}"
  [[ -f "$f" ]] || die "jfr-summary: file not found: $f"
  command -v jfr >/dev/null 2>&1 || die "jfr-summary: the JDK 'jfr' tool is not on PATH"
  echo "== jfr summary (recording)"
  jfr summary "$f" | awk '/^ *(Start|Duration|Version|VM Arguments)/ || / jdk\.(CPULoad|GCHeapSummary|ResidentSetSize|PhysicalMemory|GarbageCollection) /'
  echo "== thesis numbers"
  jfr print --events jdk.CPULoad,jdk.GCHeapSummary,jdk.ResidentSetSize,jdk.PhysicalMemory "$f" \
    | jfr_values | awk '
      { n[$1]++; s[$1] += $2; if (!($1 in mx) || $2 > mx[$1]) mx[$1] = $2 }
      function line(k, label, unit, mean) {
        if (!(k in n)) { printf "%-34s n/a\n", label; return }
        if (mean) printf "%-34s mean %10.2f  max %10.2f %s  (n=%d)\n", label, s[k] / n[k], mx[k], unit, n[k]
        else      printf "%-34s max %10.0f %s  (n=%d)\n", label, mx[k], unit, n[k]
      }
      END {
        line("cpu", "process CPU (% of all cores)", "%", 1)
        line("machine", "machine CPU total", "%", 1)
        line("heap_after", "heap used after GC", "kB", 1)
        line("heap_before", "heap used before GC", "kB", 0)
        line("heap_committed", "heap committed (after GC)", "kB", 0)
        line("rss", "RSS", "kB", 1)
        line("rss_peak", "RSS peak", "kB", 0)
        line("phys_total", "machine physical memory", "kB", 0)
      }'
}

# ---- sampling ----------------------------------------------------------------------------------

pid=""; match=""; interval=1; out=""; label=""; use_jstat=1
if [[ "${1:-}" == "jfr-summary" ]]; then
  jfr_summary "${2:-}"
  exit $?
fi
while [[ $# -gt 0 ]]; do
  case "$1" in
    --pid) pid="${2:-}"; shift 2 ;;
    --match) match="${2:-}"; shift 2 ;;
    --interval) interval="${2:-}"; shift 2 ;;
    --out) out="${2:-}"; shift 2 ;;
    --label) label="${2:-}"; shift 2 ;;
    --no-jstat) use_jstat=0; shift ;;
    -h|--help) usage 0 ;;
    *) printf 'procmon: unknown argument: %s\n' "$1" >&2; usage 1 ;;
  esac
done
[[ -n "$pid" || -n "$match" ]] || usage 1
[[ -n "$pid" && -n "$match" ]] && die "use --pid or --match, not both"
[[ "$interval" =~ ^[0-9]+([.][0-9]+)?$ ]] || die "--interval must be a number of seconds"

if [[ -n "$match" ]]; then
  echo "procmon: waiting for a java process matching: $match" >&2
  while :; do
    cands=()
    for p in $(pgrep -f -- "$match" 2>/dev/null); do
      # Only java processes: skips this script, its shell and pgrep, whose args contain PATTERN.
      [[ "$p" != "$$" && "$(cat "/proc/$p/comm" 2>/dev/null)" == "java" ]] && cands+=("$p")
    done
    if [[ ${#cands[@]} -eq 1 ]]; then pid="${cands[0]}"; break; fi
    if [[ ${#cands[@]} -gt 1 ]]; then
      for p in "${cands[@]}"; do printf '  %s %s\n' "$p" "$(tr '\0' ' ' < "/proc/$p/cmdline" | cut -c1-150)" >&2; done
      die "several java processes match; use a narrower --match or --pid"
    fi
    sleep 0.5
  done
fi
[[ "$pid" =~ ^[0-9]+$ && -r "/proc/$pid/stat" ]] || die "no such process: $pid"
[[ -n "$label" ]] || label="$(cat "/proc/$pid/comm" 2>/dev/null)"
[[ -n "$out" ]] || out="procmon-${label}-$(date +%Y%m%d-%H%M%S).csv"
mkdir -p "$(dirname "$out")"
if [[ $use_jstat -eq 1 ]] && ! command -v jstat >/dev/null 2>&1; then use_jstat=0; fi

hz="$(getconf CLK_TCK)"
ncpu="$(nproc)"

# utime + stime in clock ticks (fields 14, 15; parsed after the last ")" of the comm field).
cpu_ticks() {
  local s
  s="$(cat "/proc/$pid/stat" 2>/dev/null)" || return 1
  [[ -n "$s" ]] || return 1
  s="${s##*) }"
  awk '{ print $12 + $13 }' <<<"$s"
}

# "rss_kb hwm_kb threads" from /proc/PID/status.
mem_threads() {
  awk '/^VmRSS:/ { r = $2 } /^VmHWM:/ { h = $2 } /^Threads:/ { t = $2 }
       END { if (r == "") exit 1; print r, h, t }' "/proc/$pid/status" 2>/dev/null
}

# "heap_used_kb heap_committed_kb gc_count" from jstat -gc (KB columns), or three empty fields.
heap_gc() {
  [[ $use_jstat -eq 1 ]] || { echo ",,"; return; }
  timeout 5 jstat -gc "$pid" 2>/dev/null | awk '
    NR == 1 { for (i = 1; i <= NF; i++) c[$i] = i; next }
    NR == 2 && ("EU" in c) {
      u = $c["S0U"] + $c["S1U"] + $c["EU"] + $c["OU"]
      k = $c["S0C"] + $c["S1C"] + $c["EC"] + $c["OC"]
      g = $c["YGC"] + (("FGC" in c) ? $c["FGC"] : 0)
      printf "%.0f,%.0f,%d\n", u, k, g; ok = 1
    }
    END { if (!ok) print ",," }'
}

stop=0
trap 'stop=1' INT TERM

echo "timestamp,elapsed_s,label,pid,cpu_total_pct,cpu_per_core_pct,rss_kb,vmhwm_kb,threads,heap_used_kb,heap_committed_kb,gc_count" > "$out"
echo "procmon: pid $pid ($label), interval ${interval}s, $ncpu cores, jstat $([[ $use_jstat -eq 1 ]] && echo on || echo off) -> $out" >&2

t_start="$(date +%s.%N)"
prev_t="$t_start"
prev_ticks="$(cpu_ticks)" || die "process $pid exited"
while [[ $stop -eq 0 ]]; do
  sleep "$interval" & wait $! 2>/dev/null
  [[ $stop -eq 0 ]] || break
  now="$(date +%s.%N)"
  ticks="$(cpu_ticks)" || { echo "procmon: process $pid exited" >&2; break; }
  mt="$(mem_threads)" || { echo "procmon: process $pid exited" >&2; break; }
  hg="$(heap_gc)"
  awk -v ts="$(date +%Y-%m-%dT%H:%M:%S.%3N)" -v t0="$t_start" -v pt="$prev_t" -v t="$now" \
      -v pk="$prev_ticks" -v k="$ticks" -v hz="$hz" -v n="$ncpu" -v lb="$label" -v pid="$pid" \
      -v mt="$mt" -v hg="$hg" 'BEGIN {
        dt = t - pt; if (dt <= 0) dt = 1e-9
        tot = (k - pk) / hz / dt * 100
        split(mt, m, " ")
        printf "%s,%.3f,%s,%s,%.2f,%.2f,%s,%s,%s,%s\n", ts, t - t0, lb, pid, tot, tot / n, m[1], m[2], m[3], hg
      }' >> "$out"
  # Interval measured from this sample on: jstat time is then part of the next delta.
  prev_t="$now"; prev_ticks="$ticks"
done
trap - INT TERM

awk -F, -v out="$out" 'NR == 1 { next }
  { n++; ct += $5; cc += $6; if ($5 > mct) mct = $5; if ($6 > mcc) mcc = $6
    r += $7; if ($7 > mr) mr = $7; if ($8 > mh) mh = $8; if ($9 > mt) mt = $9
    if ($10 != "") { hn++; hs += $10; if ($10 > mhu) mhu = $10; if ($11 > mhc) mhc = $11; g = $12 } }
  END {
    printf "== procmon summary (%s, %d samples)\n", out, n
    if (n == 0) { print "no samples"; exit }
    printf "CPU total (100%% = 1 core)  mean %8.2f %%   max %8.2f %%\n", ct / n, mct
    printf "CPU per core (100%% = all) mean %8.2f %%   max %8.2f %%\n", cc / n, mcc
    printf "RSS                        mean %8.0f kB  max %8.0f kB\n", r / n, mr
    printf "VmHWM (peak RSS)                          %8.0f kB\n", mh
    printf "threads                                   max %d\n", mt
    if (hn > 0) printf "heap used (jstat)          mean %8.0f kB  max %8.0f kB  (committed max %.0f kB, GCs %d)\n", hs / hn, mhu, mhc, g
  }' "$out"