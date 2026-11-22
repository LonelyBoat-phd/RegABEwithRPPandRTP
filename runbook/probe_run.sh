#!/usr/bin/env bash
# 外部内存采样包装器：跑一条 supplement.run，同时每 2 秒记录该进程的 VmRSS / VmHWM。
# 采样在进程外部完成，不改任何源码，因此不会改变源码指纹。
# 用法：bash runbook/probe_run.sh <输出目录> [supplement.run 的参数...]
set -uo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."

PY=${REGABE_PY:-.venv/bin/python}

out=${1:?usage: probe_run.sh <output-dir> [run args...]}
shift
mkdir -p "$(dirname "$out")" 2>/dev/null || true

samples="${out%/}-mem-samples.csv"
echo "epoch_s,rss_mib,hwm_mib" > "$samples"
start=$(date +%s.%N)

"$PY" -u -m supplement.run "$@" --output "$out" &
pid=$!

# 采样循环：每 2 秒读一次 /proc/<pid>/status
while kill -0 "$pid" 2>/dev/null; do
  line=$(grep -E '^(VmRSS|VmHWM):' "/proc/$pid/status" 2>/dev/null | awk '{print $2}')
  rss=$(echo "$line" | sed -n 1p); hwm=$(echo "$line" | sed -n 2p)
  if [ -n "${rss:-}" ]; then
    now=$(date +%s.%N)
    awk -v t="$now" -v s="$start" -v r="$rss" -v h="$hwm" 'BEGIN{printf "%.1f,%.1f,%.1f\n", t-s, r/1024, h/1024}' >> "$samples"
  fi
  sleep 2
done
wait "$pid"; rc=$?
echo "probe: exit=$rc samples=$(($(wc -l < "$samples")-1)) file=$samples"
exit "$rc"
