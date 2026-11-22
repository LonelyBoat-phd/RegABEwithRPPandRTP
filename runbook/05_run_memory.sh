#!/usr/bin/env bash
# P6 峰值内存：每个参数点单独一个进程，用 probe_run.sh 在进程外部轮询 /proc/<pid>/status。
# 因为 VmHWM 只增不减，混跑会累计，所以必须一点一进程、串行执行。
# 统一口径 10 个丢弃预热 + 50 个独立正式样本（registration only）。
# 用法：bash runbook/05_run_memory.sh
set -uo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."

PY=${REGABE_PY:-.venv/bin/python}
WARMUPS=10     # 统一口径：丢弃预热 fixture 数
MEASURED=50    # 统一口径：独立正式 fixture 数（n=50）
LOGDIR=${REGABE_LOGDIR:-results/_logs}
mkdir -p "$LOGDIR"

echo "== 预检 =="
"$PY" tools/check_integrity.py || exit 1
[ -f native/libregabe_type1.so ] || "$PY" tools/build_native.py || exit 1
echo "口径：${WARMUPS} 预热 + ${MEASURED} 正式（registration only）。"
echo "注意：本脚本串行执行，期间不要并行跑别的实验，否则外部采样会被污染。"
echo "start: $(date -Is)"
echo

for pt in 8:32 16:32 32:32 64:32 32:128; do
  L=${pt%%:*}; u=${pt##*:}
  out="results/mem-L${L}-u${u}"
  echo "===== memory point (L,u)=($L,$u) ${WARMUPS} warm-ups + ${MEASURED} measured, registration only ====="
  bash runbook/probe_run.sh "$out" \
    --profile formal --warmups "$WARMUPS" --repeats "$MEASURED" \
    --grid "$pt" --registration-only \
    2>&1 | tee "$LOGDIR/$(basename "$out").log" | tail -3
  echo "exit=${PIPESTATUS[0]}  $(date -Is)"
  echo
done
echo "MEMORY DONE $(date -Is)"
