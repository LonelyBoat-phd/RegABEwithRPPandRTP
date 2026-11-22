#!/usr/bin/env bash
# 正式主实验：7 个参数点，统一口径 10 个丢弃预热 + 50 个独立正式样本。
# 用法：bash runbook/01_run_formal_main.sh [输出目录]
#   默认输出 results/formal-main
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."

PY=${REGABE_PY:-.venv/bin/python}
WARMUPS=10     # 统一口径：丢弃预热 fixture 数
MEASURED=50    # 统一口径：独立正式 fixture 数（n=50）
OUT=${1:-results/formal-main}
LOGDIR=${REGABE_LOGDIR:-results/_logs}
mkdir -p "$LOGDIR"

echo "== 预检 =="
"$PY" tools/check_integrity.py
[ -f native/libregabe_type1.so ] || "$PY" tools/build_native.py
"$PY" -c 'import regabe; print("regabe", regabe.__version__)'
echo "口径：${WARMUPS} 预热 + ${MEASURED} 正式；7 个点 × 60 = 420 个 fixture。"
echo "预计：约 35-40 h（参考机器实测外推），已完成的检查点会复用。"
echo

nohup "$PY" -u -m supplement.run \
  --profile formal \
  --warmups "$WARMUPS" --repeats "$MEASURED" \
  --grid 8:32 16:32 32:32 64:32 32:16 32:64 32:128 \
  --update-grid 8:32 16:32 32:32 64:32 32:16 32:64 32:128 \
  --history-grid 16:32 32:32 64:32 \
  --history-lengths 1 8 32 128 \
  --checkpoint-events 8 \
  --output "$OUT" \
  > "$LOGDIR/$(basename "$OUT").log" 2>&1 &
pid=$!
echo "$pid" > "$LOGDIR/$(basename "$OUT").pid"
echo "started pid=$pid"
echo "log  : $LOGDIR/$(basename "$OUT").log"
echo "进度 : bash runbook/progress.sh $OUT"
echo "状态 : cat $OUT/execution-status.json"
