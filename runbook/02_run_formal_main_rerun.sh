#!/usr/bin/env bash
# 第二遍主实验：与 01 完全相同的工作负载形状，换独立的公开工作负载种子。
# 用途是得到与第一遍独立的第二组 50 个正式样本，便于核对批间波动。
# 用法：bash runbook/02_run_formal_main_rerun.sh [输出目录]
#   默认输出 results/formal-main-rerun
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."

PY=${REGABE_PY:-.venv/bin/python}
WARMUPS=10            # 统一口径：丢弃预热 fixture 数
MEASURED=50           # 统一口径：独立正式 fixture 数（n=50）
SEED_BASE=20261109    # 第二遍主实验使用的公开工作负载种子
OUT=${1:-results/formal-main-rerun}
LOGDIR=${REGABE_LOGDIR:-results/_logs}
mkdir -p "$LOGDIR"

echo "== 预检 =="
"$PY" tools/check_integrity.py
[ -f native/libregabe_type1.so ] || "$PY" tools/build_native.py
echo "口径：${WARMUPS} 预热 + ${MEASURED} 正式；seed-base=${SEED_BASE}。"
echo

nohup "$PY" -u -m supplement.run \
  --profile formal \
  --warmups "$WARMUPS" --repeats "$MEASURED" \
  --seed-base "$SEED_BASE" \
  --grid 8:32 16:32 32:32 64:32 32:16 32:64 32:128 \
  --update-grid 8:32 16:32 32:32 64:32 32:16 32:64 32:128 \
  --history-grid 16:32 32:32 64:32 \
  --history-lengths 1 8 32 128 \
  --checkpoint-events 8 \
  --output "$OUT" \
  > "$LOGDIR/$(basename "$OUT").log" 2>&1 &
pid=$!
echo "$pid" > "$LOGDIR/$(basename "$OUT").pid"
echo "started pid=$pid  log=$LOGDIR/$(basename "$OUT").log"
