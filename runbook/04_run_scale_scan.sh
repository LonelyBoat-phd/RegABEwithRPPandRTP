#!/usr/bin/env bash
# 大参数点补充扫描：(L,u)=(128,32) 与 (32,256)，注册 + 更新。
# 这两个点不在正式主网格里，用于核对 L 与 u 的伸缩趋势。
# 统一口径 10 个丢弃预热 + 50 个独立正式样本。
# 用法：bash runbook/04_run_scale_scan.sh
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
echo "口径：${WARMUPS} 预热 + ${MEASURED} 正式。"
echo "start: $(date -Is)"
echo

for pt in 128:32 32:256; do
  tag="scale-L${pt%%:*}-u${pt##*:}"
  echo "===== $tag : ${WARMUPS} warm-ups + ${MEASURED} measured, registration + updates ====="
  "$PY" -u -m supplement.run \
    --profile formal --warmups "$WARMUPS" --repeats "$MEASURED" \
    --grid "$pt" --update-grid "$pt" \
    --output "results/$tag" 2>&1 | tee "$LOGDIR/$tag.log" | tail -3
  echo "exit=${PIPESTATUS[0]}  $(date -Is)"
  echo
done
echo "SCALE DONE $(date -Is)"
