#!/usr/bin/env bash
# 资格密度（q=0.1/0.5/0.9）与 access 表：串行跑完，全部可续跑。
# 统一口径 10 个丢弃预热 + 50 个独立正式样本。
# 用法：bash runbook/03_run_density_and_access.sh
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

for q in 0.1 0.5 0.9; do
  tag="density-q${q}"
  echo "===== $tag : (L,u)=(32,32), registration only, ${WARMUPS} warm-ups + ${MEASURED} measured, q=$q ====="
  "$PY" -u -m supplement.run \
    --profile formal --warmups "$WARMUPS" --repeats "$MEASURED" --density "$q" \
    --grid 32:32 --registration-only \
    --output "results/$tag" 2>&1 | tee "$LOGDIR/$tag.log" | tail -3
  echo "exit=${PIPESTATUS[0]}  $(date -Is)"
  echo
done

tag="access-formal"
echo "===== $tag : (L,u)=(32,128), access K=16/64, ${WARMUPS} warm-ups + ${MEASURED} measured ====="
"$PY" -u -m supplement.run \
  --profile formal --warmups "$WARMUPS" --repeats "$MEASURED" \
  --grid 32:128 --include-access \
  --output "results/$tag" 2>&1 | tee "$LOGDIR/$tag.log" | tail -3
echo "exit=${PIPESTATUS[0]}  $(date -Is)"
echo
echo "ALL DONE $(date -Is)"
