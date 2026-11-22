#!/usr/bin/env bash
# 查看 RegABE 正式测量的进度。只读，不会干扰正在跑的实验。
# 用法：
#   bash runbook/progress.sh [结果目录|auto]          # 打印一次
#   bash runbook/progress.sh --watch [结果目录|auto]  # 每 10 秒刷新（Ctrl-C 退出）
# auto（默认）自动挑选 results/ 下最近还在跑的那一条。
set -uo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."

OUT=auto
WATCH=0
for arg in "$@"; do
  case "$arg" in
    --watch) WATCH=1 ;;
    *) OUT="$arg" ;;
  esac
done

PY=${REGABE_PY:-.venv/bin/python}
LOGDIR=${REGABE_LOGDIR:-results/_logs}

show() {
  "$PY" - "." "$OUT" "$LOGDIR" <<'PY'
import json, sys, os, glob, time, datetime

root, out, logdir = sys.argv[1], sys.argv[2], sys.argv[3]
if out in ('', 'auto'):
    candidates = []
    now = time.time()
    for mf in glob.glob(os.path.join(root, 'results', '*', 'manifest.json')):
        d = os.path.dirname(mf)
        if os.path.basename(d).startswith('_'):
            continue
        st = os.path.join(d, 'execution-status.json')
        if os.path.isfile(st):
            try:
                status = json.load(open(st)).get('status', '?')
            except Exception:
                status = '?'
            mtime = os.path.getmtime(st)
        else:
            # a run that has a manifest but has not finished its first fixture yet
            status = 'starting' if now - os.path.getmtime(mf) < 7200 else 'stale'
            mtime = os.path.getmtime(mf)
        rank = {'running': 3, 'starting': 2, 'measurements_complete': 1, 'complete': 0}.get(status, 1)
        candidates.append((rank, mtime, d, status))
    if not candidates:
        print(f'auto: no runs under {root}/results')
        raise SystemExit
    candidates.sort(key=lambda c: (c[0], c[1]))
    out = candidates[-1][2]
    print(f"(auto) 当前运行: {os.path.basename(out)}  status={candidates[-1][3]}")
    print()

base = os.path.join(root, out)
if not os.path.isdir(base):
    base = out

# 每个点在没有样本时的保守估计(s)，用于开跑初期的 ETA
DEFAULT = {(8,32):18, (16,32):72, (32,32):211, (64,32):727, (32,16):103, (32,64):371, (32,128):677,
           (128,32):2900, (32,256):1500, (256,32):11300}

now = datetime.datetime.now().strftime('%H:%M:%S')
print(f'RegABE 正式测量进度  [{now}]')
print(f'目录: {base}')

mf = os.path.join(base, 'manifest.json')
if not os.path.isfile(mf):
    print('\n尚未开始（还没有 manifest.json）。')
    if os.path.isdir(base):
        print('目录已存在但没有清单，可能刚创建或已中断在初始化阶段。')
    else:
        print('该输出目录还不存在 —— 实验还没有写第一个检查点。')
else:
    recipe = json.load(open(mf))['recipe']
    grid = [tuple(p) for p in recipe['grid']]
    warm = recipe['warmups']; reps = recipe['repeats']; per = warm + reps
    total = len(grid) * per
    files = sorted(glob.glob(os.path.join(base, 'rounds', '*.json')), key=os.path.getmtime)

    done = {}
    durations = {}
    prev = None
    for f in files:
        try:
            o = json.load(open(f))
        except Exception:
            continue
        key = (o['L'], o['u'])
        done[key] = done.get(key, 0) + 1
        mt = os.path.getmtime(f)
        if prev is not None:
            durations.setdefault(key, []).append(mt - prev)
        prev = mt

    ndone = sum(done.values())
    status = {}
    st = os.path.join(base, 'execution-status.json')
    if os.path.isfile(st):
        try: status = json.load(open(st))
        except Exception: status = {}
    pct = ndone / total * 100 if total else 0
    print(f"状态: {status.get('status') or 'starting'}   完成 {ndone}/{total} ({pct:.1f}%)   本进程已跑 "
          f"{status.get('elapsed_this_invocation_s', 0)/3600:.2f} h")
    if status.get('last_completed'):
        print(f"最近完成: {status['last_completed']}")
    print(f"口径: {len(grid)} 个点 × ({warm} 预热 + {reps} 正式) = {total} 个 fixture")

    # ETA
    remaining = 0.0
    for key in grid:
        have = done.get(key, 0)
        left = per - have
        if left <= 0:
            continue
        if durations.get(key):
            est = sum(durations[key]) / len(durations[key])
        else:
            est = DEFAULT.get(key, 300)
        remaining += left * est
    eta = datetime.datetime.now() + datetime.timedelta(seconds=remaining)
    if remaining <= 0:
        print("预计还需: 已全部完成\n")
    else:
        print(f"预计还需: {remaining/3600:.1f} h （约 {eta.strftime('%m-%d %H:%M')} 结束）\n")

    print(f"{'点 (L,u)':>12} {'完成':>7} {'状态':>10} {'本点均时':>9} {'累计':>9}")
    for key in grid:
        have = done.get(key, 0)
        if have >= per: state = '✓ 完成'
        elif have == 0: state = '待跑'
        else: state = f'进行中 {have}/{per}'
        d = durations.get(key)
        avg = f'{sum(d)/len(d):.0f}s' if d else '-'
        cum = f'{sum(d)/60:.1f}m' if d else '-'
        print(f"{str(key):>12} {have:>4}/{per:<2} {state:>12} {avg:>9} {cum:>9}")

    log = os.path.join(root, logdir, os.path.basename(base) + '.log')
    if os.path.isfile(log):
        print('\n日志最后一行:')
        try:
            with open(log, 'rb') as fh:
                fh.seek(0, os.SEEK_END)
                size = fh.tell()
                fh.seek(max(0, size - 2000))
                tail = fh.read().decode('utf-8', 'replace').strip().splitlines()
            print('  ' + tail[-1] if tail else '  (空)')
        except Exception:
            pass
PY
}

if [ "$WATCH" = "1" ]; then
  while true; do
    clear
    show
    sleep 10
  done
else
  show
fi
