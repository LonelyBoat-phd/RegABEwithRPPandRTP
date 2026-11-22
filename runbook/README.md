# 运行手册（runbook）

本目录是产出论文全部计时数据的**实际运行脚本**。所有脚本都在仓库根目录之外无需任何软链接：
进入脚本时自动 `cd` 到仓库根，直接 `bash runbook/<脚本>` 即可。

## 统一口径（唯一标准）

| 项 | 值 | 说明 |
|---|---|---|
| 丢弃预热 `--warmups` | **10** | 每个参数点先跑 10 个 fixture，只用于稳定缓存/分支预测，不进入统计 |
| 独立正式样本 `--repeats` | **50** | 每个参数点 50 个独立 fixture；均值与双侧 95% Student-t 区间都以 n=50 计算 |
| 每点 fixture 数 | **60** | 10 + 50 |
| 冒烟 `--profile smoke` | 1 + 2 | **仅**验证流程与续跑，不产生任何性能结论 |
| 内层重复 | `access_inner_repeats=5`、`history_replays=1` | 在单个 fixture 内取平均，**不是**独立样本，不进入置信区间 |

这 10/50 与代码里的 profile 默认值一致（`supplement/run.py::make_recipe`，并由
`supplement/tests/test_supplement.py::test_formal_sample_counts` 断言）。脚本里仍然显式写出
`--warmups 10 --repeats 50`，因为这两个值会写进 `manifest.json`，续跑时按值强校验。
**不要在单个脚本里改动这两个数**，否则该目录的结果与该口径不可比。

## 脚本清单

| 脚本 | 作用 | 是否计时数据 |
|---|---|---|
| `01_run_formal_main.sh` | 正式主实验：7 个参数点的注册 + 更新 + 历史 | 是 |
| `02_run_formal_main_rerun.sh` | 第二遍主实验：同形状、换独立工作负载种子 | 是 |
| `03_run_density_and_access.sh` | 资格密度 q=0.1/0.5/0.9 + access 表 | 是 |
| `04_run_scale_scan.sh` | 大参数点 (128,32)、(32,256) | 是 |
| `05_run_memory.sh` | P6 峰值内存，进程外部采样 | 是 |
| `progress.sh` | 只读进度面板（`--watch` 每 10 秒刷新） | 否 |
| `probe_run.sh` | 外部内存采样包装器，被 `05` 调用 | 否 |

全部脚本串行、单进程。除 `progress.sh` 外都用 `nohup` 或 `tee` 把日志写到
`results/_logs/`（该目录已被 `.gitignore` 忽略）。

## 环境

Linux / WSL2，Python 3.12+，C 编译器与 GMP 头文件。首次使用先建环境：

```bash
bash setup.sh                      # 校验完整性 + venv + 原生桥 + 两套测试
```

脚本默认用 `.venv/bin/python`；已有解释器时用 `REGABE_PY=/path/to/python` 覆盖。

## 执行顺序与时间预算

按下面的顺序串行跑。表里的耗时是参考机器实测外推到 10+50 后的**估算**，用于排期，不是承诺。

| 步骤 | 命令 | fixture 数 | 估算 |
|---|---|---|---|
| 1 | `bash runbook/01_run_formal_main.sh` | 7 点 × 60 = 420 | 约 35–40 h |
| 2 | `bash runbook/02_run_formal_main_rerun.sh` | 420 | 约 35–40 h |
| 3 | `bash runbook/03_run_density_and_access.sh` | 3×60 + 60 | 约 20–24 h |
| 4 | `bash runbook/04_run_scale_scan.sh` | 2×60 | 约 70–75 h |
| 5 | `bash runbook/05_run_memory.sh` | 5×60（仅注册） | 约 10–20 h |

如果想缩短，**减少参数点或减少重复次数时必须同步改论文里的样本数说明**；
不要只改脚本不改口径，否则 `manifest.json` 里的 recipe 与论文正文互相矛盾。

## 续跑

同一输出目录、完全相同的命令重跑即可：已完成的 fixture 会打印 `[resume]` 并复用。
`manifest.json` 会强校验源码指纹、参数、环境与 recipe，任一不一致就拒绝续跑并要求换新目录。
因此：**改代码、改参数、换机器之后一律新开输出目录**。

查看进度（只读，不会影响正在跑的实验）：

```bash
bash runbook/progress.sh            # auto：自动挑最近在跑的那条
bash runbook/progress.sh --watch results/formal-main
```

## 结果文件对照

| 分析目标 | 文件 |
|---|---|
| 注册总体成本与 RPP 增量 | `summary.csv`、`paired-increments.csv` |
| 注册机制分解 | `registration-stages.csv` |
| 每用户注册原始记录 | `registration-user-samples.csv` |
| 初始化 / 预计算账目 | `initialization-summary.csv` |
| 全局 vs 逐式 Y | `y-verification-comparison.csv` |
| 单事件 RA/KC/客户端分项 | `update-stages.csv`、`update-event-samples.csv` |
| 离线历史累计 | `history-summary.csv`、`history-paired-increments.csv` |
| 真实编码字节组成 | `byte-components-summary.csv` |
| 计时外准备成本 | `history-preparation-samples.csv` |
| 环境与口径 | `manifest.json` |
| 自动绘图 | `figures/` |

读数注意：

- `gen_*` 是整个 roster 的总量；逐用户均值只看 `generation_mean_user_s`。
- `revoke_prepare_s` 含提案材料准备，不等于纯 RA 密码运算（对比 `ra_*` 分项）。
- 历史时间是已有内存对象上的重放，不是下载/网络时间。
- 总时间与子阶段重叠，**不能相加**。
- 主结果保持完整源公钥验证（`source_validation=full`）；`--source-validation cached` 只作辅助诊断。

## 测量期间的环境纪律

- 串行运行，不要并行开别的实验或重负载任务（代码本身是单线程）。
- 保持同一机器、同一 WSL 发行版、同一解释器；正式运行中不要 `apt upgrade`。
- 机器不要休眠（Windows 电源计划设为“从不睡眠”），否则 WSL 会挂起、计时结果作废。
- 正式结果目录整体保留，尤其 `manifest.json` 与 `rounds/`。

## 与 `SHA256SUMS` 的关系

`tools/check_integrity.py` 的清单覆盖实现与文档，**不包含 `runbook/`**：
这些脚本本来就是按机器和参数点改的，改网格或输出目录不需要重刷清单。
如果改了实现或文档，用 `python3 tools/check_integrity.py --write` 重刷。
