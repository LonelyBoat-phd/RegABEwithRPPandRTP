# RegABE 参考实现 — v1.3.2

本仓库是论文所用 **注册式属性基加密（Registered ABE）** 原型：私有注册 + 版本化属性撤销。
它覆盖注册、聚合、全局 Y 检查、更新、客户端处理与离线历史重放，用于产出计时与字节统计；
**不是**生产级库，也不是完整服务实现。

英文主文档见 [`README.md`](README.md)（测量契约、计时边界、输出字段的完整说明都在那里），
发行记录见 `CHANGELOG.md`，验证结果见 `VALIDATION.md`。

## 统一测量口径

全仓库只有一个口径，代码默认值、CLI 示例、`runbook/` 脚本与 `bench.py` 完全一致：

| 项 | 值 | 作用 |
|---|---|---|
| `--warmups` | **10** | 每个参数点先跑的丢弃预热 fixture，不进入统计 |
| `--repeats` | **50** | 每个参数点的独立正式 fixture，n=50 |
| 每点 fixture 数 | **60** | 10 + 50 |
| `--profile smoke` | 1 + 2 | 只验证流程与续跑，不产生性能结论 |
| 内层重复 | `access_inner_repeats=5`、`history_replays=1` | 在单个 fixture 内平均，不是独立样本 |

置信区间是以 50 个独立 fixture 为样本量的双侧 95% Student-t 区间；
内层重复不参与置信区间。这组数字由 `supplement/tests/test_supplement.py::test_formal_sample_counts`
断言，并写入 `manifest.json`，续跑时按值强校验。

## 目录

| 路径 | 内容 |
|---|---|
| `regabe/` | 密码学核心：原语、注册、撤销、历史、度量 |
| `supplement/` | 实验层：recipe/manifest、协议驱动、报告与 CSV/绘图、测试 |
| `native/type1.c` | PBC Type-1 桥（构建时编译，不随包分发二进制） |
| `vendor/` | 未修改的 PBC 0.5.14 源码包及其许可证 |
| `params/` | 固定的 Type A 参数 |
| `tests/`、`supplement/tests/` | 后端/协议测试与实验层测试 |
| `tools/` | 原生构建、源码完整性校验、参数生成 |
| `runbook/` | 产出论文数据的实际运行脚本，见 `runbook/README.md` |

## 安装与验证

Linux / WSL2，Python 3.12+，需要 C 编译器与 GMP 开发头文件。发行包内含 PBC 源码与固定参数，
无需联网取第三方库。

```bash
bash setup.sh                                            # 校验 + venv + 原生桥 + 两套测试
.venv/bin/python -m unittest discover -s tests           # 25 项
.venv/bin/python -m unittest discover -s supplement/tests # 31 项
```

`setup.sh` 只装核心依赖（cffi、cryptography）。要跑实验与出图还需 `supplement/requirements.txt`
（scipy、matplotlib）。

## 运行

```bash
# 冒烟：只验证流程，1 预热 + 2 正式
.venv/bin/python -u -m supplement.run --profile smoke --grid 3:4 \
  --update-grid 3:4 3:8 4:4 --history-grid 3:4 \
  --history-lengths 1 3 --checkpoint-events 1 --history-replays 2 \
  --output results/smoke

# 正式：7 个参数点，10 预热 + 50 正式
bash runbook/01_run_formal_main.sh results/formal-main

# 只重出报告，不重算
.venv/bin/python -m supplement.report results/formal-main
```

同一输出目录、完全相同的命令重跑即可续跑；`manifest.json` 会拒绝源码指纹、参数、
环境或 recipe 不一致的续跑，所以改过任何一项都要新开输出目录。

## 输出

`manifest.json`（源码/环境/参数/口径）、`rounds/*.json`（每个 fixture 的原始记录）、
`timing-samples.csv` 与 `summary.csv`（观测与置信区间）、`paired-increments.csv`（配对增量）、
`*-stages.csv`（分相）、`*-samples.csv`（原始样本）、`byte-components*.csv`（字节账目）、
`figures/`（自动绘图）。字段含义见英文主文档的 Outputs and statistics 一节。
私钥、掩码、权重与检查点不落盘。

读数注意：`gen_*` 是整个 roster 的总量，逐用户均值只看 `generation_mean_user_s`；
父阶段与叶子阶段计时**重叠**，不能相加；历史时间是内存对象上的重放，不是下载时间。

## 范围限制

无对象级解码器、无网络传输、无 ACA 机器审核、无完整服务绑定；串行、单线程、
可变时间算术；内存只记整进程峰值。测试与计时都不构成安全性或生产可用性结论。

## 许可

项目代码由 AI 工具辅助生成，见 `NOTICE`。**本仓库未提供 `LICENSE` 文件**，因此适用默认版权，
在权利人选定许可证之前不得再分发。PBC 与其他依赖保留各自的许可证（见 `vendor/PBC-COPYING`）。
引用时请指明具体的 release 或 commit。
