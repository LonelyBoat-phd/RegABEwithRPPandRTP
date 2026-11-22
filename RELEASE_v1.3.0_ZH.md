# RegABE v1.3.0：第一批注册实验改动

本版本基于用户提供的 v1.2.1，仅完成已确定的第一批工作。

## 已完成

1. 正式 P/Private roster 验证默认在计时内执行完整源公钥验证。
2. 注册掩码改由每次新 RegGen 独立生成，不再保存在 SourceSecret。
3. 注册公共固定基表按每个 fixture 一次建立，初始化成本单列；
   后续生成采用明确的预计算后口径，表绑定检查仍在调用内执行。
4. 新增逐用户注册记录，以及随机性、承诺、X、Y、split、证书签发、
   证明首消息、哈希、响应的分项；全局 Y 增加权重、MSM、配对分项。
5. 新增相同记录上的逐式 Y 只读参考，复用相同必要验证规则，
   不重复逐关系成员检查，不安装参考状态，也不覆盖全局失败结果。
6. 增加注册专用入口、显式参数点、缓存源验证辅助模式及结果导出。
   访问性能默认关闭；原有 P/R/F 更新与计时外自查保留。

## 测量口径

输入为内存中的已有对象，不包含解码、网络和 ACA 审核服务。
完整 roster 验证包含快照固定、源验证、证明及证书、成员检查、Y、
聚合与已有认证结构。预计算、缓存源验证准备分别列账。

`generation_mean_user_s` 是逐用户调用时间的均值，不等于将含调度开销的
总时间直接除以 L。`gen_*_s` 在 fixture 汇总表中是整个 roster 的分项总量；
逐用户数据在 `registration-user-samples.csv`。总量和子阶段不可重复求和。

逐式 Y 只用于机制诊断。每个 fixture 仍只有一次正式全局随机接纳；
逐式与全局执行顺序交替，二者使用相同记录和必要验证。

## 运行示例

```bash
bash setup.sh
bash run_experiments.sh --profile smoke --registration-only --y-reference --grid 2:1 3:4 --output results/v130-check
bash run_experiments.sh --profile formal --registration-only --output results/v130-formal
```

逐式 Y 会执行 uL(L-1) 个关系检查，建议显式选择小规模参数，避免直接
在全部正式大规模点启用。正式实验未在交付环境中执行；smoke 只验证流程。
验证范围和结果见 `VALIDATION.md`，全部选项和字段说明见 `README.md`。

## 本版本不包含

ACA 机器审核、完整原始注册绑定／Base 注册表绑定、服务认证与编码重构、
授权状态服务、持久化提交与恢复、完整解码器、离线历史驱动、RTP 分项计时、
资格密度扫描、内存实验，以及针对测量结果的新优化。

## 兼容性

SourceSecret 删除 xi；source_keygen 不再接受 xi 参数。
注册数据仍使用原紧凑证明格式；统计字段与计时口径已改变，旧结果目录
不可与 v1.3.0 混用。SHA256SUMS 覆盖源代码和说明，运行生成物不随包发布。
