# RegABE v1.3.1：第二批实验原型改动

本版本在 v1.3.0 基础上完成第二批工作，未扩建服务层或解码链路。

## 1. 更新算法分项

- RA：输入／活动状态检查、PRF 与 FieldMap、预计算查验、纠正群运算、
  后继 helper 运算、helper 树、纠正向量认证、Head 签名及暂存复制。
- KC：固定输入快照、RA 签名、事件与计数器、完整向量成员检查和认证、
  后继运算、helper 树、属性状态维护、摘要／Head 检查及签名暂存。
- 客户端：输入、签名、绑定、成员、路径、连续性、PRF、自检、本地安装。
- 公共目标配置采用对应分项，仍正确维护后继 helper 和认证状态；
  它不执行 Full 专有的 PRF 或私有自检，也不虚构外部纠正向量验证。

现有安全检查均保留。revoke_prepare_s 是提案准备流程总量，包含本地
材料准备，不直接等同于 RA 密码运算；proposal_* 与 ra_* 已分别记录。
所有总量独立计时，子项互斥，残余字段核对未归因工作和计时开销。

## 2. L／u 更新扫描

新增 --update-grid，显式选择更新参数点；--update-events 设置单 fixture
中不同合法撤销事件数。指定的更新和历史参数点会加入 fixture 并集，
避免只生成注册结果而静默遗漏更新。不会生成全参数笛卡尔积。

初始化独立存放在 updates[scheme].initialization，不再放入逐事件均值。
现有长度为 u 的容器复制保留在计时中，没有预先做结构优化。

## 3. 离线历史重放

新增 --history-lengths、--history-grid、--checkpoint-events 和
--history-replays。用户 0 作为未被针对观察用户；R/F 使用匹配的合法序列。
可在 genesis 或已提交的非零版本建立私有检查点，然后处理 H 个连续的
已提交事件。每次内部重复都从原检查点恢复，不复用已同步状态。

历史生成、材料提取、编码字节统计、参考用户处理、检查点创建／恢复均
放在重放计时之外，并单列 preparation 记录。重放只处理预先可用的内存
对象，保留所有认证和本地状态更新。不报告解码、下载或网络耗时。

H 不计 Abort、未提交提案、Retry 或自查；事件不重复使用已经失效的
用户—属性对。初始资格密度与 v1.3.0 相同，预留观察用户后，所需合法事件
数不可超过 (L-1)*floor(u/2)，前缀与离线历史共同占用这一容量。

重复次数在 fixture 内平均，不当作独立样本；不同 H 前缀具有相关性。
结果以独立 fixture 汇总，提供 R/F 配对增量。

## 4. 真实编码字节分解

补充注册、公开发布、单客户端响应和累计历史响应的组成表。
所有分项之和等于已有编码器得到的真实总长度，包括封装、重复 Head、
签名、纠正项与两条认证路径；不虚构路径去重或网络头部。
材料保持内存对象形式，未新增解码器。

## 运行示例

```bash
bash setup.sh
bash run_experiments.sh --profile smoke --grid 3:4 \
  --update-grid 3:4 3:8 4:4 --history-grid 3:4 \
  --history-lengths 1 3 --checkpoint-events 1 --history-replays 2 \
  --output results/v131-smoke
```

以上只验证流程，不是论文正式测量。正式配方和所有字段见 README.md；
实际自查范围和结果见 VALIDATION.md。

## 主要新增输出

- update-event-samples.csv / update-stages.csv：事件原始分项及 fixture 汇总。
- byte-components.csv / byte-components-summary.csv：真实编码组成及统计。
- history-samples.csv / history-inner-samples.csv / history-summary.csv：历史样本。
- history-paired-increments.csv：R/F 配对增量。
- history-initialization-samples.csv / history-preparation-samples.csv：计时外成本。
- figures/target-privacy-cost.*：L、u 两个方向的服务器和客户端结果。
- figures/history-catchup.*：已启用参数点的 H 扩展结果。

## 保持的范围取舍与兼容性

仍不补 ACA 机器审核、完整 eta_i／Base 注册表绑定、完整服务认证与编码
重构、授权状态服务、持久化提交恢复或完整解码器。资格密度、内存和新优化
留待后续按结果需要开展。访问性能默认关闭，保留少量计时外正确性自查。

密码学数据格式与 v1.3.0 相同；方法新增可选 metrics 关键字，原调用方式
仍可使用。实验结果结构有扩展，初始化位置有调整，必须使用新的输出目录，
不与 v1.3.0 或开发中间版本的检查点混用。私有掩码、密钥和检查点不写入结果。
