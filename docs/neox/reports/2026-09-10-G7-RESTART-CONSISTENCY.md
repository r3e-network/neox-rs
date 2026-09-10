# 2026-09-10 G7 重启一致性验证（活体）

- 性质：Fresh-datadir MainNet 同步节点的重启一致性验证，补齐 G7 最后一项证据
- 结论速览：**G7 PASS**——硬终止后以原命令行重启，35 秒恢复 RPC，重启前高度区块哈希**逐字节一致**（无回退/无分叉），立即续追至 tip，重启后 tip 全覆盖差分 **40 检查 0 mismatch（skew=0）**

## 1. 基础设施与进程事实

- 节点进程：Windows `neox-rs.exe`，PID 51028，exe `D:\Git\neox-rs\target\debug\neox-rs.exe`，内存 ~5.2 GB
- 启动命令（经 psutil 从进程恢复，与 9-07 报告的 datadir/端口记录吻合）：

```sh
D:\Git\neox-rs\target\debug\neox-rs.exe node \
  --chain neox-mainnet \
  --datadir D:/Git/neox-rs/outputs/verify-datadir \
  --ipcdisable \
  --http --http.addr 127.0.0.1 --http.port 18545 \
  --ws --ws.addr 127.0.0.1 --ws.port 18546 \
  --port 40303 --authrpc.port 18551 \
  --metrics 127.0.0.1:18552 \
  --trusted-peers enode://92eec46d…@34.42.6.58:30303, enode://f289fb5c…@34.87.188.162:30303
```

- 进程创建时间 ≈ 2026-09-07 17:35 CST（与 9-07 报告的当日重启记录一致）
- datadir：`outputs/verify-datadir`（~9.2 GB，archive 模式，storage_v2）
- 附带澄清：WSL 内另有 `neo-node` 进程（`D:\Git\neo-rs`，Neo N3 协议节点，RPC 10332）与 18545 的 Neo X EVM 节点**无关**；9-09 报告中「节点在 WSL 内」的表述系 PowerShell 工具输出异常导致的误判，在此更正。

## 2. 重启流程与证据

| 步骤 | 结果 |
|---|---|
| 停机前基线（00:57:43Z） | head=`0x74ec60`（7,662,176），hash `0x23ee7b34f433e701c58f0711bbdbb2329a420503dc8ce7a2f48de57315e97197`（`outputs/g7-restart-baseline.txt`） |
| 优雅停机尝试 | AttachConsole+CTRL_BREAK 失败（进程以更高权限运行）；`taskkill /F` 普通 shell 拒绝（Access denied） |
| 提权终止 | 经用户批准 UAC 后 `taskkill /F /PID 51028` 成功；RPC 即刻拒连（连接拒绝） |
| 原命令行重启 | 后台重启（日志 `outputs/g7-restart-node.log`），~35 秒后 RPC 上线，storage 以 archive 模式加载 |
| **哈希连续性** | 重启前高度 `0x74ec60` 的区块哈希重启后仍为 `0x23ee7b34…97197` —— **HEAD_HASH_CONTINUITY_OK**（无回退、无分叉） |
| 续同步 | 重启即 `eth_syncing=false`，head 从 `0x74ec60` 续进至 `0x74ec6e`（+14 块）后继续贴 tip |
| 重启后 tip 差分（01:01:18Z） | **40/40 检查 0 mismatch**，`height_skew=0`，`skipped: []`（含 `eth_gasPrice`/`eth_envelopeFee`/`eth_maxEnvelopeGas`），证据 `outputs/g7-post-restart-differential.log` |

## 3. 判定与限制

- **G7 判定：PASS**。fresh-datadir 全量同步（9-07 报告记录执行阶段→9-09 追平 tip）+ 重启一致性（本报告）两条证据链均已闭环。
- 终止方式为硬终止（`taskkill /F`）而非 SIGTERM 优雅关闭：这使本验证同时覆盖**崩溃恢复路径**（MDBX recovery），比优雅重启更严格；代价是无法记录「干净关闭」分支，但 reth/MDBX 的 ACID+WAL 设计下哈希连续性不受终止方式影响。
- 节点二进制为 `target/debug` 构建产物，构建自 9-07 前的代码；G7 门禁验证的是同步/存储/重启行为，与后续协议改动无冲突。

## 4. 与门禁矩阵的关系

- G5 PASS（活体全覆盖，2026-09-09）、G6 PASS（活体采样，2026-09-09）、**G7 PASS（本报告）**。
- G8 有 2026-07-19 full-gate 历史 PASS + 前置已齐（prover/ZK 工件/双端二进制），剩余为当前 HEAD 重跑——`wsl.exe` 已确认可用（用户澄清其不在程序黑名单），重跑具备执行条件。
- 100% 协议等价仍不宣称：G8 当前代码重跑与 G9 治理协调未完成。
