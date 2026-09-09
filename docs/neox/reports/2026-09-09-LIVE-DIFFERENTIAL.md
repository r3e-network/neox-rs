# 2026-09-09 活体差分验证（G5/G6/G7 同步面）

- 日期：2026-09-09（两轮：12:19Z 首跑，12:26–12:32Z 带显式端点复跑）
- 性质：在活体基础设施上的 RPC 差分与同步验证，取代此前 G5/G6 的 BLOCKED 判定
- 结论速览：**G5 PASS（tip 全覆盖 40 检查 0 mismatch）**；**G6 采样 PASS（7 个历史高度 0 mismatch，其中 2 个高度含执行级交易/回执比对）**；G7 同步面证据完成（head 与参考对齐、`eth_syncing=false`），重启一致性仍欠

## 1. 基础设施

| 角色 | 端点/标识 | 说明 |
|---|---|---|
| 本地节点 | `http://127.0.0.1:18545`（PID 51028，neox-rs） | 宿主 WSL 内运行；Windows 进程表查不到 cmdline（已知限制） |
| 参考 Geth | `https://mainnet-1.rpc.banelabs.org` | Neo X 主网 canonical Geth 公共 RPC，即 [OPERATIONS.md](../../OPERATIONS.md) 差分门禁运行手册指定端点（亦为 9-07 G5 高度 0 运行所用端点） |
| 链 | chainId `0xba93`（47763，Neo X 主网） | 双方在每轮差分中经 `eth_chainId` 比对一致（含于 37 基础检查） |
| 运行环境 | `NO_PROXY=127.0.0.1,localhost`（本地直连）；参考端点经系统代理 | 沿用 2026-07-24 验证报告同款约束 |

## 2. 方法

`scripts/neox-rpc-differential.py`（每轮输出机器可读 JSON，全部落盘）：

- 基础 37 检查 = 区块头字段集（`eth_getBlockByNumber` 双端逐字段）+ `eth_chainId` + Policy 合约 5 个存储槽（`eth_getStorageAt`）+ 系统合约 `eth_getCode`。
- head 对齐（skew=0）时追加 3 个 head-only Policy 方法：`eth_gasPrice`、`eth_envelopeFee`、`eth_maxEnvelopeGas`（合计 40）。
- `--check-execution` 时对区块内每笔交易比对 `eth_getTransactionByHash` 与 `eth_getTransactionReceipt` 全字段。
- 判定：任一 mismatch → rc=1；端点错误 → rc=2；全绿 rc=0。

首跑（12:19Z）命令未随日志记录端点（证据瑕疵）；复跑（12:26–12:32Z）将端点与命令行显式写入日志头。两轮结论一致，以下仅引复跑数字。

## 3. 结果（复跑轮，日志 `outputs/g5-g6-differential-20260909-run2.log`）

| # | 时刻(UTC) | 检查高度 | skew | 检查数 | 执行级交易 | mismatch | rc |
|---|---|---|---|---|---|---|---|
| 1 | 12:26:54 | tip (0x74d858) | 1 | 37 | 0 | **0** | 0 |
| 2 | 12:27:10 | 7,650,000 | 0 | 37 | 0 | **0** | 0 |
| 3 | 12:27:26 | 7,630,000 | 0 | 37 | 0 | **0** | 0 |
| 4 | 12:27:42 | 3,749,760 | 0 | 37 | 0 | **0** | 0 |
| 5 | 12:27:58 | 3,623,040 | 0 | 37 | 0 | **0** | 0 |
| 6 | 12:28:14 | 0 (genesis) | 0 | 37 | 0 | **0** | 0 |
| 7 | 12:28:30 | 7,630,000（空块，exec 模式） | 0 | 37 | 0 | **0** | 0 |
| 8 | 12:30:45 | 7,654,800 | 1 | 71 | 1 | **0** | 0 |
| 9 | 12:31:14 | 7,654,000 | 0 | 139 | 3 | **0** | 0 |
| 10 | 12:32:40 | **tip（head 对齐）** (0x74d87f) | 0 | **40** | 0 | **0** | 0 |

- 首跑轮（12:19Z，`outputs/g5-g6-differential-20260909.log`）独立复核：tip 40 检查 + 5 个采样高度全部 0 mismatch。
- 两次运行合计：tip 差分 ×4、历史采样高度 ×7（两轮）、执行级交易 ×4（3+1 笔，交易+回执全字段）。**全部 0 mismatch。**
- 运行期间本地 head 与参考 head 持续同追（skew 0–1，1 秒出块下的正常抖动）；`eth_syncing` 返回 `false`。
- #10 为**全覆盖**轮：head 对齐且 `skipped: []`，包含全部基础检查 + 3 个 head-only Policy 方法，40/40 一致。

## 4. 与既有证据的关系

- 9-07 报告 G5（高度 0，37 检查）与 G5b（genesis hash 双端一致）当时已 PASS；本次把差分面从「创世单点」扩展到「tip 全覆盖 + 7 个历史采样 + 执行级抽样」，且是在节点完成全量同步之后。
- 执行级覆盖为**抽样**（4 笔），不替代 `scripts/neox-full-differential.py` 全历史门禁（该门禁此前已对 368,040 笔交易全量通过，见 CHANGELOG；如需对当前节点状态重放全量门禁，属后续可选动作）。
- 参考 Geth 为公共 RPC（banelabs mainnet-1），非本仓管控；其可用性/限流不受控（本轮出现一次瞬时代理 502，重试即过）。

## 5. G7 / G8 现状

- **G7 同步面**：节点已同步至与参考 head 相等（多轮 skew=0），`eth_syncing=false`，tip 差分 0 mismatch。**缺**：重启一致性证据——节点进程在 WSL 内，启动命令尚未捕获，需确认重启后 head 不回退再关闭 G7。
- **G8**：2026-09-10 核实后前置已齐——DKG prover 二进制存在（WSL `~/.neox-rs/bin/neox-dkg-prover`），六件 ZK ceremony 工件已下载至 `neox-geth/privnet/zk/`（`r1cs/R1CS_{1,2,7}`+`provingkey/PK_{1,2,7}`，字节数与源站 Content-Length 逐一吻合），`privnet/zk` 九节点拓扑含 antimev-keystore。原「缺 prover/ZK 工件」判定**过重**，正式更正；剩余为实际运行混合 epoch。

## 6. 判定

| Gate | 本轮判定 |
|---|---|
| G5 RPC differential | **PASS（活体）**——tip 全覆盖 40 检查 0 mismatch，双轮独立复核一致 |
| G6 Full historical differential | **PASS（活体采样）**——7 个历史高度 0 mismatch（含 genesis 与两个执行级高度）；全量 368k 门禁此前已通过，本轮为采样级活体复核 |
| G7 Fresh sync/restart | **IN PROGRESS**——同步面证据完成；待重启一致性 |
| G8 Mixed-client DKG epoch | **BLOCKED**（前置未变） |

不改变总审计口径：本轮把「活体验证缺失」的最大空白（G5/G6）补为有证据的 PASS，但 100% 协议等价仍不宣称——G7 重启一致性与 G8 混合客户端 epoch 仍未完成。
