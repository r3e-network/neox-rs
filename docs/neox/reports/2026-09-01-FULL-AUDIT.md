# Neo X 全量协议审计 — 2026-09-01

## 审计范围与结论

本轮以 `D:\Git\neox-rs` 为被审计实现，以 `D:\Git\neox-oracle-geth`（Geth `bane-main`，`f0e236838bb334c7c0d29eeca33533ed0cfda254`）为行为 oracle，并核对 Reth 上游：项目基线为 `3bc71d43f7101f772bbb4f9e15d3cdd58f60e958`，Reth 当前 `main` 已漂移至 `3a1cc31f02060e8689f06b5247eeaac296a55aeb`。

已完成静态取证的面：链参数/genesis、dBFT header extra 与共识验证、EVM/系统合约、Policy/交易池、Anti-MEV/TPKE、网络协议、DKG、同步/引擎。当前可确认：

- Geth oracle 自上一基线后 **0 drift**。
- MainNet/TestNet genesis 的 chain ID 与 alloc 数量通过静态解析核对：MainNet `47763`、TestNet `12227332`，各 26 个 alloc。
- 当前 Neo X 自定义共识路径未发现已证实的 canonical MainNet/TestNet 状态根分叉点。
- 已发现并修复一个真实代码偏差：sealed header 的 `withdrawals_root` 校验此前无条件要求空根；现已按 Shanghai 激活条件门控，与 Geth 及 proposal 路径一致。
- 修复提交：`603c4f3d3ba2eb1f533b50a205da7b5d63cf495d`，已推送到 `origin/neox`。

## 1. 链参数、genesis 与硬分叉

### 已核对一致

- chain ID：MainNet `47763`，TestNet `12227332`。
- Neo X 分叉高度：MainNet DKG `3623040`、Anti-MEV/EthSig `3749760`；TestNet DKG `1990080`、Anti-MEV `2088000`、EthSig `3750000`。
- Shanghai/Cancun/Prague/Osaka 时间戳、blob schedule、gas limit、dBFT block period（5 秒）、coinbase、standby validators、genesis extra/mixHash 语义一致。
- Genesis alloc 两侧均为 26 个账户，字段语义一致；Rust 文件尾部 EOL 导致原始 SHA-256 与 oracle 文件字节哈希不同，但 JSON 语义一致。

### 已知差异

1. Rust 对自定义委员会限制 `1..=256`，Geth 仅拒绝空委员会。仅影响畸形/自定义 genesis，canonical 网络不可达。
2. Rust 的 Neo X 分叉条件未显式与 London 取合取，且缺少 Geth 的 fork-order 检查；仅影响非 canonical 畸形配置。
3. Rust genesis 文件与 baseline 的 Geth SHA-256 锚点存在 EOL 字节差异；无共识影响，但应增加规范化哈希 CI 自检。

## 2. dBFT header extra 与共识验证

### 已核对一致

- V0 ECDSA 长度 466；V1/V2 ECDSA 长度 499；V1/V2 threshold 长度 178。
- 字段顺序、阈值签名长度、BLS DST、next-consensus 承诺、seal hash、签名者排序/单调合并、法定人数公式一致。
- difficulty 1/2、primary、nonce、时间戳单调性、gas limit、base fee 非 EIP-1559 计算、coinbase、ommers 禁止规则一致。

### 已修复

`crates/neox/consensus-engine/src/lib.rs`：sealed header 现在仅在 Shanghai 激活后要求 `Some(EMPTY_ROOT_HASH)`；激活前要求 `None`。新增 `withdrawals_root_is_gated_by_shanghai_activation` 回归测试。

### 保留的低概率/防御性差异

- Rust 仅接受 ECDSA recovery id 0/1，Geth 接受至多 3；2/3 需要极低概率的 secp256k1 非标准恢复情形。
- Rust 对 threshold infinity/subgroup、零地址和重复验证者更严格；这些输入需要父区块已承诺恶意验证者集合，属于停链式而非外部可达分叉面。
- 未密封 proposal 的 extra 长度 Rust 早拒，Geth 可能延迟到 sealed block 再拒；最终区块有效性集合一致。

## 3. EVM 与 Neo X 系统合约

### 已核对一致

- 11 个系统合约地址一致，包含 PolicyProxy、GovernanceRewardProxy、KeyManagementProxy 等。
- Policy slot 1/2/3/5/6/7、Solidity mapping key 推导一致。
- `onPersist` / `onPersistV2` selector、调用顺序、SYSTEM_ADDRESS、失败处理和状态提交语义一致。
- DKG 后预编译/MCOPY 与 Geth 的 Neo X EVM 配置语义一致。

### 已排除误报

先前基于 revm 43.0.0 的 system-call gas limit 差异不适用于当前树：当前 Cargo.lock 锁定 `revm-handler 42.0.1`，其 `SYSTEM_CALL_GAS_LIMIT` 同样为 `30_000_000`。

### 开放项

- Osaka modexp EIP-7823/7883 的 gas 表尚未逐项与 Geth 计算实现做独立向量验证。
- revm system-call 对 callee 的 EIP-2929 warm 状态尚未完成独立确认。

## 4. Policy、交易池与 RPC

### 已核对一致

- sender 黑名单、内部 call target 黑名单、minGasTipCap、baseFee、envelopeFee、maxEnvelopeGasLimit、maxEnvelopesPerBlock 的存储槽和区块执行核心规则一致。
- Envelope 识别均排除 Blob 与 EIP-7702；Envelope 外层/内层 gas、tip、费用叠加和 fallback 语义基本一致。
- Rust proposal pool admission 与 Geth staticPool 的最终拒绝目标一致。

### 重要开放差异：RPC 模拟

Geth `TransactionArgs.ToMessage` 将 `SkipTransactionChecks=true`，因此 `eth_call`/`eth_estimateGas` 会跳过 sender Policy、Envelope gas/tip/fee 等 preCheck；目标地址黑名单仍在 EVM call frame 检查。

Rust `NeoXEvm::transact_raw` 在满足 fee-policy gate 时调用 `validate_policy`。因此带正常费用字段的 RPC 模拟可能出现：Geth 成功，Rust 拒绝。该差异不影响已执行区块，但属于可见 behavioral/RPC 偏差。当前未修改，需先决定是否准确复刻 Geth 的 `SkipTransactionChecks` 语义并补 RPC 回归测试。

另有一个架构差异：Rust reconstruction 使用轻量 static-pool admission，不完全建模 Geth staticPool 的 nonce/balance/capacity；最终失败通常 fallback/drop，但拒绝时机和错误路径不同，需活体和差分测试覆盖。

## 5. Anti-MEV 与 TPKE

### 已核对一致/基本一致

- Envelope 前缀、目标地址、最小 calldata 长度 348、内层最低 gas 21000、current/previous round 的 PreCommit share 包装格式一致。
- Rust 对解密 share 数量、重复 index、曲线点格式和累计 gas 做显式边界校验；Geth 也执行对应的 current/previous 聚合与 fallback 流程。

### 开放项

- Geth `antimev` 路径中未见与 Rust `encrypted_key.verify()` 完全对应的 commitment-scalar 关系显式检查；尚未确认 `FromBytes` 是否隐式完成该验证。此项可能影响 malformed ciphertext 的 proposal 可见性，优先级高于普通行为差异。
- 需要跨实现固定向量：有效 envelope、错误 commitment、错误 round、share 不足、current/previous 混合和 fallback。

## 6. DKG 委员会与密钥生命周期

Rust 已具备 DKG epoch、PVSS、recovery、keystore、canonical replay/store 等完整模块；Geth 的 dBFT 状态机和部分 DKG 逻辑依赖外部 `nspcc-dev/dbft`，oracle 仓库未 vendor 该依赖。

未能从仓库静态完成的项目：

- 外部 dbft 库的 M()/视图/超时/recovery 内部语义与 Rust 状态机的逐字段等价性。
- Geth 与 Rust DKG epoch 边界、committee pending/active 切换、PVSS/R1CS proof 生命周期的完整活体等价性。
- keystore 加密参数、跨重启恢复、旧 round 清理与异常恢复的端到端一致性。

这些不是已确认 bug；在没有混合客户端 DKG epoch gate 前，不应宣称 DKG parity 已证明。

## 7. BEACON/2、dBFT wire protocol

### 已核对的静态锚点

- `beacon/1` 与 `beacon/2` capability 名称、版本号、消息数量：分别 8 与 10。
- Status、NewBlockHashes、NewBlock、blob 及 beacon/2 transaction request/response 的 message ID 与 RLP 结构存在对应实现。
- `dbft/0` 消息编号 Announce `0x00`、Get `0x01`、Message `0x02`，最大消息 4 MiB；beacon 最大消息 10 MiB。

### 开放项

- 尚未完成 Rust handler 与 Geth peer handler 的逐字段握手失败/peer disconnect/请求 tracker/缓存淘汰时序差分。
- 尚未完成 beacon/2 blob legacy/versioned sidecar 与 transaction request 的跨客户端实际互通向量。
- 尚未完成 dbft RecoveryMessage/PreCommit 在所有 recovery 分支的字节级互通测试。

## 8. 同步驱动、区块产出与 Engine API

Rust 的 `sync.rs`、proposal/reconstruction、future-message cache、sidecar 和 engine 集成覆盖了 Geth fetcher/dbft 流程的主要语义；已落地 propagated-block stale window（7 blocks）过滤，与 Geth `maxUncleDist` 对齐。`spawn_propagated_block_importer` 在消费队列时读取 `beacon.status()`（`sync.rs:112-115`），因此不存在“入队时保存旧 canonical 快照”的已确认问题。消费后到 `newPayload` 前仍有状态变化竞态，但最终父链校验应承担防线，当前仅列为防御性建议。

仍需活体验证：

1. fresh datadir MainNet sync 到 canonical hash；
2. 重启后 head/state/static-file equality；
3. 混合 Rust/Geth SNAP/ETH + dBFT block production；
4. controlled reorg/crash/unwind across persistence boundary；
5. DKG epoch gate；
6. RPC differential suite；
7. beacon/2 与 dbft/0 mixed-peer interoperability。

## 9. Reth 上游漂移

Geth 无新增漂移；Reth `3bc71d43f7` → `3a1cc31f02` 新增 7 commits，涉及 engine-tree、overlay、BAL、RPC、provider 和 nightly formatting。当前差异未直接触及 Neo X 自定义协议文件，因此本轮不自动合入。建议单独进行 Reth tip sync rehearsal，并重新跑 Windows storage/provider 与 Neo X 全量门禁。

## 10. 验证状态与交付判断

- 静态 JSON/常量核对：通过。
- `git diff --check`：通过。
- withdrawals_root 修复：已提交并推送。
- 目标 Rust 测试：未完成。Windows `blst` 编译阶段出现 `C1056`，无法更新 `target` 下对象时间戳；这是宿主 target 文件系统/权限问题，不能记为测试通过。
- 活体协议门禁：未完成。

**发布判断：不能据此宣称“全量协议验证通过”或“已证明混合客户端共识等价”。当前结论是：canonical 配置与已完成静态面的协议锚点一致；仍有 RPC 模拟、TPKE commitment 隐式校验、wire 互通、DKG 状态机和活体同步门禁开放。**
