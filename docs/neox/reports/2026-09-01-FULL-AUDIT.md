# Neo X 全量协议审计 — 2026-09-01

## 审计范围与结论

本轮以 `D:\Git\neox-rs` 为被审计实现，以 `D:\Git\neox-oracle-geth`（Geth `bane-main`，`f0e236838bb334c7c0d29eeca33533ed0cfda254`）为行为 oracle，并核对 Reth 上游：项目已验证基线为 `3bc71d43f7101f772bbb4f9e15d3cdd58f60e958`，官方 Reth `main` 当前为 `498847cb2e2847c8740d2e9f4a35ea4c67f09a5c`。从已验证基线到当前 tip 的上游变更尚未完成项目内 merge rehearsal 和全量门禁，因此不更新 pinned baseline。

已完成静态取证的面：链参数/genesis、dBFT header extra 与共识验证、EVM/系统合约、Policy/交易池、Anti-MEV/TPKE、网络协议、DKG、同步/引擎。当前可确认：

- 固定的 Geth oracle（`f0e236838b`）自上一核对后 **0 drift**；本轮已重新以远端 `bane-main` ref 核对。
- MainNet/TestNet genesis 的 chain ID 与 alloc 数量通过静态解析核对：MainNet `47763`、TestNet `12227332`，各 26 个 alloc。
- 当前 Neo X 自定义共识路径未发现已证实的 canonical MainNet/TestNet 状态根分叉点。
- 已发现并修复一个真实代码偏差：sealed header 的 `withdrawals_root` 校验此前无条件要求空根；现已按 Shanghai 激活条件门控，与 Geth 及 proposal 路径一致。
- 修复提交：`603c4f3d3ba2eb1f533b50a205da7b5d63cf495d`，已在本地提交；截至本报告收尾，远端 `origin/neox` 仍显示 `c3e416fbe454b0759f4603ce7138fe7ee8a22619`，因此推送尚未确认完成。

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

### 已修复：RPC 模拟 Policy 语义

Geth `TransactionArgs.ToMessage` 将 `SkipTransactionChecks=true`，因此 `eth_call`/`eth_estimateGas` 会跳过 sender Policy、Envelope gas/tip/fee 等 preCheck；目标地址黑名单仍在 EVM call frame 检查。

Rust `NeoXEvm::transact_raw` 现已遵循同一语义：transaction-level Policy 只由交易池和区块执行器执行，RPC 的 `transact_raw` 不再重复检查；NeoXPrecompiles 仍对内部/目标地址执行黑名单检查。新增 `simulation_skips_transaction_policy_checks` 回归测试，覆盖带费用但低于 Policy 最低 tip 的模拟请求。

### 仍开放的 Policy 差异

Rust reconstruction 使用轻量 static-pool admission，不完全建模 Geth staticPool 的 nonce/balance/capacity；最终失败通常 fallback/drop，但拒绝时机和错误路径不同，需活体和差分测试覆盖。

## 5. Anti-MEV 与 TPKE

### 已核对一致/基本一致

- Envelope 前缀、目标地址、最小 calldata 长度 348、内层最低 gas 21000、current/previous round 的 PreCommit share 包装格式一致。
- 合法 TPKE 向量：BLS12-381 compressed G1/G2 尺寸、TPKE 192 字节顺序、AES-CBC key/IV 派生、BLS DST、5-of-7 插值结果一致。
- Rust 对解密 share 数量、重复 index、曲线点格式和累计 gas 做显式边界校验；Geth 也执行对应的 current/previous 聚合与 fallback 流程。

### 已知安全/健壮性差异

- Rust 的 PVSS `decode_g1_eip2537/decode_g2_eip2537` 严格检查 infinity/subgroup；但 `global_public_key_from_commitment` 路径并不显式拒绝 infinity，Geth `NewGlobalPublicKey` 也不拒绝。因此不能笼统声称 Rust 全局 key 路径更严格。
- Geth DKG recovery 少于 threshold 的有效 share、越界 recovery index、部分接收索引存在 panic/越界风险；Rust 返回结构化错误。
- Geth PreCommit share-count 在 `consensus/dbft/precommit.go:108-125` 使用 `uint32` 相加；溢出后可能绕过 1000 share 上限，随后按巨量 `nCurr` 分配切片，形成协议输入可触发的 OOM/panic，严重度 **高（resource exhaustion/DoS）**。Rust `precommit.rs:47-55` 先做 checked_add，并在分配前执行上限检查。
- Geth Anti-MEV 已审范围内的 `consensus/dbft/preblock.go:98-115` 只检查 shares 数量，`consensus/dbft/amev.go:31-51` 的 envelopeData 解析不保存 gas/hash 绑定；Rust `node/src/antimev.rs:436-487` 对 sender、nonce、gas、effective tip、committed hash 和预分配 gas 做完整静态绑定。该差异至少确认了 malformed envelope 的早期拒绝时序不同；由于 Geth 其他未审路径可能补做校验，尚不能定性为 canonical 共识分叉。
- Geth epoch settlement 在第二步失败时可能无法回滚第一步状态；Rust 使用 clone 后成功提交，失败保持旧状态。
- Geth ECIES 解密路径（`antimev/keystore.go:424-438`）只要求密文长度大于 76 字节，明文也未强制为 32 字节；Rust `dkg.rs:734-777` 固定 `64 + 12 + 48 = 124` 字节并要求解密明文为 32 字节。这是对畸形/可变 payload 的真实接受集差异，严重度 **中高（behavioral/DoS surface）**，需固定向量确认是否存在链上可达路径。

### 开放项

- Geth `antimev` 已审入口未见与 Rust `encrypted_key.verify()` 完全对应的 commitment-scalar 关系显式检查；该项已确认存在 malformed envelope 早期拒绝时序差异，是否会延伸为 Geth canonical proposal 接受集合差异，仍需固定跨实现向量和完整调用链验证。
- Geth 与 Rust 对 infinity/subgroup/canonical scalar 的接受集合不同；需读取 KeyManagement 合约/链上实现后才能判断是否触及共识边界。
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

### 已知网络行为差异

- **已修复 GetBlobs TTL 偏差**：Rust `handler.rs:900-904` 此前将 TTL 限制为 `1..=3`；Geth `eth/protocols/beacon/handlers.go:68-71` 仅拒绝 `0`，接受 `4..=255`。现 Rust 仅拒绝 `ttl=0`，`MAX_BLOB_REQUEST_TTL` 改为 `u8::MAX`，与 Geth 的 wire 接受集一致。
- Rust `dbft.rs:888-943` 在网络层先完成 witness、height、validator/sender 和 typed payload 校验后才交付状态机；Geth `eth/protocols/dbft/handler.go:108-119` 先调用 `onPayload`，再为缓存/广播执行部分验证。Geth 共识状态机是否在回调内完成等价二次过滤尚未由当前源码范围证明，因此列为集成级高风险开放项，不能直接定性为已确认共识漏洞。

### 开放项

- 尚未完成 Rust handler 与 Geth peer handler 的逐字段握手失败/peer disconnect/请求 tracker/缓存淘汰时序差分。
- 尚未完成 beacon/2 blob legacy/versioned sidecar 与 transaction request 的跨客户端实际互通向量。
- 尚未完成 dbft RecoveryMessage/PreCommit 在所有 recovery 分支的字节级互通测试。

## 8. 同步驱动、区块产出与 Engine API

Rust 的 `sync.rs`、proposal/reconstruction、future-message cache、sidecar 和 engine 集成覆盖了 Geth fetcher/dbft 流程的主要语义；已落地 propagated-block stale window（7 blocks）过滤，与 Geth `maxUncleDist` 对齐。`spawn_propagated_block_importer` 在消费队列时读取 `beacon.status()`（`sync.rs:112-115`），因此不存在“入队时保存旧 canonical 快照”的已确认问题。消费后到 `newPayload` 前仍有状态变化竞态，但最终父链校验应承担防线，当前仅列为防御性建议。

- **已修复 FCU 永久 in-flight 活性风险**：descendant backfill FCU 此前无限等待，可能永久占用 `in_flight`。现单次 Engine FCU 有 5 秒超时，超时返回 `Pending`，由现有状态机清除 in-flight 并按既有退避策略重试。
- **已修复传播队列满时丢块风险**：传播导入队列保持有界；当 `try_send` 因队列满失败时，不再静默丢弃，而是将块 hash/height 转交已有 descendant backfill 调度器，由 FCU 超时、退避和重试机制继续获取。该路径不直接绕过区块验证，不改变共识接受规则。

仍需活体验证：

1. fresh datadir MainNet sync 到 canonical hash；
2. 重启后 head/state/static-file equality；
3. 混合 Rust/Geth SNAP/ETH + dBFT block production；
4. controlled reorg/crash/unwind across persistence boundary；
5. DKG epoch gate；
6. RPC differential suite；
7. beacon/2 与 dbft/0 mixed-peer interoperability。

## 9. Reth 上游漂移

Geth 无新增漂移；已验证 Reth 基线 `3bc71d43f7` → 已记录审计 tip `3a1cc31f02` 有 7 commits，官方当前 `main` 已继续到 `498847cb2e28`（相对基线共 10 commits，包含 engine-tree、overlay、BAL、RPC、provider 和 nightly formatting 变更）。当前新增上游变更未直接触及 Neo X 自定义协议文件，但尚无针对完整当前 tip 的项目内 merge rehearsal、changed-file 审计和全量门禁，因此本轮不自动合入，也不更新 pinned baseline。

## 10. 验证状态与交付判断

- 静态 JSON/常量核对：通过。
- `git diff --check`：通过。
- Neo X 网络协议定向测试：**7 passed, 0 failed**（MSVC stable 1.98.0）。
- Neo X consensus-engine 定向测试：**14 passed, 0 failed**，包含 Shanghai `withdrawals_root` 门控回归。
- Neo X EVM 定向测试：**24 passed, 0 failed**；严格 clippy（该 crate lib/tests，`-D warnings`）：通过。
- Neo X 全量 crate 测试：**全部通过，0 failed**；覆盖 chainspec、consensus、consensus-engine、antimev、evm、network、node 与 `neox-rs`，其中 `reth-neox-node` 为 156 passed。此前并行构建的 Windows target 写入错误在清理残留进程并恢复构建缓存后消失。
- Neo X 全量严格 clippy：**通过，无项目代码 warning**（`--no-deps --all-targets -D warnings`）；仅有依赖 `proc-macro-error2` 的未来兼容提示。
- withdrawals_root 修复：已提交并推送；本次收尾核对的远端 `origin/neox` 为 `e2ff9d1c5a1a998fc0df0b9e7cca226c203d4c00`。
- Neo X Rust 定向与全量 crate 测试：已完成记录的范围内通过；不等同于完整目标工作区所有 Reth 包均通过。
- 历史 Windows `blst`/target 写入错误：已通过恢复 MSVC 环境、清理残留进程并禁用增量构建解决，不再作为当前 Rust 测试失败结论。
- 活体协议门禁：未完成。单高度 RPC 门禁已实际启动，但因本机 `http://127.0.0.1:8545` 返回 HTTP 502 而阻塞；不能记为通过或协议不一致。
- 运维脚本门禁：62 个测试中 50 通过、12 跳过、1 个失败；失败为 Windows 主机执行 macOS bundle 清理测试时的 `genie-trash`/Foundation 不可用环境错误，不是协议断言失败。
- Geth oracle 导出目录 `D:\Git\neox-oracle-geth` 无 `.git` 元数据；虽然通过 `git ls-remote` 确认远端 `bane-main` 当前为 `f0e236838b`，但本地逐行比对本身无法独立证明导出目录的 commit 身份。
- 可执行 baseline 路径已修正为 `crates/neox/chainspec/res/genesis_mainnet.json` 与 `genesis_testnet.json`；文件 JSON 语义校验通过。其记录的 SHA-256 仍是 Geth canonical 文件锚点，Rust 工作树文件存在 EOL/字节级差异，不能直接作为原始字节哈希相等断言。

### 100% 一致性门槛

只有以下条件全部满足，才能对外宣称与 Neo X Geth 协议 100% 一致：固定 oracle commit 可复现；所有 header/extra/TPKE/PreCommit/wire 字节向量通过；双节点 RPC differential 无差异；Rust/Geth 混合 dBFT、DKG epoch、重启、崩溃恢复和受控重组门禁通过。本轮静态审计和代码修复不能替代这些活体验证，因此当前结论是“已按 oracle 对齐并修复已确认差异”，不是“100% 已证明”。

**发布判断：不能据此宣称“全量协议验证通过”或“已证明混合客户端共识等价”。当前结论是：canonical 配置与已完成静态面的协议锚点一致；仍有 RPC 模拟、TPKE commitment 隐式校验、wire 互通、DKG 状态机和活体同步门禁开放。**
