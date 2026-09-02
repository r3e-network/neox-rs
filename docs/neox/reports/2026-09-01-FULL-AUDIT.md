# Neo X 全量协议审计 — 2026-09-01

## 审计范围与结论

本轮以 `D:\Git\neox-rs` 为被审计实现，以 `D:\Git\neox-oracle-geth`（Geth `bane-main`，`f0e236838bb334c7c0d29eeca33533ed0cfda254`）为行为 oracle，并核对 Reth 上游：项目已验证基线为 `3bc71d43f7101f772bbb4f9e15d3cdd58f60e958`。审计过程中记录的 Reth `main` 历史 tip 为 `498847cb2e2847c8740d2e9f4a35ea4c67f09a5c`、`3c31377d6533f4298739dbb4ab6c371a8d5b3eb6`；截至 2026-09-02 核验，远端实时 `main` 已前进至 `0b3475a83e0712beb3d1f639ea467c55c5117412`，该 tip 已获取到 `refs/audit/reth-main-20260902`；相对前一 tip 新增 4 个提交、12 个文件（483 insertions / 156 deletions）。以临时 merge commit `2859683d9532c92345bca69474f187e3c4a1de5b` 完成无冲突合并演练，并在合并树中通过 Neo X 四个核心 crate 回归与严格 clippy；受影响 workspace 的 `reth-engine-tree` 持久化重组测试仍失败，完整 workspace/live 门禁尚未通过，因此不更新 pinned baseline。

已完成静态取证的面：链参数/genesis、dBFT header extra 与共识验证、EVM/系统合约、Policy/交易池、Anti-MEV/TPKE、网络协议、DKG、同步/引擎。当前可确认：

- 固定的 Geth oracle（`f0e236838b`）自上一核对后 **0 drift**；本轮已重新以远端 `bane-main` ref 核对。
- MainNet/TestNet genesis 的 chain ID 与 alloc 数量通过静态解析核对：MainNet `47763`、TestNet `12227332`，各 26 个 alloc。
- 当前 Neo X 自定义共识路径未发现已证实的 canonical MainNet/TestNet 状态根分叉点。
- 已发现并修复一个真实代码偏差：sealed header 的 `withdrawals_root` 校验此前无条件要求空根；现已按 Shanghai 激活条件门控，与 Geth 及 proposal 路径一致。
- 已确认的代码修复均已提交并推送；本轮新增的 Reth tip 审计证据仍待本次文档提交完成后推送。

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

- Rust 已新增 Osaka modexp EIP-7823/7883 的最低 gas、1024-byte 上限、33-byte complexity 和真实预编译地址回归测试；仍需与 Geth 做独立跨实现向量验证。
- Rust 已新增 system-call 内重复 `SLOAD` warm、以及 warm 状态不泄漏到后续普通交易的 gas 回归测试；仍需与 Geth 做独立 gas-observable differential。

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

- ~~Geth `antimev` 已审入口未见与 Rust `encrypted_key.verify()` 完全对应的 commitment-scalar 关系显式检查~~
  **2026-09-02 关闭并升级为确证分歧**：检查确实"存在"于 `crypto/tpke/encryption.go:77`
  （`CipherText.Verify()`），但**全树零非测试调用点**。含完整调用链与两侧可执行证明，
  见第 5.1 节。后果为**活性停滞**而非状态分叉（5.1 节内含对我早先"链分裂"判断的更正）。
- Geth 与 Rust 对 infinity/subgroup/canonical scalar 的接受集合不同；需读取 KeyManagement 合约/链上实现后才能判断是否触及共识边界。
- 需要跨实现固定向量：有效 envelope、错误 commitment、错误 round、share 不足、current/previous 混合和 fallback。
  - **2026-09-02 关闭**：有效 envelope、错误 commitment、share 不足、错误 round 的字段解析
    已由离线跨实现向量验证；**current/previous 混合与 fallback（reshare）同日关闭**
    （密码学层，见下方补充第 3.4 节）；**调度层（在何高度触发 `OnEpochChange`）同日关闭**
    （静态分析 + 单元测试，见第 6.1 节）；**Envelope 轮次过滤器接受集同日关闭**
    （两侧表驱动测试，见第 5.2 节）。
  - **仍未覆盖**：链上 KeyManagement 契约对 `lastRoundCmt` 提交权限与错误 round 罚没的
    实际判定——需链上/合约层审计，本机无节点，本轮无法执行。

#### 2026-09-02 补充：Anti-MEV 跨实现向量验证

在参考客户端（`bane-labs/go-ethereum` 基准提交 `f0e236838bb334c7c0d29eeca33533ed0cfda254`）
的 `antimev` 包内**新增**导出器（未修改任何既有文件），重放其 7 节点 / 5 门限 privnet DKG 夹具
并导出全部中间值；Rust 侧新增三个集成测试做断言。结果：

- `reth-neox-antimev` 全量 **88 通过 / 0 失败**（45 原有单元 + 9 跨实现正向量 + 14 负向量
  + 16 current/previous 轮次分离向量 + 4 PKCS#7 可达性证明）；
  clippy `--all-targets --all-features` **0 警告**；nightly rustfmt 干净；**协议实现代码零改动**。
- 已验证一致：committee scaler = 360、Envelope 布局常量（348/192/48/21000/目标地址）、
  全局公钥推导、逐参与方公私钥份额、**解密份额 7/7 逐字节一致**、5-of-7 门限解密恢复相同
  AES 密钥与明文、子集无关性。
- **G2 压缩编码风险解除**：参考客户端（gnark-crypto）导出的 G2 生成元压缩编码与
  BLS12-381 的 IETF/blst 标准值逐字节相同，两种库的 G2 压缩字节序兼容。
  此项原为可致共识分叉级别的隐患。
- 关于首条开放项：参考客户端 `crypto/tpke.CipherText.Verify()` 校验
  `e(R,g2)·e(g1,C)=1`，与 Rust `TpkeCiphertext::verify()` 语义**一致**，
  该对应检查确实存在，只是位于 `crypto/tpke` 而非 `antimev` 入口。
  但两者都只校验恢复出的 `r·PK` 与密文声明的随机承诺，**不把加密消息 `M` 绑定到该证明**
  （Geth `startWorker` 注释亦明确说明）；`M` 的完整性由对称层兜底，两实现行为一致。

**新增确证分歧（PKCS#7 解填充严格性）**：参考客户端 `pkcs7UnPadding` 只拒绝「填充长度大于
缓冲区」，不校验长度落在 `1..=16`、也不校验填充字节是否重复声明值；Rust 三者均拒绝。
实测（用参考客户端自身的 AES-CBC 例程构造）：末字节 `0x00` → Geth 接受并返回 128 字节；
末字节 `0x14` → Geth 接受并返回 108 字节；声明 8 字节但内容不一致 → Geth 接受并返回 120 字节；
Rust 对三者均返回 `InvalidPkcs7Padding`。分歧方向为 **Rust 更严格**（安全加固，非本仓库缺陷）。
#### 4.1 链上可达性：已构造性证明（严重度由「中」上调为「高」）

上一版把该项记为「大概率不可达」，**该判断已被推翻**。此前假设「被污染字节后续 RLP 解码会
失败」，这只对*随机*污染成立；而填充长度与内容均由**封装方自选**
（`KeyStore.Encrypt` 自行挑选 AES 密钥点 `randPG1()` 与随机性 `r`，故完全掌握 AES 密钥，
进而完全决定 AES-CBC 明文的每个字节），无需任何委员会成员配合。

已执行的构造（Geth 侧 `TestPKCS7Reachability`，断言全通过）：

1. 一条真实签名的 EIP-1559 交易序列化为 112 字节 `tx`。
2. 追加 32 字节尾部、末字节置 `0x20`。选 32（而非 20）是为使 `112+32` 仍是 16 的倍数
   （`AESDecrypt` 要求块对齐）；中间 31 字节故意不等于 `0x20`，构成第二条独立的拒绝理由。
3. Geth 规则 `data[..len-data[len-1]]` 返回 `data[..144-32]` = **完整 `tx`**。
4. 走真实链路 `AggregateAndDecryptWithShare`：返回**非 nil**、与 `tx` 逐字节相等，
   `UnmarshalBinary` 成功，哈希与发送方均正确恢复。

```
REACHABILITY: padding=32 (Rust rejects >16), decrypted=112 bytes,
              inner tx=0x87d9ffa086c88b491f30dd663075feaf3659286979e20b64435f0a8fd9452657
```

Rust 侧对照（`geth_pkcs7_reachability.rs`，4/4）：**份额聚合成功**（证明解填充之前每一步
两实现都一致），`decrypt_message` 返回 `InvalidPkcs7Padding`；且独立验证那 112 字节是
**可解码、可往返编码、哈希自洽**的规范 EIP-2718 交易——参考客户端拿到的不是垃圾。

**为何构成共识分叉**：`consensus/dbft/dbft.go` 中，`decryptedTxsBytes[j] == nil` /
`UnmarshalBinary` 失败 / `validateDecryptedTx` 失败 → 回退为「按原样执行 Envelope」；
全部通过 → **执行解密出的内层交易**。Rust 在第 0 步（解填充）即拒绝并回退，
Geth 一路走到底执行内层交易。同一区块槽位两笔不同交易 →
收据根/状态根/区块哈希全不同 → **混合客户端网络中链分裂**。

**残余不确定性（诚实标注）**：第 1–3 步为**实际执行验证**；第 4 步
`validateDecryptedTx` 未能端到端运行（它是 `*DBFT` 方法，需完整 chain backend 与
pre-block receipt）。其比较项（nonce、发送方、`encrypted_hash`、gas）均在 Envelope
**明文**部分、由同一攻击者填写，故均可满足——这是**代码论证**，不是执行验证。

**修复方向**：要与主网保持共识，Rust 须复刻参考客户端的解填充规则（只拒绝 `n > len`，
不校验收窄到 `1..=16`、也不校验填充字节重复声明值），或推动参考客户端收紧。
**两实现对齐前，不应在混合客户端网络中运行。本轮未改动任何协议代码，风险仍在。**

严重度：**高**（实现层分歧已确证 + 链上可达性已构造性证明 + 后果为共识分叉）。

**3.4 current / previous 轮次分离与 fallback（reshare，同日关闭）**

Neo X 通过 DKG 再共享轮换 Anti-MEV 委员会。轮换后 keystore 同时持有两个密钥组：
`shared`（新组，负责当前轮）与 `reshared`（用上一轮聚合承诺重建，仍可开启轮换前的
Envelope，即 fallback）。参考客户端仅在 `OnEpochChange(..., lastRoundCmt, ...)` 的
`lastRoundCmt` 非空时构建 `reshared`。导出器按 `OnSharePeriodStart(false)` +
`DKGReshare()` + `DKGShare()` 并把第一轮聚合承诺作为 `lastRoundCmt` 回传的方式跑两轮 DKG，
一次导出两个密钥组的完整材料。

非平凡性前提（两轮必须不同，否则分离断言无意义）：

```
previous_round.global_public_key = 8f2df85bc8add14e…a7b6f75
current_round.global_public_key  = 90d2a7ea34b67eb3…0e366b86   （不同 ✅）
```

两轮聚合承诺与逐参与方私钥份额亦全不同。Rust 侧 16/16 通过，要点：

- previous 轮 Envelope 用 previous 组开启、current 轮用 current 组开启，均解密到原明文；
  换一组 5-of-7 子集结果相同。
- **跨轮组合全部被拒绝**，且拒绝发生在配对校验层（`InvalidDecryptionShares`），
  不依赖下层 AES 解填充失败：previous 密文 + current 份额、current 密文 + previous 份额、
  previous 密文 + previous 份额但用 current 全局公钥、混合两轮的 5 人法定人数（3+2）。
- fallback 路径**没有**因 resharing 放宽门限：previous 轮只给 4/5 份额同样被拒绝。
- 两轮各自 7/7 公钥份额与 7/7 解密份额逐字节一致。

**参考客户端来源已验证（含两处更正）**：本机 `D:\Git\neox-oracle-geth` 不是 git 工作副本
（无 `.git`），已拉取基准提交 `f0e2368` 做逐文件比对——按
`git ls-tree -r FETCH_HEAD -- antimev crypto/tpke` 的实际清单为
**`crypto/tpke/` 16/16、`antimev/` 既有文件 10/10、合计 26/26 逐字节相同**，
确认向量来源且未改动参考客户端协议代码。

更正一：本轮早些时候记录的「18/18、9/9」为人工统计错误，实际为 16 与 10。
更正二：早先那次比对是把 `FETCH_HEAD` 检出到工作树后再 `git diff`，而本机
`core.autocrlf=true`，`git diff` 会先把工作树的 CRLF 归一化成 LF，故那次实际是
「内容一致、行尾不比」。本次改用 `git show FETCH_HEAD:<path>` 与工作树文件逐字节比对，
确认 26/26 **逐字节**一致。（早先 `git checkout` 的副作用曾把 26 个上游文件行尾从 LF
改成 CRLF，已还原为 LF，`gofmt -l` 与 `go vet` 均干净。）

#### 5.1 新增确证分歧：参考客户端从不调用 `CipherText.Verify()`（严重度 高）

上一小节曾写「该对应检查确实存在，只是位于 `crypto/tpke` 而非 `antimev` 入口」——
这句话**在「函数已定义」的意义上成立，但在「函数被调用」的意义上不成立**，
现已用全树 grep 与可执行测试推翻。

`crypto/tpke/encryption.go:77` 定义了

```go
// Verify checks the ciphertext's commitment: e(R, g2) · e(g1, commitment) == 1
func (t *CipherText) Verify() error
```

但对 `antimev/`、`consensus/`、`core/`、`crypto/tpke/` 全树检索 `.Verify()` 的
**非测试调用点为零**。Envelope 的准入判定实际只由三道检查构成：

| 检查 | 位置 | 内容 |
| --- | --- | --- |
| `IsEnvelope` | `antimev/envelope.go:53` | 非 Blob/SetCode 类型、目标地址为 `0x1212…0003`、calldata ≥ 348 且带 `0xffffffff` 前缀 |
| `decodeEnvelopeData` → `CipherText.FromBytes` | `consensus/dbft/amev.go:31` / `crypto/tpke/encryption.go:50` | 反序列化三个曲线点（隐式满足 on-curve 与 in-subgroup），**不做配对校验** |
| txpool 校验 | `core/txpool/validation.go:227-244` | 仅 `maxEnvelopeGasLimit`、`MinEncryptedGasLimit`、Envelope gas 覆盖、Envelope fee |

Rust 侧在**两个**位置调用 `TpkeCiphertext::verify()`：交易池准入
（`NeoXPoolPolicyError::InvalidEnvelopeCiphertext`，永久拒绝）与提案解析
（`AntiMevProposalError::InvalidCiphertext`，`?` 传播为
`DbftProposalError::AntiMevProposal`，整块提案被拒）。

**已构造性证明（两侧共 8 个测试全通过）**：对合法密文的 `R` 槽做一次 `R + g1` 平移，
得到配对关系被破坏但**仍能正常反序列化**的密文。

| 侧 | 测试 | 结果 |
| --- | --- | --- |
| Geth `antimev` | `TestCiphertextAdmission` | `FromBytes` 成功、`IsEnvelope` 为 true、`Verify()` 返回 `ErrTPKECiphertext`；投入全部 7 份 share 后 `AggregateAndDecryptWithShare` 返回 `ErrDecryptionFailed`（即 C(7,5)=21 个法定组合**全部**失败）；未篡改对照样本解密逐字节一致 |
| Geth `antimev` | `TestCiphertextAdmissionTamperSanity` | 只有 `R` 槽变化，结果仍可反序列化（排除"失败源于别处"） |
| Geth `consensus/dbft` | `TestEnvelopeDecodeAcceptsUnverifiedCiphertext` | 走**真实**解析路径 `PreBlock.SetTransactions` → `decodeEnvelopeData`，两条 Envelope 均被接受，仅篡改件 `Verify()` 报错 |
| Geth `consensus/dbft` | `TestEnvelopeDecodeRejectsRoundZero` | 解析器确实会拒绝 round 0（防止"解析器什么都收"的质疑） |
| Rust `reth-neox-antimev` | `geth_ciphertext_admission.rs`（3/3） | 反序列化与参考客户端一致（故这是**校验**差异而非**解析**差异）；`verify()` 返回 `InvalidCiphertextCommitment` |
| Rust `reth-neox-node` | `pool_admission_rejects_the_envelope_the_reference_client_admits` | 交易池以 `InvalidEnvelopeCiphertext` 拒绝，且 `is_bad_transaction()` 为真（永久拒绝） |

**后果——是活性分歧，不是状态分叉（此处更正我早先的初步判断）**：
最初我判断这会造成本质链分裂，该判断**错误**。`AggregateAndDecrypt`
（`encryption.go:202`）执行的配对校验是
`e(PK, commitment)·e(rpk, g2) == 1`，与 `Verify()` 的
`e(R, g2)·e(g1, commitment) == 1` **互为等价条件**。因此**不存在**「参考客户端能解密、
Rust 拒绝」的输入——两侧在"这条 Envelope 能不能开"上判断一致，差别只在
**这条 Envelope 能不能进入区块**。真实后果是：

1. Geth 主节点把该 Envelope 收进交易池并打包。
2. `SetData` → `aggregateAndDecrypt` 配对校验失败 → `AggregateAndDecryptWithShare` 返回 error。
3. `consensus/dbft/dbft.go:1129-1141` 对 current/prev 两个桶**都** `return fmt.Errorf(...)`
   （注释写的是「wait for more shares to be collected」）。
4. `nspcc-dev/dbft@v0.3.2/check.go:79-85`：`ProcessPreBlock` 返回 error 时仅
   `return` 并等待更多 PreCommit。
5. 更多 share **永远**无法挽救（密文本身不可解，21 个法定组合已穷尽）→
   **该高度永久停滞**。

而 Rust 主节点在第 0 步就拒绝该 Envelope，根本不会打包。

严重度：**高**。触发成本极低（一次椭圆曲线点加法，无需任何委员会成员配合，
不需要掌握私钥），后果是全网出块停滞。

**修复方向**：Rust 侧不应单方面放宽（那会让网络接受不可解密的 Envelope）。
合理方向是推动参考客户端在 `decodeEnvelopeData` 或 txpool 校验中调用已有的
`Verify()`；在此之前，混合客户端网络存在单向活性风险。
**本轮未改动任何协议代码，风险仍在。**

#### 5.2 Envelope 轮次过滤器的实际接受集：两侧一致，但过滤器宽于其注释

`consensus/dbft/preblock.go:145`：

```go
if d.dkgRound < min(1, b.dkgRound-1) || b.dkgRound < d.dkgRound {
    continue
}
```

两个操作数均为 `uint32`，故 `b.dkgRound-1` 在 0 处回绕；且用的是内置 `min`
（不是 `max`），因此下界恒为 1。相邻注释写的是「not from current/previous DKG round」，
但**该谓词实际上接受任意更早轮次的 Envelope**。配合 `SetData`（`preblock.go:69-91`）
把所有非当前轮统一归入 previous 桶，以及 `aggregateAndDecrypt` 对**整批**做一次配对校验，
结论是：**一个更早轮次的不可解密 Envelope 会污染整个 previous 桶里的所有 Envelope**，
把 5.1 的单条 Envelope 停滞放大为"该桶内所有跨轮 Envelope 全部无法解密"。

两侧对照测试（均通过）：

| 侧 | 测试 | 覆盖 |
| --- | --- | --- |
| Geth | `TestEnvelopeRoundFilterAdmitsEveryEarlierRound` | 主动轮 0..=12 × Envelope 轮 1..=12 全表比对真实 `SetTransactions` 与独立书写的期望；并显式钉住"主动轮 5 时轮 1 与轮 4 都被接受" |
| Rust | `envelope_round_filter_matches_the_reference_client_bound_for_bound` | 同一张表从 `AntiMevProposal::from_transactions` 侧比对，并断言 epoch 划分（`dkg_round == active_round` 为 `Current`，否则 `Previous`） |
| Rust | `round_zero_envelopes_are_never_admitted` | 轮 0 永不准入 |

**结论：这不是共识分歧**——Rust 复刻了同一个过滤器，接受集逐项相同，
故任何一侧单独"修正"都会立刻造成网络分裂。它是**两侧共有的放大面**：
5.1 的活性风险在此被放大。因此两侧都加了表驱动测试，
使任一客户端的修改都会**测试失败**而非静默导致网络失步。

## 6. DKG 委员会与密钥生命周期

Rust 已具备 DKG epoch、PVSS、recovery、keystore、canonical replay/store 等完整模块；Geth 的 dBFT 状态机和部分 DKG 逻辑依赖外部 `nspcc-dev/dbft`，oracle 仓库未 vendor 该依赖。

#### 6.1 调度层对比：静态分析 + 单元测试（**不是**活体门禁）

本小节关闭第 5 节遗留的「在哪个高度触发 `OnEpochChange`」这一项，但**仅限静态与离线测试**，
不得计入活体验证。

**高度检查点：两侧公式逐项一致，且 Rust 侧有测试钉住。**

Geth `consensus/dbft/dkg.go:186-189`：

```go
targetHeight       := snapshot.EpochStartHeight + epochDuration
shareStartHeight   := targetHeight - 2*sharePeriodDuration
recoverStartHeight := shareStartHeight + sharePeriodDuration
recoverCheckHeight := recoverStartHeight + sharePeriodDuration/2
```

Rust `crates/neox/node/src/dkg.rs:50-72`（`DkgSchedule::new`）复刻同一组公式，
`phase_at`（`:75-87`）导出 `Idle` / `Share` / `Recover` / `ReshareRecover` / `EpochChange`。
已通过的测试：`dkg_schedule_matches_geth_checkpoint_boundaries`、
`reads_live_mainnet_governance_dkg_schedule`、`dkg_schedule_rejects_impossible_governance_timing`、
`dkg_task_watcher_waits_checks_retries_and_expires`、`checks_receipts_the_geth_oracle_confirms_blindly`、
`reads_live_testnet_round_from_raw_solidity_storage`（**6/6 通过**）。

**架构差异（非语义分歧）：Geth 是增量状态机，Rust 是幂等重放。**

| 维度 | Geth | Rust |
| --- | --- | --- |
| 驱动方式 | `handleDKG`（`dkg.go:107`）按高度增量推进，由 `dbft.go:1613 / :2171 / :2787` 调用，入口受 `c.lastIndex >= dkgEnablingHeight` 约束 | `dkg_replay.rs` 从链上 canonical 状态幂等重放（`apply_dkg_canonical_epoch:368`、`rebuild_dkg_canonical_round_inner:323`） |
| 正常 epoch 切换 | `OnEpochChange` @ `dkg.go:159`，门槛 `snapshot.initDone && currentHeight >= EpochStartHeight+epochDuration` 且 `snapshot.Round == keystore.Round()+1` | `DkgKeyStore::on_epoch_change`（`antimev/src/dkg_state.rs:454`）原子推进或回退 |
| 落后追赶 | `OnEpochChange` @ `dkg.go:253`，条件 `keystoreRound < snapshot.Round-1` | `validate_store_round`（`dkg_replay.rs:392`）：`canonical_round != store.round()+1` 直接 `RoundMismatch`，由重放兜底 |
| `lastCommitment` 来源 | epoch 路径取 `snapshot.Round-1`（`dkg.go:155`）；追赶路径取 `snapshot.Round-2`，且受 `if snapshot.Round > 2` 保护（`:247-248`） | 重放读链上 canonical 承诺；缺失时 `on_epoch_change` 返回 `MissingPreviousCommitment`（`dkg_state.rs:482`）而非静默推进 |
| 回退 | `RevertRound()` @ `dkg.go:202`（落后一轮且仍在 share 期之前）；落后超过一轮则 `Reset(round-2)` @ `:209` | `revert_round`（`dkg_state.rs:319`） |
| 重启语义 | 依赖本地 keystore 的落盘状态 | 幂等重放，**重启天然安全**（不依赖本地中间态） |

结论：两者在**检查点高度**与**推进/回退语义**上静态等价；Rust 的重放架构在重启与追赶路径上
**更严格**（Geth 的 `snapshot.Round > 2` 保护意味着 round ≤ 2 时追赶路径不读 `Round-2` 承诺，
Rust 则以显式错误拒绝）。这是 Rust 更保守的方向，不构成共识分歧。

**提交权限**：Geth 侧 `taskReshare` / `taskShare` 以是否属于 `CurrentCNs` / `PendingCNs`
为门槛，即仅委员会成员可提交。**在已读路径中未发现对错误 round 提交的罚没逻辑**——
这是"已读路径未见"，不是"全树不存在"的断言，链上 KeyManagement 合约未在本轮审计范围内。

未能从仓库静态完成的项目：

- 外部 dbft 库的 M()/视图/超时/recovery 内部语义与 Rust 状态机的逐字段等价性。
- Geth 与 Rust DKG epoch 边界、committee pending/active 切换、PVSS/R1CS proof 生命周期的完整活体等价性。
- keystore 加密参数、跨重启恢复、旧 round 清理与异常恢复的端到端一致性。

这些不是已确认 bug；在没有混合客户端 DKG epoch gate 前，不应宣称 DKG parity 已证明。

## 7. BEACON/2、dBFT wire protocol

### 已核对的静态锚点

- `beacon/1` 与 `beacon/2` capability 名称、版本号、消息数量：分别 8 与 10。
- Status、NewBlockHashes、NewBlock、blob 及 beacon/2 transaction request/response 的 message ID 与 RLP 结构存在对应实现。
- `dbft/0` 消息编号 Announce `0x00`、Get `0x01`、Message `0x02`，最大消息 4 MiB；beacon 最大消息 10 MiB。Rust typed dBFT 类型常量位于 `crates/neox/network/src/dbft.rs:76-108`：ChangeView `0x00`、PrepareRequest `0x20`、PrepareResponse `0x21`、Commit `0x30`、PreCommit `0x31`、RecoveryRequest `0x40`、RecoveryMessage `0x41`；对应 payload 的选择和校验位于 `crates/neox/network/src/dbft_payload.rs:822-850`。

### 已知网络行为差异

- **已修复 GetBlobs TTL 偏差**：Rust `handler.rs:900-904` 此前将 TTL 限制为 `1..=3`；Geth `eth/protocols/beacon/handlers.go:68-71` 仅拒绝 `0`，接受 `4..=255`。现 Rust 仅拒绝 `ttl=0`，`MAX_BLOB_REQUEST_TTL` 改为 `u8::MAX`，与 Geth 的 wire 接受集一致。
- dBFT/0 入站静态复核确认：Rust `crates/neox/network/src/dbft.rs:888-943` 在缓存和事件交付前完成 witness、height、validator/sender 及 typed payload 校验；Geth `eth/protocols/dbft/handler.go:108-119` 的入口顺序为 `decode → OnPayload → BroadcastMessage`，入口 pool 校验范围较窄。Geth 外部 `nspcc-dev/dbft` 是否在 `OnPayload` 内完成等价二次过滤，当前源码范围无法证明，因此列为集成级高风险开放项，不能直接定性为已确认共识漏洞。
- Rust `crates/neox/network/src/dbft_payload.rs` 对 Recovery payload 施加数量上限；已审 Geth dBFT/0 handler 未见直接对应的入站数量上限。该差异需要固定异常向量和混合节点验证，以判断是否仅为资源边界差异，不能直接推断为 canonical 共识分叉。

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

当前主机的活体前置条件核对结果：`neox-rs` 仓库没有独立 `privnet` fixture 或一键 dBFT/0 拓扑；Geth oracle 的 `privnet/zk` 目录缺少必要的 ceremony `.ccs`/`.pk` 文件，且本机缺少可执行 `geth.exe`、`neox-dkg-prover.exe`、`make` 及完整 Linux static ELF 环境。现有 `neox-rpc-differential.py`、`neox-full-differential.py` 和 `neox-mixed-dkg-e2e.py` 只连接已运行端点，不负责初始化节点、datadir、bootnode 或密钥。因此本轮无法执行混合 dBFT、DKG epoch 或完整 RPC live gate。

## 9. Reth 上游漂移

Geth 无新增漂移。Reth 已验证基线保持为 `3bc71d43f7`；`498847cb2e28`、`3c31377d6533`、`00d9e9e1cf65` 作为历史观察 tip 保留，远端实时 `main` 已前进至 `0b3475a83e0712beb3d1f639ea467c55c5117412`。基线到实时 tip 的本地可复现 compare 包含 19 个上游提交、68 个文件（2019 insertions / 650 deletions）；其中相对前一 tip 的增量为 4 个提交、12 个文件（483 insertions / 156 deletions）。新 tip 没有直接修改 `crates/neox`，但增加了以下间接影响面：

- `f0166c32`：engine/tree、payload processor/prewarm、state-root strategy、BlockchainProvider 和 storage-overlay 统一使用 `OverlayStateProviderFactory`；涉及 `crates/engine/tree/src/tree/*`、`crates/storage/provider/src/providers/blockchain_provider.rs` 和 `crates/storage/storage-overlay/src/{changeset_cache.rs,provider.rs}`，其中 worker/prewarm 通过 `database_provider_ro()` 创建只读视图。需验证 Neo X parent anchor、canonical/pending changeset 合并、Policy slot、DKG/Anti-MEV 状态读取、状态根、重组和重启。该项在本轮完成了通用编译与受影响包测试，但 Neo X live state-root differential 仍未执行。
- `8ead4dc9`：BAL decode failure 改为 Engine API `INVALID`，`latestValidHash = null`，涉及 `crates/engine/primitives/src/error.rs`、`crates/engine/tree/src/tree/{mod.rs,payload_validator.rs}`、`crates/rpc/rpc-engine-api/src/error.rs`，并同步更新 `crates/ethereum/node/tests/e2e/invalid_payload.rs`。Neo X `crates/neox/node/src/engine.rs` 直接委托 Ethereum validator；未来 Amsterdam 激活前后需验证 malformed BAL、V5/V6 及自定义 header/extra 包装路径。
- `931c9c71`：`crates/rpc/rpc-eth-api/src/helpers/estimate.rs` 的 basic-transfer shortcut 改为依据 `db.basic(to)` 和实际 `tx_gas_used()`，不再固定返回 21000。Neo X 需覆盖 StateOverride、value/fresh recipient、fork 边界、Envelope，以及 RPC 跳过 transaction-level Policy 但保留 call-frame target blacklist 的语义。
- `1e9a9438`：`crates/rpc/rpc/src/eth/filter.rs` 对 `fromBlock > head` 从空结果改为 JSON-RPC `-32602`。Neo X 需覆盖 `head`、`head+1`、`latest`、`to < from`、head/reorg 变化和 block-hash filter。
- `9d315f28`：engine tree 为下载区块获取 BAL；`0b3475a8`：下载/执行错误日志补充 bad block hash；两者保持 Neo X 的 `block_access_list_hash` 验证入口不变，但需活体验证 BAL 下载、缺失/畸形 BAL 与 Engine `INVALID` 返回。
- `98120568`：在 `OverlayStateProvider` 实现 multiproof v2；该变化直接触及 Neo X 状态根、Policy slot、DKG/Anti-MEV 读取与重组一致性，当前只完成编译和通用单元测试，尚未完成 Neo X live state-root differential。
- `e72d761c`：blob sidecar 转换期间持有 semaphore permit，属于资源并发修复，不改变交易编码；仍需在 Neo X blob policy 与 Beacon/2 互通环境验证。

相关 BAL getter/replay resource guard 也已纳入实时 tip 的本地 changed-file 审计。针对最新 tip 执行的 `git merge-tree --write-tree HEAD refs/audit/reth-main-20260902` 无冲突，合并树为 `661a569b35f40fe2352b1c2688815f4cbe08fea5`；临时测试合并提交为 `2859683d9532c92345bca69474f187e3c4a1de5b`。该合并结果已通过 `reth-neox-antimev` 45、`reth-neox-network` 47、`reth-neox-consensus-engine` 14、`reth-neox-evm` 28 项测试及对应核心严格 clippy，均为 0 failed/warning。受影响 workspace 测试中，`reth-chain-state` 33/33、`reth-downloaders` 82/82、`reth-engine-primitives` 16/16 通过；`reth-engine-tree` 169 项中 168 通过，唯一失败为 `persistence::tests::test_read_only_consistency_across_reorg`（`persistence.rs:746`，Windows MDBX `Disconnect(Os error 1224)`）。该结果不等同于完整 workspace、RPC、Engine、同步、DKG、重启、崩溃恢复或混合客户端门禁通过，因此不自动合入，也不更新 pinned baseline。

## 10. 验证状态与交付判断

- 静态 JSON/常量核对：通过。
- `git diff --check`：通过。
- Neo X Anti-MEV/DKG 定向测试：**45 passed, 0 failed**（包含 TPKE、PreCommit、DKG state、keystore 和 recovery vectors）；对应 `scripts/tests/test_neox_*.py` 运维/门禁测试为 **45 passed, 0 failed**。
- Neo X 网络协议定向测试：**47 passed, 0 failed**（包含 BEACON/2、dBFT/0、RLP、缓存和队列边界；MSVC stable 1.98.0）。
- Neo X consensus-engine 定向测试：**14 passed, 0 failed**，包含 Shanghai `withdrawals_root` 门控回归。
- Neo X EVM 定向测试：**28 passed, 0 failed**，包含 Osaka modexp 与 system-call warm 回归；严格 clippy（该 crate lib/tests，`-D warnings`）：通过。
- 本轮主仓库 Neo X 核心复核：**134 passed, 0 failed**（Anti-MEV/DKG 45、consensus-engine 14、EVM 28、network 47）。
- 此前记录的 Neo X 全量 crate 测试曾通过（覆盖 chainspec、consensus、consensus-engine、antimev、evm、network、node 与 `neox-rs`，其中 `reth-neox-node` 为 156 passed）；本轮重新复核的范围为四个核心 crate，结果为 134 passed / 0 failed。此前并行构建的 Windows target 写入错误在清理残留进程并恢复构建缓存后消失。
- Neo X 全量严格 clippy：**通过，无项目代码 warning**（`--no-deps --all-targets -D warnings`）；仅有依赖 `proc-macro-error2` 的未来兼容提示。
- Reth 实时 tip 合并树核心 crate 严格 clippy：**通过，无项目代码 warning**，覆盖 `reth-neox-antimev`、`reth-neox-network`、`reth-neox-consensus-engine`、`reth-neox-evm` 的 `--all-targets --no-deps -D warnings`；同样仅出现 `proc-macro-error2` future-incompatibility 提示。
- Reth 最新 tip `0b3475a83e` 合并树受影响 workspace 测试部分通过：`reth-chain-state` 33/33、`reth-downloaders` 82/82、`reth-engine-primitives` 16/16；`reth-engine-tree` 169 项中 168 通过，唯一失败为 `persistence::tests::test_read_only_consistency_across_reorg`（`persistence.rs:746`，Windows MDBX `Disconnect(Os error 1224: user-mapped section open)`）。该失败属于通用持久化/Windows 映射文件生命周期阻塞，未形成 Neo X 状态根或协议断言差异；因此当前不计为完整 workspace 通过，也不升级 pinned baseline。
- **2026-09-02 A/B 对照（本机 `x86_64-pc-windows-gnullvm` 工具链，同一 `target` 目录、同一环境变量，仅切换补丁）**：针对该失败的本地修复尝试（`reth-provider` static file 侧的 `remove_cached_provider_for_block()` 与 `invalidate_cached_reader()`，在三处破坏性 prune 及 `delete_current_and_open_previous` 前释放 mmap）**未改变任何结果**——打补丁与不打补丁均为 `persistence` 模块 **13 passed / 1 failed**，失败位置同为 `persistence.rs:744`，错误值同为 `Other(Disconnect(Os { code: 1224, message: "The requested operation cannot be performed on a file with a user-mapped section open." }))`。该补丁已判定为对该门禁无效并全部还原，未提交，vendored Reth 源码与 pinned baseline `3bc71d43f7` 均未被改动。
- **根因收敛**：该测试会在同一数据目录额外打开第二个只读 MDBX 环境（`ProviderFactoryBuilder::open_read_only`），primary 的 unwind 提交需要收缩数据库文件，而 Windows 不允许在文件仍被用户映射时截断（Linux 允许）。因此这是 **MDBX + Windows 的平台限制**，落在通用 Reth 持久化测试内，与 Neo X 状态根、header、交易执行或协议断言无关，也不是 static file 的 mmap 缓存问题。据此，本轮不修改协议实现、不修改 vendored Reth 代码、不升级 pinned baseline。
- **主仓库 HEAD 完整计数**：`cargo test -p reth-engine-tree --lib` 为 **166 项，165 passed / 1 failed**，唯一失败仍是该测试。需与最新 tip 合并树的 **169** 项区分，两者不可混用。
- **归属证明**：`git diff 3bc71d43f7101f772bbb4f9e15d3cdd58f60e958 HEAD -- crates/engine/tree/src/persistence.rs` 与同命令作用于 `crates/storage/provider/src/providers/static_file/` 的输出**均为空**，即失败测试文件与 static file 目录都与上游 pinned 基线逐字节一致，Neo X 未改动。据此该失败可判定为**未经修改的上游 Reth 测试在 Windows + MDBX 下的平台限制**，不是 Neo X 引入的回归。
- **Linux 交叉验证未执行**：该测试在 Linux 上应可通过（POSIX 允许截断已映射文件），但本机 `wsl.exe` 被安全策略列入程序黑名单且无 Docker，无法在本机完成交叉验证；此为未完成项，不记为通过。
- withdrawals_root、Beacon TTL、RPC Policy、同步以及本轮 EVM 和 dBFT/0 审计证据：代码修复已提交并推送；本轮最新 Reth tip 文档证据将在本次收尾提交后推送。
- Neo X Rust 定向与全量 crate 测试：已完成记录的范围内通过；不等同于完整目标工作区所有 Reth 包均通过。
- 历史 Windows `blst`/target 写入错误：已通过恢复 MSVC 环境、清理残留进程并禁用增量构建解决，不再作为当前 Rust 测试失败结论。
- 活体协议门禁：未完成。单高度 RPC 门禁已实际启动，但因本机 `http://127.0.0.1:8545` 返回 HTTP 502 而阻塞；不能记为通过或协议不一致。BEACON/2、dBFT/0 的本地定向 wire/RLP 测试已通过，但尚未完成 Rust/Geth mixed-peer 实际互通。`where geth`、`where reth` 均未找到可执行文件；Geth prover、ceremony artifacts 和 live RPC 同样缺失。
- 运维脚本门禁：62 个测试中 50 通过、12 跳过、1 个失败；失败为 Windows 主机执行 macOS bundle 清理测试时的 `genie-trash`/Foundation 不可用环境错误，不是协议断言失败。
- Geth oracle 导出目录 `D:\Git\neox-oracle-geth` 无 `.git` 元数据；虽然通过 `git ls-remote` 确认远端 `bane-main` 当前为 `f0e236838b`，但本地逐行比对本身无法独立证明导出目录的 commit 身份。
- 可执行 baseline 路径已修正为 `crates/neox/chainspec/res/genesis_mainnet.json` 与 `genesis_testnet.json`；文件 JSON 语义校验通过。其记录的 SHA-256 仍是 Geth canonical 文件锚点，Rust 工作树文件存在 EOL/字节级差异，不能直接作为原始字节哈希相等断言。

### 100% 一致性门槛

只有以下条件全部满足，才能对外宣称与 Neo X Geth 协议 100% 一致：固定 oracle commit 可复现；所有 header/extra/TPKE/PreCommit/wire 字节向量通过；双节点 RPC differential 无差异；Rust/Geth 混合 dBFT、DKG epoch、重启、崩溃恢复和受控重组门禁通过。本轮静态审计和代码修复不能替代这些活体验证，因此当前结论是“已按 oracle 对齐并修复已确认差异”，不是“100% 已证明”。

**发布判断：不能据此宣称“全量协议验证通过”或“已证明混合客户端共识等价”。当前结论是：canonical 配置与已完成静态面的协议锚点一致；仍有 RPC 模拟、TPKE commitment 隐式校验、wire 互通、DKG 状态机和活体同步门禁开放。**
