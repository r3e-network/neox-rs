# Anti-MEV 跨实现固定向量验证（2026-09-02）

本轮关闭审计报告 `docs/neox/reports/2026-09-01-FULL-AUDIT.md` 开放项中的
「需要跨实现固定向量」一项中**可在本机离线完成**的部分，并额外确证了一处
真实的跨实现行为分歧。

## 1. 结论摘要

| 项目 | 结果 |
| --- | --- |
| 跨实现互操作向量（正向量） | **9/9 通过** |
| 拒绝路径向量（负向量） | **14/14 通过** |
| current/previous 轮次分离向量（reshare） | **16/16 通过** |
| PKCS#7 分歧的链上可达性证明 | **Geth 侧构造成功 / Rust 侧拒绝，4/4 通过** |
| Envelope 密文准入向量（`Verify()` 零调用） | **Geth 4/4、Rust 4/4 通过** |
| Envelope 轮次过滤器接受集全表 | **Geth 1/1、Rust 2/2 通过** |
| DKG 调度层检查点单元测试 | **6/6 通过** |
| crate 原有单元测试 | **45/45 通过** |
| `reth-neox-antimev` 全量 | **88 通过 / 0 失败** |
| clippy `--all-targets --all-features` | **0 警告** |
| nightly rustfmt | **干净** |
| 协议实现代码改动 | **无** |
| 确证的跨实现分歧 | **2 处**：PKCS#7 解填充严格性（状态分叉，严重度高）；`CipherText.Verify()` 零调用（活性停滞，严重度高） |

已验证一致的确定性项：committee scaler、G2 压缩编码字节序、Envelope 布局常量、
全局公钥推导、逐参与方公私钥份额、解密份额字节、AES 密钥派生、
5-of-7 门限解密结果，以及 **DKG 再共享后的 previous/current 轮次隔离**。

> **重要更正**：本文件早先版本与审计报告曾写「`CipherText.Verify()` 与
> `TpkeCiphertext::verify()` 语义一致，该对应检查确实存在」。该表述在"函数已定义"层面
> 成立，但**参考客户端从不调用它**（全树零非测试调用点）。详见第 4.2 节。

## 2. 方法

采用**导出—验证**两阶段，而不是硬编码猜测值：

1. 在参考客户端 `bane-labs/go-ethereum`（分支 `bane-main`）的 `antimev` 包内
   **新增**（未修改任何既有文件）两个测试文件，重放其既有的 7 节点 / 5 门限
   privnet DKG 夹具，导出全部中间值：
   - `neox_cross_vectors_test.go`：DKG 结果、全局公钥、密文、逐参与方私钥份额与解密份额、
     恢复出的 AES 密钥点、Envelope 布局常量、G1/G2 生成元编码。
   - `neox_pkcs7_probe_test.go`：用参考客户端自己的 AES-CBC 例程加密手工构造的填充块，
     探测其解填充的接受集。
   - `neox_cross_vectors_test.go` 中的 `TestExportReshareVectors`：跑两轮 DKG
     （初始 sharing，再 `OnSharePeriodStart(false)` + `DKGReshare()` + `DKGShare()`，
     并把第一轮聚合承诺作为 `lastRoundCmt` 传入 `OnEpochChange`），
     导出 previous round 与 current round 两个密钥组的完整材料。
   - `neox_pkcs7_reachability_test.go`：用畸形填充构造一个完整 Envelope，
     走真实解封装链路，证明该分歧**链上可达**（见第 4.1 节）。
2. 在 Rust 侧新增四个集成测试，用导出值做断言：
   - `crates/neox/antimev/tests/geth_cross_vectors.rs`（9 项）
   - `crates/neox/antimev/tests/geth_negative_vectors.rs`（14 项）
   - `crates/neox/antimev/tests/geth_reshare_vectors.rs`（16 项）
   - `crates/neox/antimev/tests/geth_pkcs7_reachability.rs`（4 项）

导出器源码已归档于 `docs/neox/vectors/geth-exporter/`，向量 JSON 为
`docs/neox/vectors/geth-tpke-vectors.json`、
`docs/neox/vectors/geth-pkcs7-vectors.json` 与
`docs/neox/vectors/geth-reshare-vectors.json`。

### 参考客户端来源验证

本机 `D:\Git\neox-oracle-geth` **不是 git 工作副本**（无 `.git` 目录），
无法直接证明其源码对应基准提交 `f0e236838bb334c7c0d29eeca33533ed0cfda254`。
为免把未验证的来源当作已验证，已拉取该提交做逐文件比对：

```
git init && git remote add origin git@github.com:bane-labs/go-ethereum.git
git fetch --depth 1 origin f0e236838bb334c7c0d29eeca33533ed0cfda254
git checkout FETCH_HEAD -- antimev crypto/tpke
```

比对结果（**逐字节**，含行尾）：

| 目录 | 与基准提交逐字节相同的文件 | 差异 |
| --- | --- | --- |
| `crypto/tpke/` | 16 / 16 | 无 |
| `antimev/`（既有文件） | 10 / 10 | 无 |
| **合计** | **26 / 26** | **无** |

`antimev/` 下另有 2 个文件为本轮**新增**的导出器（`neox_cross_vectors_test.go`、
`neox_pkcs7_probe_test.go`），在基准提交中不存在，故不在比对范围内。

结论：向量确由基准提交的参考客户端代码产生，且本轮**未修改参考客户端任何协议代码**。

#### 两处需要更正的先前记录

1. **文件计数更正**：本轮早些时候记录的「`crypto/tpke/` 18/18、`antimev/` 9/9」有误，
   实际为 16 与 10（合计 26）。该数字是人工统计得出的，未与 `git ls-tree` 的输出对齐。
   现已按 `git ls-tree -r FETCH_HEAD -- antimev crypto/tpke` 的实际清单重新统计。
2. **比对强度更正**：早先的比对是把 `FETCH_HEAD` 检出到工作树后再 `git diff`，
   而本机 `core.autocrlf=true`，`git diff` 会把工作树的 CRLF 归一化成 LF 后再比较，
   因此那次实际上是「**内容**一致、行尾不比」。本次改用
   `git show FETCH_HEAD:<path>` 与工作树文件逐字节比对，确认 26/26 **逐字节**一致。
   （顺带说明：早先的 `git checkout` 副作用把 26 个上游文件的行尾从 LF 改成了 CRLF，
   已还原为 LF，`gofmt -l` 与 `go vet` 均干净。）

### 关于确定性的重要说明

参考客户端自带的 `antimev.TestTPKE` **不能**直接作为固定向量来源：其
`KeyStore.Encrypt` 内部调用 `randPG1()` 生成随机 AES 密钥，随机 nonce 亦参与密文构造。
实测连续两次运行得到的 `encryptedKey` 完全不同。

因此本报告不使用「某次运行输出的字节 == 另一次运行输出的字节」这一意义上的固定向量，
而是导出**一次完整运行中所有自洽的中间值**，验证 Rust 能在其上完成互操作。
测试内硬编码的是该次运行的快照，故 **Rust 测试本身是可重复、确定性的**；
而 scaler、布局常量、编码格式、份额生成算法等结论不受随机性影响，反复运行均成立。

## 3. 已验证一致的项

### 3.1 确定性常量

| 项 | 参考客户端 | Rust | 一致 |
| --- | --- | --- | --- |
| committee scaler（5-of-7） | `getScaler(7,5)` = 360 | `NEOX_DKG_SCALER` = 360 | ✅ |
| Envelope 前缀 | `ffffffff` | `ENCRYPTED_DATA_PREFIX = [0xff;4]` | ✅ |
| round / gas / hash 字段长度 | 4 / 4 / 32 | 4 / 4 / 32 | ✅ |
| 密文长度 | `CipherTextSize` = 192 | `TPKE_CIPHERTEXT_LEN` = 192 | ✅ |
| 最短 Envelope calldata | 348 | `MIN_ENVELOPE_DATA_LEN` = 348 | ✅ |
| 最小 inner gas | 21000 | `MIN_ENCRYPTED_GAS_LIMIT` = 21000 | ✅ |
| Envelope 目标地址 | `0x1212…0003` | `ENVELOPE_TARGET` | ✅ |
| 解密份额长度 | 48 | `DECRYPTION_SHARE_LEN` = 48 | ✅ |

### 3.2 G2 压缩编码字节序（此前的重大风险点，已解除）

参考客户端使用 gnark-crypto（G2 元素以 `X.A0 + X.A1·u` 表示），Rust 使用
blst/IETF 序列化（压缩格式为 `x.c1 ‖ x.c0`）。两者若顺序不同，Envelope 密文中的
96 字节配对承诺将无法互通，属于可致共识分叉级别的隐患。

实测参考客户端导出的 G2 生成元压缩编码为：

```
93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e
024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8
```

该值与 BLS12-381 的 IETF/blst 标准 G2 生成元压缩编码**逐字节相同**，
gnark 的 `G2Affine.Bytes()` 与 blst 的压缩格式兼容。**该风险点已解除。**

### 3.3 互操作结果

- 全局公钥：由 128 字节 EIP-2537 padded 承诺经 scaler 推导，与参考客户端记录的
  压缩公钥**逐字节一致**。该承诺的前 16 字节与 `[64:80]` 全零，符合 Rust 的 padding 校验前提。
- 逐参与方公钥份额：由私钥份额推导，7/7 **逐字节一致**。
- **解密份额：7/7 逐字节一致**。这是本轮最严格的检查——它证明 `PreCommit` 路径上
  两个实现产生相同的线上字节，而不只是「都能解密成功」。
- 5-of-7 门限解密：用前 5 个参与方的份额恢复 AES 密钥并解密，得到与参考客户端**相同的明文**。
- 子集无关性：改用后 5 个参与方（索引 3..7）恢复，得到**相同的密钥**，
  证明 Lagrange 插值与 scaler 的配合不依赖具体参与者组合。
- Envelope 字段解析：`dkg_round`、`encrypted_gas`、`encrypted_hash` 解析值与写入值一致。

### 3.4 previous / current 轮次分离与 fallback（reshare）

Neo X 通过 DKG **再共享**（resharing）轮换 Anti-MEV 委员会。轮换后每个 keystore 同时持有
两个密钥组：

- `shared`：轮换后的新组，负责当前轮 Envelope 的封装与开启；
- `reshared`：用**上一轮**聚合承诺重建的组，仍能开启轮换前封装的 Envelope（即 fallback 路径）。

参考客户端在 `OnEpochChange(selfPvss, aggregatedCmt, lastRoundCmt, isMemberOfNewGroup)` 中，
仅当 `lastRoundCmt` 非空时才构建 `reshared` 组。本轮导出的向量正是走这条路径。

**非平凡性前提**：若两轮全局公钥相同，则下面所有分离断言都将失去意义。导出器用
`require.NotEqual` 强制校验，实际结果：

```
previous_round.global_public_key = 8f2df85bc8add14e…a7b6f75
current_round.global_public_key  = 90d2a7ea34b67eb3…0e366b86   （不同 ✅）
```

两轮的聚合承诺、逐参与方私钥份额亦全部不同。

**Rust 侧断言（16/16 通过）**：

| 用例 | 期望 | 结果 |
| --- | --- | --- |
| 两轮全局公钥不同 | 非平凡前提 | ✅ |
| 两轮聚合承诺不同 | 非平凡前提 | ✅ |
| 两轮全局公钥均可由各自承诺推导得出 | 一致 | ✅ |
| 两轮密文各自通过配对承诺校验 | 接受 | ✅ |
| 两轮逐参与方公钥份额（7+7） | 逐字节一致 | ✅ |
| 两轮逐参与方解密份额（7+7） | 逐字节一致 | ✅ |
| previous 轮 Envelope 用 previous 组开启 | 解密到原明文 | ✅ |
| current 轮 Envelope 用 current 组开启 | 解密到原明文 | ✅ |
| 换一组 5-of-7 子集开启 previous 轮 | 同样明文 | ✅ |
| previous 密文 + current 份额 | 拒绝 `InvalidDecryptionShares` | ✅ |
| current 密文 + previous 份额 | 拒绝 `InvalidDecryptionShares` | ✅ |
| previous 密文 + previous 份额 + current 全局公钥 | 拒绝 `InvalidDecryptionShares` | ✅ |
| 混合两轮的 5 人法定人数（3+2） | 拒绝 `InvalidDecryptionShares` | ✅ |
| previous 轮不足门限（4/5） | 拒绝 `InvalidDecryptionShares` | ✅ |
| 两轮私钥份额不同 | — | ✅ |
| scaler 一致 | 360 | ✅ |

**结论**：Rust 实现与参考客户端在轮次隔离上语义一致——跨轮份额、跨轮全局公钥、
混合法定人数全部被拒绝，且拒绝发生在配对校验层（`InvalidDecryptionShares`），
而非依赖下层的 AES 解填充失败。fallback 路径（用 `reshared` 组开启轮换前的 Envelope）
可正常工作，且**没有**因 resharing 而放宽门限要求。

## 4. 确证的跨实现分歧：PKCS#7 解填充严格性

参考客户端 `crypto/tpke.pkcs7UnPadding` 仅拒绝「填充长度大于缓冲区」一种情况，
既不校验填充长度落在 `1..=16`，也不校验各填充字节是否等于声明的长度值。
Rust `DecryptedKey::decrypt_message` 对三者均严格拒绝。

用参考客户端自身的 AES-CBC 例程构造并实测，结果如下（`Accept` 表示参考客户端未返回错误）：

| 构造 | 参考客户端行为 | Rust 行为 |
| --- | --- | --- |
| 规范填充（对照） | 接受，返回 112 字节 | 接受，返回 112 字节 ✅ |
| 末字节 `0x00`（长度 0，越界） | **接受，返回 128 字节**（完全未剥离） | 拒绝 `InvalidPkcs7Padding` |
| 末字节 `0x14`（长度 20 > 块大小） | **接受，返回 108 字节**（多剥 4 字节） | 拒绝 `InvalidPkcs7Padding` |
| 声明 8 字节但前 7 字节不为 `0x08` | **接受，返回 120 字节** | 拒绝 `InvalidPkcs7Padding` |

**性质判断**：分歧方向为 **Rust 更严格**。「更严格」不等于「更安全」——
在混合客户端网络中它恰恰是**共识分叉的成因**，见下节。

### 4.1 链上可达性：已证明可达（严重度上调为「高」）

上一版报告把这一项记为「大概率不可达」。**该判断已被本轮的构造性证明推翻。**
原因是我此前假设「被污染的字节（108/120/128）后续 RLP 解码会失败」，
这只对**随机**污染成立；而填充长度与填充内容都是**加密方自选**的，
攻击者可以精确控制解填充的输出。

**加密方为什么能控制一切**：Envelope 的封装方自己挑选 AES 密钥点（`KeyStore.Encrypt`
里的 `randPG1()`）与随机性 `r`，因此它完全知道 AES 密钥，也就完全决定了
AES-CBC 明文的每一个字节。构造畸形填充不需要任何委员会成员的配合。

**已执行的构造**（Geth 侧 `TestPKCS7Reachability`，全部断言通过）：

1. 取一条真实签名的 EIP-1559 交易，`MarshalBinary` 得 112 字节（记为 `tx`）。
2. 追加 32 字节尾部，末字节置 `0x20`（32）。选 32 而非 20 是为了让
   `112 + 32` 仍是 16 的倍数（`AESDecrypt` 要求块对齐）。
   中间 31 字节故意**不等于** `0x20`，构成第二条独立的 Rust 拒绝理由。
3. 参考客户端的 `pkcs7UnPadding` 规则是 `data[..len - data[len-1]]`，
   于是返回 `data[..144-32]` = `data[..112]` = **完整的 `tx`**。
4. 走真实链路 `AggregateAndDecryptWithShare`：
   返回**非 nil**、结果与 `tx` **逐字节相等**，`UnmarshalBinary` 成功，
   哈希与发送方均正确恢复。

实测输出：

```
REACHABILITY: padding=32 (Rust rejects >16), decrypted=112 bytes,
              inner tx=0x87d9ffa086c88b491f30dd663075feaf3659286979e20b64435f0a8fd9452657
```

**Rust 侧对照**（`geth_pkcs7_reachability.rs`，4/4 通过）：份额聚合**成功**
（证明两者在解填充之前每一步都一致），`decrypt_message` 返回
`InvalidPkcs7Padding`；且 Rust 侧独立验证了那 112 字节是一条
**可解码、可往返编码、哈希自洽**的规范 EIP-2718 交易——即参考客户端拿到手的
不是垃圾，而是会被真正执行的交易。

**为什么这构成共识分叉**：`consensus/dbft/dbft.go` 的处理是

| 条件 | 行为 |
| --- | --- |
| `decryptedTxsBytes[j] == nil` | 回退为「按原样执行 Envelope」（`errEnvelopeDecryption`） |
| `UnmarshalBinary` 失败 | 回退（`errDecryptedDecoding`） |
| `validateDecryptedTx` 失败 | 回退 |
| 全部通过 | **执行解密出的内层交易** |

Rust 在第 0 步（解填充）就拒绝 → 回退为「按原样执行 Envelope」；
Geth 一路走到底 → **执行内层交易**。同一个区块槽位里两笔不同的交易 →
收据根、状态根、区块哈希全不同 → **混合客户端网络中链分裂**。

**残余不确定性（诚实标注）**：第 1–3 步是**实际执行**并验证的；
第 4 步的 `validateDecryptedTx` 未能端到端跑起来（它是 `*DBFT` 的方法，
需要完整 chain backend 与 pre-block receipt）。但从代码看它比较的每一项
——nonce、发送方、`encrypted_hash`、gas —— 都在 Envelope 的**明文**部分，
由同一个攻击者填写，因此均可满足。这是**代码论证**，不是执行验证。

**修复方向**：要与主网保持共识，Rust 必须复刻参考客户端的解填充规则
（只拒绝 `n > len`，不校验收窄到 `1..=16`、也不校验填充字节重复声明值），
或者反过来推动参考客户端收紧。**在两实现对齐之前，不应在混合客户端网络中运行。**

## 4.2 第二处分歧：参考客户端从不调用 `CipherText.Verify()`

### 发现

第 290 行的「附带发现」曾记录两侧配对校验均不保护加密消息 `M`，并称
「该对应检查确实存在」。这句话只对了一半：`crypto/tpke/encryption.go:77` **定义了**
`(*CipherText).Verify()`，但对 `antimev/`、`consensus/`、`core/`、`crypto/tpke/`
全树 grep `.Verify()` 的**非测试调用点为零**：

```bash
$ grep -rn "\.Verify()" --include="*.go" antimev/ consensus/ core/ crypto/tpke/ | grep -v _test.go
（无输出）
```

于是 Envelope 的准入实际只有三道闸：

| 闸 | 位置 | 校验内容 |
| --- | --- | --- |
| `IsEnvelope` | `antimev/envelope.go:53` | 类型、目标地址 `0x1212…0003`、长度 ≥ 348、`0xffffffff` 前缀 |
| `decodeEnvelopeData` → `FromBytes` | `consensus/dbft/amev.go:31` / `crypto/tpke/encryption.go:50` | 反序列化三个曲线点（隐式 on-curve + in-subgroup），**无配对校验** |
| txpool | `core/txpool/validation.go:227-244` | `maxEnvelopeGasLimit`、`MinEncryptedGasLimit`、gas 覆盖、Envelope fee |

Rust 在两个位置调用 `verify()`：交易池准入（`InvalidEnvelopeCiphertext`，永久拒绝）
与提案解析（`InvalidCiphertext` → `DbftProposalError::AntiMevProposal`，整块提案被拒）。

### 构造

对合法密文的 `R` 槽做一次 `R + g1` 平移。破坏后的密文仍可正常反序列化
（`R + g1` 仍是合法曲线点），但 `e(R, g2)·e(g1, commitment) != 1`。
无需任何私钥、无需任何委员会成员配合，一次点加法即可。

向量导出在 `docs/neox/vectors/geth-ciphertext-admission.json`
（`ciphertext_valid` / `ciphertext_invalid` 各 192 字节，
`envelope_data_valid` / `envelope_data_invalid` 各 364 字节）。

### 两侧测试结果（全通过）

| 侧 | 文件 | 测试 | 断言要点 |
| --- | --- | --- | --- |
| Geth `antimev` | `neox_ciphertext_admission_test.go` | `TestCiphertextAdmission` | `IsEnvelope` 为真、`FromBytes` 成功、`Verify()` 返回 `ErrTPKECiphertext`；投入 7/7 share 后 `AggregateAndDecryptWithShare` 返回 `ErrDecryptionFailed`（21 个法定组合全败）；对照样本解密逐字节一致 |
| Geth `antimev` | 同上 | `TestCiphertextAdmissionTamperSanity` | 仅 `R` 槽变化、结果仍可反序列化（排除"失败源于别处"） |
| Geth `consensus/dbft` | `neox_admission_decode_test.go`（生成） | `TestEnvelopeDecodeAcceptsUnverifiedCiphertext` | 走**真实**解析路径 `SetTransactions` → `decodeEnvelopeData`，两条均被接受 |
| Geth `consensus/dbft` | 同上 | `TestEnvelopeDecodeRejectsRoundZero` | 解析器会拒绝 round 0（防止"什么都收"的质疑） |
| Geth `consensus/dbft` | 同上 | `TestEnvelopeRoundFilterAdmitsEveryEarlierRound` | 见 4.3 |
| Rust `reth-neox-antimev` | `tests/geth_ciphertext_admission.rs` | 3 个 | 反序列化与参考客户端**一致**（故是校验差异，非解析差异）；`verify()` 返回 `InvalidCiphertextCommitment`；除密文外两 Envelope 逐字节相同 |
| Rust `reth-neox-node` | `src/pool.rs` | `pool_admission_rejects_the_envelope_the_reference_client_admits` | 交易池以 `InvalidEnvelopeCiphertext` 拒绝且 `is_bad_transaction()` 为真 |

### 后果：活性停滞，不是状态分叉（含对我早先判断的更正）

我最初判断这是"确定性链分裂"。**该判断错误，此处更正。**
`AggregateAndDecrypt`（`encryption.go:202`）的配对校验是
`e(PK, commitment)·e(rpk, g2) == 1`，与 `Verify()` 的
`e(R, g2)·e(g1, commitment) == 1` **互为等价条件**。
因此**不存在**「参考客户端能解密、Rust 拒绝」的输入——两侧对"这条 Envelope 能否打开"
判断一致，分歧只在**它能否进入区块**。真实链路：

1. Geth 收进交易池并打包。
2. `SetData` → `aggregateAndDecrypt` 配对校验失败 → `AggregateAndDecryptWithShare` 返回 error。
3. `consensus/dbft/dbft.go:1129-1141`：current / prev 两个桶**都** `return fmt.Errorf(...)`。
4. `nspcc-dev/dbft@v0.3.2/check.go:79-85`：`ProcessPreBlock` 返回 error 时仅 `return`
   并记录 "waiting for more PreCommits to be collected"。
5. 更多 share 永远无法挽救 → **该高度永久停滞**。

Rust 主节点在第 0 步就拒收，根本不会打包，于是网络出现**单向活性风险**：
Geth 主节点卡死，Rust 主节点继续出块。

严重度：**高**。触发成本极低，后果是全网出块停滞。
**本轮未改动任何协议代码，风险仍在。**

### 4.3 Envelope 轮次过滤器：两侧一致，但过滤器宽于其注释，并放大 4.2

`consensus/dbft/preblock.go:145`：

```go
if d.dkgRound < min(1, b.dkgRound-1) || b.dkgRound < d.dkgRound {
    continue
}
```

两操作数均为 `uint32`（故 `b.dkgRound-1` 在 0 处回绕），且用内置 `min`
（不是 `max`），下界恒为 1。相邻注释写「not from current/previous DKG round」，
但该谓词**实际接受任意更早轮次的 Envelope**。配合 `SetData`（`preblock.go:69-91`）
把所有非当前轮归入 previous 桶，以及 `aggregateAndDecrypt` 对**整批**做一次配对校验，
结论是：**一个更早轮次的不可解密 Envelope 会污染 previous 桶里的所有 Envelope**。

两侧对照测试（均通过），覆盖主动轮 0..=12 × Envelope 轮 1..=12 全表：

| 侧 | 测试 |
| --- | --- |
| Geth | `TestEnvelopeRoundFilterAdmitsEveryEarlierRound`（真实 `SetTransactions` vs 独立书写的期望表；并显式钉住"主动轮 5 时轮 1 与轮 4 都被接受"） |
| Rust | `envelope_round_filter_matches_the_reference_client_bound_for_bound`（同表从 `AntiMevProposal::from_transactions` 侧比对，并断言 epoch 划分） |
| Rust | `round_zero_envelopes_are_never_admitted` |

**这不是共识分歧**——Rust 复刻了同一个过滤器，接受集逐项相同。
因此任何一侧单独"修正"都会立刻造成网络分裂。两侧都加了表驱动测试，
使任一客户端的修改会**测试失败**而非静默导致网络失步。

严重度：**高**（实现层分歧已确证 + 链上可达性已构造性证明 + 后果为共识分叉）。

## 5. 负向量覆盖（14/14 通过）

| 用例 | 期望 | 结果 |
| --- | --- | --- |
| 规范填充 | 接受 | ✅ |
| 填充长度 0 | 拒绝 | ✅ |
| 填充长度 20 | 拒绝 | ✅ |
| 填充字节不一致 | 拒绝 | ✅ |
| AES 密文长度非 16 倍数 | 拒绝 | ✅ |
| AES 密文为空 | 拒绝 | ✅ |
| 篡改配对承诺 | 拒绝 | ✅ |
| 份额数低于门限（4/5） | 拒绝 | ✅ |
| 重复份额伪造法定人数 | 拒绝 | ✅ |
| 份额索引为 0 | 拒绝 | ✅ |
| 承诺 padding 非零 | 拒绝 | ✅ |
| scaler 为 0 | 拒绝 | ✅ |
| 常量守卫 | — | ✅ |
| 替换加密消息 | 见下 | ✅ |

### 附带发现：配对校验不保护加密消息 `M`

测试中原本预期「替换 `M` 会被配对校验捕获」，实测**聚合仍然成功**（返回了不同的密钥），
篡改只在 AES 层暴露。查证参考客户端 `crypto/tpke.startWorker` 的注释与其行为一致：

> *"If a user (the encryptor) use a different r to generate cMsg, no error will be detected
> here, but the following aes decryption will fail."*

即两个实现都只校验恢复出的 `r·PK` 与密文声明的随机承诺一致，**不把 `M` 绑定到该证明**。
这不是缺陷，而是 TPKE 方案的固有性质；`M` 的完整性由对称层兜底。
测试已按真实语义重写（断言：替换后密钥不同，且该密钥无法恢复原明文），
以确保两实现不会在此边界上静默漂移。

## 6. 仍未完成的项

以下开放项**未**在本轮关闭，不应计为通过：

- ~~**current/previous 混合与 fallback**~~：**已于本轮关闭**（见 3.4）。
- ~~**调度层：在哪个高度触发 `OnEpochChange`**~~：**已于本轮关闭，但仅限静态分析 +
  单元测试**（Geth `consensus/dbft/dkg.go:186-189` 的四个检查点与 Rust
  `crates/neox/node/src/dkg.rs:50-72` 的 `DkgSchedule::new` 公式逐项一致；
  Rust 侧 6/6 测试通过）。架构上 Geth 是增量状态机、Rust 是幂等重放，
  Rust 在重启与追赶路径上更严格（`snapshot.Round > 2` 保护 vs 显式 `RoundMismatch`）。
  详见审计报告第 6.1 节。**这不能替代混合客户端 DKG epoch 活体门禁。**
- ~~**Envelope 轮次过滤器的接受集**~~：**已于本轮关闭**（见 4.3）。结论是两侧一致，
  但该过滤器宽于其自身注释，并把 4.2 的活性风险放大为整桶污染。
- **错误 round 的语义绑定**：`dkg_round` 字段的解析、长度与过滤器接受集已验证；
  但 round 与链上 KeyManagement 契约的绑定语义需链上验证。
- **链上 `lastRoundCmt` 提交权限与错误 round 罚没**：静态阅读确认 Geth 侧
  `taskShare` / `taskReshare` 以 `CurrentCNs` / `PendingCNs` 成员资格为门槛，
  **已读路径中未见罚没逻辑**；但这是"已读路径未见"，不是"全树不存在"。
  链上 KeyManagement 合约未在本轮审计范围内，需合约层审计才能定论。
- **活体门禁**：RPC differential、Geth/Rust 混合 peer、混合客户端出块、
  MainNet fresh sync、崩溃恢复、受控 reorg。  本机无节点（8545/8546/8551/30303 均关闭），
  这些项**仍然全部未完成**。
- ~~**PKCS#7 分歧的链上可达性**~~：**已于本轮关闭**（见 4.1 节，构造性证明）。
  残余不确定性仅剩 `validateDecryptedTx` 未能端到端执行（需完整 chain backend），
  以及修复方案尚未实施——**代码本身未改，风险仍在**。

## 7. 复现步骤

```bash
# 1) 参考客户端导出向量（需 Go，本机位于 C:\Program Files\Go\bin\go.exe）
cd D:/Git/neox-oracle-geth
export PATH="/c/Program Files/Go/bin:$PATH"
NEOX_VECTOR_OUT='D:/Git/neox-rs/docs/neox/vectors/geth-tpke-vectors.json' \
  go test ./antimev/ -run TestExportCrossImplementationVectors -count=1 -v
NEOX_VECTOR_IN='D:/Git/neox-rs/docs/neox/vectors/geth-tpke-vectors.json' \
NEOX_PKCS7_OUT='D:/Git/neox-rs/docs/neox/vectors/geth-pkcs7-vectors.json' \
  go test ./antimev/ -run TestReferenceClientPKCS7Strictness -count=1 -v
NEOX_RESHARE_OUT='D:/Git/neox-rs/docs/neox/vectors/geth-reshare-vectors.json' \
  go test ./antimev/ -run TestExportReshareVectors -count=1 -v
NEOX_REACHABILITY_OUT='D:/Git/neox-rs/docs/neox/vectors/geth-pkcs7-reachability.json' \
  go test ./antimev/ -run TestPKCS7Reachability -count=1 -v
NEOX_ADMISSION_OUT='D:/Git/neox-rs/docs/neox/vectors/geth-ciphertext-admission.json' \
  go test ./antimev/ -run TestCiphertextAdmission -count=1 -v

# 1b) 由向量生成 consensus/dbft 侧的解析/轮次过滤测试，然后运行
cd D:/Git/neox-rs && python docs/neox/vectors/gen_admission_decode_test.py
gofmt -w 'D:/Git/neox-oracle-geth/consensus/dbft/neox_admission_decode_test.go'
cd D:/Git/neox-oracle-geth
go test ./consensus/dbft/ -run 'TestEnvelopeDecodeAcceptsUnverifiedCiphertext|TestEnvelopeDecodeRejectsRoundZero|TestEnvelopeRoundFilterAdmitsEveryEarlierRound' -count=1 -v

# 2) Rust 侧验证（gnullvm 工具链需要两个环境变量）
cd D:/Git/neox-rs
export PATH="/c/Program Files/Rust stable LLVM 1.95/bin:$PATH"
export CXXFLAGS="-D_WIN32_WINNT=0x0A00"
export BINDGEN_EXTRA_CLANG_ARGS="--target=x86_64-pc-windows-gnu -mmmx"
cargo test -p reth-neox-antimev
cargo clippy -p reth-neox-antimev --all-targets --all-features
```

注意：Go 在 Windows 上需要 `D:/...` 形式的路径，`/d/...` 形式的 POSIX 路径会被
写到错误位置（本轮已踩过）。
