# Anti-MEV 跨实现固定向量验证（2026-09-02）

本轮关闭审计报告 `docs/neox/reports/2026-09-01-FULL-AUDIT.md` 开放项中的
「需要跨实现固定向量」一项中**可在本机离线完成**的部分，并额外确证了一处
真实的跨实现行为分歧。

## 1. 结论摘要

| 项目 | 结果 |
| --- | --- |
| 跨实现互操作向量（正向量） | **9/9 通过** |
| 拒绝路径向量（负向量） | **14/14 通过** |
| crate 原有单元测试 | **45/45 通过** |
| `reth-neox-antimev` 全量 | **68 通过 / 0 失败** |
| clippy `--all-targets --all-features` | **0 警告** |
| nightly rustfmt | **干净** |
| 协议实现代码改动 | **无** |
| 确证的跨实现分歧 | **1 处（PKCS#7 解填充严格性）** |

已验证一致的确定性项：committee scaler、G2 压缩编码字节序、Envelope 布局常量、
全局公钥推导、逐参与方公私钥份额、解密份额字节、AES 密钥派生与
5-of-7 门限解密结果。

## 2. 方法

采用**导出—验证**两阶段，而不是硬编码猜测值：

1. 在参考客户端 `bane-labs/go-ethereum`（分支 `bane-main`）的 `antimev` 包内
   **新增**（未修改任何既有文件）两个测试文件，重放其既有的 7 节点 / 5 门限
   privnet DKG 夹具，导出全部中间值：
   - `neox_cross_vectors_test.go`：DKG 结果、全局公钥、密文、逐参与方私钥份额与解密份额、
     恢复出的 AES 密钥点、Envelope 布局常量、G1/G2 生成元编码。
   - `neox_pkcs7_probe_test.go`：用参考客户端自己的 AES-CBC 例程加密手工构造的填充块，
     探测其解填充的接受集。
2. 在 Rust 侧新增两个集成测试，用导出值做断言：
   - `crates/neox/antimev/tests/geth_cross_vectors.rs`（9 项）
   - `crates/neox/antimev/tests/geth_negative_vectors.rs`（14 项）

导出器源码已归档于 `docs/neox/vectors/geth-exporter/`，向量 JSON 为
`docs/neox/vectors/geth-tpke-vectors.json` 与
`docs/neox/vectors/geth-pkcs7-vectors.json`。

### 参考客户端来源验证

本机 `D:\Git\neox-oracle-geth` **不是 git 工作副本**（无 `.git` 目录），
无法直接证明其源码对应基准提交 `f0e236838bb334c7c0d29eeca33533ed0cfda254`。
为免把未验证的来源当作已验证，已拉取该提交做逐文件比对：

```
git init && git remote add origin git@github.com:bane-labs/go-ethereum.git
git fetch --depth 1 origin f0e236838bb334c7c0d29eeca33533ed0cfda254
git checkout FETCH_HEAD -- antimev crypto/tpke
```

比对结果：

| 目录 | 与基准提交逐字节相同的文件 | 差异 |
| --- | --- | --- |
| `crypto/tpke/` | 18 / 18 | 无 |
| `antimev/` | 9 / 9（既有文件） | 无 |

`antimev/` 下另有 2 个文件为本轮**新增**的导出器（`neox_cross_vectors_test.go`、
`neox_pkcs7_probe_test.go`），在基准提交中不存在，故不在比对范围内。

结论：向量确由基准提交的参考客户端代码产生，且本轮**未修改参考客户端任何协议代码**。

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

**性质判断**：分歧方向为 **Rust 更严格**，属于安全加固而非本仓库的缺陷。

**未确证部分**：尚不能定性为链上可达的共识分叉。参考客户端在
`AggregateAndDecryptWithShare` 中忽略 `AESDecrypt` 的错误并把结果置为 `nil`，
故其「接受」后拿到的是被污染的字节（108/120/128 字节），后续 inner transaction
的 RLP 解码大概率失败，最终可能与 Rust 的拒绝殊途同归。
但「大概率」不等于「必然」，填充末字节有 1/256 概率使 Geth 得到看似合法的长度，
是否存在可构造的差异化接受路径仍需链上调用链验证。

严重度暂记 **中（实现层分歧已确证，链上可达性待验证）**。

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

- **current/previous 混合与 fallback**：需要 reshare（再共享）流程的向量，
  本轮导出器只覆盖首次 sharing，未覆盖 `reshared` 密钥组。
- **错误 round 的语义绑定**：`dkg_round` 字段的解析与长度已验证，
  但 round 与 DKG epoch / 链上 KeyManagement 契约的绑定语义需链上验证。
- **活体门禁**：RPC differential、Geth/Rust 混合 peer、混合客户端出块、
  MainNet fresh sync、崩溃恢复、受控 reorg。本机无节点（8545/8546/8551/30303 均关闭），
  这些项**仍然全部未完成**。
- **PKCS#7 分歧的链上可达性**：见第 4 节。

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
