# 2026-09-09 已提交 HEAD 门禁复核 + Geth 高度门控实现

- 日期：2026-09-09
- 对象：Rust 仓库 `D:\Git\neox-rs`，HEAD `2da0e8fc9c9a42359a9d13053a9d5cbc7259d22c`（含 `e877f29b81` 代码提交）
- 性质：提交后的独立门禁复核（提交前的 G1–G4 结果不能直接当作入库树证据）

## 1. G1–G4 复核结论（双源交叉验证）

| Gate | 结论 | 证据来源 |
|---|---|---|
| G1 Neo X Rust 套件 | **PASS — 420 passed / 0 failed** | 两个独立运行数字完全一致：① QA 会话遗留的单包日志（`outputs/gate-20260909/G1-summary.txt`：node 172 + antimev 95 + chainspec 17 + network 47 + consensus 18 + consensus-engine 14 + evm 28 = 391，`G1b-neox-rs-bins.log` 以 `--bins` 补 neox-rs 29）；② 本会话合并重跑（`outputs/gate-20260909/gates-committed-head.log`，29+95+17+18+14+28+47+172 = 420） |
| G2 严格 clippy | **PASS — 0 warnings**（两次运行 rc=0） | `G2-clippy.log` 与合并重跑同段；唯一提示为第三方依赖 `proc-macro-error2` 的 future-incompat 通知，非代码告警 |
| G3 Python 工具 | **PARTIAL — 57 passed / 12 skipped / 1 env-blocked** | `G3-python.log`（unittest，`Ran 70 tests`，失败项为 `test_macos_bundle_does_not_require_linux_only_prover`：Windows 宿主缺 darwin genie-trash 可执行文件与 Foundation/CoreServices，属环境阻断，与 9-07/9-08 基线一致，非协议回归） |
| G4 Anti-MEV 跨实现向量 | **PASS — 95 passed / 0 failed** | G1 中 `reth-neox-antimev` 包 95 项（47 lib 相关 + 3 + 9 + 15 + 5 + 16） |

**判读说明**：
- `neox-rs` 包以 `--lib` 跑会报 `no library targets found`（rc=101）——该包为纯 binary crate，须以 `--bins`/`--tests` 运行。这不是回归。
- QA 成员（software-qa-engineer-5）在写汇总报告前因 429 中断；本报告的数字直接取自其落盘的机器日志并经本会话独立重跑交叉确认，未采信任何未经核验的转述。
- G3 的 pytest 尝试因托管 Python 无 pytest 模块而无效，已弃用；有效证据为 unittest 日志。

## 2. Geth 侧高度门控实现（T01–T04）

基线：`D:\Git\neox-geth` HEAD `f0e236838bb334c7c0d29eeca33533ed0cfda254`。
设计依据：[2026-09-09-GETH-PKCS7-HEIGHT-GATE-DESIGN.md](2026-09-09-GETH-PKCS7-HEIGHT-GATE-DESIGN.md)（行号证据已由主流程逐条抽验命中）。

**发现并记录**：canonical Geth 工作树自 9-05 canonical 验证后遗留 strict 补丁应用状态（`git status`：`crypto/tpke/{aes.go,util.go,util_test.go}`，`+55/-6`）。本次实现直接在该状态之上叠加高度门控；最终工件为「干净基线 → 基线+高度门控 strict」的完整补丁。

已完成的改动（对齐设计 §2.2/§3.3/§8 硬性约束）：

| 任务 | 文件 | 改动 |
|---|---|---|
| T01-A | `params/config.go` | 新增 `NeoXPkcs7StrictBlock *big.Int`（JSON 标签逐字 `neoXPkcs7StrictBlock,omitempty`） |
| T01-B | `params/config.go` | 新增 `IsNeoXPkcs7Strict`（**不带** IsLondon 前件，与 Rust 纯高度语义对称，注释说明） |
| T01-C | `params/config.go` | `CheckConfigForkOrder` 注册 `neoXPkcs7StrictBlock`（optional） |
| T01-D | `params/config.go` | `checkCompatible` 新增回滚保护 |
| T01-E | `params/config.go` | 启动 banner 增加 `NeoXPkcs7Strict` 行 |
| T02 | `crypto/tpke/util.go` | `pkcs7UnPadding(data, blockSize, strict)` 双模：strict 分支与 Rust `tpke.rs:432-441` 逐条对应；legacy 分支保持 `length-unPadding < 0` 判定（不加多余检查）；`length%blockSize` 公共守卫对两模式生效（对齐 Rust `:406`） |
| T02 | `crypto/tpke/aes.go` | `AESDecrypt` → `AESDecryptWithMode(..., strict bool)`，不留隐式 legacy 默认签名 |
| T03 | `antimev/tpke.go` | `AggregateAndDecryptWithShare` / `WithReshare` 增加 `strict bool` 形参并透传 |
| T03 | `consensus/dbft/dbft.go` | `processPreBlockCb` 内新增 `strict := c.chain.Config().IsNeoXPkcs7Strict(pre.header.Number)`（**目标区块自身高度**，注释禁止误用 `:1092` 的父高度），两个解密调用共用同一 `strict` |
| T04 | `crypto/tpke/util_test.go` | `TestPKCS7UnPaddingModes`：valid 1..16 双模同值；zero/oversized(32B)/inconsistent 两例为 legacy 接受 + strict 拒绝；byte_255/非对齐/空输入双模拒绝 |
| T04 | `crypto/tpke/aes_test.go` | legacy 与 strict 双模式解密同明文 |
| T04 | `antimev/tpke_test.go` | 3 个调用点传 `false`（保持 legacy 语义断言） |
| T04 | `params/config_pkcs7strict_test.go` | nil 恒 false / 49 false / 50 true / 100 true / 0 恒 true（镜像 `spec.rs:713-746`）；fork 顺序校验正反两例 |

验证命令与结果见本文 §3（待 gofmt/vet/test 运行完成后回填）。

## 3. Geth 侧验证结果

- `go vet ./crypto/tpke/... ./antimev/... ./params/... ./consensus/dbft/...`：**干净**。
- `go test`（count=1）：
  - `crypto/tpke` **ok**（含重写后的 `TestPKCS7UnPaddingModes` 双模矩阵：valid 1..16 双模同值；zero/oversized/inconsistent 为 legacy 接受 + strict 拒绝；byte_255/非对齐/空输入双模拒绝）
  - `antimev` **ok**（3 个调用点以 legacy 模式保持原断言）
  - `params` **ok**（`TestIsNeoXPkcs7Strict`：nil 恒 false / 49 false / 50 true / 100 true / 0 恒 true；`TestCheckConfigForkOrderNeoXPkcs7Strict` 正反两例。注：`shanghaiTime` 为非可选分叉，配置必须先启用它——首版测试因此失败，已按真实 `checkConfigForkOrder` 语义修正）
  - `consensus/dbft` **ok**（全套，含 light）
- **跨实现向量面兼容性**：`docs/neox/vectors/geth-exporter/` 四个 `package antimev` 注入式测试已适配新签名（legacy 模式），拷入 Geth 树后 `go vet` 干净、`go test ./antimev/` 全绿，随后移除拷贝。
- **补丁工件**：`outputs/geth-pkcs7-strict-height-gate.patch`，初始 9 文件 `+199/-18`（sha256 `368c8f5462c3aac8d23280dc4353cd71166c32e324db50f4fd61b037c585a223`）；2026-09-10 并入 F 项修复（`eth/tracers/api.go` fork override + 单测）后为 **11 文件 `+243/-18`**，sha256 `26f19d844fa2ba7b55f10ad10421c0afd72f54841f4e8669049eb6e98d29c98f`，双向 apply 校验复验通过（FORWARD_OK/REVERSE_OK）。
  - **正向 apply --check**：对 `git archive HEAD`（纯净基线 `f0e2368…`）导出树 **FORWARD_APPLY_CHECK_OK**
  - **逆向 apply --check**：对当前门控树 **REVERSE_CHECK_OK**（树状态与补丁"after"态逐字节一致）
- `gofmt -l` 说明：该 Geth 树几乎所有文件（含未触碰文件）都被 go1.27 gofmt 标记，属整树 CRLF/版本漂移的既有状况，非本次引入；权威信号为 go vet 与 go test 全绿。
- G9 状态：**技术阻塞已消除**（无条件严格化分歧源已被高度门控取代）；正式关闭仍需 ①两侧部署带门控二进制 ②治理设定同一 `neoXPkcs7StrictBlock` 激活高度 ③跨实现向量在 strict/legacy 双模式下回归通过。

## 3.b 遗留与后续（T05 剩余）

- ~~probe 双模式向量回归~~ → **已完成（2026-09-09 晚）**：probe 升级为双模式记录后，对共享密钥向量实测四类 padding，Geth legacy/strict 判定与 Rust 完全一致，且四条密文与 `geth_negative_vectors.rs` 常量**逐字节一致**（`ALL_BYTE_EXACT`）。详见 [2026-09-09-DUAL-MODE-VECTOR-PARITY.md](2026-09-09-DUAL-MODE-VECTOR-PARITY.md)。T05 双模式向量回归闭环，G9 仅余治理/运营。
- ~~G5/G6 活体差分~~ → **已完成（2026-09-09 深夜）**：本地节点追平主网 tip 后，tip 全覆盖 40 检查 0 mismatch、7 个历史采样高度 0 mismatch、执行级 4 笔交易+回执 0 mismatch。详见 [2026-09-09-LIVE-DIFFERENTIAL.md](2026-09-09-LIVE-DIFFERENTIAL.md)。
- ~~`eth/tracers/api.go` 的 fork override 未覆盖 `NeoXPkcs7StrictBlock`~~ → **已修复（2026-09-10）**：`overrideConfig` 新增 `NeoXPkcs7StrictBlock` 分支（nil 保持 canonical / 非 nil 复制并标记 non-canonical，与 `NeoXAMEVBlock` 同语义），新增单测 `TestOverrideConfigNeoXPkcs7Strict` PASS，`go vet`/`go build` 干净。`NeoXEthSigBlock` 的同类遗漏仍保留（上游既有状况，超出本审计项范围）。已并入补丁工件（11 文件版）。

## 4. 对 U1–U7 的裁决（team-lead）

- **U1**：确认。G9 关闭判据 = 双侧高度门控补丁 + 治理设定同一激活高度 + 跨实现向量回归通过。三者缺一不可。
- **U4**：确认。全仓检索确认 Rust 生产解密路径仅 `sync/anti_mev.rs:207` 一处；`decrypt_and_validate` legacy 包装仅测试调用（9-08 审查结论维持）。
- **U5**：不加 IsLondon 前件（已实现，注释说明理由）。
- **U7**：旧无条件补丁 `outputs/geth-pkcs7-strict.patch`（sha256 `a2cc2fa3…`）**标记为 SUPERSEDED，禁止单独部署**。冻结工件本身不改动（保持与快照哈希一致），作废声明记录于本文件与状态文档。
