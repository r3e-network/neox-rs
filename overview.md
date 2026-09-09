# Neo X 审计续审概览

本概览汇总 Neo X Rust 与 Neo X Geth oracle 的 Anti-MEV/TPKE、dBFT、同步与存储审计状态。当前已完成 PKCS#7 跨实现修复设计、canonical Geth 本地迁移门禁和 Rust 侧版本化激活门控，但仍不能宣称“100% 协议等价已证明”：G5–G8 需要活体基础设施，G9 需要双方发布与治理协调。

## 当前结论

- `neox-v2.5.2` 已发布，包含 `Pkcs7Strict` 版本化硬分叉门控及相关 P2 活性修复。
- 提交 `2d6231012f` 已落地可选 genesis 字段 `neoXPkcs7StrictBlock`；按区块高度选择 legacy/strict 解包模式。未配置该字段的链继续使用 legacy 行为，以保持与未打补丁参考客户端的历史字节兼容。
- canonical Geth checkout/apply/test 门禁已于 **2026-09-05 CLOSED**。证据见 [`docs/neox/reports/2026-09-05-GETH-PKCS7-CANONICAL-VALIDATION.md`](docs/neox/reports/2026-09-05-GETH-PKCS7-CANONICAL-VALIDATION.md)：固定 oracle commit `f0e236838bb334c7c0d29eeca33533ed0cfda254`，真实 `git apply --check`、`gofmt`、TPKE 测试、26 个 PKCS#7 子测试和 `go vet` 均通过。
- G1–G4 已于 2026-09-08 在最终工作树上重跑并确认（Rust crate suite 420 passed、strict clippy 0 warnings、Python 工具 PARTIAL——`install.sh` 下载路径属环境阻断、Anti-MEV 跨实现向量 95 passed；方法与命令见 [`docs/neox/reports/2026-09-07-VERIFICATION.md`](docs/neox/reports/2026-09-07-VERIFICATION.md)）。对应工作树改动已提交为 `e877f29b81`。
- G5–G8 当前 **BLOCKED**：分别缺少稳定的双端活体 RPC/同步拓扑、完成同步的本地与参考节点、fresh-datadir 长时 peers 运行，以及 Geth、DKG prover 和 ZK ceremony 工件。
- G9 是双方补丁与 `neoXPkcs7StrictBlock` 激活高度的协调门禁。激活后禁止 strict/legacy validator 混跑，也禁止通过 ad-hoc rollback 回退到不一致的解析规则。
- 2026-09-09：Geth 侧**高度门控**严格化补丁已实现并验证（`outputs/geth-pkcs7-strict-height-gate.patch`，sha256 `368c8f5462c3aac8d23280dc4353cd71166c32e324db50f4fd61b037c585a223`，9 文件 +199/-18）：新增可选 genesis 字段 `neoXPkcs7StrictBlock`（与 Rust 逐字同名），`dbft.go` 按目标区块自身高度选择 legacy/strict，未配置时恒 legacy、与未打补丁参考 Geth 字节兼容；`go vet` 干净，`go test` crypto/tpke、antimev、params、consensus/dbft 全绿，对纯净基线 `f0e2368…` 正向 apply 与门控树逆向 apply 双向校验通过。该补丁**取代**无条件的 `geth-pkcs7-strict.patch`（`a2cc2fa3…`，自即日起禁止单独部署）。共享向量测试（`docs/neox/vectors/geth-exporter/`）已适配新签名。G9 技术阻塞消除，正式关闭仍需两侧部署、同一激活高度与双模式向量回归。
- 2026-09-09 晚：**T05 双模式跨实现向量回归闭环**——probe 升级为双模式后实测四类 padding 向量，Geth 与 Rust 判定完全一致且密文与 Rust 常量**逐字节一致**（`ALL_BYTE_EXACT`，见 [2026-09-09-DUAL-MODE-VECTOR-PARITY.md](docs/neox/reports/2026-09-09-DUAL-MODE-VECTOR-PARITY.md)）。G9 三项技术要求（双侧门控补丁、双模式向量回归、未配置时 legacy 兼容）全部满足，**G9 仅余治理/运营动作**：两侧部署带门控二进制 → 一次治理变更设定同一激活高度（在未来、留观察窗口）→ 激活后禁止 strict/legacy 混跑与 ad-hoc rollback，并留痕 `dumpconfig`/banner 与 Rust 侧 `is_pkcs7_strict_active_at_block` 输出。

## 已完成与保留的 MDBX 审计背景

- Linux MDBX PID 类型修复保持不变：`crates/storage/db/src/implementation/mdbx/mod.rs` 将 `process_id` 显式转换为 `u32`，并以局部 `#[allow(clippy::unnecessary_cast)]` 处理平台差异；该修改不触碰协议实现或 vendored Reth。对应提交为 `b7c7c619eff52716fe19b2156e8bffe3494c4b17`。
- WSL Linux persistence targeted 验证已记录为 14/14，重点测试 exact 验证为 1/1。Windows `ERROR_USER_MAPPED_FILE` / `Disconnect(1224)` 的 A/B 结果一致，归类为 Windows user-mapped section 与通用 MDBX 生命周期限制，不等同于 Neo X 协议缺陷。
- 相关跨实现向量、Windows 门禁和 Linux 验证证据保留在 `outputs/`；不要将 targeted 通过扩大解释为 full live equivalence。

## G1–G9 状态矩阵

| Gate | 内容 | 当前状态与限制 |
|---|---|---|
| G1 | Neo X Rust crate suite | **PASS**（2026-09-08 在最终工作树重跑：420 passed / 0 failed） |
| G2 | Strict clippy (`-D warnings`) | **PASS**（2026-09-08 重跑：0 warnings） |
| G3 | Python tooling / baseline docs | **PARTIAL**（2026-09-08 重跑：57 passed / 12 skipped / 1 env-blocked；`install.sh` 下载路径属环境阻断，非协议回归） |
| G4 | Anti-MEV 跨实现向量 | **PASS**（2026-09-08 重跑：95 passed / 0 failed） |
| G5 | RPC differential | **BLOCKED**：缺少可同时复现的本地与参考活体 HTTP endpoint |
| G6 | Full historical differential | **BLOCKED**：缺少已同步到可比高度的本地与参考节点 |
| G7 | Fresh-datadir MainNet sync/restart | **BLOCKED**：需要长时同步、稳定 peers 和重启后 head 一致性证据 |
| G8 | Mixed-client DKG epoch | **BLOCKED**：缺少 Geth、DKG prover、ZK ceremony 工件及七验证者拓扑 |
| G9 | PKCS#7 coordinated activation | **OPEN / governance**：技术阻塞已消除（2026-09-09 高度门控补丁，见 [2026-09-09-COMMIT-VERIFICATION.md](docs/neox/reports/2026-09-09-COMMIT-VERIFICATION.md)）；剩余为两侧部署、同一激活高度与激活后禁止 strict/legacy 混跑的运维纪律 |

## 长期未关闭风险

以下风险仍需单独的可复现证据，不因 G1–G4 或 canonical Geth 本地门禁通过而自动关闭：

- 链上 `KeyManagement` 合约 PVSS commitment/renovate 校验强度尚缺完整证明。
- Geth `CipherText.Verify()` 零调用路径仍是活性停滞风险（目前不是已证明的状态分叉）。
- controlled reorg 注入与恢复场景仍缺 standalone injector 及完整回归证据。
- 历史 malformed-padding census、mixed-client replay 及正式参考客户端部署仍待完成。

## 复核顺序

1. 已完成（2026-09-08）：工作树改动已提交为 `e877f29b81`，G1–G4 已在最终改动上重跑通过；「生产解密路径均使用 chainspec 门控 API」的审查结论维持有效。
2. 准备 G5–G8 所需的双 RPC、同步节点、Geth、prover、ZK ceremony 和七验证者拓扑，保存可复现日志。
3. 执行历史 Envelope/padding census 与 mixed-client replay。
4. 由双方协调 `neoXPkcs7StrictBlock` 激活高度和发布窗口；在激活后禁止 strict/legacy 混跑，不采用 ad-hoc rollback。

**审计判定：离线静态门禁已有较强证据，canonical Geth 本地迁移门禁已关闭；活体验证与治理协调仍未完成，因此当前不是 100% 协议等价结论。**
