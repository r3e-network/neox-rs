# Neo X 审计续审概览

本概览汇总 Neo X Rust 与 Neo X Geth oracle 的 Anti-MEV/TPKE、dBFT、同步与存储审计状态。当前已完成 PKCS#7 跨实现修复设计、canonical Geth 本地迁移门禁和 Rust 侧版本化激活门控，但仍不能宣称“100% 协议等价已证明”：G5–G8 需要活体基础设施，G9 需要双方发布与治理协调。

## 当前结论

- `neox-v2.5.2` 已发布，包含 `Pkcs7Strict` 版本化硬分叉门控及相关 P2 活性修复。
- 提交 `2d6231012f` 已落地可选 genesis 字段 `neoXPkcs7StrictBlock`；按区块高度选择 legacy/strict 解包模式。未配置该字段的链继续使用 legacy 行为，以保持与未打补丁参考客户端的历史字节兼容。
- canonical Geth checkout/apply/test 门禁已于 **2026-09-05 CLOSED**。证据见 [`docs/neox/reports/2026-09-05-GETH-PKCS7-CANONICAL-VALIDATION.md`](docs/neox/reports/2026-09-05-GETH-PKCS7-CANONICAL-VALIDATION.md)：固定 oracle commit `f0e236838bb334c7c0d29eeca33533ed0cfda254`，真实 `git apply --check`、`gofmt`、TPKE 测试、26 个 PKCS#7 子测试和 `go vet` 均通过。
- G1–G4 已于 2026-09-08 在最终工作树上重跑并确认（Rust crate suite 420 passed、strict clippy 0 warnings、Python 工具 PARTIAL——`install.sh` 下载路径属环境阻断、Anti-MEV 跨实现向量 95 passed；方法与命令见 [`docs/neox/reports/2026-09-07-VERIFICATION.md`](docs/neox/reports/2026-09-07-VERIFICATION.md)）。对应工作树改动已提交为 `e877f29b81`。
- 2026-09-09 深夜：**G5/G6 活体差分 PASS**——本地 neox-rs 节点（`127.0.0.1:18545`，Windows 进程 `neox-rs.exe` PID 51028；9-10 已更正「在 WSL 内」的误判）已同步至主网 tip，与参考 Geth（`mainnet-1.rpc.banelabs.org`，OPERATIONS.md 运行手册端点）head 持续对齐（skew 0–1）。tip 全覆盖差分 **40 检查（含 head-only Policy RPC）0 mismatch**；7 个历史采样高度（含 genesis）0 mismatch；执行级抽样 4 笔交易+回执全字段 0 mismatch。两轮独立运行结论一致，证据见 [2026-09-09-LIVE-DIFFERENTIAL.md](docs/neox/reports/2026-09-09-LIVE-DIFFERENTIAL.md) 与 `outputs/g5-g6-differential-20260909{,-run2}.log`。
- 2026-09-10 上午：**G7 重启一致性 PASS**——经 psutil 从进程恢复完整启动命令，硬终止（用户批准 UAC 后 `taskkill /F`）后以原命令行重启，35 秒恢复 RPC，重启前高度 `0x74ec60` 区块哈希**逐字节一致**（无回退/无分叉），立即续追 tip，重启后 tip 全覆盖差分 40 检查 0 mismatch（skew=0）。硬终止路径使本验证同时覆盖崩溃恢复，强于优雅重启。证据见 [2026-09-10-G7-RESTART-CONSISTENCY.md](docs/neox/reports/2026-09-10-G7-RESTART-CONSISTENCY.md) 与 `outputs/g7-restart-{baseline.txt,node.log,post-restart-differential.log}`。
- 早期表述更正：此前「G5–G8 本地不可解」的分类过重——本地即可编译 Geth、节点即可同步至 tip，活体差分当场可跑。教训记录：先核实基础设施，再下 BLOCKED 结论。
- G9 是双方补丁与 `neoXPkcs7StrictBlock` 激活高度的协调门禁。激活后禁止 strict/legacy validator 混跑，也禁止通过 ad-hoc rollback 回退到不一致的解析规则。
- 2026-09-09：Geth 侧**高度门控**严格化补丁已实现并验证（`outputs/geth-pkcs7-strict-height-gate.patch`，sha256 `26f19d844fa2ba7b55f10ad10421c0afd72f54841f4e8669049eb6e98d29c98f`，11 文件 +243/-18）：新增可选 genesis 字段 `neoXPkcs7StrictBlock`（与 Rust 逐字同名），`dbft.go` 按目标区块自身高度选择 legacy/strict，未配置时恒 legacy、与未打补丁参考 Geth 字节兼容；并补齐 `eth/tracers/api.go` fork override 对 `NeoXPkcs7StrictBlock` 的支持（设计 F 项，含单测 `TestOverrideConfigNeoXPkcs7Strict`）；`go vet` 干净，`go test` crypto/tpke、antimev、params、consensus/dbft、eth/tracers 全绿，对纯净基线 `f0e2368…` 正向 apply 与门控树逆向 apply 双向校验通过（2026-09-10 复验 FORWARD_OK/REVERSE_OK）。该补丁**取代**无条件的 `geth-pkcs7-strict.patch`（`a2cc2fa3…`，自即日起禁止单独部署）。共享向量测试（`docs/neox/vectors/geth-exporter/`）已适配新签名。G9 技术阻塞消除，正式关闭仍需两侧部署、同一激活高度与双模式向量回归。
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
| G5 | RPC differential | **PASS（活体，2026-09-09）**：tip 全覆盖 40 检查（含 head-only Policy RPC）0 mismatch，双轮独立复核一致；见 [2026-09-09-LIVE-DIFFERENTIAL.md](docs/neox/reports/2026-09-09-LIVE-DIFFERENTIAL.md) |
| G6 | Historical differential | **PASS（活体采样，2026-09-09）**：7 个历史高度（含 genesis、含 2 个执行级高度共 4 笔交易+回执全字段）0 mismatch；368k 全量门禁此前已通过，本轮为采样级活体复核 |
| G7 | Fresh-datadir MainNet sync/restart | **PASS（2026-09-10）**：同步面（9-07 执行阶段 → 9-09 追平 tip，head 对齐 + `eth_syncing=false`）+ 重启一致性（硬终止后原命令重启，35s 恢复，重启前高度哈希逐字节一致，重启后 tip 差分 40/40 0 mismatch）；见 [2026-09-10-G7-RESTART-CONSISTENCY.md](docs/neox/reports/2026-09-10-G7-RESTART-CONSISTENCY.md) |
| G8 | Mixed-client DKG epoch | **历史 PASS（2026-07-19）+ 前置已齐，当前代码重跑具备执行条件**——此前「缺 prover/ZK 工件」结论过重：DKG prover 二进制实际存在（WSL `~/.neox-rs/bin/neox-dkg-prover`），六件 ZK ceremony 工件已从 bane-labs zkstorage 下载至 `neox-geth/privnet/zk/`（`r1cs/R1CS_{1,2,7}` + `provingkey/PK_{1,2,7}`，字节与 HTTP Content-Length 逐一吻合）；且 `docs/neox/reports/mixed-client-e2e-2026-07-19.json` 记录 full DKG epoch gate `status: ok`（1 Reth + 6 Geth，round 5→6、prover attempts 2、0 失败、RPC 差分 40 检查 0 mismatch）。剩余：在当前 HEAD（含 PKCS#7 门控）上重跑以更新证据（`wsl.exe` 已确认可用） |
| G9 | PKCS#7 coordinated activation | **OPEN / governance**：技术阻塞已消除（2026-09-09 高度门控补丁，见 [2026-09-09-COMMIT-VERIFICATION.md](docs/neox/reports/2026-09-09-COMMIT-VERIFICATION.md)）；剩余为两侧部署、同一激活高度与激活后禁止 strict/legacy 混跑的运维纪律 |

## 长期未关闭风险

以下风险仍需单独的可复现证据，不因 G1–G4 或 canonical Geth 本地门禁通过而自动关闭：

- 链上 `KeyManagement` 合约 PVSS commitment/renovate 校验强度尚缺完整证明。
- Geth `CipherText.Verify()` 零调用路径仍是活性停滞风险（目前不是已证明的状态分叉）。
- controlled reorg 注入与恢复场景仍缺 standalone injector 及完整回归证据。
- 历史 malformed-padding census、mixed-client replay 及正式参考客户端部署仍待完成。

## 复核顺序

1. 已完成（2026-09-08）：工作树改动已提交为 `e877f29b81`，G1–G4 已在最终改动上重跑通过；「生产解密路径均使用 chainspec 门控 API」的审查结论维持有效。
2. 已完成（2026-09-09）：G5/G6 活体差分 PASS（见复核顺序顶部结论与 [2026-09-09-LIVE-DIFFERENTIAL.md](docs/neox/reports/2026-09-09-LIVE-DIFFERENTIAL.md)）；可选后续——对当前节点状态重放 `scripts/neox-full-differential.py` 全量 368k 门禁。
3. ~~G7 收尾~~ 已完成（2026-09-10）：启动命令经 psutil 恢复 → 硬终止（UAC 批准）→ 原命令重启 → 哈希连续性 + tip 差分全过。
4. G8：前置已齐（prover、ZK 工件、历史 full-gate PASS 见 `mixed-client-e2e-2026-07-19.json`）——在当前 HEAD 重跑 `scripts/neox-mixed-dkg-e2e.py` 更新证据；需 WSL 命令执行权（`wsl.exe` 当前在 WorkBuddy 程序黑名单中，须用户在安全中心移除后进行），届时按 zk-network-2026-07-20 报告的配方：`neox-dkg-migrate` 迁移 keystore → `privnet_start_zk` 拉起 8 Geth → Rust 验证者以 trusted-peers 入网 → 跑满 share 窗口至 epoch 切换。
5. 执行历史 Envelope/padding census 与 mixed-client replay。
6. 由双方协调 `neoXPkcs7StrictBlock` 激活高度和发布窗口；在激活后禁止 strict/legacy 混跑，不采用 ad-hoc rollback。

**审计判定：离线静态门禁已有较强证据，canonical Geth 本地迁移门禁已关闭，活体差分（G5/G6）与 fresh sync/重启一致性（G7）均已在主网活体基础设施上通过；G8 有 2026-07-19 的 full-gate 历史证据且前置已齐，剩余为当前 HEAD 上重跑混合 epoch（`wsl.exe` 已确认可用，具备执行条件）；G9 属治理协调。在 G8 当前代码重跑与 G9 完成前，当前不是 100% 协议等价结论。**
