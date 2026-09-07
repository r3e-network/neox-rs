# Neo X 审计状态与进度审计 — 2026-09-08

## 1. 概览（TL;DR）

审计已从「PKCS#7 跨实现分歧高风险 + 无法证明 canonical Geth 可追溯」推进到
「PKCS#7 已有版本化硬分叉门控修复、Geth canonical 门禁 CLOSED、离线门禁 G1–G4 可执行」。
**当前未发现 P0（共识分叉级）缺陷**。剩余开放项集中在**活体验证（G5–G8）与运营/治理（G9）**，
因此仍**不能宣称「100% 协议等价已证明」**。

- 审计 HEAD：`256998be02`（`neox` 分支，相对 `origin/neox` ahead 3，含 `neox-v2.5.2`）
- 最近审计依据：[2026-09-07-FULL-AUDIT.md](../docs/neox/reports/2026-09-07-FULL-AUDIT.md)

## 2. 固定基线（Pinned Baselines）

| 组件 | Pin |
|---|---|
| Reth 审计基线 | `3bc71d43f7101f772bbb4f9e15d3cdd58f60e958` |
| Neo X Geth oracle | `f0e236838bb334c7c0d29eeca33533ed0cfda254`（`bane-main`, `0.7.0-dev`）|
| Neo X 发布版本 | `neox-v2.5.2`（提交 `b23feaeac6`）|
| Geth 补丁工件 | `outputs/geth-pkcs7-strict.patch`，SHA-256 `a2cc2fa3…cb4f281`（`+55/-6`，三文件）|

## 3. 已关闭门禁（有证据）

| 门禁 | 结论 | 证据 |
|---|---|---|
| Geth PKCS#7 canonical checkout / apply | **CLOSED 2026-09-05** | `D:\Git\neox-geth` 以 `git fetch --depth 1` + `checkout --detach FETCH_HEAD` 得到 `HEAD == f0e236…`；`git apply` 得 `3 files changed, 55 insertions, 6 deletions`；`gofmt -l` 干净；`go test ./crypto/tpke` 通过；26 个 `TestPKCS7UnPaddingStrict` 子测试通过；`go vet` 干净 |
| PKCS#7 历史重放 / activation 风险（Rust 侧设计） | **已设计并落地** | 提交 `2d6231012f`：新增可选 genesis 字段 `neoXPkcs7StrictBlock` 与 `Pkcs7Strict` 硬分叉；按区块高度选择 legacy/strict；未配置 fork 的链与未打补丁参考客户端字节兼容 |
| `reth-neox-antimev` 向量回归 | **PASS** | 45 unit + 3 admission + 9 cross + 14 negative + 4 reachability + 16 reshare + 0 doctest，全部通过 |
| `reth-neox-node` 测试解锁 | **PASS** | 159 unit/integration（`pool`/`proposal`/`reconstruction`/`sync`/`validator`/`dkg`），此前 Windows GNU/Clang 环境阻断已通过工具链配置解除 |
| MDBX Linux PID 类型 | **已修复** | 提交 `b7c7c619ef`（`process_id as u32`）|
| Windows MDBX `Disconnect(1224)` | **判定为平台限制** | `ERROR_USER_MAPPED_FILE`，A/B 对照结果一致，非 Neo X 协议缺陷 |

## 4. 进行中 / 未提交的工作（需复核）

> **更新（2026-09-08 晚间）**：以下改动已通过 G1–G4 复核（G1 420 passed、G2 0 warnings、G3 PARTIAL 环境阻断、G4 95 passed）并提交为 `e877f29b81`；本节保留为提交前快照记录。

工作树存在 **7 个已修改文件、约 +1310/-1145 行未提交改动**，对应 9-07 晚间至 9-08 的继续修复：

- `crates/neox/node/src/antimev.rs`：`decrypt_and_validate` 便利包装默认改为 **legacy**（`strict: false`），注释说明 MainNet/T4 省略 `neoXPkcs7StrictBlock`，历史重建须匹配未打补丁参考客户端
- `crates/neox/node/src/sync.rs`、`sync/anti_mev.rs`：Anti-MEV 瞬时重试 backoff 唤醒
- `crates/neox/node/src/sync/sidecar.rs`：错失通知场景的 sidecar 归档补齐
- `crates/neox/node/src/dkg_executor.rs`：较大重构（531→543 行）
- `crates/neox/antimev/tests/geth_negative_vectors.rs`：legacy padding 矩阵测试补充
- `docs/neox/README.md`：文档同步

**风险提示**：这些改动**尚未提交、尚未重新跑通 G1–G4 门禁**，其结论不能计入“已验证”。
`decrypt_and_validate` 默认值由 strict 改 legacy 是**安全语义变更**，必须确认所有生产调用路径都走
带 chainspec 门控的 `decrypt_and_validate_with_mode`，否则 activation 后高度可能被误用 legacy 解析。

## 5. 仍开放的门禁（不得宣称通过）

按 [2026-09-07-VERIFICATION.md](../docs/neox/reports/2026-09-07-VERIFICATION.md) 的 G1–G9 矩阵：

| Gate | 内容 | 状态 |
|---|---|---|
| G1–G4 | Rust crate 套件 / clippy / Python 工具 / Anti-MEV 跨实现向量 | 本机可跑，需在工作树改动后**重跑确认** |
| G5 | RPC differential | 需两个活体 HTTP endpoint — **BLOCKED**（本机 8545/8546/8551 等均未监听）|
| G6 | 全历史 differential | 需已同步本地 + 参考节点 — **BLOCKED** |
| G7 | Fresh-datadir MainNet sync | 需长时运行 + peers — **BLOCKED** |
| G8 | 混合客户端 DKG epoch | 需 Geth + prover + ZK ceremony 工件 — **BLOCKED** |
| G9 | PKCS#7 strict 双方协同激活 | **治理/运营动作**：两客户端都打补丁 + 设定激活高度；activation 后禁止 strict/legacy 混跑 |

其他长期未关闭项：链上 `KeyManagement` 合约 PVSS commitment/renovate 校验强度证明、
Geth `CipherText.Verify()` 零调用（活性停滞，非状态分叉）、受控 reorg 注入（仓库无 standalone injector）。

## 6. 文档一致性缺陷（本轮发现）

`overview.md` 仍停留在 9-02 口径，与当前事实冲突，需更新：

- 仍写「oracle 目录仍无正式 Geth commit」「PKCS#7 风险尚不能标记为正式关闭」——
  但 canonical Geth 门禁已于 **9-05 CLOSED**（`D:\Git\neox-geth`，真实 checkout/apply/测试）
- 仍写 RPC differential、mixed-peer、fresh sync 等「未全部关闭」未区分 **已设计完成（PKCS#7 activation）** 与 **仍 BLOCKED（G5–G8）**
- 未反映 `neox-v2.5.2` 发布、P2 活性修复、以及 `reth-neox-node` 159 项测试解锁

## 7. 建议下一步（按依赖顺序）

1. ✅ **已完成（2026-09-08）**：G1–G4 在最终工作树重跑通过（G1 420、G2 0 warnings、G3 PARTIAL、G4 95）；改动已提交为 `e877f29b81`
2. ✅ **已完成（2026-09-08）**：`overview.md` 已刷新为当前审计口径
3. **G9 运营推进**：与 Geth 侧协调 `neoXPkcs7StrictBlock` 激活高度，明确 activation 后禁止 legacy 混跑与回滚策略
4. **G5–G8 环境准备**：准备两个 fresh datadir + 参考 RPC、Geth 二进制、prover 与 ZK ceremony 工件
5. 执行历史 Envelope census：使用 `scripts/neox-scan-history-pkcs7.py` 扫描历史 padding 风险（注意：该扫描器无法解密阈值密文，只能界定迁移风险范围，不能替代 padding 验证）
