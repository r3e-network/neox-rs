# PKCS#7 双模式跨实现向量回归（T05）— 2026-09-09

## 1. 结论

**PASS（字节级、离线）**。Geth 侧（高度门控补丁后）与 Rust 侧对**同一组字节完全相同的向量**在 legacy/strict 两种模式下的 accept/reject 判定**完全一致**。至此 G9 的三项技术要求（①双侧高度门控补丁 ②跨实现双模式向量回归 ③未配置时 legacy 字节兼容）**全部满足**；G9 剩余部分为纯治理/运营动作（两侧部署带门控二进制、设定同一 `neoXPkcs7StrictBlock` 激活高度、激活后禁止 strict/legacy 混跑）。

## 2. 证据链

- Geth 侧被测代码：`D:\Git\neox-geth`（HEAD `f0e236838bb334c7c0d29eeca33533ed0cfda254` + 高度门控补丁 `outputs/geth-pkcs7-strict-height-gate.patch`，sha256 `368c8f5462c3aac8d23280dc4353cd71166c32e324db50f4fd61b037c585a223`）。
- 探测器：`docs/neox/vectors/geth-exporter/neox_pkcs7_probe_test.go`（升级为双模式记录，新增 `strict_accept` 字段），拷入 Geth 树 `antimev/` 运行后移除。
- 密钥向量：`docs/neox/vectors/geth-tpke-vectors.json`（早前审计导出的共享 `recovered_aes_key_g1_uncompressed`）。
- 结果工件：`outputs/pkcs7-dual-mode-probe-20260909.json`（含每个用例的密文 hex，可复放）。
- Rust 侧对照：`crates/neox/antimev/tests/geth_negative_vectors.rs` 的 `PKCS7_VALID` / `PKCS7_ZERO_PADDING` / `PKCS7_OVERSIZED_PADDING` / `PKCS7_INCONSISTENT_PADDING` 常量与 `legacy_mode_accepts_reference_client_padding_matrix`（:160）。
- **字节级一致性**：以脚本比对 probe 输出密文与 Rust 常量，四个向量全部 `BYTE_EXACT`（`ALL_BYTE_EXACT`）。

## 3. 判定矩阵（同一字节向量，两侧 × 双模式）

| 向量 | 构造 | Rust legacy | Geth legacy（实测） | Rust strict | Geth strict（实测） |
|---|---|---|---|---|---|
| PKCS7_VALID | 112B 载荷 + 16×0x10 规范填充 | accept | **ACCEPTED len=112** | accept | **ACCEPTED len=112** |
| PKCS7_ZERO_PADDING | 末字节 0x00（pad=0） | accept | **ACCEPTED len=128**（原样返回） | reject | **REJECTED** |
| PKCS7_OVERSIZED_PADDING | 末字节 0x14（pad=20>16） | accept | **ACCEPTED len=108** | reject | **REJECTED** |
| PKCS7_INCONSISTENT_PADDING | 声明 8 字节填充但前 7 字节非 0x08 | accept | **ACCEPTED len=120** | reject | **REJECTED** |

- Geth strict 拒绝路径与 Rust `tpke.rs:432-441` 逐条对应（pad==0 / pad>blockSize / 尾字节不一致均报 `invalid pkcs7 padding`）。
- Geth legacy 输出长度（128/108/120）与基线宽松行为一致；未配置 `neoXPkcs7StrictBlock` 的链（MainNet/T4）升级后行为零变化。

## 4. 对 G9 状态的更新

- `docs/neox/reports/2026-09-07-VERIFICATION.md` G9 行：技术阻塞已消除 → **技术要求全部满足，仅余治理/运营**。
- 运营纪律（强制，摘自设计 §6.3）：①全量部署两侧带门控二进制 → ②观察（banner 无 `NeoXPkcs7Strict` 行）→ ③两侧 genesis 同一次变更设定**同一**激活高度 H（须在未来、留足观察窗口）→ ④到 H 后双方同时 strict；禁止混跑、禁止 ad-hoc rollback（`CheckCompatible` 会拦截但不得依赖其作为回滚手段）。
- 激活前后留痕：Geth `dumpconfig`/启动 banner + Rust `is_pkcs7_strict_active_at_block(H-1)`/`(H)` 输出。

## 5. 遗留（不阻塞 G9）

- `eth/tracers/api.go` fork override 未覆盖 `NeoXPkcs7StrictBlock`（P2，不影响共识；既有代码同样遗漏 `NeoXEthSigBlock`）。
- probe 密文为固定 128 字节块构造；如需更宽覆盖可在后续审计轮扩展（当前四类已覆盖分歧判定的全部分支）。
