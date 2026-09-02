# 审计续审概览

本轮继续完成 Neo X Rust 与 Neo X Geth oracle 的 Anti-MEV/TPKE 跨实现审计，并整理 Geth 严格 PKCS#7 迁移工件。

## 本轮已完成

- Geth oracle 侧严格 PKCS#7 解填充迁移补丁：`outputs/geth-pkcs7-strict.patch`
- 配套审计记录：`outputs/geth-pkcs7-strict-audit.md`
- 补丁仅涉及 `crypto/tpke/util.go`、`crypto/tpke/aes.go`、`crypto/tpke/util_test.go`。
- `pkcs7UnPadding` 现在要求整块输入、padding 在 `1..=blockSize`，并验证全部尾部字节；`AESDecrypt` 在 `CryptBlocks` 前拒绝空/非整块 ciphertext，避免 malformed input panic。
- 在 oracle 快照执行：三文件 `gofmt -d` 退出码 0；`go.exe -C D:/Git/neox-oracle-geth test ./crypto/tpke` 退出码 0。
- 使用固定 baseline `f0e236838bb334c7c0d29eeca33533ed0cfda254` 的原始 blob，并在关闭换行转换的临时基线中验证：正向 `git apply --check` 退出码 0；oracle 快照反向 `git apply --reverse --check` 退出码 0；numstat 为 util.go 10/5、aes.go 4/1、util_test.go 41/0。
- 补丁 SHA-256：`c23bc475d50b1f7ad6fd7626f488bdddd99d371a2f1d03605843d54fb75c1280`。
- 更正工件已提交到 Rust 仓库本地提交 `19c4ee43d644c38c7c1ed1a52df8232a8a81cf44`，未推送；oracle 目录仍无正式 Geth commit。

## 必须保持开放的门禁

PKCS#7 风险尚不能标记为正式关闭。仍需在正式、可追溯的 Geth 工作树中应用补丁并提交；完成全量 Geth/Rust Anti-MEV、dBFT 和共识测试；执行历史回放、malformed padding 扫描、protocol activation/version gate 和 mixed-client replay。不得在 activation 后混用 strict 与 legacy validator，也不得通过放宽 Rust、双解析或 ad-hoc rollback 规避分歧。

此前 MDBX Linux PID 类型修复提交 `b7c7c619eff52716fe19b2156e8bffe3494c4b17` 保持不变。WSL persistence targeted 结果为 14/14 与 exact 1/1；Windows `ERROR_USER_MAPPED_FILE` 仍归类为通用 MDBX + Windows 平台限制，不等同于 Neo X 协议缺陷。RPC differential、mixed-peer、混合 dBFT/DKG、fresh sync、崩溃恢复、controlled reorg、链上 PVSS 强度和 `CipherText.Verify()` 零调用风险仍未全部关闭。
