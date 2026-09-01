# 审计概览

已完成 Neo X Rust 实现与 Neo X Geth oracle 的全量协议面静态审计，覆盖链参数/genesis、dBFT header extra、EVM/系统合约、Policy/交易池、Anti-MEV/TPKE、DKG、BEACON/2、dBFT/0 与同步/Engine API。

已修复并提交 Shanghai 激活门控下的 withdrawals_root 校验偏差，提交 `603c4f3d3b`。已生成完整审计报告 `docs/neox/reports/2026-09-01-FULL-AUDIT.md`，提交 `280217c6cb`。

本轮继续收敛审计结论：保留已验证 Reth 基线 `3bc71d43f7`，将官方当前 tip `498847cb2e28` 标记为待审计，不提前更新 pinned baseline；修正审计报告的网络 bullet、历史测试状态和远端提交状态，并把 README 的 MainNet 证明措辞改为范围明确的记录性表述。核心 Neo X 网络、consensus-engine、EVM 测试重新通过（47 + 14 + 24）。脚本门禁为 50 passed / 12 skipped / 1 个 Windows 主机 macOS bundle 清理环境失败；差分脚本语法与主网 genesis JSON 校验通过。单高度 RPC 门禁因本机 `127.0.0.1:8545` 返回 HTTP 502 阻塞，未计为通过。仍需双节点活体验证、DKG epoch/recovery、RPC differential、Reth tip rehearsal 后才能宣称 Geth 混合网络 100% 一致。
