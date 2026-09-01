# 审计概览

已完成 Neo X Rust 实现与 Neo X Geth oracle 的全量协议面静态审计，覆盖链参数/genesis、dBFT header extra、EVM/系统合约、Policy/交易池、Anti-MEV/TPKE、DKG、BEACON/2、dBFT/0 与同步/Engine API。

已修复并提交 Shanghai 激活门控下的 withdrawals_root 校验偏差、Beacon GetBlobs TTL、RPC simulation Policy 语义、同步活性与传播队列处理；相关代码和审计文档已推送至 `origin/neox`，完整审计报告位于 `docs/neox/reports/2026-09-01-FULL-AUDIT.md`。

本轮继续收敛审计结论：保留已验证 Reth 基线 `3bc71d43f7`；历史观察 tip `498847cb2e28` 已被远端实时 `3c31377d6533` 取代，当前 tip 尚未获取和审计，不提前更新 pinned baseline；修正审计报告的网络 bullet、历史测试状态和远端提交状态，并把 README 的 MainNet 证明措辞改为范围明确的记录性表述。核心 Neo X Anti-MEV/DKG、网络、consensus-engine、EVM 测试重新通过（45 + 47 + 14 + 28），对应 Neo X 脚本门禁 45 项通过；新增 EVM 回归覆盖 Osaka modexp 最低 gas/1024-byte 上限/33-byte complexity/真实预编译地址，以及 system-call 内 warm SLOAD 和跨交易不泄漏。严格 EVM clippy 通过。脚本门禁为 50 passed / 12 skipped / 1 个 Windows 主机 macOS bundle 清理环境失败；差分脚本语法与主网 genesis JSON 校验通过。单高度 RPC 门禁因本机 `127.0.0.1:8545` 返回 HTTP 502 阻塞，未计为通过。Reth 历史 compare 中 10 个上游提交未直接修改 `crates/neox`，但 `OverlayStateProviderFactory` 和 Engine API BAL 错误分类仍需覆盖 Neo X Policy、DKG、Anti-MEV、状态根、重组、重启与 Engine 委托路径；当前实时 tip 尚未获取和审计。仍需 Geth/Rust 跨实现向量、双节点活体验证、DKG epoch/recovery、RPC differential、Reth tip rehearsal 后才能宣称 Geth 混合网络 100% 一致。
