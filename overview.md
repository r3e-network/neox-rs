# 审计概览

已完成 Neo X Rust 实现与 Neo X Geth oracle 的全量协议面静态审计，覆盖链参数/genesis、dBFT header extra、EVM/系统合约、Policy/交易池、Anti-MEV/TPKE、DKG、BEACON/2、dBFT/0 与同步/Engine API。

已修复并提交 Shanghai 激活门控下的 withdrawals_root 校验偏差，提交 `603c4f3d3b`。已生成完整审计报告 `docs/neox/reports/2026-09-01-FULL-AUDIT.md`，提交 `280217c6cb`。

主要开放项：TPKE commitment 绑定的跨实现向量、Beacon/dbft 混合互通、DKG epoch/recovery 活体门禁、Reth 最新 tip 的独立同步演练。Windows blst/aws-lc C 编译遇到 target 权限错误，脚本门禁有 1 个主机特定失败，目标测试未记为通过。
