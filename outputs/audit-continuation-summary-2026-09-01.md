# Neo X 全量协议审计续审摘要

## 本轮完成

- 复核固定 Neo X Geth oracle：`bane-main` commit `f0e236838bb334c7c0d29eeca33533ed0cfda254`，未发现新增 drift。
- 获取 Reth 最新 upstream `main`：`00d9e9e1cf654c8aa5cdf4acc5be3ea549a45b4b`，保存至 `refs/audit/reth-main-20260901`。
- 确认 pinned Reth baseline 仍为 `3bc71d43f7101f772bbb4f9e15d3cdd58f60e958`，未提前升级。
- baseline 到最新 tip 的 compare：15 个提交、61 个文件、1544 insertions / 502 deletions。
- `git merge-tree --write-tree HEAD refs/audit/reth-main-20260901` 无冲突，merge tree 为 `32781d001c66be731be9a6883d1ba08ddfe57f14`。
- 最新 tip 合并树核心 Neo X 测试通过：Anti-MEV/DKG 45、network 47、consensus-engine 14、EVM 28，均 0 failed。
- 最新 tip 合并树核心严格 clippy 通过，无项目代码 warning。

## 持久化门禁归因

受影响 workspace 的 `reth-engine-tree::persistence::tests::test_read_only_consistency_across_reorg` 未通过，但对照表明这不是最新 Reth tip 引入的 Neo X 协议回归：

- 最新 tip 合并树：在 `persistence.rs:707` 失败，测试夹具构造的 signer 在 block 1 不存在。
- 主仓库 pinned baseline：在 `persistence.rs:744` 失败，Windows MDBX `Disconnect(Os error 1224)`，原因是 user-mapped section 仍打开。
- 两次失败都发生在 Reth 通用持久化测试，未出现 Neo X 状态根、header、交易执行或协议断言差异。
- 失败点依赖测试夹具和 Windows MDBX snapshot/映射生命周期，当前记录为未解决的持久化测试/环境阻塞，不能记为完整 workspace 通过。

## 文档与状态

已更新：

- `docs/neox/source-baseline.toml`：最新 `tip_under_review`、历史 tip 链和固定 baseline。
- `docs/neox/reports/2026-09-01-FULL-AUDIT.md`：最新 Reth 证据、核心门禁和持久化对照结果。
- `overview.md`：当前审计状态和未完成 live gates。
- `.workbuddy/memory/2026-09-01.md`：追加本轮可复现事实。

格式校验：`git diff --check` 通过；`source-baseline.toml` TOML 解析通过。

## 当前发布判断

仍不能宣称与 Neo X Geth 已达到“100% 已证明协议一致”。RPC differential、Geth/Rust mixed-peer wire、混合 dBFT 出块、DKG/recovery、MainNet fresh sync、重启/崩溃恢复、persistence boundary 和 controlled reorg live gates 仍未全部完成。
