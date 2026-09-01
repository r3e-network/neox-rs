# Neo X 审计续审摘要

日期：2026-09-01

## 本轮完成

- 主仓库 `neox` 核心 Rust 门禁复核通过：
  - `reth-neox-antimev`：45 passed
  - `reth-neox-consensus-engine`：14 passed
  - `reth-neox-evm`：28 passed
  - `reth-neox-network`：47 passed
  - 合计：134 passed，0 failed
- 主仓库上述四个核心 crate 的严格 clippy 通过：`--all-targets --no-deps -- -D warnings`，无项目代码 warning。
- Neo X Python 门禁：45 passed，0 failed。
- `scripts` compileall 与 `git diff --check` 通过。
- 47 个 genesis JSON 文件及 `docs/neox/source-baseline.toml` 解析通过。

## Reth 最新 tip 受影响 workspace 复核

在临时合并工作树 `D:/Git/neox-rs-reth-tip-20260901` 中，使用独立 target 串行复跑：

- `reth-chain-state`：33 passed，0 failed
- `reth-downloaders`：82 passed，0 failed
- `reth-engine-primitives`：16 passed，0 failed
- `reth-engine-tree`：166 项中 165 passed，1 failed

唯一失败：

```text
persistence::tests::test_read_only_consistency_across_reorg
crates/engine/tree/src/persistence.rs:746
Disconnect(Os error 1224: The requested operation cannot be performed on a file with a user-mapped section open.)
```

该失败是 Reth 通用 persistence/reorg 测试在 Windows 上的 MDBX/NippyJar 映射生命周期问题。源码审阅确认测试会在 reorg commit 前持有 read-only provider；静态文件 reader 的 mmap 仍存活时执行文件截断或删除，Windows 可能返回 1224。该路径不涉及 Neo X dBFT、Anti-MEV、DKG、状态根或自定义协议断言。

## 版本结论

- Neo X Geth oracle：`bane-labs/go-ethereum@bane-main`，commit `f0e236838bb334c7c0d29eeca33533ed0cfda254`，本轮无新增 drift。
- Reth pinned baseline 仍为 `3bc71d43f7101f772bbb4f9e15d3cdd58f60e958`。
- 最新 Reth tip 仍为 `00d9e9e1cf654c8aa5cdf4acc5be3ea549a45b4b`，已完成 changed-file audit、无冲突 merge rehearsal、Neo X 核心测试与严格 clippy；不因 persistence 测试未全通过而升级 pinned baseline。

## 发布判断

当前可以确认：已按固定 Geth oracle 对齐并修复已确认的 Neo X 协议差异，主仓库核心静态/单元门禁通过。

当前不能宣称：完整 workspace、RPC differential、Rust/Geth mixed-peer wire interoperability、mixed-client dBFT/DKG、MainNet fresh sync、重启/崩溃恢复、persistence boundary 和 controlled reorg 已全部通过；因此仍不能宣称与 Neo X Geth 达到“100% 已证明一致”。
