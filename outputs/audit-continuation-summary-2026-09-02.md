# Neo X 审计续审摘要

日期：2026-09-02

## 上游核验

- Neo X Geth oracle `bane-main` 仍为 `f0e236838bb334c7c0d29eeca33533ed0cfda254`，本轮无新增 drift。
- Reth `main` 已更新到 `0b3475a83e0712beb3d1f639ea467c55c5117412`，保存为 `refs/audit/reth-main-20260902`。
- 相对上一审计 tip `00d9e9e1cf654c8aa5cdf4acc5be3ea549a45b4b`：4 个提交、12 个文件、483 insertions / 156 deletions。
- 相对 pinned baseline `3bc71d43f7101f772bbb4f9e15d3cdd58f60e958`：19 个提交、68 个文件、2019 insertions / 650 deletions。
- 新 tip 没有直接修改 `crates/neox`。关键间接影响为 engine tree 下载/保留 BAL、Overlay multiproof v2、blob sidecar 转换并发，以及 bad block hash 日志。
- merge rehearsal 无冲突：树 `661a569b35f40fe2352b1c2688815f4cbe08fea5`；用于测试的临时 merge commit `2859683d9532c92345bca69474f187e3c4a1de5b`。

## 最新 tip 合并树门禁

Neo X 核心测试全部通过：

- `reth-neox-antimev`：45 passed
- `reth-neox-consensus-engine`：14 passed
- `reth-neox-evm`：28 passed
- `reth-neox-network`：47 passed
- 合计：134 passed，0 failed
- 核心严格 clippy `--all-targets --no-deps -- -D warnings`：通过，无项目代码 warning

受影响包：

- `reth-chain-state`：33 passed，0 failed
- `reth-downloaders`：82 passed，0 failed，包含新增 BAL 下载测试
- `reth-engine-primitives`：16 passed，0 failed
- `reth-engine-tree`：169 项中 168 passed，1 failed

唯一失败仍为：

```text
persistence::tests::test_read_only_consistency_across_reorg
crates/engine/tree/src/persistence.rs:746
Disconnect(Os error 1224: The requested operation cannot be performed on a file with a user-mapped section open.)
```

该失败发生在通用 Reth persistence/reorg 测试的 Windows MDBX/NippyJar mmap 生命周期路径，与 Neo X dBFT、Anti-MEV、DKG、状态根或自定义协议断言无关。它阻止完整受影响 workspace 记为通过，也阻止升级 pinned Reth baseline。

## 当前结论

本轮确认新 Reth tip 不引入 Neo X 核心测试或 clippy 回归，且新 BAL/Overlay/sidecar 相关通用测试通过。pinned baseline 保持不变。

仍未完成的 100% 门禁包括：双客户端 RPC differential、Rust/Geth mixed-peer BEACON/2 与 dBFT/0、mixed-client dBFT/DKG、TPKE/PreCommit/Envelope 跨实现 vectors、MainNet fresh sync、重启/状态和 static-file equality、crash recovery、persistence boundary、unwind 与 controlled reorg。当前不能宣称与 Neo X Geth 达到“100% 已证明一致”。
