# MDBX Linux 交叉验证结果（2026-09-02）

## 结论

本轮确认 Linux 下的跨平台类型修复可以编译并通过 targeted persistence 回归；尚未宣称完整 workspace 或全部 persistence/live 门禁通过。

## 修复

文件：`crates/storage/db/src/implementation/mdbx/mod.rs`

```rust
#[allow(clippy::unnecessary_cast)]
let message = if is_current_process(process_id as u32) {
```

该修改恢复 `mdbx_pid_t` 到 `u32` 的显式转换：Linux 下底层类型为 `i32`，而 `is_current_process` 接收 `u32`；局部属性用于抑制 Windows 平台上可能出现的 `unnecessary_cast` 警告。未修改协议实现、`reth-engine-tree` persistence 测试或 vendored Reth 代码。

## WSL Ubuntu 测试证据

### Persistence 选择器

命令：

```bash
cargo test -p reth-engine-tree --lib -- persistence
```

结果：

```text
14 passed; 0 failed; 0 ignored; 152 filtered
```

重点测试 `persistence::tests::test_read_only_consistency_across_reorg` 通过。

### Round 2 targeted exact

命令：

```bash
cargo test -p reth-engine-tree --lib \
  persistence::tests::test_read_only_consistency_across_reorg -- --exact --nocapture
```

结果：

```text
1 passed; 0 failed; 165 filtered
```

## 首轮异常结果

QA 首轮曾观察到：

```text
primary: signer must exist at block 1
```

该失败在后续 persistence suite 和 Round 2 targeted exact 回归中均未复现。当前没有足够证据证明其具体根因，因此不将其归因于协议实现、测试断言或某一确定的环境机制；应保留为一次未复现的异常观察。

## Windows 结果口径

Windows 上既有的：

```text
Disconnect(Os error 1224)
ERROR_USER_MAPPED_FILE
```

仍有 A/B 证据支持其属于 MDBX 与 Windows user-mapped section 生命周期的兼容性限制，且失败路径与 pinned Reth 基线一致。Linux targeted 通过增强了该平台归属判断，但不等同于完整 workspace 通过，也不替代 RPC differential、Rust/Geth mixed-peer、混合 dBFT/DKG、fresh sync、重启/崩溃恢复和 controlled reorg 门禁。

## 工作树与格式

- `git diff --check`：通过。
- 唯一 tracked 源码修改：`crates/storage/db/src/implementation/mdbx/mod.rs`。
- `crates/engine/tree/src/persistence.rs`：未修改。
- `crates/storage/provider/src/providers/static_file/`：未修改。
- 未提交、未推送。

## QA 路由

**NoOne**：Round 2 targeted 与 persistence suite 均通过，首轮异常未复现；本轮没有可确认的源码或 QA 测试缺陷。但完整 workspace/live 门禁仍需另行执行，不能由本报告替代。
