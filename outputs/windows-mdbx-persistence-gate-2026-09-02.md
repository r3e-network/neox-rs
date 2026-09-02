# Windows MDBX persistence 门禁：A/B 对照与根因收敛

日期：2026-09-02
仓库：`D:\Git\neox-rs`，HEAD `a6433067ab1dae91f087aa713799a3cced0b96d7`

## 结论（先说结果）

1. 针对 `reth-engine-tree::persistence::tests::test_read_only_consistency_across_reorg` 的本地修复尝试
   **对该门禁无效**，已还原、未提交。
2. 根因收敛为 **MDBX + Windows 的平台限制**，落在通用 Reth 持久化测试内，与 Neo X 协议无关。
3. vendored Reth 源码与 pinned baseline `3bc71d43f7101f772bbb4f9e15d3cdd58f60e958` **均未被改动**。
4. 远端 `origin/neox` 已确认在 `a6433067ab`，与本地一致；此前记录的“推送被 TLS 拦截”不成立。

## 被测对象

```text
reth-engine-tree
persistence::tests::test_read_only_consistency_across_reorg
crates/engine/tree/src/persistence.rs:744   （`provider_rw.commit()`，位于 reorg 线程）
```

## A/B 对照

同一 `target` 目录、同一环境变量、同一命令，唯一变量是补丁是否应用：

```bash
export CXXFLAGS="-D_WIN32_WINNT=0x0A00"
export BINDGEN_EXTRA_CLANG_ARGS="--target=x86_64-pc-windows-gnu -mmmx"
export CARGO_TARGET_DIR=target-msvc-gate
cargo test -p reth-engine-tree --lib -- persistence
```

| 组别 | 结果 | 失败位置 | 错误 |
|---|---|---|---|
| 应用补丁（生产侧 static file 修复） | 13 passed / 1 failed | `persistence.rs:744` | `Disconnect(Os 1224)` |
| 对照组（干净 HEAD，无补丁） | 13 passed / 1 failed | `persistence.rs:744` | `Disconnect(Os 1224)` |

两组错误值完全相同：

```text
called `Result::unwrap()` on an `Err` value:
Other(Disconnect(Os { code: 1224, kind: Uncategorized,
  message: "The requested operation cannot be performed on a file with a user-mapped section open." }))
```

即：补丁为**已验证的 no-op**，不构成对该门禁的修复，因此不入提交。

## 完整套件计数（主仓库 HEAD，干净工作树）

```bash
cargo test -p reth-engine-tree --lib
```

```text
test result: FAILED. 165 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;
```

即 `reth-engine-tree` 共 **166 项，165 通过，1 失败**，唯一失败仍是上述测试。

注意区分两个易混数字：**166** 是主仓库 pinned baseline 上的计数；此前记录中的 **169**
是最新 Reth tip 合并树的计数（上游新增了 BAL 下载等相关测试）。两者不应混用。

## 归属证明：失败路径是纯上游代码

将失败文件与 pinned 上游 Reth 基线逐字节比对：

```bash
git diff --stat 3bc71d43f7101f772bbb4f9e15d3cdd58f60e958 HEAD \
    -- crates/engine/tree/src/persistence.rs
git diff --stat 3bc71d43f7101f772bbb4f9e15d3cdd58f60e958 HEAD \
    -- crates/storage/provider/src/providers/static_file/
```

两条命令输出均为空，即 `persistence.rs` 与整个 `static_file/` 目录都与上游基线完全一致，
Neo X 未改动这些文件。

结合 A/B 对照与根因分析，结论闭合：
**该失败是未经修改的上游 Reth 测试，在 Windows + MDBX 下因平台限制而失败，
不是 Neo X 引入的回归。**

## Linux 交叉验证：本机当前不可行

该测试在 Linux 上应可通过（POSIX 允许截断已映射文件）。但本机条件不满足：

- `wsl.exe` 被安全策略列入程序黑名单，无法启动；
- 无 Docker。

因此"在 Linux 上复跑以取得真实通过结果"这一彻底解除阻塞的方案，
需在有 Linux/WSL 环境的机器上执行，本机暂无法完成。

## 被还原的补丁内容

- `crates/storage/provider/src/providers/static_file/manager.rs`
  新增 `remove_cached_provider_for_block()`。
- `crates/storage/provider/src/providers/static_file/writer.rs`
  新增 `invalidate_cached_reader()`，并在三处破坏性 prune 与 `delete_current_and_open_previous` 前调用。
- `crates/storage/provider/src/providers/static_file/mod.rs`
  测试中提前 `drop(sf_rw)`。

补丁机理本身成立（`StaticFileProviderInner.map` 是
`DashMap<(BlockNumber, Segment), LoadedJar>` 强引用，移除条目即释放 mmap），
但实测表明该门禁的阻塞**不在 static file 的 mmap 缓存路径上**。

### 另剔除一处无效 hack

补丁原还在 `persistence.rs` 测试中加入两行 `initialize_index()`。经查
`initialize_index()` 仅重建 `self.indexes`（段范围索引），
完全不触碰持有 mmap 的 `self.map`，对释放映射毫无作用，属掩盖而非修复，已还原。

## 根因收敛

测试会在同一数据目录额外打开**第二个只读 MDBX 环境**：

```rust
let secondary = ProviderFactoryBuilder::<MockNodeTypes>::default()
    .open_read_only(..., ReadOnlyConfig::from_datadir(provider_factory.db_ref().path()), ...)
```

随后 primary 执行 unwind 提交（`remove_block_and_execution_above(1)` → `commit()`），
需要收缩数据库文件；而 Windows 不允许在文件仍被用户映射时截断
（`ERROR_USER_MAPPED_FILE` / 1224），Linux 允许。因此该测试在 Windows 上结构性失败。

判定：通用 Reth 持久化测试 + MDBX Windows 平台限制。
未出现 Neo X 状态根、header、交易执行或协议断言差异。

## 本机工具链修正（不改变仓库内容）

PATH 中的 `cargo`/`rustc` 实际为 `C:\Program Files\Rust stable LLVM 1.95\bin`，
host 为 `x86_64-pc-windows-gnullvm`（并非 `rustup show` 显示的 msvc 工具链），
链接依赖 WinGet 的 llvm-mingw（clang 22），因此需两个环境变量才能完成构建：

| 问题 | 现象 | 解法 |
|---|---|---|
| RocksDB `env_win.cc` | `FILE_ID_INFO` / `FileIdInfo` 未声明 | `CXXFLAGS="-D_WIN32_WINNT=0x0A00"` |
| `reth-mdbx-sys` bindgen | `mmintrin.h` `__builtin_shufflevector` 错误 | `BINDGEN_EXTRA_CLANG_ARGS="--target=x86_64-pc-windows-gnu -mmmx"` |

注：曾临时向 WinGet llvm-mingw 的 `bin/x86_64-pc-windows-gnu.cfg` 追加宏作为替代方案，
验证有效但会改动系统状态，**已完整还原**并以环境变量方案取代。

## 未受影响 / 未改变

- pinned Reth baseline：`3bc71d43f7101f772bbb4f9e15d3cdd58f60e958`（保持不变）
- 上游 tip 审计：`0b3475a83e0712beb3d1f639ea467c55c5117412`（仅审计候选，未合入）
- Geth oracle：`f0e236838bb334c7c0d29eeca33533ed0cfda254`
- 协议实现代码：本轮零改动

## 仍未完成，不能宣称 100% 一致

RPC differential、Rust/Geth mixed-peer、mixed-client dBFT/DKG、fresh sync、
重启/崩溃恢复、persistence boundary、controlled reorg 等活体门禁尚未完成。
