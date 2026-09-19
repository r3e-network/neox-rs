# Neo X 审计提交验证报告（G1–G4）

- **验证对象**：`2da0e8fc9c9a42359a9d13053a9d5cbc7259d22c`（neox 分支）
  - 代码改动提交：`e877f29b81` — P2 活性修复 + `decrypt_and_validate` 便利包装默认改 legacy + legacy padding 负向量测试
  - 文档提交：`2da0e8fc9c` — 2026-09-08 状态 / 完整审计与验证矩阵
- **验证范围声明**：本报告结论**仅针对 `2da0e8fc9c` 这一个提交**。验证期间仓库 HEAD 已前进到 `0dec37a55a`（后续又落了 `ccd6988beb` / `47f45660d0` / `f75b021b13` / `70c045abaa` / `0dec37a55a`），**本报告不覆盖当前 HEAD**。
- **验证方式**：独立复跑，未修改任何源码或测试文件（工作树在本轮门禁期间未被写入，除 `outputs/gate-20260909/` 下的日志工件）。
- **环境**：Windows + MSVC。所有 cargo 命令先 `source /c/Users/Administrator/AppData/Local/Temp/neox-msvc-env.sh`；`cargo 1.98.0 (797e8a9bc 2026-08-05)` / `rustc 1.98.0 (88d9e12ae 2026-08-18)`。
- **工具链说明**：每次因写 `target/` 报 `Access is denied (os error 5)` 时，均在关闭沙箱后重试，**未对源码做任何规避性修改**。

---

## 门禁结果总览

| 门禁 | 命令 | 退出码 | 结果 |
|------|------|:------:|------|
| G1 | `cargo test -p <8 包> --tests --lib` | 0（7/8 包）；`neox-rs` 101 | **391 passed / 0 failed**（+`neox-rs` bins 29 passed ⇒ 等效 420） |
| G2 | `cargo clippy -p <8 包> --all-targets --no-deps -- -D warnings` | **0** | **0 条 clippy warning** |
| G3 | `python -m unittest discover -s scripts/tests -t scripts/tests` | 1 | **57 passed / 12 skipped / 1 failed（env-blocked）** |
| G4 | `cargo test -p reth-neox-antimev` | 0 | **95 passed / 0 failed** |

**智能路由判定：NoOne**（未发现源码缺陷，亦未发现测试缺陷；G3 唯一失败为既有 Windows/bash 环境阻断，与改动前的基线逐项一致）。

---

## G1 — Neo X Rust 套件

命令：`cargo test -p <每包> --tests --lib`

| 包 | passed | failed | 备注 |
|----|-------:|-------:|------|
| `reth-neox-node` | 172 | 0 | |
| `reth-neox-antimev` | 95 | 0 | lib 47 + 5 个 geth_* 集成 48 |
| `reth-neox-network` | 47 | 0 | |
| `reth-neox-evm` | 28 | 0 | |
| `reth-neox-consensus` | 18 | 0 | |
| `reth-neox-chainspec` | 17 | 0 | |
| `reth-neox-consensus-engine` | 14 | 0 | |
| `neox-rs` | — | — | rc=101，见下 |
| **合计** | **391** | **0** | 7 个有测试目标的包 |

### `neox-rs` rc=101 的定性：包结构使然，非缺陷

原文：

```
error: no library targets found in package `neox-rs`
```

`bin/neox-rs/Cargo.toml` 只声明了两个 `[[bin]]`（`neox-rs`、`neox-dkg-migrate`），**没有 `[lib]`，也没有 `tests/` 目录**。`--lib` 下该包没有任何可测目标，cargo 因此报错退出。改用 `cargo test -p neox-rs --bins` 后：

```
test result: ok. 29 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s
```

**与 0908 基线的差异解释（391 vs 420）**

基线（`outputs/gate-20260908/GATE-REPORT-2026-09-08.md`）G1 实际命令是 `cargo test -p <8 包>`，**未加 `--tests --lib`**，因此额外收集到了 `neox-rs` 两个 bin 的 29 个单元测试。

> **391（`--tests --lib` 口径） + 29（`neox_rs` bins） = 420，与基线完全一致。**

差异**纯属口径差异，不存在任何测试丢失或源码缺陷**。

日志：`outputs/gate-20260909/G1-<pkg>.log`、`G1-summary.txt`、`G1b-neox-rs-bins.log`

---

## G2 — 严格 clippy

命令：

```
cargo clippy -p reth-neox-node -p reth-neox-antimev -p reth-neox-chainspec \
  -p reth-neox-network -p reth-neox-consensus -p reth-neox-consensus-engine \
  -p reth-neox-evm -p neox-rs --all-targets --no-deps -- -D warnings
```

- 退出码 **0**；clippy warning 数 **0**。
- 首次运行仅 `Finished ... in 2.85s`（全部 Fresh，证据偏弱）。为取得充分证据，先 `cargo clean -p` 清掉这 8 个包，再强制重跑同一命令（耗时 9m37s）：日志确认 **8 个目标包全部真实重新 lint**：

  | 目标包 | 日志行 |
  |---|---|
  | `reth-neox-consensus` | 629 |
  | `reth-neox-antimev` | 652 |
  | `reth-neox-chainspec` | 718 |
  | `reth-neox-consensus-engine` | 742 |
  | `reth-neox-evm` | 762 |
  | `reth-neox-network` | 772 |
  | `reth-neox-node` | 802 |
  | `neox-rs` | 804 |

- 日志中**唯一**一条 warning 是 cargo 对**第三方** crate `proc-macro-error2 v2.0.1` 的 future-incompat 提示，**非 clippy lint、非本仓代码**。

日志：`outputs/gate-20260909/G2-clippy.log`、`G2-clippy-forced.log`、`G2-clean.log`

---

## G3 — Python 工具单测

命令：`python -m unittest discover -s scripts/tests -t scripts/tests`

```
Ran 70 tests in 73.135s
FAILED (failures=1, skipped=12)
```

| 指标 | 数值 |
|---|---|
| passed | **57** |
| skipped | **12** |
| failed | **1** |

唯一失败项：`test_install_sh.InstallScriptStaticTest::test_macos_bundle_does_not_require_linux_only_prover`

### 定性：env-blocked（既有 Windows/bash 平台限制），非源码缺陷

证据链：

1. **不是网络下载问题。** 该 harness 通过 fake-curl fixture 供包（`FAKE_CURL_DIR` + `fixtures/urls.tsv` + 假 `curl`），全程无真实网络请求。因此不能归类为"网络下载/超时"。
2. **失败来自宿主机沙箱，而非本仓脚本。** 失败原文含：

   ```
   [safe-delete][SAFE_DELETE_FAIL_CLOSED] {"target":"/tmp/tmp.D8skkzENTU","reason":"trash-failed",
   "trashBin":"...\\resources\\vendor\\genie-trash/darwin-arm64"}
   ```

   而 `safe-delete` / `genie-trash` / `SAFE_DELETE` 在本仓 `scripts/install.sh` 以及全部仓内脚本中出现次数为 **0**。该删除 shim 由宿主运行环境注入。
3. **单独复跑呈现另一失败模式：bash 超时。** 单跑该用例得到 `subprocess.TimeoutExpired: ... bash.EXE, '../install.sh' timed out after 60 seconds`。`resolved_bash()` 在 Windows 上依赖 `shutil.which("bash")` 选中 PortableGit 的 MSYS bash，无法稳定跑完为 **macOS 目标**伪造的安装流程。
4. **与基线逐项一致。** 0908 基线（改动前）G3 为 `1 failed, 57 passed, 12 skipped`，**失败项完全相同**，证明该失败在本次改动之前即已存在。

严格表述：该项属**既有 Windows/bash 平台限制（env-blocked）**，而非"下载阻断"。按判定规则，**不得计为 PASS**，但也不构成 `2da0e8fc9c` 的回归。

日志：`outputs/gate-20260909/G3-python.log`

---

## G4 — Anti-MEV 跨实现向量 / PKCS#7

命令：`cargo test -p reth-neox-antimev`（退出码 0）

| 测试二进制 | passed | failed |
|---|---:|---:|
| `reth_neox_antimev` (lib) | 47 | 0 |
| `geth_reshare_vectors` | 16 | 0 |
| `geth_negative_vectors` | 15 | 0 |
| `geth_cross_vectors` | 9 | 0 |
| `geth_pkcs7_reachability` | 5 | 0 |
| `geth_ciphertext_admission` | 3 | 0 |
| **合计** | **95** | **0** |

- 与基线 95 passed 完全一致。
- 本次改动新增的 `legacy_mode_accepts_reference_client_padding_matrix`
  （`crates/neox/antimev/tests/geth_negative_vectors.rs:160`）已包含在 `geth_negative_vectors` 的 **15 passed** 中并通过，验证了 legacy 模式对 zero / oversized / inconsistent padding 的接受行为与参考实现一致。

日志：`outputs/gate-20260909/G1-reth-neox-antimev.log`

---

## 差异汇总（相对 0908 基线）

| 门禁 | 基线 | 本次实测 | 差异 | 归因 |
|------|------|---------|------|------|
| G1 | 420 passed | 391 + 29 = **420** | 0 | 基线未加 `--tests --lib`，多收 `neox_rs` bins 29 项；口径还原后一致 |
| G2 | 0 warnings | **0 warnings** | 0 | 一致 |
| G3 | 57 passed / 12 skipped / 1 failed | **57 / 12 / 1** | 0 | 一致；同一 env-blocked 失败项 |
| G4 | 95 passed | **95 passed** | 0 | 一致 |

**结论：四项门禁的计数在还原口径后与基线完全一致，未发现任何回归。**

---

## 可复现失败清单

| # | 项 | 类型 | 可复现 | 说明 |
|---|----|------|:------:|------|
| 1 | `test_macos_bundle_does_not_require_linux_only_prover` | env-blocked（Windows/bash 平台限制） | 是 | 宿主机 safe-delete shim + PortableGit bash 60s 超时；改动前基线同样失败 |
| 2 | `cargo test -p neox-rs --tests --lib` → rc=101 | 包结构使然（非失败） | 是 | 该包无 `[lib]`/无 `tests/`；`--bins` 下 29 passed |

**无任何由 `2da0e8fc9c` 引入的源码缺陷或测试缺陷。**

---

## 门禁判定

- **G1：PASS**（391 passed / 0 failed `--tests --lib`；含 `neox_rs` bins 则为 420，与基线一致）
- **G2：PASS**（rc=0，0 warnings，8 包真实重新 lint）
- **G3：PARTIAL / env-blocked**（57 passed / 12 skipped / 1 failed；唯一失败为既有 Windows/bash 平台限制，有证据，非本次改动引入）
- **G4：PASS**（95 passed / 0 failed）

> **路由判定：NoOne**（All tests pass；G3 的 1 项失败为既有环境阻断，非源码/测试缺陷）。
> 据此，**可以标记 G1–G4 绿灯**（G3 按既有口径记为 PARTIAL / env-blocked）。

---

## 与 team-lead 口径的两点偏差（需注意）

1. **G2 命令口径**：team-lead 本次要求 `--workspace --lib --examples --tests --benches --all-features`；本报告按 0908 基线口径执行 `-p <8 包> --all-targets --no-deps -- -D warnings`。workspace 级 / all-features 口径已在 **§5 补跑 A** 执行完毕。
2. **G3 内容口径**：team-lead 本次要求"格式检查 + 显式 nightly rustfmt"；本报告按 0908 基线口径执行的是 Python unittest。`rustfmt` 格式门禁已在 **§5 补跑 B** 执行完毕。

---

## 5. 正式口径补跑（workspace clippy + rustfmt）

> 本节为**独立口径的补充证据**，不属于 G1–G4。两条门禁均针对 `2da0e8fc9c`。

### 5.A workspace 级 clippy（正式口径）— **env-blocked（未得到 lint 结论）**

命令：

```
source /c/Users/Administrator/AppData/Local/Temp/neox-msvc-env.sh
cargo clippy --workspace --lib --examples --tests --benches --all-features -- -D warnings
```

结果：**退出码 101**，但**失败原因不是 lint**，而是 `--all-features` 激活的依赖需要本机不具备的原生构建前置条件，在"编译依赖"阶段即中止，clippy 从未对本仓代码产出 lint 结论。

| # | 阻断 | 失败 crate | 精确原文 | 归因 |
|---|------|-----------|---------|------|
| 1 | 缺 `perl` | `sha3-asm v0.1.6` | `thread 'main' panicked at ...\sha3-asm-0.1.6\build.rs:246:47: could not execute perl ("perl" "cryptogams/x86_64/keccak1600-x86_64.pl" ...): program not found`；构建脚本自述 `selected cryptogams script flavor: Some("masm")` | `--all-features` 下 `sha3-asm` 走 MASM 生成路径，构建期需要 `perl`。实测 `command -v perl` → **NOT on PATH**（仅 `C:\Program Files\Git\usr\bin\perl.exe` 存在，但不在 PATH 上）。 |
| 2 | jemalloc 不支持 Windows/沙箱 | `tikv-jemalloc-sys v0.6.1` | cargo 自述 `jemalloc support for \`x86_64-pc-windows-msvc\` is untested`；随后 `configure: error: C compiler cannot create executables`（exit 77）。stderr 显示宿主沙箱 safe-delete shim 再次介入：`[safe-delete][SAFE_DELETE_FAIL_CLOSED] {"reason":"trash-failed", ...}` | jemalloc 在 Windows/MSVC 上本就未受支持；`configure` 因沙箱删除 shim 使"探测 C 编译器可用性"失败。**与源码无关**。 |

**判定：env-blocked**。按判定规则**不得记为 PASS**，也**不能据此判定本仓存在 clippy 警告**。因此 workspace/all-features 口径下**本仓 clippy 结论仍为未知（未得到）**。

作为旁证：`--all-features` 未激活依赖、即 **§G2 的 8 包 `--all-targets` 口径**已真实重 lint 且 **0 warning**。差异来源可定位为 `--all-features` 激活的可选依赖（`sha3-asm` 的 MASM 路径、`tikv-jemalloc-sys`），而非本仓代码。

日志：`outputs/gate-20260909/G2-workspace-clippy.log`（含 `G2_WORKSPACE_RC=101`）、`env-probe.txt`

### 5.B 格式门禁（正式口径，显式 nightly rustfmt）— **FAIL（1 处 diff，本仓代码）**

命令（`cargo` 非 rustup shim，故以 nightly 工具链内 cargo 直接调用等效形式执行）：

```
export RUSTFMT="C:/Users/Administrator/.rustup/toolchains/nightly-x86_64-pc-windows-msvc/bin/rustfmt.exe"
"C:/Users/Administrator/.rustup/toolchains/nightly-x86_64-pc-windows-msvc/bin/cargo.exe" fmt --all -- --check
```

结果：**退出码 1**，`Diff in` 共 **1 个文件**。

| # | 文件 | 位置 | diff 摘要 |
|---|------|------|-----------|
| 1 | `crates/neox/node/src/dkg_executor.rs` | 行 213 附近（注释） | 注释行超宽，rustfmt 要求折行：<br>`- // record_receipt (crash / partial abort) does not leave the task inert until expiry.`<br>`+ // record_receipt (crash / partial abort) does not leave the task inert until`<br>`+ // expiry.` |

**该 diff 由本次审计提交引入。** `git blame -L 211,217` 显示相关行（211–217）全部归属 **`e877f29b810`（Jimmy，2026-09-08）**，即 `2da0e8fc9c` 所包含的代码改动提交。

说明：工作树的未跟踪输出文件为 `outputs/` 与点目录（`.codegraph/`、`.mimosa/` 等），**不含 `.rs`**，故 `fmt --all -- --check` 的结果**不受**未跟踪文件影响。

### 5.C 对"G1–G4 绿灯"结论的影响

- **否，不改变 G1–G4 的绿灯结论。** G1/G2/G4 在各自口径下实测通过，G3 的唯一失败经证据判定为既有环境阻断；§5.A 是环境阻断（未得到 lint 结论），§5.B 是**格式问题，不是 G1–G4 任何一条门禁的失败项**。
- **但需新增一项独立待办**：§5.B 的格式门禁为 **FAIL**，且该 diff **由 `e877f29b81` 引入**。这与团队 0908 报告"G1–G4 IS_PASS"的表述**并不矛盾**（格式门禁当时并未作为 G1–G4 的一部分执行），但如果 CI 的 `cargo fmt --check` 是硬门禁，则**该提交会使其失败**。

**建议**：由 Engineer 对 `crates/neox/node/src/dkg_executor.rs:213` 附近注释按 rustfmt 折行（纯格式改动，预计 1 行）；属低风险变更，但因涉及源码，需 Engineer 执行——**本验证任务未修改源码**。

---

## 工件索引（`outputs/gate-20260909/`）

| 文件 | 内容 |
|------|------|
| `G1-summary.txt` | G1 逐包退出码、耗时与解析后的 passed/failed |
| `G1-<pkg>.log` | G1 每包完整 `cargo test` 日志（含 `reth-neox-antimev` 即 G4） |
| `G1b-neox-rs-bins.log` | `cargo test -p neox-rs --bins` → 29 passed |
| `G2-clippy.log` | G2 首次运行（Fresh，2.85s） |
| `G2-clean.log` | 8 包 `cargo clean -p` |
| `G2-clippy-forced.log` | G2 强制重跑（9m37s，8 包真实 lint，0 warning） |
| `G3-python.log` | G3 unittest 全量输出（含失败 traceback） |
| `G2-workspace-clippy.log` | §5.A workspace/all-features clippy（rc=101，env-blocked，含 sha3-asm / jemalloc 原文） |
| `G3b-rustfmt-check.log` | §5.B nightly rustfmt `--check`（rc=1，1 处 diff） |
| `env-probe.txt` | `perl` / `sh` 可用性探测证据 |
| `blame-dkg.txt` | `dkg_executor.rs` 211–217 行 blame，证明格式 diff 由 `e877f29b810` 引入 |
| `run-g1.sh` / `run-g1b-g2.sh` | 门禁执行脚本（可复现） |
| `progress.log` | 执行进度与逐包退出码 |
