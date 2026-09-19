# Neo X Policy 验证流程文档

## 概述

Neo X 全节点在执行交易前会进行多层 Policy 验证，确保交易符合链上治理规则。本文档详细说明验证流程、系统合约调用顺序和 Envelope 特殊规则。

## 验证流程架构

```
┌─────────────────────────────────────────────────────┐
│          块执行开始 (Block Execution)                │
└─────────────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────────┐
│  阶段 1: 块级验证 (apply_pre_execution_changes)      │
│  ├─ 1.1 Base Fee 验证                               │
│  ├─ 1.2 系统合约 OnPersist 调用                      │
│  └─ 1.3 读取 Envelope 限制                          │
└─────────────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────────┐
│  阶段 2: 交易级验证 (execute_transaction)            │
│  ├─ 2.1 Envelope 计数检查                           │
│  ├─ 2.2 Policy 黑名单检查                           │
│  ├─ 2.3 Policy Gas 限制检查 (Envelope)              │
│  ├─ 2.4 Policy 优先费检查                           │
│  └─ 2.5 EVM 执行                                    │
└─────────────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────────┐
│  阶段 3: 交易提交 (commit_transaction)               │
│  └─ 状态变更提交到数据库                            │
└─────────────────────────────────────────────────────┘
```

---

## 阶段 1: 块级验证

### 1.1 Base Fee 验证

**位置**: `crates/neox/evm/src/executor.rs:182-193`

**目的**: 确保块头的 `baseFee` 与父状态的 `PolicyProxy.baseFee` 一致

```rust
fn validate_policy_base_fee(evm: &mut impl Evm<Tx = TxEnv>) -> Result<(), BlockExecutionError> {
    let expected = read_policy_storage(evm, policy_storage_key(POLICY_BASE_FEE_SLOT))?;
    let actual = U256::from(evm.block().basefee());
    if actual != expected {
        return Err(BlockValidationError::other(NeoXExecutionError::InvalidPolicyBaseFee {
            expected,
            actual,
        }).into());
    }
    Ok(())
}
```

**验证规则**:
- 从父状态读取 `PolicyProxy.baseFee` (slot 3)
- 与块头的 `baseFee` 字段比较
- 必须**完全相等**（不允许任何偏差）

**失败行为**: 整个块无效

### 1.2 系统合约 OnPersist 调用

**位置**: `crates/neox/evm/src/executor.rs:273-283`

**目的**: 执行共识奖励分配、验证器更新等系统级操作

```rust
fn apply_on_persist_calls(evm: &mut impl Evm<DB: DatabaseCommit>, dkg_active: bool) -> Result<(), BlockExecutionError> {
    if dkg_active {
        apply_system_call(evm, KEY_MANAGEMENT_PROXY_ADDRESS, on_persist_v2_selector())?;
    }
    let governance_selector = if dkg_active { on_persist_v2_selector() } else { governance_on_persist_selector() };
    apply_system_call(evm, GOVERNANCE_PROXY_ADDRESS, governance_selector)
}
```

**调用顺序**:

**DKG 激活前** (block < dkg_block):
1. `Governance.onPersist()` (0xa681dfec)
   - 验证器奖励分配
   - 投票者奖励分配
   - Epoch 切换检查

**DKG 激活后** (block >= dkg_block):
1. `KeyManagement.onPersistV2()` (0xf46754a1) - **先执行**
   - DKG 密钥轮换
   - 阈值密钥管理
   - Round 更新
2. `Governance.onPersistV2()` (0xf46754a1) - **后执行**
   - 验证器奖励分配
   - 投票者奖励分配
   - Epoch 切换检查

**系统调用特性**:
- 调用者: `SYSTEM_ADDRESS` (0xffff...fffe)
- Gas: 无限制
- 失败行为: 整个块无效（系统调用必须成功）
- 状态变更: 立即提交

### 1.3 读取 Envelope 限制

**位置**: `crates/neox/evm/src/executor.rs:87-98`

```rust
if block_number >= U256::from(self.anti_mev_block) {
    self.envelope_limit = self.inner.evm.db_mut()
        .storage(POLICY_PROXY_ADDRESS, policy_storage_key(POLICY_MAX_ENVELOPES_PER_BLOCK_SLOT))
        .map_err(BlockExecutionError::other)?
        .saturating_to();
}
```

**验证规则**:
- 只在 Anti-MEV 激活后生效
- 从 `PolicyProxy.maxEnvelopesPerBlock` (slot 6) 读取
- 用于后续交易验证

---

## 阶段 2: 交易级验证

### 2.1 Envelope 计数检查

**位置**: `crates/neox/evm/src/executor.rs:108-111`

**目的**: 限制每个块中 Envelope 交易的数量

```rust
if envelope && self.inner.evm.block().number() >= U256::from(self.anti_mev_block) {
    enforce_envelope_count(&mut self.envelope_count, self.envelope_limit)?;
}
```

**验证规则**:
- 只在 Anti-MEV 激活后生效
- `envelope_count < envelope_limit`
- 每个 Envelope 执行前递增计数
- **失败的 Envelope 会回滚计数** (L114-116)

**Envelope 识别**:
```rust
is_envelope(tx_env.tx_type, tx_env.kind.to().copied(), tx_env.data.as_ref())
```

判断条件:
- `tx_type == 0` (Legacy) 或 `tx_type == 1` (EIP-2930)
- `to != None` (有接收地址)
- `data[0..4] == 0x7368616c` ("shal" 前缀)

### 2.2 Policy 黑名单检查

**位置**: `crates/neox/evm/src/executor.rs:307-314`

**目的**: 拒绝黑名单地址的交易

```rust
let blacklist_key = policy_blacklist_storage_key(tx.caller);
let blocked = read_policy_storage(evm, blacklist_key)?;
if !blocked.is_zero() {
    return Err(BlockValidationError::other(NeoXExecutionError::BlockedSender {
        sender: tx.caller,
    }).into());
}
```

**存储键计算**:
```rust
// mapping(address => bool) isBlackListed
keccak256(address_padded || uint256(POLICY_BLACKLIST_SLOT))
```

**验证规则**:
- 从 `PolicyProxy.isBlackListed[sender]` (slot 1) 读取
- 非零值表示被封禁
- 任何非零值都拒绝交易

### 2.3 Policy Gas 限制检查 (Envelope)

**位置**: `crates/neox/evm/src/executor.rs:318-348`

**目的**: 验证 Envelope 交易的 Gas 分配正确性

仅当 `is_envelope_policy(tx.kind, tx.data)` 为 true 时执行:

```rust
if is_envelope_policy(tx.kind.to().copied(), tx.data.as_ref()) {
    // 检查 1: 外层 Gas 不超过策略最大值
    let maximum_gas = read_policy_storage(evm, policy_storage_key(POLICY_MAX_ENVELOPE_GAS_LIMIT_SLOT))?;
    if U256::from(tx.gas_limit) > maximum_gas {
        return Err(/* EnvelopeGasAbovePolicy */);
    }

    // 检查 2: 加密交易 Gas 不低于最小值
    let inner_gas = encrypted_gas(tx.data.as_ref());
    if inner_gas < MIN_ENCRYPTED_GAS_LIMIT {  // 21000
        return Err(/* EncryptedGasBelowMinimum */);
    }

    // 检查 3: 外层 Gas 足够覆盖内层
    if tx.gas_limit < u64::from(inner_gas) {
        return Err(/* EnvelopeGasBelowEncrypted */);
    }

    // 检查 4: 添加 Envelope 额外费用
    let envelope_fee = read_policy_storage(evm, policy_storage_key(POLICY_ENVELOPE_FEE_SLOT))?;
    minimum_tip = minimum_tip.saturating_add(envelope_fee);
}
```

**4 层 Envelope 验证**:

| 检查 | 条件 | 错误 |
|------|------|------|
| 1. Gas 上限 | `outer_gas <= PolicyProxy.maxEnvelopeGasLimit` | `EnvelopeGasAbovePolicy` |
| 2. 最小 Gas | `inner_gas >= 21000` | `EncryptedGasBelowMinimum` |
| 3. Gas 覆盖 | `outer_gas >= inner_gas` | `EnvelopeGasBelowEncrypted` |
| 4. 额外费用 | `minimum_tip += PolicyProxy.envelopeFee` | (在优先费检查中生效) |

**inner_gas 提取**:
```rust
// data[4..8] 是 uint32 小端编码
let inner_gas = u32::from_le_bytes(data[4..8]);
```

### 2.4 Policy 优先费检查

**位置**: `crates/neox/evm/src/executor.rs:316-361`

**目的**: 确保交易支付足够的优先费

```rust
let mut minimum_tip = read_policy_storage(evm, policy_storage_key(POLICY_MIN_GAS_TIP_CAP_SLOT))?;

// Envelope 需要额外费用
if is_envelope_policy(...) {
    let envelope_fee = read_policy_storage(evm, policy_storage_key(POLICY_ENVELOPE_FEE_SLOT))?;
    minimum_tip = minimum_tip.saturating_add(envelope_fee);
}

// 计算有效优先费
let base_fee = u128::from(evm.block().basefee());
let fee_cap_tip = tx.gas_price.saturating_sub(base_fee);
let priority_tip = tx.gas_priority_fee.unwrap_or(tx.gas_price);
let effective_tip = fee_cap_tip.min(priority_tip);

if U256::from(effective_tip) < minimum_tip {
    return Err(/* GasTipBelowPolicy */);
}
```

**有效优先费计算** (EIP-1559):
```
effective_tip = min(
    gas_price - base_fee,           // 费用上限减去基础费
    max_priority_fee_per_gas        // 明确指定的优先费
)
```

**验证规则**:
- 普通交易: `effective_tip >= PolicyProxy.minGasTipCap`
- Envelope: `effective_tip >= PolicyProxy.minGasTipCap + PolicyProxy.envelopeFee`

---

## Policy 存储布局

所有 Policy 参数存储在 `PolicyProxy` (0x1212...0002):

| 参数 | Slot | 类型 | 说明 |
|------|------|------|------|
| `isBlackListed[address]` | 1 | mapping | 黑名单 |
| `minGasTipCap` | 2 | uint256 | 最小优先费 |
| `baseFee` | 3 | uint256 | 当前基础费 |
| `envelopeFee` | 5 | uint256 | Envelope 额外费 |
| `maxEnvelopesPerBlock` | 6 | uint256 | 块 Envelope 限制 |
| `maxEnvelopeGasLimit` | 7 | uint256 | Envelope Gas 上限 |
| `sponsorRate` | 8 | uint256 | 赞助比例 (GovPaymaster) |

---

## 验证顺序的重要性

### 为什么块级验证在前？

1. **避免状态污染**: Base Fee 错误的块不应该执行任何交易
2. **系统一致性**: OnPersist 必须在所有交易前执行（奖励分配、验证器更新）
3. **性能优化**: 块级失败可以立即拒绝，不需要验证单个交易

### 为什么黑名单检查在最前？

1. **快速拒绝**: 封禁地址的交易应该最早被拒绝
2. **安全性**: 避免封禁地址执行任何状态读取
3. **成本**: 黑名单检查只需要 1 次存储读取

### 为什么 Gas 检查在优先费之前？

1. **逻辑顺序**: 先确保 Gas 分配合理，再检查费用
2. **Envelope 特性**: Gas 检查会影响 `minimum_tip`（添加 envelope_fee）

---

## 失败处理

### 块级验证失败
- **影响**: 整个块无效
- **行为**: 块被拒绝，不进入链
- **原因**: Base Fee 不匹配或系统调用失败

### 交易级验证失败
- **影响**: 单个交易被拒绝
- **行为**: 跳过该交易，继续执行后续交易
- **Envelope 特殊处理**: 失败的 Envelope 回滚计数，不占用限额

### 错误类型

所有 Policy 验证错误都通过 `NeoXExecutionError` 返回:

```rust
pub enum NeoXExecutionError {
    InvalidPolicyBaseFee { expected: U256, actual: U256 },
    EnvelopeNumberLimitReached { limit: u64 },
    EnvelopeGasAbovePolicy { gas_limit: u64, maximum_gas: U256 },
    EncryptedGasBelowMinimum { inner_gas: u32 },
    EnvelopeGasBelowEncrypted { gas_limit: u64, inner_gas: u32 },
    BlockedSender { sender: Address },
    GasTipBelowPolicy { sender: Address, effective_tip: u128, minimum_tip: U256 },
    SystemCallEvm { contract: Address, error: String },
    SystemCallFailed { contract: Address },
}
```

---

## 与 Geth 对比

### 相同点
- 系统合约调用机制
- Envelope 识别规则
- Policy 参数定义

### Neo X reth 更严格
1. **验证时机更早**: 所有 Policy 检查在 EVM 执行前完成
2. **Envelope 检查更完整**: 4 层 Gas 验证（Geth 只有 2 层）
3. **错误信息更详细**: 9 种具体错误类型

---

## 测试覆盖

Policy 验证有充分的测试覆盖:

- ✅ `rejects_a_blacklisted_sender` - 黑名单拒绝
- ✅ `enforces_base_fee_consensus` - Base Fee 验证
- ✅ `rejects_divergent_base_fee` - Base Fee 不匹配
- ✅ `rejects_envelope_above_the_policy_gas_limit` - Envelope Gas 上限
- ✅ `rejects_encrypted_gas_below_the_minimum` - 加密 Gas 最小值
- ✅ `rejects_envelope_below_the_encrypted_gas` - Gas 覆盖检查
- ✅ `enforces_policy_tip_for_regular_transactions` - 普通交易优先费
- ✅ `enforces_envelope_fee_on_top_of_the_minimum_tip` - Envelope 额外费用
- ✅ `applies_canonical_on_persist_before_the_dkg_fork` - OnPersist 调用

---

## 运营建议

### 监控指标

1. **Policy 违规率**:
   - 黑名单拒绝次数
   - Gas 不足拒绝次数
   - 优先费不足拒绝次数

2. **Envelope 使用**:
   - 每个块的 Envelope 数量
   - Envelope 限额使用率
   - Envelope 失败率

3. **系统合约健康**:
   - OnPersist 执行时间
   - OnPersist 失败次数（应该为 0）

### 故障排查

**症状**: 块验证失败（Base Fee 不匹配）
- **原因**: Proposer 使用了错误的 Base Fee
- **解决**: 检查 PolicyProxy 状态，确认 proposer 配置

**症状**: 大量交易被拒绝（GasTipBelowPolicy）
- **原因**: `minGasTipCap` 太高或用户未更新 gas price
- **解决**: 检查 Policy 参数，考虑治理调整

**症状**: Envelope 交易失败（EnvelopeNumberLimitReached）
- **原因**: 块已达到 Envelope 限制
- **解决**: 正常行为，用户需要等待下一个块

---

## 参考资料

- **代码位置**: `crates/neox/evm/src/executor.rs`
- **系统合约**: `crates/neox/evm/src/system_contracts.rs`
- **审计报告**: `docs/neox/audit/03-evm-executor-findings.md`

---

**最后更新**: 2026-09-16  
**文档版本**: v1.0
