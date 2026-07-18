//! Neo X native system-contract addresses and storage layout.

use alloy_primitives::{address, keccak256, Address, B256, U256};

/// Caller reserved for consensus-triggered system-contract invocations.
pub const SYSTEM_ADDRESS: Address = address!("fffffffffffffffffffffffffffffffffffffffe");

/// Proxy administrator for the Governance contract.
pub const GOVERNANCE_PROXY_ADMIN_ADDRESS: Address =
    address!("1212000000000000000000000000000000000000");
/// Governance proxy responsible for validator voting and reward accounting.
pub const GOVERNANCE_PROXY_ADDRESS: Address = address!("1212000000000000000000000000000000000001");
/// Policy proxy holding transaction-fee and blacklist policy.
pub const POLICY_PROXY_ADDRESS: Address = address!("1212000000000000000000000000000000000002");
/// Governance reward proxy used as the dBFT block beneficiary.
pub const GOVERNANCE_REWARD_PROXY_ADDRESS: Address =
    address!("1212000000000000000000000000000000000003");
/// Bridge proxy.
pub const BRIDGE_PROXY_ADDRESS: Address = address!("1212000000000000000000000000000000000004");
/// Bridge management proxy.
pub const BRIDGE_MANAGEMENT_PROXY_ADDRESS: Address =
    address!("1212000000000000000000000000000000000005");
/// Non-upgradeable bridge treasury.
pub const TREASURY_ADDRESS: Address = address!("1212000000000000000000000000000000000006");
/// Committee multisignature proxy.
pub const COMMITTEE_MULTISIG_PROXY_ADDRESS: Address =
    address!("1212000000000000000000000000000000000007");
/// DKG and threshold-key management proxy.
pub const KEY_MANAGEMENT_PROXY_ADDRESS: Address =
    address!("1212000000000000000000000000000000000008");
/// First reserved system-contract proxy.
pub const RESERVED_ONE_PROXY_ADDRESS: Address =
    address!("1212000000000000000000000000000000000009");
/// Second reserved system-contract proxy.
pub const RESERVED_TWO_PROXY_ADDRESS: Address =
    address!("121200000000000000000000000000000000000a");

/// Solidity storage slot of `Policy.isBlackListed`.
pub const POLICY_BLACKLIST_SLOT: u64 = 1;
/// Solidity storage slot of `Policy.minGasTipCap`.
pub const POLICY_MIN_GAS_TIP_CAP_SLOT: u64 = 2;
/// Solidity storage slot of `Policy.baseFee`.
pub const POLICY_BASE_FEE_SLOT: u64 = 3;
/// Solidity storage slot of `Policy.envelopeFee`.
pub const POLICY_ENVELOPE_FEE_SLOT: u64 = 5;
/// Solidity storage slot of `Policy.maxEnvelopesPerBlock`.
pub const POLICY_MAX_ENVELOPES_PER_BLOCK_SLOT: u64 = 6;
/// Solidity storage slot of `Policy.maxEnvelopeGasLimit`.
pub const POLICY_MAX_ENVELOPE_GAS_LIMIT_SLOT: u64 = 7;

/// Returns the `PolicyProxy` storage key for `isBlackListed[account]`.
pub fn policy_blacklist_storage_key(account: Address) -> U256 {
    let mut input = [0_u8; 64];
    input[12..32].copy_from_slice(account.as_slice());
    input[32..].copy_from_slice(&U256::from(POLICY_BLACKLIST_SLOT).to_be_bytes::<32>());
    U256::from_be_bytes(keccak256(input).0)
}

/// Returns a scalar Solidity storage slot as a revm storage key.
pub const fn policy_storage_key(slot: u64) -> U256 {
    U256::from_limbs([slot, 0, 0, 0])
}

/// Returns the first four bytes of `keccak256(signature)` as an ABI function selector.
pub fn function_selector(signature: &str) -> [u8; 4] {
    let hash: B256 = keccak256(signature.as_bytes());
    hash[..4].try_into().expect("four-byte selector slice")
}

/// ABI selector for `Governance.onPersist()`.
pub fn governance_on_persist_selector() -> [u8; 4] {
    function_selector("onPersist()")
}

/// ABI selector for `Governance.onPersistV2()` and `KeyManagement.onPersistV2()`.
pub fn on_persist_v2_selector() -> [u8; 4] {
    function_selector("onPersistV2()")
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{b256, B256};

    #[test]
    fn policy_scalar_slots_match_solidity_layout() {
        assert_eq!(policy_storage_key(POLICY_MIN_GAS_TIP_CAP_SLOT), U256::from(2));
        assert_eq!(policy_storage_key(POLICY_BASE_FEE_SLOT), U256::from(3));
        assert_eq!(policy_storage_key(POLICY_ENVELOPE_FEE_SLOT), U256::from(5));
        assert_eq!(policy_storage_key(POLICY_MAX_ENVELOPES_PER_BLOCK_SLOT), U256::from(6));
        assert_eq!(policy_storage_key(POLICY_MAX_ENVELOPE_GAS_LIMIT_SLOT), U256::from(7));
    }

    #[test]
    fn blacklist_key_uses_solidity_mapping_layout() {
        let account = address!("34a3b2abb99b4c128acf61dcbbd1fcac0b161652");
        let expected: B256 =
            b256!("72591b613deaf8f116731868959a1ff5d89eb9807bf733cb6d67619b81f0d14d");

        assert_eq!(B256::from(policy_blacklist_storage_key(account)), expected);
    }

    #[test]
    fn persistence_selectors_are_canonical() {
        assert_eq!(governance_on_persist_selector(), [0xa6, 0x81, 0xdf, 0xec]);
        assert_eq!(on_persist_v2_selector(), [0xf4, 0x67, 0x54, 0xa1]);
    }
}
