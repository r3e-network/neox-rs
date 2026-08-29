//! Neo X execution-layer extensions for Reth and revm.
//!
//! Neo X follows Ethereum execution rules with a small set of consensus-critical differences:
//! the DKG fork activates MCOPY and the Cancun/Prague cryptographic precompiles early, and native
//! system contracts govern fees, validator rotation, and Anti-MEV state.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod config;
mod executor;
mod factory;
mod system_contracts;

pub use config::NeoXEvmConfig;
pub use executor::{NeoXBlockExecutor, NeoXBlockExecutorFactory, NeoXExecutionError};
pub use factory::{NeoXEvmFactory, NeoXPrecompiles};
// Explicit re-export instead of a glob so the public system-contract surface stays reviewable:
// every name this crate exposes at its root is listed here, and adding or removing one is a
// visible diff.
pub use system_contracts::{
    address_mapping_storage_key, dynamic_array_element_storage_key, function_selector,
    governance_current_consensus_storage_key, governance_on_persist_selector,
    governance_pending_consensus_storage_key, mapping_storage_key, nested_uint_mapping_storage_key,
    on_persist_v2_selector, policy_blacklist_storage_key, policy_storage_key,
    uint_mapping_storage_key, BRIDGE_MANAGEMENT_PROXY_ADDRESS, BRIDGE_PROXY_ADDRESS,
    COMMITTEE_MULTISIG_PROXY_ADDRESS, GOVERNANCE_CURRENT_CONSENSUS_SLOT,
    GOVERNANCE_CURRENT_EPOCH_START_HEIGHT_SLOT, GOVERNANCE_EPOCH_DURATION_SLOT,
    GOVERNANCE_PAYMASTER_PROXY_ADDRESS, GOVERNANCE_PENDING_CONSENSUS_SLOT,
    GOVERNANCE_PROXY_ADDRESS, GOVERNANCE_PROXY_ADMIN_ADDRESS, GOVERNANCE_REWARD_PROXY_ADDRESS,
    GOVERNANCE_SHARE_PERIOD_DURATION_SLOT, KEY_MANAGEMENT_AGGREGATED_COMMITMENTS_SLOT,
    KEY_MANAGEMENT_MESSAGE_PUBKEYS_SLOT, KEY_MANAGEMENT_PROXY_ADDRESS,
    KEY_MANAGEMENT_RECOVER_MSGS_SLOT, KEY_MANAGEMENT_RESHARE_MSGS_SLOT,
    KEY_MANAGEMENT_RESHARE_PVSS_SLOT, KEY_MANAGEMENT_ROUND_NUMBER_SLOT,
    KEY_MANAGEMENT_SHARED_PUBS_SLOT, KEY_MANAGEMENT_SHARE_MSGS_SLOT,
    KEY_MANAGEMENT_SHARE_PVSS_SLOT, POLICY_BASE_FEE_SLOT, POLICY_BLACKLIST_SLOT,
    POLICY_ENVELOPE_FEE_SLOT, POLICY_MAX_ENVELOPES_PER_BLOCK_SLOT,
    POLICY_MAX_ENVELOPE_GAS_LIMIT_SLOT, POLICY_MIN_GAS_TIP_CAP_SLOT, POLICY_PROXY_ADDRESS,
    POLICY_SPONSOR_RATE_SLOT, RESERVED_ONE_PROXY_ADDRESS, RESERVED_TWO_PROXY_ADDRESS,
    SYSTEM_ADDRESS, TREASURY_ADDRESS,
};
