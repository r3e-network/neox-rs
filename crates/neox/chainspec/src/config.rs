use crate::NEOX_MAX_VALIDATOR_COUNT;
use alloc::vec::Vec;
use alloy_primitives::Address;
use serde::{Deserialize, Serialize};

/// Neo X extensions embedded in the `config` object of a Geth genesis file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NeoXGenesisConfig {
    /// Block that activates Neo X DKG execution rules.
    #[serde(rename = "neoXDKGBlock")]
    pub dkg_block: u64,
    /// Block that activates Anti-MEV Envelope processing.
    #[serde(rename = "neoXAMEVBlock")]
    pub anti_mev_block: u64,
    /// Block that activates Ethereum-compatible dBFT signatures.
    #[serde(rename = "neoXEthSigBlock")]
    pub eth_signature_block: u64,
    /// Block that activates strict PKCS#7 unpadding for Anti-MEV payloads.
    #[serde(default, rename = "neoXPkcs7StrictBlock", skip_serializing_if = "Option::is_none")]
    pub pkcs7_strict_block: Option<u64>,
    /// dBFT genesis configuration.
    pub dbft: DbftConfig,
}

impl NeoXGenesisConfig {
    /// Returns `true` when the static dBFT configuration has a valid non-empty validator count.
    pub const fn has_expected_validator_count(&self) -> bool {
        let count = self.dbft.standby_validators.len();
        count > 0 && count <= NEOX_MAX_VALIDATOR_COUNT
    }

    /// Returns the configured standby validator count.
    pub const fn validator_count(&self) -> usize {
        self.dbft.standby_validators.len()
    }
}

/// Static dBFT values defined at genesis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DbftConfig {
    /// Target block period in seconds.
    pub period: u64,
    /// Validators used before governance elects a complete active set, or as fallback.
    pub standby_validators: Vec<Address>,
    /// Address that receives block rewards before system-contract distribution.
    pub coinbase: Address,
}
