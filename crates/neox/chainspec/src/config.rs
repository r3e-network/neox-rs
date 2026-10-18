use crate::NEOX_MAX_VALIDATOR_COUNT;
use alloc::vec::Vec;
use alloy_primitives::Address;
use serde::{Deserialize, Serialize};

/// Sentinel for a Neo X fork that is not scheduled in the genesis file.
///
/// Geth models the `neoX*Block` config fields as optional pointers and treats a missing field as
/// "fork never activates". `u64::MAX` preserves that meaning in a fixed-width field: no reachable
/// block height reaches it, and [`crate::NeoXChainSpec`] omits the corresponding hardfork entry.
pub const NEOX_FORK_NEVER: u64 = u64::MAX;

const fn fork_never() -> u64 {
    NEOX_FORK_NEVER
}

const fn is_fork_never(value: &u64) -> bool {
    *value == NEOX_FORK_NEVER
}

/// Neo X extensions embedded in the `config` object of a Geth genesis file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NeoXGenesisConfig {
    /// Block that activates Neo X DKG execution rules, or [`NEOX_FORK_NEVER`] when omitted.
    #[serde(
        default = "fork_never",
        rename = "neoXDKGBlock",
        skip_serializing_if = "is_fork_never"
    )]
    pub dkg_block: u64,
    /// Block that activates Anti-MEV Envelope processing, or [`NEOX_FORK_NEVER`] when omitted.
    #[serde(
        default = "fork_never",
        rename = "neoXAMEVBlock",
        skip_serializing_if = "is_fork_never"
    )]
    pub anti_mev_block: u64,
    /// Block that activates Ethereum-compatible dBFT signatures, or [`NEOX_FORK_NEVER`] when
    /// omitted.
    #[serde(
        default = "fork_never",
        rename = "neoXEthSigBlock",
        skip_serializing_if = "is_fork_never"
    )]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn omitted_forks_deserialize_and_serialize_as_absent() {
        let encoded = r#"{
            "dbft": {
                "period": 5,
                "standbyValidators": [],
                "coinbase": "0x1212000000000000000000000000000000000003"
            }
        }"#;
        let config: NeoXGenesisConfig = serde_json::from_str(encoded).unwrap();
        assert_eq!(config.dkg_block, NEOX_FORK_NEVER);
        assert_eq!(config.anti_mev_block, NEOX_FORK_NEVER);
        assert_eq!(config.eth_signature_block, NEOX_FORK_NEVER);

        let roundtrip = serde_json::to_string(&config).unwrap();
        for field in ["neoXDKGBlock", "neoXAMEVBlock", "neoXEthSigBlock"] {
            assert!(!roundtrip.contains(field), "unscheduled {field} must stay omitted");
        }
    }
}
