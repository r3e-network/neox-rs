use alloc::{vec, vec::Vec};
use alloy_primitives::{keccak256, Address, Bytes, B256};
use thiserror::Error;

/// Number of bytes used to encode an ECDSA signature, including recovery ID.
pub const ECDSA_SIGNATURE_LEN: usize = 65;

/// Compressed BLS12-381 G1 public-key length used by Neo X TPKE.
pub const THRESHOLD_PUBLIC_KEY_LEN: usize = 48;

/// Compressed BLS12-381 G2 signature length used by Neo X TPKE.
pub const THRESHOLD_SIGNATURE_LEN: usize = 96;

/// Hashable prefix length for V0 `extraData`.
pub const HASHABLE_EXTRA_V0_LEN: usize = 1;

/// Hashable prefix length for V1/V2 `extraData`.
pub const HASHABLE_EXTRA_V1_LEN: usize = 1 + 1 + 32;

/// Neo X dBFT `extraData` version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ExtraVersion {
    /// Sorted validator addresses followed by a BFT quorum of ECDSA signatures.
    V0 = 0,
    /// DKG-aware format using legacy Neo X threshold-signature hashing.
    V1 = 1,
    /// DKG-aware format using Ethereum-compatible threshold-signature hashing.
    V2 = 2,
}

impl TryFrom<u8> for ExtraVersion {
    type Error = DbftExtraError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::V0),
            1 => Ok(Self::V1),
            2 => Ok(Self::V2),
            value => Err(DbftExtraError::UnsupportedVersion(value)),
        }
    }
}

/// Signature scheme used by V1/V2 dBFT extras.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SignatureScheme {
    /// Fallback validator-address list with ECDSA multisignatures.
    Ecdsa = 0,
    /// TPKE global public key with an aggregated threshold signature.
    Threshold = 1,
}

impl TryFrom<u8> for SignatureScheme {
    type Error = DbftExtraError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Ecdsa),
            1 => Ok(Self::Threshold),
            value => Err(DbftExtraError::UnsupportedSignatureScheme(value)),
        }
    }
}

/// Hashable dBFT extra data carried by an unsealed `PrepareRequest` header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DbftExtraPrefix {
    version: ExtraVersion,
    signature_scheme: SignatureScheme,
    fallback_next_consensus: Option<B256>,
}

impl DbftExtraPrefix {
    /// Decodes the hashable prefix and deliberately ignores any subsequently appended seal.
    pub fn decode(raw: &[u8]) -> Result<Self, DbftExtraError> {
        let (&version, _) = raw.split_first().ok_or(DbftExtraError::Empty)?;
        let version = ExtraVersion::try_from(version)?;
        match version {
            ExtraVersion::V0 => Ok(Self {
                version,
                signature_scheme: SignatureScheme::Ecdsa,
                fallback_next_consensus: None,
            }),
            ExtraVersion::V1 | ExtraVersion::V2 => {
                if raw.len() < HASHABLE_EXTRA_V1_LEN {
                    return Err(DbftExtraError::InvalidLength {
                        expected: HASHABLE_EXTRA_V1_LEN,
                        actual: raw.len(),
                    })
                }
                Ok(Self {
                    version,
                    signature_scheme: SignatureScheme::try_from(raw[1])?,
                    fallback_next_consensus: Some(B256::from_slice(&raw[2..HASHABLE_EXTRA_V1_LEN])),
                })
            }
        }
    }

    /// Extra format version selected for the proposed height.
    pub const fn version(self) -> ExtraVersion {
        self.version
    }

    /// Block signature scheme selected by the proposal.
    pub const fn signature_scheme(self) -> SignatureScheme {
        self.signature_scheme
    }

    /// ECDSA fallback next-consensus commitment present in V1/V2 proposals.
    pub const fn fallback_next_consensus(self) -> Option<B256> {
        self.fallback_next_consensus
    }
}

/// Decoded Neo X dBFT header `extraData`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DbftExtra {
    /// ECDSA multisignature form used by V0 and as the V1/V2 fallback.
    Ecdsa {
        /// Format version.
        version: ExtraVersion,
        /// V1/V2 fallback next-consensus hash. V0 stores it in the header mix hash only.
        fallback_next_consensus: Option<B256>,
        /// Consensus validator addresses in their encoded order.
        validators: Vec<Address>,
        /// Recoverable ECDSA signatures.
        signatures: Vec<[u8; ECDSA_SIGNATURE_LEN]>,
    },
    /// Threshold-signature form used after DKG activation.
    Threshold {
        /// V1 or V2 format version.
        version: ExtraVersion,
        /// Fallback next-consensus value committed in the hashable prefix.
        fallback_next_consensus: B256,
        /// Compressed BLS12-381 G1 TPKE public key.
        public_key: [u8; THRESHOLD_PUBLIC_KEY_LEN],
        /// Compressed BLS12-381 G2 aggregated signature.
        signature: [u8; THRESHOLD_SIGNATURE_LEN],
    },
}

impl DbftExtra {
    /// Constructs the deterministic V0 extra used by a dBFT genesis block.
    pub fn genesis_v0(mut validators: Vec<Address>) -> Self {
        validators.sort_unstable();
        let signatures = vec![[0_u8; ECDSA_SIGNATURE_LEN]; bft_honest_node_count(validators.len())];
        Self::Ecdsa {
            version: ExtraVersion::V0,
            fallback_next_consensus: None,
            validators,
            signatures,
        }
    }

    /// Decodes a dBFT extra using the active validator count.
    pub fn decode(raw: &[u8], validator_count: usize) -> Result<Self, DbftExtraError> {
        let (&version, _) = raw.split_first().ok_or(DbftExtraError::Empty)?;
        let version = ExtraVersion::try_from(version)?;

        match version {
            ExtraVersion::V0 => Self::decode_ecdsa(raw, version, validator_count, None),
            ExtraVersion::V1 | ExtraVersion::V2 => {
                if raw.len() < HASHABLE_EXTRA_V1_LEN {
                    return Err(DbftExtraError::InvalidLength {
                        expected: HASHABLE_EXTRA_V1_LEN,
                        actual: raw.len(),
                    })
                }
                let scheme = SignatureScheme::try_from(raw[1])?;
                let fallback_next_consensus = B256::from_slice(&raw[2..HASHABLE_EXTRA_V1_LEN]);
                match scheme {
                    SignatureScheme::Ecdsa => Self::decode_ecdsa(
                        raw,
                        version,
                        validator_count,
                        Some(fallback_next_consensus),
                    ),
                    SignatureScheme::Threshold => {
                        let expected = HASHABLE_EXTRA_V1_LEN +
                            THRESHOLD_PUBLIC_KEY_LEN +
                            THRESHOLD_SIGNATURE_LEN;
                        if raw.len() != expected {
                            return Err(DbftExtraError::InvalidLength {
                                expected,
                                actual: raw.len(),
                            })
                        }
                        let mut public_key = [0_u8; THRESHOLD_PUBLIC_KEY_LEN];
                        public_key.copy_from_slice(
                            &raw[HASHABLE_EXTRA_V1_LEN..
                                HASHABLE_EXTRA_V1_LEN + THRESHOLD_PUBLIC_KEY_LEN],
                        );
                        let mut signature = [0_u8; THRESHOLD_SIGNATURE_LEN];
                        signature.copy_from_slice(&raw[expected - THRESHOLD_SIGNATURE_LEN..]);
                        Ok(Self::Threshold {
                            version,
                            fallback_next_consensus,
                            public_key,
                            signature,
                        })
                    }
                }
            }
        }
    }

    fn decode_ecdsa(
        raw: &[u8],
        version: ExtraVersion,
        validator_count: usize,
        fallback_next_consensus: Option<B256>,
    ) -> Result<Self, DbftExtraError> {
        let prefix_len = match version {
            ExtraVersion::V0 => HASHABLE_EXTRA_V0_LEN,
            ExtraVersion::V1 | ExtraVersion::V2 => HASHABLE_EXTRA_V1_LEN,
        };
        let signature_count = bft_honest_node_count(validator_count);
        let expected = prefix_len +
            validator_count * Address::len_bytes() +
            signature_count * ECDSA_SIGNATURE_LEN;
        if raw.len() != expected {
            return Err(DbftExtraError::InvalidLength { expected, actual: raw.len() })
        }

        let validators_start = prefix_len;
        let signatures_start = validators_start + validator_count * Address::len_bytes();
        let validators = raw[validators_start..signatures_start]
            .chunks_exact(Address::len_bytes())
            .map(Address::from_slice)
            .collect();
        let signatures = raw[signatures_start..]
            .chunks_exact(ECDSA_SIGNATURE_LEN)
            .map(|signature| {
                let mut result = [0_u8; ECDSA_SIGNATURE_LEN];
                result.copy_from_slice(signature);
                result
            })
            .collect();

        Ok(Self::Ecdsa { version, fallback_next_consensus, validators, signatures })
    }

    /// Encodes the exact header `extraData` representation.
    pub fn encode(&self) -> Bytes {
        let mut raw = Vec::new();
        match self {
            Self::Ecdsa { version, fallback_next_consensus, validators, signatures } => {
                raw.push(*version as u8);
                if !matches!(version, ExtraVersion::V0) {
                    raw.push(SignatureScheme::Ecdsa as u8);
                    raw.extend_from_slice(
                        fallback_next_consensus
                            .as_ref()
                            .expect("V1/V2 ECDSA extra requires fallback next consensus")
                            .as_slice(),
                    );
                }
                for validator in validators {
                    raw.extend_from_slice(validator.as_slice());
                }
                for signature in signatures {
                    raw.extend_from_slice(signature);
                }
            }
            Self::Threshold { version, fallback_next_consensus, public_key, signature } => {
                raw.push(*version as u8);
                raw.push(SignatureScheme::Threshold as u8);
                raw.extend_from_slice(fallback_next_consensus.as_slice());
                raw.extend_from_slice(public_key);
                raw.extend_from_slice(signature);
            }
        }
        raw.into()
    }

    /// Returns the prefix included in the dBFT seal hash.
    pub fn hashable_prefix(raw: &[u8]) -> Result<&[u8], DbftExtraError> {
        let (&version, _) = raw.split_first().ok_or(DbftExtraError::Empty)?;
        let expected = match ExtraVersion::try_from(version)? {
            ExtraVersion::V0 => HASHABLE_EXTRA_V0_LEN,
            ExtraVersion::V1 | ExtraVersion::V2 => HASHABLE_EXTRA_V1_LEN,
        };
        raw.get(..expected).ok_or(DbftExtraError::InvalidLength { expected, actual: raw.len() })
    }

    /// Returns ECDSA validator addresses when this extra uses ECDSA multisignatures.
    pub fn validators(&self) -> Option<&[Address]> {
        match self {
            Self::Ecdsa { validators, .. } => Some(validators),
            Self::Threshold { .. } => None,
        }
    }

    /// Returns the encoded format version.
    pub const fn version(&self) -> ExtraVersion {
        match self {
            Self::Ecdsa { version, .. } | Self::Threshold { version, .. } => *version,
        }
    }

    /// Returns the signature scheme selected by this extra.
    pub const fn signature_scheme(&self) -> SignatureScheme {
        match self {
            Self::Ecdsa { .. } => SignatureScheme::Ecdsa,
            Self::Threshold { .. } => SignatureScheme::Threshold,
        }
    }

    /// Returns the fallback next-consensus commitment encoded by V1/V2.
    pub const fn fallback_next_consensus(&self) -> Option<B256> {
        match self {
            Self::Ecdsa { fallback_next_consensus, .. } => *fallback_next_consensus,
            Self::Threshold { fallback_next_consensus, .. } => Some(*fallback_next_consensus),
        }
    }

    /// Returns ECDSA signatures when this extra uses ECDSA multisignatures.
    pub fn signatures(&self) -> Option<&[[u8; ECDSA_SIGNATURE_LEN]]> {
        match self {
            Self::Ecdsa { signatures, .. } => Some(signatures),
            Self::Threshold { .. } => None,
        }
    }

    /// Returns the compressed TPKE public key when this extra uses threshold signatures.
    pub const fn threshold_public_key(&self) -> Option<&[u8; THRESHOLD_PUBLIC_KEY_LEN]> {
        match self {
            Self::Ecdsa { .. } => None,
            Self::Threshold { public_key, .. } => Some(public_key),
        }
    }

    /// Returns the compressed aggregated threshold signature.
    pub const fn threshold_signature(&self) -> Option<&[u8; THRESHOLD_SIGNATURE_LEN]> {
        match self {
            Self::Ecdsa { .. } => None,
            Self::Threshold { signature, .. } => Some(signature),
        }
    }
}

/// Minimum number of honest nodes required by Neo X dBFT.
pub const fn bft_honest_node_count(node_count: usize) -> usize {
    node_count - node_count.saturating_sub(1) / 3
}

/// Calculates the Neo X next-consensus hash from already ordered consensus identifiers.
pub fn next_consensus_hash<T: AsRef<[u8]>>(validators: &[T]) -> B256 {
    let capacity = validators.iter().map(|validator| validator.as_ref().len()).sum();
    let mut flattened = Vec::with_capacity(capacity);
    for validator in validators {
        flattened.extend_from_slice(validator.as_ref());
    }
    keccak256(flattened)
}

/// Errors produced when decoding dBFT `extraData`.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DbftExtraError {
    /// `extraData` is empty.
    #[error("dBFT extraData is empty")]
    Empty,
    /// The version byte is not supported.
    #[error("unsupported dBFT extraData version {0}")]
    UnsupportedVersion(u8),
    /// The V1/V2 signature scheme byte is not supported.
    #[error("unsupported dBFT signature scheme {0}")]
    UnsupportedSignatureScheme(u8),
    /// The payload does not match the exact length for its format and validator count.
    #[error("invalid dBFT extraData length: expected {expected}, got {actual}")]
    InvalidLength {
        /// Exact length required by the selected format.
        expected: usize,
        /// Supplied byte length.
        actual: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, b256};

    fn validators() -> Vec<Address> {
        vec![
            address!("34a3b2abb99b4c128acf61dcbbd1fcac0b161652"),
            address!("641ec1c538fa17e6ad8193c9b580f6850b114280"),
            address!("e3973f57e8a0aa312c1917ab0e6a05d8b6af6609"),
            address!("a61ac4a4f006f4fceeb72ee0012a2d3367168d10"),
            address!("e6d1a9db6a0893926bd81c0ef93aaaa543c116f0"),
            address!("4fe8af0dbb633283d8e9703668142fd130f2818d"),
            address!("763452f65353fffe73d46539e51a6ddfc0e2c86a"),
        ]
    }

    #[test]
    fn genesis_v0_matches_mainnet_layout() {
        let extra = DbftExtra::genesis_v0(validators());
        let encoded = extra.encode();

        assert_eq!(bft_honest_node_count(7), 5);
        assert_eq!(encoded.len(), 1 + 7 * 20 + 5 * 65);
        assert_eq!(DbftExtra::hashable_prefix(&encoded).unwrap(), &[0]);
        assert_eq!(DbftExtra::decode(&encoded, 7).unwrap(), extra);
        assert_eq!(
            next_consensus_hash(extra.validators().unwrap()),
            b256!("eb59c093e3a02bfa4e0d4677d4769022cd9399bbc8b93ad1e892acd6a08aa533")
        );
    }

    #[test]
    fn threshold_roundtrip() {
        let extra = DbftExtra::Threshold {
            version: ExtraVersion::V2,
            fallback_next_consensus: B256::repeat_byte(0x12),
            public_key: [0x23; THRESHOLD_PUBLIC_KEY_LEN],
            signature: [0x34; THRESHOLD_SIGNATURE_LEN],
        };
        let encoded = extra.encode();

        assert_eq!(encoded.len(), HASHABLE_EXTRA_V1_LEN + 48 + 96);
        assert_eq!(DbftExtra::hashable_prefix(&encoded).unwrap().len(), 34);
        assert_eq!(DbftExtra::decode(&encoded, 7).unwrap(), extra);
        assert_eq!(
            DbftExtraPrefix::decode(&encoded).unwrap(),
            DbftExtraPrefix {
                version: ExtraVersion::V2,
                signature_scheme: SignatureScheme::Threshold,
                fallback_next_consensus: Some(B256::repeat_byte(0x12)),
            }
        );
        assert_eq!(DbftExtra::hashable_prefix(&encoded).unwrap(), &encoded[..34]);
    }

    #[test]
    fn decodes_real_unsealed_prepare_request_prefixes() {
        assert_eq!(
            DbftExtraPrefix::decode(&[ExtraVersion::V0 as u8]).unwrap().signature_scheme(),
            SignatureScheme::Ecdsa
        );
        let mut threshold = vec![ExtraVersion::V1 as u8, SignatureScheme::Threshold as u8];
        threshold.extend_from_slice(B256::repeat_byte(0x44).as_slice());
        let decoded = DbftExtraPrefix::decode(&threshold).unwrap();
        assert_eq!(decoded.version(), ExtraVersion::V1);
        assert_eq!(decoded.signature_scheme(), SignatureScheme::Threshold);
        assert_eq!(decoded.fallback_next_consensus(), Some(B256::repeat_byte(0x44)));
    }

    #[test]
    fn rejects_truncated_payload() {
        assert_eq!(
            DbftExtra::decode(&[ExtraVersion::V1 as u8], 7),
            Err(DbftExtraError::InvalidLength { expected: 34, actual: 1 })
        );
    }
}
