use alloc::vec::Vec;
use alloy_consensus::Header;
use alloy_primitives::{keccak256, Address, Bytes, Signature, B256, U256};
use alloy_rlp::Encodable;
use blst::{min_pk, BLST_ERROR};
use thiserror::Error;

use crate::{next_consensus_hash, DbftExtra, DbftExtraError, ExtraVersion, SignatureScheme};

/// In-turn difficulty used by Neo X dBFT.
pub const DIFFICULTY_IN_TURN: u64 = 2;

/// Out-of-turn difficulty used by Neo X dBFT.
pub const DIFFICULTY_OUT_OF_TURN: u64 = 1;

/// Domain separation tag used by Neo X TPKE BLS signatures.
pub const TPKE_BLS_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// Calculates the Keccak256 dBFT seal hash used by V0 and V1/V2 ECDSA headers.
pub fn ecdsa_seal_hash(header: &Header) -> Result<B256, DbftExtraError> {
    let mut unsigned = header.clone();
    unsigned.extra_data = Bytes::copy_from_slice(DbftExtra::hashable_prefix(&header.extra_data)?);
    Ok(unsigned.hash_slow())
}

/// Returns the RLP message mapped to BLS12-381 G2 for a threshold-signed header.
pub fn threshold_seal_message(header: &Header) -> Result<Vec<u8>, DbftExtraError> {
    let mut unsigned = header.clone();
    unsigned.extra_data = Bytes::copy_from_slice(DbftExtra::hashable_prefix(&header.extra_data)?);
    let mut message = Vec::new();
    unsigned.encode(&mut message);
    Ok(message)
}

/// Verifies the next-consensus commitment inherited by a child header.
pub fn validate_parent_consensus(
    child: &DbftExtra,
    parent: &DbftExtra,
    parent_next_consensus: B256,
) -> Result<(), DbftValidationError> {
    let (expected, actual) = match child.signature_scheme() {
        SignatureScheme::Ecdsa => {
            let validators = child.validators().ok_or(DbftValidationError::WrongScheme)?;
            let expected = if matches!(child.version(), ExtraVersion::V0) ||
                matches!(parent.version(), ExtraVersion::V0)
            {
                parent_next_consensus
            } else {
                parent
                    .fallback_next_consensus()
                    .ok_or(DbftValidationError::MissingFallbackNextConsensus)?
            };
            (expected, next_consensus_hash(validators))
        }
        SignatureScheme::Threshold => {
            let public_key =
                child.threshold_public_key().ok_or(DbftValidationError::WrongScheme)?;
            (parent_next_consensus, keccak256(public_key))
        }
    };

    if expected == actual {
        Ok(())
    } else {
        Err(DbftValidationError::NextConsensusMismatch { expected, actual })
    }
}

/// Verifies the BFT quorum of ECDSA signatures in a Neo X header.
pub fn verify_ecdsa_signatures(
    seal_hash: B256,
    extra: &DbftExtra,
) -> Result<Vec<Address>, DbftValidationError> {
    let validators = extra.validators().ok_or(DbftValidationError::WrongScheme)?;
    let signatures = extra.signatures().ok_or(DbftValidationError::WrongScheme)?;
    let mut allowed = validators.to_vec();
    allowed.sort_unstable();

    let mut recovered = Vec::with_capacity(signatures.len());
    for (index, raw) in signatures.iter().enumerate() {
        let parity = match raw[64] {
            0 => false,
            1 => true,
            value => return Err(DbftValidationError::InvalidRecoveryId { index, value }),
        };
        let signature = Signature::from_bytes_and_parity(raw, parity);
        let signer = signature
            .recover_address_from_prehash(&seal_hash)
            .map_err(|_| DbftValidationError::InvalidSignature(index))?;
        recovered.push(signer);
    }
    recovered.sort_unstable();

    // Match Neo X Geth's monotonic merge: this simultaneously proves membership and prevents a
    // validator from satisfying more than one quorum slot unless it is duplicated in the set.
    let mut allowed_index = 0;
    for signer in &recovered {
        let mut matched = false;
        while allowed_index < allowed.len() {
            if allowed[allowed_index] == *signer {
                matched = true;
            }
            allowed_index += 1;
            if matched {
                break
            }
        }
        if !matched {
            return Err(DbftValidationError::UnauthorizedSigner(*signer))
        }
    }

    Ok(recovered)
}

/// Verifies a V1/V2 Neo X TPKE threshold signature.
pub fn verify_threshold_signature(
    header: &Header,
    extra: &DbftExtra,
) -> Result<(), DbftValidationError> {
    let public_key = extra.threshold_public_key().ok_or(DbftValidationError::WrongScheme)?;
    let mut signature_bytes =
        *extra.threshold_signature().ok_or(DbftValidationError::WrongScheme)?;

    // Neo X V1 aggregated signatures were produced with the negated G2 result. Flipping the
    // compressed point's sort bit negates Y and matches Geth's sig.Neg() verification path.
    if matches!(extra.version(), ExtraVersion::V1) {
        signature_bytes[0] ^= 0x20;
    }

    let public_key = min_pk::PublicKey::key_validate(public_key)
        .map_err(|_| DbftValidationError::InvalidThresholdPublicKey)?;
    let signature = min_pk::Signature::sig_validate(&signature_bytes, true)
        .map_err(|_| DbftValidationError::InvalidThresholdSignature)?;
    let message = threshold_seal_message(header)?;
    let result = signature.verify(true, &message, TPKE_BLS_DST, &[], &public_key, true);
    if result == BLST_ERROR::BLST_SUCCESS {
        Ok(())
    } else {
        Err(DbftValidationError::InvalidThresholdSignature)
    }
}

/// Result of validating a dBFT header seal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifiedSeal {
    /// Distinct ECDSA validators recovered from the header quorum.
    Ecdsa(Vec<Address>),
    /// A valid BLS12-381 TPKE threshold signature.
    Threshold,
}

/// Verifies a Neo X dBFT header, including parent commitment, difficulty, and signature.
pub fn validate_header(
    header: &Header,
    parent: &Header,
    validator_count: usize,
    standby_validator_count: usize,
) -> Result<VerifiedSeal, DbftValidationError> {
    let extra = DbftExtra::decode(&header.extra_data, validator_count)?;
    let parent_extra = DbftExtra::decode(&parent.extra_data, validator_count)?;
    validate_parent_consensus(&extra, &parent_extra, parent.mix_hash)?;
    validate_difficulty(header, standby_validator_count)?;

    match extra.signature_scheme() {
        SignatureScheme::Ecdsa => {
            Ok(VerifiedSeal::Ecdsa(verify_ecdsa_signatures(ecdsa_seal_hash(header)?, &extra)?))
        }
        SignatureScheme::Threshold => {
            verify_threshold_signature(header, &extra)?;
            Ok(VerifiedSeal::Threshold)
        }
    }
}

/// Verifies the header's dBFT ECDSA seal and parent next-consensus link.
pub fn validate_ecdsa_header(
    header: &Header,
    parent: &Header,
    validator_count: usize,
    standby_validator_count: usize,
) -> Result<Vec<Address>, DbftValidationError> {
    let extra = DbftExtra::decode(&header.extra_data, validator_count)?;
    let parent_extra = DbftExtra::decode(&parent.extra_data, validator_count)?;
    validate_parent_consensus(&extra, &parent_extra, parent.mix_hash)?;
    validate_difficulty(header, standby_validator_count)?;
    verify_ecdsa_signatures(ecdsa_seal_hash(header)?, &extra)
}

fn validate_difficulty(
    header: &Header,
    standby_validator_count: usize,
) -> Result<(), DbftValidationError> {
    if standby_validator_count == 0 {
        return Err(DbftValidationError::EmptyStandbyValidatorSet)
    }
    let primary = u64::from_be_bytes(header.nonce.0) as u8 as u64;
    let expected_difficulty = if header.number % standby_validator_count as u64 == primary {
        U256::from(DIFFICULTY_IN_TURN)
    } else {
        U256::from(DIFFICULTY_OUT_OF_TURN)
    };
    if header.difficulty != expected_difficulty {
        return Err(DbftValidationError::WrongDifficulty {
            expected: expected_difficulty,
            actual: header.difficulty,
        })
    }
    Ok(())
}

/// Errors produced by static Neo X dBFT header validation.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DbftValidationError {
    /// Header extra data could not be decoded.
    #[error(transparent)]
    Extra(#[from] DbftExtraError),
    /// The operation requires a different signature scheme.
    #[error("dBFT extraData uses the wrong signature scheme")]
    WrongScheme,
    /// A V1/V2 parent did not expose its fallback next-consensus value.
    #[error("V1/V2 parent is missing fallback next-consensus")]
    MissingFallbackNextConsensus,
    /// The child validator identifier does not match the commitment inherited from its parent.
    #[error("invalid next-consensus commitment: expected {expected}, got {actual}")]
    NextConsensusMismatch {
        /// Commitment inherited from the parent.
        expected: B256,
        /// Commitment calculated from the child validator identifiers.
        actual: B256,
    },
    /// The signature recovery ID is not 0 or 1.
    #[error("invalid recovery ID {value} in dBFT signature {index}")]
    InvalidRecoveryId {
        /// Signature index.
        index: usize,
        /// Invalid recovery ID.
        value: u8,
    },
    /// An ECDSA signature could not be recovered.
    #[error("invalid dBFT ECDSA signature at index {0}")]
    InvalidSignature(usize),
    /// A recovered signer is not a distinct member of the validator set.
    #[error("unauthorized or duplicate dBFT signer {0}")]
    UnauthorizedSigner(Address),
    /// The compressed G1 public key is not a valid BLS12-381 subgroup point.
    #[error("invalid dBFT threshold public key")]
    InvalidThresholdPublicKey,
    /// The compressed G2 signature is invalid or does not verify against the header.
    #[error("invalid dBFT threshold signature")]
    InvalidThresholdSignature,
    /// Static difficulty does not match the primary turn encoded in the nonce.
    #[error("invalid dBFT difficulty: expected {expected}, got {actual}")]
    WrongDifficulty {
        /// Expected in-turn or out-of-turn difficulty.
        expected: U256,
        /// Header difficulty.
        actual: U256,
    },
    /// Difficulty validation cannot run without standby validators.
    #[error("standby validator set is empty")]
    EmptyStandbyValidatorSet,
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, b256, hex, Bloom, B64};

    const MAINNET_GENESIS_HASH: B256 =
        b256!("2ee57478315c7d3182997a812d7885dafee48612cd88cb30b615847b0dd8dbd7");
    const MAINNET_NEXT_CONSENSUS: B256 =
        b256!("eb59c093e3a02bfa4e0d4677d4769022cd9399bbc8b93ad1e892acd6a08aa533");

    fn validators() -> Vec<Address> {
        vec![
            address!("34a3b2abb99b4c128acf61dcbbd1fcac0b161652"),
            address!("4fe8af0dbb633283d8e9703668142fd130f2818d"),
            address!("641ec1c538fa17e6ad8193c9b580f6850b114280"),
            address!("763452f65353fffe73d46539e51a6ddfc0e2c86a"),
            address!("a61ac4a4f006f4fceeb72ee0012a2d3367168d10"),
            address!("e3973f57e8a0aa312c1917ab0e6a05d8b6af6609"),
            address!("e6d1a9db6a0893926bd81c0ef93aaaa543c116f0"),
        ]
    }

    fn mainnet_genesis_header() -> Header {
        Header {
            extra_data: DbftExtra::genesis_v0(validators()).encode(),
            mix_hash: MAINNET_NEXT_CONSENSUS,
            ..Default::default()
        }
    }

    fn mainnet_block_one_header() -> Header {
        let extra = hex!("0034a3b2abb99b4c128acf61dcbbd1fcac0b1616524fe8af0dbb633283d8e9703668142fd130f2818d641ec1c538fa17e6ad8193c9b580f6850b114280763452f65353fffe73d46539e51a6ddfc0e2c86aa61ac4a4f006f4fceeb72ee0012a2d3367168d10e3973f57e8a0aa312c1917ab0e6a05d8b6af6609e6d1a9db6a0893926bd81c0ef93aaaa543c116f004e77ca08a66e4d28be34e0ed7f47a8b1a7dcda7fb123dab546c0c003dcc57d612cca79c453607123f5ad076d611fb38dca6a5d81365a0c88fea6c47f180d995005f0b6209b437003bc27d3a72201ab0a7fc59333e31d519fe83fe7a87c24cd89772195d4e82ac7438e1a77808b515dae0b0bf507c91f9cc196d62130bda0bebfc01ee3a5e15d5f10e2065d5ddf8a5efdc8ca9aa1e714f6b9c8cbd57b8d58fdfea0b58507fdc52f75a364e49553897e5bbd3ae3c27a69e3b58af005c621ddfab4ec30139cf1cea4891782eb3ca5f92b80df8794f9bd94ee358f461cc9d3b50267e21e6280f84e0e6b9c2dbdbad07beae9d06c422dddd20404808e90b1b75629f95c80d00cf0c3a99676838f0b69bb536ef7faa87a110a9bd2ecf026cf77ac96c7ac33fa20e02b53664e5404ff8de8aeb2fe6be6815671e958fcd6868a3d90df95a311aee00");
        Header {
            parent_hash: MAINNET_GENESIS_HASH,
            ommers_hash: b256!("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"),
            beneficiary: address!("1212000000000000000000000000000000000003"),
            state_root: b256!("92a17dd5e486b5c86a582af0768594ef85b013046a5c19d80e08af4bce2ccd9c"),
            transactions_root: b256!(
                "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
            ),
            receipts_root: b256!(
                "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
            ),
            logs_bloom: Bloom::ZERO,
            difficulty: U256::from(DIFFICULTY_OUT_OF_TURN),
            number: 1,
            gas_limit: 30_000_000,
            gas_used: 0,
            timestamp: 0x66a0_f5a5,
            extra_data: Bytes::copy_from_slice(&extra),
            mix_hash: MAINNET_NEXT_CONSENSUS,
            nonce: B64::ZERO,
            base_fee_per_gas: Some(20_000_000_000),
            withdrawals_root: Some(b256!(
                "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
            )),
            ..Default::default()
        }
    }

    fn testnet_v1_threshold_parent() -> Header {
        let extra = hex!(
            "0101072bc064323344cba6d63cad4ca88afbea585fc612919e3e351f457ea3704f76b35589cdf498cfaf4559e1ea0a91f0026afdbab42279172cb9d2452e5ac021860edd210dc463c8209ee6b5539be9340693b9c0987a437d241eef30b396a21a40b6fc3c8dfd5eafb9ffce7e0a3f1b9de53ed8b72160198787311591a7ec7700b816076a71aa62ae34149cd0b61e0b0a93930c314f8b71f17d30930771fed136f09c6a78a3524c919875028b06dd1e18fa"
        );
        Header {
            extra_data: Bytes::copy_from_slice(&extra),
            mix_hash: b256!("54a26e04c2f84197d5041ff281cd420fc69e6641391643d0399605896edd7dd5"),
            ..Default::default()
        }
    }

    fn testnet_v1_threshold_header() -> Header {
        let extra = hex!(
            "0101072bc064323344cba6d63cad4ca88afbea585fc612919e3e351f457ea3704f76b35589cdf498cfaf4559e1ea0a91f0026afdbab42279172cb9d2452e5ac021860edd210dc463c8209ee6b5539be93406908916a17de3f6b0255bd81fcec1079ac896bd208b3ccee0eafd6297a3fb14c1483729bcfebf31f27d1314385194945007866ad4dfa268c9bbe1fa6b8883fb82f3b4f3fec86924b3ba392d1e8a3784f473fab0ad1a634bfa20ecbc6758bc0b9d"
        );
        Header {
            parent_hash: b256!("e6ca959bdb637884d2686e031ef244c110c966c35c3cd2b6f410b7750cf7e48e"),
            ommers_hash: b256!("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"),
            beneficiary: address!("1212000000000000000000000000000000000003"),
            state_root: b256!("f31b6fb9c4a56b3f941068f96d529631e57849f8d3b64a049eceb6cfb501ccb6"),
            transactions_root: b256!(
                "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
            ),
            receipts_root: b256!(
                "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
            ),
            logs_bloom: Bloom::ZERO,
            difficulty: U256::from(DIFFICULTY_IN_TURN),
            number: 0x1f_dd40,
            gas_limit: 30_000_000,
            gas_used: 0,
            timestamp: 0x67d9_a738,
            extra_data: Bytes::copy_from_slice(&extra),
            mix_hash: b256!("54a26e04c2f84197d5041ff281cd420fc69e6641391643d0399605896edd7dd5"),
            nonce: B64::from([0, 0, 0, 0, 0, 0, 0, 2]),
            base_fee_per_gas: Some(20_000_000_000),
            withdrawals_root: Some(b256!(
                "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
            )),
            ..Default::default()
        }
    }

    fn testnet_v2_threshold_parent() -> Header {
        let extra = hex!(
            "0201072bc064323344cba6d63cad4ca88afbea585fc612919e3e351f457ea3704f7697cbfe3649c0ae4cf27deca9a3c760563b5a96342e5afad9e768418b1a0cec5f3d9874137fe43648ff0a1ec7b752004586676094fe54ab2db845a639e2f4ff43ac508c8e4facfef476f24fb6394eadcbb3ac667cc28175d76e66f1816c68b9f0010da6a595c8c5b57570e635e25fdf1c07a0bd5908e74fd9a81078cc42999614e739a31d8548800250c1c7c407b37562"
        );
        Header {
            extra_data: Bytes::copy_from_slice(&extra),
            mix_hash: b256!("893dab7bbab84fad3d0e93f8f8df4740dcd1f5bd235deaaed9cb3519f010cc49"),
            ..Default::default()
        }
    }

    fn testnet_v2_threshold_header() -> Header {
        let extra = hex!(
            "0201072bc064323344cba6d63cad4ca88afbea585fc612919e3e351f457ea3704f7697cbfe3649c0ae4cf27deca9a3c760563b5a96342e5afad9e768418b1a0cec5f3d9874137fe43648ff0a1ec7b75200458a8e4eccbc2ce3ab61e28e8e1e039ad8485a3e84950fe8ce32aad06f0e7ae45a9350a86195cf2b9671d35be63536767603f8aa9de9798ce725492b9a9ab97f6ee7cd4acd2eeac231d3eebb207de72e9a99f7ad417a8972a48ee54d2e747b1b65"
        );
        Header {
            parent_hash: b256!("35fe2ed4613c2c24680b00b75686b7558905ed275dff3a66a04d0e33efd230f8"),
            ommers_hash: b256!("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"),
            beneficiary: address!("1212000000000000000000000000000000000003"),
            state_root: b256!("19aeb170c318238ffd04750cc7ccc83f96372904cdff5bb89d3efa7ccd623b90"),
            transactions_root: b256!(
                "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
            ),
            receipts_root: b256!(
                "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
            ),
            logs_bloom: Bloom::ZERO,
            difficulty: U256::from(DIFFICULTY_IN_TURN),
            number: 0x39_3870,
            gas_limit: 30_000_000,
            gas_used: 0,
            timestamp: 0x685a_c692,
            extra_data: Bytes::copy_from_slice(&extra),
            mix_hash: b256!("893dab7bbab84fad3d0e93f8f8df4740dcd1f5bd235deaaed9cb3519f010cc49"),
            nonce: B64::from([0, 0, 0, 0, 0, 0, 0, 2]),
            base_fee_per_gas: Some(20_000_000_000),
            withdrawals_root: Some(b256!(
                "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
            )),
            ..Default::default()
        }
    }

    #[test]
    fn validates_live_mainnet_block_one() {
        let parent = mainnet_genesis_header();
        let header = mainnet_block_one_header();

        assert_eq!(
            header.hash_slow(),
            b256!("70350d4ae50d254187c04340fc9b173b5e0a678de7a41976e540e537af7d4848")
        );
        let signers = validate_ecdsa_header(&header, &parent, 7, 7).unwrap();
        assert_eq!(signers.len(), 5);
        assert!(signers.iter().all(|signer| validators().contains(signer)));
    }

    #[test]
    fn validates_live_testnet_v1_threshold_block() {
        let parent = testnet_v1_threshold_parent();
        let header = testnet_v1_threshold_header();

        assert_eq!(
            header.hash_slow(),
            b256!("62ad3b20eaf17fb7ae806261e42beaca0b9d20eeea4c24df3dcee4d076d97fc8")
        );
        assert_eq!(validate_header(&header, &parent, 7, 7), Ok(VerifiedSeal::Threshold));
    }

    #[test]
    fn validates_live_testnet_v2_threshold_block() {
        let parent = testnet_v2_threshold_parent();
        let header = testnet_v2_threshold_header();

        assert_eq!(
            header.hash_slow(),
            b256!("6ff83f9cb31c323f6937ed3878d0e7a28726bb508340891970c770ae4aad29a5")
        );
        assert_eq!(validate_header(&header, &parent, 7, 7), Ok(VerifiedSeal::Threshold));
    }

    #[test]
    fn rejects_a_child_validator_set_not_committed_by_its_parent() {
        let parent = mainnet_genesis_header();
        let mut child_validators = validators();
        child_validators[0] = Address::repeat_byte(0xff);
        let child = DbftExtra::genesis_v0(child_validators);
        let parent_extra = DbftExtra::decode(&parent.extra_data, 7).unwrap();

        assert!(matches!(
            validate_parent_consensus(&child, &parent_extra, parent.mix_hash),
            Err(DbftValidationError::NextConsensusMismatch { .. })
        ));
    }

    #[test]
    fn rejects_invalid_recovery_id_before_recovery() {
        let header = mainnet_block_one_header();
        let mut extra = DbftExtra::decode(&header.extra_data, 7).unwrap();
        if let DbftExtra::Ecdsa { signatures, .. } = &mut extra {
            signatures[0][64] = 2;
        }

        assert_eq!(
            verify_ecdsa_signatures(B256::ZERO, &extra),
            Err(DbftValidationError::InvalidRecoveryId { index: 0, value: 2 })
        );
    }
}
