//! dBFT `PreCommit` decryption-share wire encoding.

use crate::{DecryptionShare, DECRYPTION_SHARE_LEN};
use alloc::vec::Vec;
use thiserror::Error;

/// Defensive decoding ceiling used by Neo X Geth.
pub const MAX_DECRYPTION_SHARES_PER_BLOCK: usize = 1_000;
const SHARE_COUNTS_LEN: usize = 8;

/// Encodes current-round and previous-round shares for a dBFT `PreCommit` payload.
pub fn encode_decryption_shares(
    current: &[DecryptionShare],
    previous: &[DecryptionShare],
) -> Result<Vec<u8>, DecryptionShareCodecError> {
    let total = current
        .len()
        .checked_add(previous.len())
        .ok_or(DecryptionShareCodecError::TooManyShares { total: usize::MAX })?;
    if total > MAX_DECRYPTION_SHARES_PER_BLOCK {
        return Err(DecryptionShareCodecError::TooManyShares { total })
    }
    let current_len = u32::try_from(current.len())
        .map_err(|_| DecryptionShareCodecError::TooManyShares { total })?;
    let previous_len = u32::try_from(previous.len())
        .map_err(|_| DecryptionShareCodecError::TooManyShares { total })?;

    let mut encoded = Vec::with_capacity(SHARE_COUNTS_LEN + total * DECRYPTION_SHARE_LEN);
    encoded.extend_from_slice(&current_len.to_le_bytes());
    encoded.extend_from_slice(&previous_len.to_le_bytes());
    for share in current.iter().chain(previous) {
        encoded.extend_from_slice(share.as_bytes());
    }
    Ok(encoded)
}

/// Decodes current-round and previous-round shares from a dBFT `PreCommit` payload.
pub fn decode_decryption_shares(
    encoded: &[u8],
) -> Result<(Vec<DecryptionShare>, Vec<DecryptionShare>), DecryptionShareCodecError> {
    if encoded.len() < SHARE_COUNTS_LEN {
        return Err(DecryptionShareCodecError::TooShort { actual: encoded.len() })
    }
    let current_len = u32::from_le_bytes(encoded[..4].try_into().expect("four-byte count"));
    let previous_len =
        u32::from_le_bytes(encoded[4..SHARE_COUNTS_LEN].try_into().expect("four-byte count"));
    let total = (current_len as usize)
        .checked_add(previous_len as usize)
        .ok_or(DecryptionShareCodecError::TooManyShares { total: usize::MAX })?;
    if total > MAX_DECRYPTION_SHARES_PER_BLOCK {
        return Err(DecryptionShareCodecError::TooManyShares { total })
    }
    let expected = SHARE_COUNTS_LEN + total * DECRYPTION_SHARE_LEN;
    if encoded.len() != expected {
        return Err(DecryptionShareCodecError::WrongLength { expected, actual: encoded.len() })
    }

    let mut offset = SHARE_COUNTS_LEN;
    let mut take = |count: usize| -> Result<Vec<DecryptionShare>, DecryptionShareCodecError> {
        let mut shares = Vec::with_capacity(count);
        for _ in 0..count {
            let end = offset + DECRYPTION_SHARE_LEN;
            shares.push(DecryptionShare::decode(&encoded[offset..end])?);
            offset = end;
        }
        Ok(shares)
    };
    let current = take(current_len as usize)?;
    let previous = take(previous_len as usize)?;
    Ok((current, previous))
}

/// dBFT `PreCommit` decryption-share codec failures.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DecryptionShareCodecError {
    /// The fixed two-count prefix is missing.
    #[error("decryption-share payload is too short: expected at least 8 bytes, got {actual}")]
    TooShort {
        /// Actual payload length.
        actual: usize,
    },
    /// The decoded or supplied share count exceeds the defensive protocol ceiling.
    #[error("too many decryption shares: got {total}, allowed 1000")]
    TooManyShares {
        /// Total current- and previous-round shares.
        total: usize,
    },
    /// The payload length does not agree with its count prefix.
    #[error("invalid decryption-share payload length: expected {expected}, got {actual}")]
    WrongLength {
        /// Length implied by the count prefix.
        expected: usize,
        /// Actual payload length.
        actual: usize,
    },
    /// A compressed G1 share is invalid.
    #[error(transparent)]
    Tpke(#[from] crate::TpkeError),
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHARE: [u8; DECRYPTION_SHARE_LEN] = alloy_primitives::hex!(
        "8dcd83e7fd7ea998b6b170354e9b87bebd4844d0dfe45d8d45650f84859adb04\
         6c8fe43ac96567e67f944915268b4d31"
    );

    #[test]
    fn precommit_share_encoding_matches_geth_layout() {
        let share = DecryptionShare::decode(&SHARE).unwrap();
        let encoded = encode_decryption_shares(&[share], &[share]).unwrap();
        assert_eq!(&encoded[..8], &[1, 0, 0, 0, 1, 0, 0, 0]);
        assert_eq!(&encoded[8..56], &SHARE);
        assert_eq!(&encoded[56..], &SHARE);
        assert_eq!(decode_decryption_shares(&encoded).unwrap(), (vec![share], vec![share]));
    }

    #[test]
    fn precommit_share_decoder_enforces_length_and_ceiling() {
        assert_eq!(
            decode_decryption_shares(&[0; 7]),
            Err(DecryptionShareCodecError::TooShort { actual: 7 })
        );
        let mut too_many = [0_u8; 8];
        too_many[..4].copy_from_slice(&1_001_u32.to_le_bytes());
        assert_eq!(
            decode_decryption_shares(&too_many),
            Err(DecryptionShareCodecError::TooManyShares { total: 1_001 })
        );
        let mut wrong = [0_u8; 8];
        wrong[..4].copy_from_slice(&1_u32.to_le_bytes());
        assert_eq!(
            decode_decryption_shares(&wrong),
            Err(DecryptionShareCodecError::WrongLength { expected: 56, actual: 8 })
        );
    }

    // Deterministic xorshift64 so the sweep is reproducible and never flaky.
    fn xorshift(state: &mut u64) -> u64 {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        x
    }

    #[test]
    fn decryption_share_decoder_never_panics_on_adversarial_bytes() {
        let share = DecryptionShare::decode(&SHARE).unwrap();
        let seeds: Vec<Vec<u8>> = vec![
            encode_decryption_shares(&[], &[]).unwrap(),
            encode_decryption_shares(&[share], &[share]).unwrap(),
            encode_decryption_shares(&[share, share, share], &[]).unwrap(),
        ];
        for seed in &seeds {
            let (current, previous) = decode_decryption_shares(seed).unwrap();
            assert_eq!(encode_decryption_shares(&current, &previous).unwrap(), *seed);
        }

        let mut state = 0xDEAD_BEEF_CAFE_F00D_u64;
        for _ in 0..50_000 {
            let bytes = if (xorshift(&mut state) & 3) == 0 {
                let len = (xorshift(&mut state) % 512) as usize;
                (0..len).map(|_| xorshift(&mut state) as u8).collect::<Vec<u8>>()
            } else {
                let mut bytes = seeds[(xorshift(&mut state) as usize) % seeds.len()].clone();
                for _ in 0..1 + xorshift(&mut state) % 4 {
                    let index = (xorshift(&mut state) as usize) % bytes.len();
                    bytes[index] ^= xorshift(&mut state) as u8;
                }
                bytes
            };
            // A malformed payload must return a Result, never panic; any successful decode must
            // re-encode without error.
            if let Ok((current, previous)) = decode_decryption_shares(&bytes) {
                let _ = encode_decryption_shares(&current, &previous);
            }
        }
    }
}
