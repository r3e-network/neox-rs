//! One-shot migration from Neo X Geth's encrypted Anti-MEV keystore.

use crate::{
    dkg_state::{validate_round_shape, DkgKeyGroup},
    DecryptionShare, DkgKeyStore, DkgKeystoreError, DkgMaterialError, DkgMessagePrivateKey,
    DkgParameters, DkgPolynomial, DkgSecretScalar, DkgStateError, G1_COMPRESSED_LEN,
};
use aes::Aes128;
use alloy_primitives::{hex, Address, U256};
use cipher::{KeyIvInit, StreamCipher};
use pbkdf2::pbkdf2_hmac;
use scrypt::{scrypt, Params as ScryptParams};
use serde::{Deserialize, Deserializer};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
    str::FromStr,
};
use subtle::ConstantTimeEq;
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

type Aes128Ctr = ctr::Ctr128BE<Aes128>;

const GETH_KEYSTORE_VERSION: u64 = 4;
const GETH_KEYSTORE_NAME: &str = "keystore";
const GETH_KEYSTORE_MAX_BYTES: u64 = 16 * 1024 * 1024;
const GETH_KDF_KEY_BYTES: usize = 32;
const GETH_CIPHER_IV_BYTES: usize = 16;
const GETH_CHECKSUM_BYTES: usize = 32;
const MAX_PBKDF2_ITERATIONS: u32 = 10_000_000;
const MAX_SCRYPT_N: u64 = 1 << 20;
const MAX_SCRYPT_R: u32 = 32;
const MAX_SCRYPT_P: u32 = 16;
const MAX_PENDING_SECRETS: usize = 32;

impl DkgKeyStore {
    /// Migrates one Geth EIP-2335 v4 Anti-MEV keystore into a new Reth DKG keystore.
    ///
    /// The source and destination are required to be private regular files. The destination is
    /// created atomically and never overwritten. The embedded validator identity must equal
    /// `expected_validator` before any migrated state is persisted.
    pub fn import_geth_encrypted_for_validator(
        source: impl AsRef<Path>,
        source_password: &[u8],
        destination: impl AsRef<Path>,
        destination_password: &[u8],
        expected_validator: Address,
    ) -> Result<Self, GethDkgMigrationError> {
        let encrypted = read_geth_keystore(source.as_ref())?;
        let plaintext = decrypt_geth_keystore(&encrypted, source_password)?;
        let mut store = decode_geth_store(&plaintext)?;
        store.bind_validator_address(expected_validator)?;
        store.save_encrypted_new(destination, destination_password)?;
        Ok(store)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GethEnvelope {
    crypto: GethCrypto,
    uuid: String,
    version: u64,
    name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GethCrypto {
    checksum: GethFunction<GethEmptyParams>,
    cipher: GethFunction<GethCipherParams>,
    kdf: GethFunction<GethKdfParams>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GethFunction<Params> {
    function: String,
    message: String,
    params: Params,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GethEmptyParams {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GethCipherParams {
    iv: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GethKdfParams {
    dklen: usize,
    salt: String,
    #[serde(default)]
    c: Option<u32>,
    #[serde(default)]
    prf: Option<String>,
    #[serde(default)]
    n: Option<u64>,
    #[serde(default)]
    r: Option<u32>,
    #[serde(default)]
    p: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GethStore {
    size: usize,
    threshold: usize,
    scaler: u64,
    address: String,
    eth_prv_key: SecretString,
    round: u64,
    recovering: Option<GethGroup>,
    resharing: Option<GethGroup>,
    reshared: Option<GethGroup>,
    sharing: Option<GethGroup>,
    shared: Option<GethGroup>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GethGroup {
    local_secret: Option<Vec<SecretDecimal>>,
    pending_secrets: Option<Vec<Vec<SecretDecimal>>>,
    received_secrets: Vec<Option<SecretDecimal>>,
    global_pubkey: String,
    local_prvkey: SecretString,
}

struct SecretString(Zeroizing<String>);

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<DeserializerType>(
        deserializer: DeserializerType,
    ) -> Result<Self, DeserializerType::Error>
    where
        DeserializerType: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Zeroizing::new).map(Self)
    }
}

struct SecretDecimal(Zeroizing<String>);

impl<'de> Deserialize<'de> for SecretDecimal {
    fn deserialize<DeserializerType>(
        deserializer: DeserializerType,
    ) -> Result<Self, DeserializerType::Error>
    where
        DeserializerType: Deserializer<'de>,
    {
        serde_json::Number::deserialize(deserializer)
            .map(|number| Self(Zeroizing::new(number.to_string())))
    }
}

fn read_geth_keystore(path: &Path) -> Result<Vec<u8>, GethDkgMigrationError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| GethDkgMigrationError::Filesystem(error.to_string()))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(GethDkgMigrationError::NotRegularFile(path.to_path_buf()))
    }
    #[cfg(unix)]
    {
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(GethDkgMigrationError::InsecurePermissions(mode))
        }
    }
    if metadata.len() == 0 || metadata.len() > GETH_KEYSTORE_MAX_BYTES {
        return Err(GethDkgMigrationError::FileSize(metadata.len()))
    }
    let file =
        File::open(path).map_err(|error| GethDkgMigrationError::Filesystem(error.to_string()))?;
    let mut encoded = Vec::with_capacity(metadata.len() as usize);
    file.take(GETH_KEYSTORE_MAX_BYTES + 1)
        .read_to_end(&mut encoded)
        .map_err(|error| GethDkgMigrationError::Filesystem(error.to_string()))?;
    if encoded.len() as u64 > GETH_KEYSTORE_MAX_BYTES {
        return Err(GethDkgMigrationError::FileSize(encoded.len() as u64))
    }
    Ok(encoded)
}

fn decrypt_geth_keystore(
    encoded: &[u8],
    password: &[u8],
) -> Result<Zeroizing<Vec<u8>>, GethDkgMigrationError> {
    let envelope: GethEnvelope = serde_json::from_slice(encoded)
        .map_err(|error| GethDkgMigrationError::Envelope(error.to_string()))?;
    if envelope.version != GETH_KEYSTORE_VERSION ||
        envelope.name != GETH_KEYSTORE_NAME ||
        envelope.uuid.is_empty()
    {
        return Err(GethDkgMigrationError::UnsupportedEnvelope)
    }
    if envelope.crypto.kdf.params.dklen != GETH_KDF_KEY_BYTES ||
        !envelope.crypto.kdf.message.is_empty()
    {
        return Err(GethDkgMigrationError::InvalidKdfParameters)
    }
    let salt = decode_variable_hex("KDF salt", &envelope.crypto.kdf.params.salt, 1, 64)?;
    let normalized_password = normalize_geth_password(password)?;
    let password = normalized_password.as_bytes();
    let mut derived_key = Zeroizing::new([0_u8; GETH_KDF_KEY_BYTES]);
    match envelope.crypto.kdf.function.as_str() {
        "pbkdf2" => {
            let parameters = &envelope.crypto.kdf.params;
            let iterations = parameters.c.ok_or(GethDkgMigrationError::InvalidKdfParameters)?;
            if iterations == 0 ||
                iterations > MAX_PBKDF2_ITERATIONS ||
                parameters.prf.as_deref() != Some("hmac-sha256") ||
                parameters.n.is_some() ||
                parameters.r.is_some() ||
                parameters.p.is_some()
            {
                return Err(GethDkgMigrationError::InvalidKdfParameters)
            }
            pbkdf2_hmac::<Sha256>(password, &salt, iterations, derived_key.as_mut());
        }
        "scrypt" => {
            let parameters = &envelope.crypto.kdf.params;
            let n = parameters.n.ok_or(GethDkgMigrationError::InvalidKdfParameters)?;
            let r = parameters.r.ok_or(GethDkgMigrationError::InvalidKdfParameters)?;
            let p = parameters.p.ok_or(GethDkgMigrationError::InvalidKdfParameters)?;
            if !n.is_power_of_two() ||
                !(2..=MAX_SCRYPT_N).contains(&n) ||
                r == 0 ||
                r > MAX_SCRYPT_R ||
                p == 0 ||
                p > MAX_SCRYPT_P ||
                parameters.c.is_some() ||
                parameters.prf.is_some()
            {
                return Err(GethDkgMigrationError::InvalidKdfParameters)
            }
            let log_n =
                u8::try_from(n.ilog2()).map_err(|_| GethDkgMigrationError::InvalidKdfParameters)?;
            let parameters = ScryptParams::new(log_n, r, p, GETH_KDF_KEY_BYTES)
                .map_err(|_| GethDkgMigrationError::InvalidKdfParameters)?;
            scrypt(password, &salt, &parameters, derived_key.as_mut())
                .map_err(|_| GethDkgMigrationError::KeyDerivation)?;
        }
        _ => return Err(GethDkgMigrationError::UnsupportedKdf),
    }

    if envelope.crypto.checksum.function != "sha256" ||
        envelope.crypto.checksum.message.len() != GETH_CHECKSUM_BYTES * 2 ||
        envelope.crypto.cipher.function != "aes-128-ctr"
    {
        return Err(GethDkgMigrationError::UnsupportedEnvelope)
    }
    let checksum =
        decode_fixed_hex::<GETH_CHECKSUM_BYTES>("checksum", &envelope.crypto.checksum.message)?;
    let ciphertext = decode_variable_hex(
        "ciphertext",
        &envelope.crypto.cipher.message,
        1,
        GETH_KEYSTORE_MAX_BYTES as usize,
    )?;
    let mut hasher = Sha256::new();
    hasher.update(&derived_key[16..]);
    hasher.update(&ciphertext);
    let actual_checksum = hasher.finalize();
    if checksum.ct_eq(actual_checksum.as_slice()).unwrap_u8() != 1 {
        return Err(GethDkgMigrationError::Authentication)
    }
    let iv =
        decode_fixed_hex::<GETH_CIPHER_IV_BYTES>("cipher IV", &envelope.crypto.cipher.params.iv)?;
    let mut plaintext = Zeroizing::new(ciphertext);
    let mut cipher = Aes128Ctr::new_from_slices(&derived_key[..16], &iv)
        .map_err(|_| GethDkgMigrationError::UnsupportedEnvelope)?;
    cipher.apply_keystream(&mut plaintext);
    Ok(plaintext)
}

/// Applies the EIP-2335 password rules the way Neo X Geth's encryptor does.
///
/// Geth encrypts the Anti-MEV keystore with `wealdtech/go-eth2-wallet-encryptor-keystorev4`, which
/// normalises the passphrase to NFKD and drops the C0, DEL and C1 code points before it reaches the
/// KDF. The key therefore commits to the normalised form, not to the bytes the operator typed, so
/// deriving from raw bytes reproduces Geth's key only when the password is pure printable ASCII.
/// Any composed non-ASCII character (`ü` as U+00FC rather than `u` + U+0308) or any embedded
/// control character yields a different key and an authentication failure that is indistinguishable
/// from a wrong password.
///
/// C1 is stripped by code point, matching the oracle: its filter is a byte map, but it is consulted
/// only for runes whose UTF-8 encoding is one byte, so the entries above `0x7f` are unreachable
/// through that path and take effect only after NFKD has already decomposed the input.
fn normalize_geth_password(password: &[u8]) -> Result<Zeroizing<String>, GethDkgMigrationError> {
    let password =
        core::str::from_utf8(password).map_err(|_| GethDkgMigrationError::PasswordEncoding)?;
    let mut normalized = Zeroizing::new(String::with_capacity(password.len()));
    normalized
        .extend(password.nfkd().filter(|character| !is_geth_stripped_password_char(*character)));
    Ok(normalized)
}

/// Whether Neo X Geth's keystore encryptor removes `character` from a passphrase.
const fn is_geth_stripped_password_char(character: char) -> bool {
    matches!(character, '\u{00}'..='\u{1f}' | '\u{7f}'..='\u{9f}')
}

fn decode_geth_store(encoded: &[u8]) -> Result<DkgKeyStore, GethDkgMigrationError> {
    let source: GethStore = serde_json::from_slice(encoded)
        .map_err(|error| GethDkgMigrationError::StateEncoding(error.to_string()))?;
    let parameters = DkgParameters::new(source.size).map_err(|_| {
        GethDkgMigrationError::InvalidGroupParameters {
            size: source.size,
            threshold: source.threshold,
            scaler: source.scaler,
        }
    })?;
    if parameters.threshold() != source.threshold || parameters.scaler() != source.scaler {
        return Err(GethDkgMigrationError::InvalidGroupParameters {
            size: source.size,
            threshold: source.threshold,
            scaler: source.scaler,
        })
    }
    let validator_address = Address::from_str(&source.address)
        .map_err(|_| GethDkgMigrationError::InvalidValidatorAddress)?;
    let message_private_key = DkgMessagePrivateKey::new(decode_fixed_hex::<32>(
        "message private key",
        &source.eth_prv_key.0,
    )?)?;
    let recovering = source.recovering.map(|group| decode_group(group, parameters)).transpose()?;
    let resharing = source.resharing.map(|group| decode_group(group, parameters)).transpose()?;
    let reshared = source.reshared.map(|group| decode_group(group, parameters)).transpose()?;
    let sharing = source.sharing.map(|group| decode_group(group, parameters)).transpose()?;
    let shared = source.shared.map(|group| decode_group(group, parameters)).transpose()?;
    validate_round_shape(source.round, shared.is_some(), reshared.is_some())
        .map_err(GethDkgMigrationError::InvalidState)?;
    Ok(DkgKeyStore {
        parameters,
        round: source.round,
        validator_address: Some(validator_address.into_array()),
        message_private_key,
        recovering,
        resharing,
        reshared,
        sharing,
        shared,
    })
}

fn decode_group(
    source: GethGroup,
    parameters: DkgParameters,
) -> Result<DkgKeyGroup, GethDkgMigrationError> {
    let local_secret = source
        .local_secret
        .map(|coefficients| decode_polynomial(coefficients, parameters))
        .transpose()?;
    let pending = source.pending_secrets.unwrap_or_default();
    if pending.len() > MAX_PENDING_SECRETS {
        return Err(GethDkgMigrationError::TooManyPendingSecrets(pending.len()))
    }
    let pending_secrets = pending
        .into_iter()
        .map(|coefficients| decode_polynomial(coefficients, parameters))
        .collect::<Result<Vec<_>, _>>()?;
    if source.received_secrets.len() != parameters.participants() {
        return Err(GethDkgMigrationError::InvalidReceivedSecretCount(source.received_secrets.len()))
    }
    let received_secrets = source
        .received_secrets
        .into_iter()
        .map(|secret| secret.as_ref().map(decode_decimal_scalar).transpose())
        .collect::<Result<Vec<_>, _>>()?;
    let global_public_key = if source.global_pubkey.is_empty() {
        None
    } else {
        let key =
            decode_fixed_hex::<G1_COMPRESSED_LEN>("global public key", &source.global_pubkey)?;
        DecryptionShare::decode(&key).map_err(|_| GethDkgMigrationError::InvalidGlobalPublicKey)?;
        Some(key)
    };
    let local_private_key = if source.local_prvkey.0.is_empty() {
        None
    } else {
        Some(DkgSecretScalar::new(decode_fixed_hex::<32>(
            "local private key",
            &source.local_prvkey.0,
        )?)?)
    };
    Ok(DkgKeyGroup {
        local_secret,
        pending_secrets,
        received_secrets,
        global_public_key,
        local_private_key,
    })
}

fn decode_polynomial(
    coefficients: Vec<SecretDecimal>,
    parameters: DkgParameters,
) -> Result<DkgPolynomial, GethDkgMigrationError> {
    if coefficients.len() != parameters.threshold() {
        return Err(GethDkgMigrationError::InvalidPolynomialLength(coefficients.len()))
    }
    let coefficients =
        coefficients.iter().map(decode_decimal_bytes).collect::<Result<Vec<_>, _>>()?;
    Ok(DkgPolynomial::from_encoded_coefficients_with_parameters(coefficients, parameters)?)
}

fn decode_decimal_scalar(value: &SecretDecimal) -> Result<DkgSecretScalar, GethDkgMigrationError> {
    Ok(DkgSecretScalar::new(decode_decimal_bytes(value)?)?)
}

fn decode_decimal_bytes(value: &SecretDecimal) -> Result<[u8; 32], GethDkgMigrationError> {
    let value = U256::from_str_radix(&value.0, 10)
        .map_err(|_| GethDkgMigrationError::InvalidDecimalScalar)?;
    Ok(value.to_be_bytes())
}

fn decode_fixed_hex<const N: usize>(
    name: &'static str,
    encoded: &str,
) -> Result<[u8; N], GethDkgMigrationError> {
    let encoded = encoded.strip_prefix("0x").unwrap_or(encoded);
    let decoded = hex::decode(encoded).map_err(|_| GethDkgMigrationError::InvalidHex(name))?;
    decoded.try_into().map_err(|_| GethDkgMigrationError::InvalidHexLength {
        name,
        expected: N,
        actual: encoded.len() / 2,
    })
}

fn decode_variable_hex(
    name: &'static str,
    encoded: &str,
    minimum: usize,
    maximum: usize,
) -> Result<Vec<u8>, GethDkgMigrationError> {
    let encoded = encoded.strip_prefix("0x").unwrap_or(encoded);
    let decoded = hex::decode(encoded).map_err(|_| GethDkgMigrationError::InvalidHex(name))?;
    if !(minimum..=maximum).contains(&decoded.len()) {
        return Err(GethDkgMigrationError::InvalidHexLength {
            name,
            expected: maximum,
            actual: decoded.len(),
        })
    }
    Ok(decoded)
}

/// Failure to authenticate or convert a Neo X Geth Anti-MEV keystore.
#[derive(Debug, Error)]
pub enum GethDkgMigrationError {
    /// Filesystem operation failed.
    #[error("Neo X Geth Anti-MEV keystore filesystem error: {0}")]
    Filesystem(String),
    /// Source keystores must not be symlinks or special files.
    #[error("Neo X Geth Anti-MEV keystore is not a regular file: {0}")]
    NotRegularFile(PathBuf),
    /// Source secrets must be owner-only.
    #[error("insecure Neo X Geth Anti-MEV keystore permissions {0:o}, expected mode 0600")]
    InsecurePermissions(u32),
    /// Source input is bounded before JSON parsing or KDF work.
    #[error("Neo X Geth Anti-MEV keystore size {0} is outside the accepted range")]
    FileSize(u64),
    /// Envelope JSON failed strict parsing.
    #[error("invalid Neo X Geth Anti-MEV keystore envelope: {0}")]
    Envelope(String),
    /// Only the deployed EIP-2335 v4 envelope is accepted.
    #[error("unsupported Neo X Geth Anti-MEV keystore envelope")]
    UnsupportedEnvelope,
    /// EIP-2335 normalisation is defined over text, so the password must be UTF-8.
    #[error("Neo X Geth Anti-MEV keystore password is not valid UTF-8")]
    PasswordEncoding,
    /// Only bounded PBKDF2-HMAC-SHA256 and Scrypt parameters are accepted.
    #[error("invalid Neo X Geth Anti-MEV keystore KDF parameters")]
    InvalidKdfParameters,
    /// The KDF function is not part of EIP-2335.
    #[error("unsupported Neo X Geth Anti-MEV keystore KDF")]
    UnsupportedKdf,
    /// The configured KDF rejected its parameters.
    #[error("Neo X Geth Anti-MEV keystore key derivation failed")]
    KeyDerivation,
    /// Wrong passwords and modified ciphertext are intentionally indistinguishable.
    #[error("Neo X Geth Anti-MEV keystore authentication failed")]
    Authentication,
    /// Decrypted state JSON failed strict parsing.
    #[error("invalid Neo X Geth Anti-MEV keystore state: {0}")]
    StateEncoding(String),
    /// The fixed 7-of-5 group parameters must match Neo X.
    #[error(
        "invalid Geth DKG group parameters: size {size}, threshold {threshold}, scaler {scaler}"
    )]
    InvalidGroupParameters {
        /// Participant count.
        size: usize,
        /// Threshold.
        threshold: usize,
        /// Interpolation scaler.
        scaler: u64,
    },
    /// The embedded validator address is malformed.
    #[error("invalid validator address in Neo X Geth Anti-MEV keystore")]
    InvalidValidatorAddress,
    /// Persisted state-machine shape is inconsistent with its settled round.
    #[error("invalid Neo X Geth DKG state: {0}")]
    InvalidState(&'static str),
    /// Pending secret history is allocation-bounded.
    #[error("too many pending secrets in Neo X Geth DKG state: {0}")]
    TooManyPendingSecrets(usize),
    /// Every group stores exactly seven received-share positions.
    #[error("invalid received-secret count in Neo X Geth DKG state: {0}")]
    InvalidReceivedSecretCount(usize),
    /// Every polynomial has five coefficients.
    #[error("invalid polynomial length in Neo X Geth DKG state: {0}")]
    InvalidPolynomialLength(usize),
    /// JSON big integers must be canonical BLS12-381 scalar values.
    #[error("invalid decimal scalar in Neo X Geth DKG state")]
    InvalidDecimalScalar,
    /// Hex field failed decoding.
    #[error("invalid {0} hex in Neo X Geth DKG state")]
    InvalidHex(&'static str),
    /// Fixed-width hex field had a different length.
    #[error("invalid {name} length {actual}, expected {expected} bytes")]
    InvalidHexLength {
        /// Field name.
        name: &'static str,
        /// Required length or maximum for a variable field.
        expected: usize,
        /// Observed length.
        actual: usize,
    },
    /// Persisted compressed threshold key failed subgroup validation.
    #[error("invalid global public key in Neo X Geth DKG state")]
    InvalidGlobalPublicKey,
    /// Converted state failed a DKG scalar invariant.
    #[error(transparent)]
    Material(#[from] DkgMaterialError),
    /// Converted identity failed a DKG state invariant.
    #[error(transparent)]
    State(#[from] DkgStateError),
    /// Destination encryption or atomic creation failed.
    #[error(transparent)]
    Destination(#[from] DkgKeystoreError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::public_key_from_private_key;
    use serde_json::json;
    use zeroize::Zeroize;

    fn write_geth_fixture(
        path: &Path,
        password: &[u8],
        validator: Address,
        use_scrypt: bool,
    ) -> [u8; 32] {
        let mut message_key = [0_u8; 32];
        message_key[31] = 9;
        let mut threshold_key = [0_u8; 32];
        threshold_key[31] = 7;
        let global_public_key = public_key_from_private_key(&threshold_key).unwrap();
        let group = json!({
            "local_secret": [1, 2, 3, 4, 5],
            "pending_secrets": [],
            "received_secrets": [1, 2, 3, 4, 5, 6, 7],
            "global_pubkey": hex::encode(global_public_key),
            "local_prvkey": hex::encode(threshold_key),
        });
        let plaintext = serde_json::to_vec(&json!({
            "size": 7,
            "threshold": 5,
            "scaler": 360,
            "address": validator.to_string(),
            "eth_prv_key": hex::encode(message_key),
            "round": 1,
            "recovering": null,
            "resharing": null,
            "reshared": null,
            "sharing": null,
            "shared": group,
        }))
        .unwrap();
        let salt = [0x11_u8; 32];
        let iv = [0x22_u8; 16];
        let mut derived_key = [0_u8; 32];
        // Geth's encryptor normalises before it derives, so a fixture that stands in for a Geth
        // keystore has to commit to the normalised form too. Deriving from the raw bytes here would
        // make the fixture agree with any implementation that also skips normalisation.
        let password = normalize_geth_password(password).unwrap();
        let password = password.as_bytes();
        let kdf = if use_scrypt {
            let parameters = ScryptParams::new(2, 1, 1, 32).unwrap();
            scrypt(password, &salt, &parameters, &mut derived_key).unwrap();
            json!({
                "function": "scrypt",
                "message": "",
                "params": {"dklen": 32, "n": 4, "p": 1, "r": 1, "salt": hex::encode(salt)}
            })
        } else {
            pbkdf2_hmac::<Sha256>(password, &salt, 2, &mut derived_key);
            json!({
                "function": "pbkdf2",
                "message": "",
                "params": {"c": 2, "dklen": 32, "prf": "hmac-sha256", "salt": hex::encode(salt)}
            })
        };
        let mut ciphertext = plaintext;
        Aes128Ctr::new_from_slices(&derived_key[..16], &iv)
            .unwrap()
            .apply_keystream(&mut ciphertext);
        let checksum =
            Sha256::new().chain_update(&derived_key[16..]).chain_update(&ciphertext).finalize();
        derived_key.zeroize();
        let envelope = json!({
            "crypto": {
                "checksum": {"function": "sha256", "message": hex::encode(checksum), "params": {}},
                "cipher": {"function": "aes-128-ctr", "message": hex::encode(ciphertext), "params": {"iv": hex::encode(iv)}},
                "kdf": kdf
            },
            "uuid": "00000000-0000-0000-0000-000000000001",
            "version": 4,
            "name": "keystore"
        });
        fs::write(path, serde_json::to_vec(&envelope).unwrap()).unwrap();
        #[cfg(unix)]
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        message_key
    }

    #[test]
    fn migrates_settled_geth_state_and_rejects_wrong_identity() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("antimev-keystore");
        let destination = directory.path().join("reth-dkg.json");
        let validator = Address::repeat_byte(0x44);
        let password = b"geth password";
        let message_key = write_geth_fixture(&source, password, validator, false);

        let store = DkgKeyStore::import_geth_encrypted_for_validator(
            &source,
            password,
            &destination,
            b"reth password",
            validator,
        )
        .unwrap();
        assert_eq!(store.round(), 1);
        assert_eq!(store.validator_address(), Some(validator));
        assert_eq!(
            store.message_public_key(),
            DkgMessagePrivateKey::new(message_key).unwrap().public_key()
        );
        assert_eq!(store.current_private_share().unwrap().as_bytes()[31], 7);

        let restored = DkgKeyStore::load_encrypted(&destination, b"reth password").unwrap();
        assert_eq!(restored.round(), 1);
        assert_eq!(restored.current_private_share().unwrap().as_bytes()[31], 7);

        let second_destination = directory.path().join("wrong-validator.json");
        assert!(matches!(
            DkgKeyStore::import_geth_encrypted_for_validator(
                &source,
                password,
                &second_destination,
                b"reth password",
                Address::repeat_byte(0x45),
            ),
            Err(GethDkgMigrationError::State(DkgStateError::ValidatorAddressMismatch { .. }))
        ));
        assert!(!second_destination.exists());
    }

    #[test]
    fn rejects_wrong_password_before_creating_destination() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("antimev-keystore");
        let destination = directory.path().join("reth-dkg.json");
        let validator = Address::repeat_byte(0x55);
        write_geth_fixture(&source, b"correct", validator, false);
        assert!(matches!(
            DkgKeyStore::import_geth_encrypted_for_validator(
                &source,
                b"wrong",
                &destination,
                b"reth password",
                validator,
            ),
            Err(GethDkgMigrationError::Authentication)
        ));
        assert!(!destination.exists());
    }

    #[test]
    fn migrates_scrypt_envelope() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("antimev-keystore");
        let destination = directory.path().join("reth-dkg.json");
        let validator = Address::repeat_byte(0x66);
        write_geth_fixture(&source, b"geth password", validator, true);

        let store = DkgKeyStore::import_geth_encrypted_for_validator(
            &source,
            b"geth password",
            &destination,
            b"reth password",
            validator,
        )
        .unwrap();
        assert_eq!(store.round(), 1);
        assert!(destination.exists());
    }

    /// Neo X Geth encrypts through `wealdtech/go-eth2-wallet-encryptor-keystorev4`, whose
    /// `normPassphrase` applies NFKD and strips C0, DEL and C1 before the KDF runs. A validator
    /// whose Geth password holds a composed non-ASCII character therefore has a key committed to
    /// the decomposed form; deriving from raw bytes cannot reproduce it, and the migration fails
    /// with an authentication error that looks exactly like a wrong password.
    #[test]
    fn migrates_keystore_whose_password_needs_nfkd() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("antimev-keystore");
        let destination = directory.path().join("reth-dkg.json");
        let validator = Address::repeat_byte(0x77);
        // U+00FC, the form a keyboard produces. NFKD decomposes it to 'u' + U+0308.
        let composed = "gr\u{fc}n passwort".as_bytes();
        let decomposed = "gru\u{308}n passwort".as_bytes();
        assert_ne!(composed, decomposed, "fixture must exercise normalisation");
        write_geth_fixture(&source, composed, validator, false);

        let store = DkgKeyStore::import_geth_encrypted_for_validator(
            &source,
            composed,
            &destination,
            b"reth password",
            validator,
        )
        .unwrap();
        assert_eq!(store.round(), 1);

        // Both spellings normalise to the same key, so either unlocks the same keystore.
        let second_destination = directory.path().join("decomposed.json");
        assert!(DkgKeyStore::import_geth_encrypted_for_validator(
            &source,
            decomposed,
            &second_destination,
            b"reth password",
            validator,
        )
        .is_ok());
    }

    /// The oracle drops control characters anywhere in the passphrase, not just a trailing newline,
    /// so a password carrying one authenticates against a keystore encrypted without it.
    #[test]
    fn strips_the_control_characters_the_oracle_strips() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("antimev-keystore");
        let validator = Address::repeat_byte(0x88);
        write_geth_fixture(&source, b"geth password", validator, false);

        for password in [
            b"geth password\n".to_vec(),
            b"geth\t password".to_vec(),
            b"\x01geth password\x7f".to_vec(),
            "geth password\u{85}".as_bytes().to_vec(),
        ] {
            let destination = directory.path().join(hex::encode(&password));
            assert!(
                DkgKeyStore::import_geth_encrypted_for_validator(
                    &source,
                    &password,
                    &destination,
                    b"reth password",
                    validator,
                )
                .is_ok(),
                "control characters must be stripped from {password:?}"
            );
        }
    }

    #[test]
    fn normalizes_exactly_what_the_oracle_normalizes() {
        // NFKD also folds compatibility forms: U+FB01 'ﬁ' becomes "fi", U+2460 '①' becomes "1".
        assert_eq!(normalize_geth_password("\u{fb01}x".as_bytes()).unwrap().as_str(), "fix");
        assert_eq!(normalize_geth_password("\u{2460}".as_bytes()).unwrap().as_str(), "1");
        // Printable ASCII is untouched, which is why an ASCII-only fixture cannot catch the bug.
        assert_eq!(normalize_geth_password(b"geth password").unwrap().as_str(), "geth password");
        // C0, DEL and C1 all go; nothing else in Latin-1 does.
        assert_eq!(
            normalize_geth_password("a\u{0}\u{1f}\u{7f}\u{9f}b".as_bytes()).unwrap().as_str(),
            "ab"
        );
        assert_eq!(
            normalize_geth_password("\u{a0}\u{a1}".as_bytes()).unwrap().as_str(),
            "\u{20}\u{a1}"
        );

        assert!(matches!(
            normalize_geth_password(&[0xff, 0xfe]),
            Err(GethDkgMigrationError::PasswordEncoding)
        ));
    }
}
