//! Authenticated encrypted persistence for Neo X DKG state.

use crate::{
    DecryptionShare, DkgKeyGroup, DkgKeyStore, DkgMessagePrivateKey, DkgPolynomial,
    DkgSecretScalar, DkgStateError, NEOX_DKG_PARTICIPANTS, NEOX_DKG_THRESHOLD,
};
use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit, Nonce,
};
use alloc::{string::String, vec::Vec};
use alloy_primitives::hex;
use rand::{rngs::OsRng, TryRngCore};
use scrypt::{scrypt, Params as ScryptParams};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{ErrorKind, Read, Write},
    path::{Path, PathBuf},
};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[cfg(unix)]
use std::os::unix::{fs::OpenOptionsExt, fs::PermissionsExt};

const KEYSTORE_FORMAT: &str = "neox-dkg-keystore";
const KEYSTORE_VERSION: u16 = 1;
const KEYSTORE_AAD: &[u8] = b"neox-dkg-keystore:v1";
const KEYSTORE_KDF: &str = "scrypt";
const KEYSTORE_CIPHER: &str = "aes-256-gcm";
const KDF_LOG_N: u8 = 17;
const KDF_R: u32 = 8;
const KDF_P: u32 = 1;
const KDF_KEY_LEN: usize = 32;
const KDF_SALT_LEN: usize = 32;
const GCM_NONCE_LEN: usize = 12;
const MAX_ENCRYPTED_KEYSTORE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_PENDING_SECRETS: usize = 32;

impl DkgKeyStore {
    /// Generates a fresh message key and atomically creates a new encrypted state file.
    ///
    /// This never overwrites an existing filesystem entry.
    pub fn create_encrypted(
        path: impl AsRef<Path>,
        password: &[u8],
    ) -> Result<Self, DkgKeystoreError> {
        validate_password(password)?;
        let path = resolve_target(path.as_ref())?;
        match fs::symlink_metadata(&path) {
            Ok(_) => return Err(DkgKeystoreError::TargetAlreadyExists(path)),
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(DkgKeystoreError::Filesystem(error.to_string())),
        }
        let store = Self::new(DkgMessagePrivateKey::generate()?);
        let encoded = encrypt_store(&store, password)?;
        atomic_write_new(&path, &encoded)?;
        Ok(store)
    }

    /// Authenticates, validates, and loads an encrypted DKG state file.
    pub fn load_encrypted(
        path: impl AsRef<Path>,
        password: &[u8],
    ) -> Result<Self, DkgKeystoreError> {
        validate_password(password)?;
        let path = resolve_target(path.as_ref())?;
        let encoded = read_private_regular_file(&path)?;
        decrypt_store(&encoded, password)
    }

    /// Authenticates and atomically replaces this store's encrypted state file.
    pub fn save_encrypted(
        &self,
        path: impl AsRef<Path>,
        password: &[u8],
    ) -> Result<(), DkgKeystoreError> {
        validate_password(password)?;
        let path = resolve_target(path.as_ref())?;
        let encoded = encrypt_store(self, password)?;
        atomic_replace(&path, &encoded)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EncryptedEnvelope {
    format: String,
    version: u16,
    kdf: KdfEnvelope,
    cipher: CipherEnvelope,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KdfEnvelope {
    name: String,
    log_n: u8,
    r: u32,
    p: u32,
    salt: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CipherEnvelope {
    name: String,
    nonce: String,
    ciphertext: String,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct PersistedStore {
    schema_version: u16,
    round: u64,
    message_private_key: [u8; 32],
    recovering: Option<PersistedGroup>,
    resharing: Option<PersistedGroup>,
    reshared: Option<PersistedGroup>,
    sharing: Option<PersistedGroup>,
    shared: Option<PersistedGroup>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct PersistedGroup {
    local_secret: Option<PersistedPolynomial>,
    pending_secrets: Vec<PersistedPolynomial>,
    received_secrets: [Option<[u8; 32]>; NEOX_DKG_PARTICIPANTS],
    global_public_key: Option<Vec<u8>>,
    local_private_key: Option<[u8; 32]>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct PersistedPolynomial {
    coefficients: [[u8; 32]; NEOX_DKG_THRESHOLD],
}

impl From<&DkgKeyStore> for PersistedStore {
    fn from(store: &DkgKeyStore) -> Self {
        Self {
            schema_version: KEYSTORE_VERSION,
            round: store.round,
            message_private_key: *store.message_private_key.as_bytes(),
            recovering: store.recovering.as_ref().map(PersistedGroup::from),
            resharing: store.resharing.as_ref().map(PersistedGroup::from),
            reshared: store.reshared.as_ref().map(PersistedGroup::from),
            sharing: store.sharing.as_ref().map(PersistedGroup::from),
            shared: store.shared.as_ref().map(PersistedGroup::from),
        }
    }
}

impl From<&DkgKeyGroup> for PersistedGroup {
    fn from(group: &DkgKeyGroup) -> Self {
        Self {
            local_secret: group.local_secret.as_ref().map(PersistedPolynomial::from),
            pending_secrets: group.pending_secrets.iter().map(PersistedPolynomial::from).collect(),
            received_secrets: core::array::from_fn(|position| {
                group.received_secrets[position].as_ref().map(|share| *share.as_bytes())
            }),
            global_public_key: group.global_public_key.map(|key| key.to_vec()),
            local_private_key: group.local_private_key.as_ref().map(|key| *key.as_bytes()),
        }
    }
}

impl From<&DkgPolynomial> for PersistedPolynomial {
    fn from(polynomial: &DkgPolynomial) -> Self {
        Self { coefficients: polynomial.encoded_coefficients() }
    }
}

impl PersistedStore {
    fn restore(&self) -> Result<DkgKeyStore, DkgKeystoreError> {
        if self.schema_version != KEYSTORE_VERSION {
            return Err(DkgKeystoreError::UnsupportedStateVersion(self.schema_version))
        }
        if self.round == 0 && (self.shared.is_some() || self.reshared.is_some()) {
            return Err(DkgKeystoreError::InvalidState(
                "round zero cannot contain settled key groups",
            ))
        }
        if self.round > 0 && self.shared.is_none() {
            return Err(DkgKeystoreError::InvalidState(
                "a settled round requires the current key group",
            ))
        }
        if self.round < 2 && self.reshared.is_some() {
            return Err(DkgKeystoreError::InvalidState(
                "a previous key group requires at least two settled rounds",
            ))
        }

        Ok(DkgKeyStore {
            round: self.round,
            message_private_key: DkgMessagePrivateKey::new(self.message_private_key)?,
            recovering: self.recovering.as_ref().map(PersistedGroup::restore).transpose()?,
            resharing: self.resharing.as_ref().map(PersistedGroup::restore).transpose()?,
            reshared: self.reshared.as_ref().map(PersistedGroup::restore).transpose()?,
            sharing: self.sharing.as_ref().map(PersistedGroup::restore).transpose()?,
            shared: self.shared.as_ref().map(PersistedGroup::restore).transpose()?,
        })
    }
}

impl PersistedGroup {
    fn restore(&self) -> Result<DkgKeyGroup, DkgKeystoreError> {
        if self.pending_secrets.len() > MAX_PENDING_SECRETS {
            return Err(DkgKeystoreError::InvalidState("too many pending DKG secrets"))
        }
        let local_secret =
            self.local_secret.as_ref().map(PersistedPolynomial::restore).transpose()?;
        let pending_secrets = self
            .pending_secrets
            .iter()
            .map(PersistedPolynomial::restore)
            .collect::<Result<Vec<_>, _>>()?;
        let mut received_secrets = Vec::with_capacity(NEOX_DKG_PARTICIPANTS);
        for share in &self.received_secrets {
            received_secrets
                .push(share.map(DkgSecretScalar::new).transpose().map_err(DkgStateError::from)?);
        }
        let received_secrets =
            received_secrets.try_into().expect("persisted fixed-size received-share array");
        let global_public_key = self
            .global_public_key
            .as_ref()
            .map(|key| {
                DecryptionShare::decode(key).map_err(|_| {
                    DkgKeystoreError::InvalidState("invalid persisted global public key")
                })?;
                key.as_slice()
                    .try_into()
                    .map_err(|_| DkgKeystoreError::InvalidState("invalid global key length"))
            })
            .transpose()?;
        let local_private_key = self
            .local_private_key
            .map(DkgSecretScalar::new)
            .transpose()
            .map_err(DkgStateError::from)?;
        if local_private_key.is_some() && global_public_key.is_none() {
            return Err(DkgKeystoreError::InvalidState(
                "a local threshold key requires a global public key",
            ))
        }
        Ok(DkgKeyGroup {
            local_secret,
            pending_secrets,
            received_secrets,
            global_public_key,
            local_private_key,
        })
    }
}

impl PersistedPolynomial {
    fn restore(&self) -> Result<DkgPolynomial, DkgKeystoreError> {
        DkgPolynomial::from_encoded_coefficients(self.coefficients)
            .map_err(DkgStateError::from)
            .map_err(DkgKeystoreError::from)
    }
}

fn encrypt_store(store: &DkgKeyStore, password: &[u8]) -> Result<Vec<u8>, DkgKeystoreError> {
    let snapshot = PersistedStore::from(store);
    let mut plaintext = serde_json::to_vec(&snapshot)
        .map_err(|error| DkgKeystoreError::StateEncoding(error.to_string()))?;
    let result = encrypt_plaintext(&plaintext, password);
    plaintext.zeroize();
    result
}

fn encrypt_plaintext(plaintext: &[u8], password: &[u8]) -> Result<Vec<u8>, DkgKeystoreError> {
    let mut salt = [0_u8; KDF_SALT_LEN];
    let mut nonce = [0_u8; GCM_NONCE_LEN];
    OsRng
        .try_fill_bytes(&mut salt)
        .and_then(|()| OsRng.try_fill_bytes(&mut nonce))
        .map_err(|error| DkgKeystoreError::Entropy(error.to_string()))?;
    let key = derive_key(password, &salt, KDF_LOG_N, KDF_R, KDF_P)?;
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).expect("scrypt derives an AES-256 key");
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad: KEYSTORE_AAD })
        .map_err(|_| DkgKeystoreError::Encryption)?;
    let envelope = EncryptedEnvelope {
        format: KEYSTORE_FORMAT.into(),
        version: KEYSTORE_VERSION,
        kdf: KdfEnvelope {
            name: KEYSTORE_KDF.into(),
            log_n: KDF_LOG_N,
            r: KDF_R,
            p: KDF_P,
            salt: hex::encode_prefixed(salt),
        },
        cipher: CipherEnvelope {
            name: KEYSTORE_CIPHER.into(),
            nonce: hex::encode_prefixed(nonce),
            ciphertext: hex::encode_prefixed(ciphertext),
        },
    };
    serde_json::to_vec(&envelope)
        .map_err(|error| DkgKeystoreError::EnvelopeEncoding(error.to_string()))
}

fn decrypt_store(encoded: &[u8], password: &[u8]) -> Result<DkgKeyStore, DkgKeystoreError> {
    let envelope: EncryptedEnvelope = serde_json::from_slice(encoded)
        .map_err(|error| DkgKeystoreError::EnvelopeEncoding(error.to_string()))?;
    validate_envelope(&envelope)?;
    let salt = decode_fixed_hex::<KDF_SALT_LEN>(&envelope.kdf.salt, "scrypt salt")?;
    let nonce = decode_fixed_hex::<GCM_NONCE_LEN>(&envelope.cipher.nonce, "GCM nonce")?;
    let ciphertext = hex::decode(&envelope.cipher.ciphertext)
        .map_err(|_| DkgKeystoreError::InvalidEnvelope("invalid ciphertext encoding"))?;
    let key = derive_key(password, &salt, envelope.kdf.log_n, envelope.kdf.r, envelope.kdf.p)?;
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).expect("scrypt derives an AES-256 key");
    let mut plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce), Payload { msg: &ciphertext, aad: KEYSTORE_AAD })
        .map_err(|_| DkgKeystoreError::Authentication)?;
    let snapshot = serde_json::from_slice::<PersistedStore>(&plaintext)
        .map_err(|error| DkgKeystoreError::StateEncoding(error.to_string()));
    plaintext.zeroize();
    snapshot?.restore()
}

fn validate_envelope(envelope: &EncryptedEnvelope) -> Result<(), DkgKeystoreError> {
    if envelope.format != KEYSTORE_FORMAT {
        return Err(DkgKeystoreError::InvalidEnvelope("unexpected format"))
    }
    if envelope.version != KEYSTORE_VERSION {
        return Err(DkgKeystoreError::UnsupportedEnvelopeVersion(envelope.version))
    }
    if envelope.kdf.name != KEYSTORE_KDF ||
        envelope.kdf.log_n != KDF_LOG_N ||
        envelope.kdf.r != KDF_R ||
        envelope.kdf.p != KDF_P
    {
        return Err(DkgKeystoreError::InvalidEnvelope("unsupported KDF parameters"))
    }
    if envelope.cipher.name != KEYSTORE_CIPHER {
        return Err(DkgKeystoreError::InvalidEnvelope("unsupported cipher"))
    }
    Ok(())
}

fn derive_key(
    password: &[u8],
    salt: &[u8],
    log_n: u8,
    r: u32,
    p: u32,
) -> Result<Zeroizing<[u8; KDF_KEY_LEN]>, DkgKeystoreError> {
    let params = ScryptParams::new(log_n, r, p, KDF_KEY_LEN)
        .map_err(|_| DkgKeystoreError::InvalidEnvelope("invalid KDF parameters"))?;
    let mut key = Zeroizing::new([0_u8; KDF_KEY_LEN]);
    scrypt(password, salt, &params, key.as_mut()).map_err(|_| DkgKeystoreError::KeyDerivation)?;
    Ok(key)
}

fn decode_fixed_hex<const N: usize>(
    encoded: &str,
    field: &'static str,
) -> Result<[u8; N], DkgKeystoreError> {
    let decoded = hex::decode(encoded)
        .map_err(|_| DkgKeystoreError::InvalidEnvelope("invalid hexadecimal field"))?;
    decoded.try_into().map_err(|_| DkgKeystoreError::InvalidEnvelope(field))
}

const fn validate_password(password: &[u8]) -> Result<(), DkgKeystoreError> {
    if password.is_empty() {
        Err(DkgKeystoreError::EmptyPassword)
    } else {
        Ok(())
    }
}

fn resolve_target(path: &Path) -> Result<PathBuf, DkgKeystoreError> {
    let filename = path.file_name().ok_or(DkgKeystoreError::InvalidPath)?;
    if filename.to_str().is_none() {
        return Err(DkgKeystoreError::InvalidPath)
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let parent =
        parent.canonicalize().map_err(|error| DkgKeystoreError::Filesystem(error.to_string()))?;
    let metadata =
        fs::metadata(&parent).map_err(|error| DkgKeystoreError::Filesystem(error.to_string()))?;
    if !metadata.is_dir() {
        return Err(DkgKeystoreError::InvalidPath)
    }
    Ok(parent.join(filename))
}

fn read_private_regular_file(path: &Path) -> Result<Vec<u8>, DkgKeystoreError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| DkgKeystoreError::Filesystem(error.to_string()))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(DkgKeystoreError::NotRegularFile(path.to_path_buf()))
    }
    #[cfg(unix)]
    {
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(DkgKeystoreError::InsecurePermissions(mode))
        }
    }
    if metadata.len() > MAX_ENCRYPTED_KEYSTORE_BYTES {
        return Err(DkgKeystoreError::FileTooLarge(metadata.len()))
    }
    let file = File::open(path).map_err(|error| DkgKeystoreError::Filesystem(error.to_string()))?;
    let mut encoded = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_ENCRYPTED_KEYSTORE_BYTES + 1)
        .read_to_end(&mut encoded)
        .map_err(|error| DkgKeystoreError::Filesystem(error.to_string()))?;
    if encoded.len() as u64 > MAX_ENCRYPTED_KEYSTORE_BYTES {
        return Err(DkgKeystoreError::FileTooLarge(encoded.len() as u64))
    }
    Ok(encoded)
}

fn atomic_write_new(path: &Path, encoded: &[u8]) -> Result<(), DkgKeystoreError> {
    let mut temporary = write_temporary(path, encoded)?;
    match fs::hard_link(&temporary.path, path) {
        Ok(()) => {
            fs::remove_file(&temporary.path)
                .map_err(|error| DkgKeystoreError::Filesystem(error.to_string()))?;
            temporary.committed = true;
            sync_parent(path)?;
            Ok(())
        }
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {
            Err(DkgKeystoreError::TargetAlreadyExists(path.to_path_buf()))
        }
        Err(error) => Err(DkgKeystoreError::Filesystem(error.to_string())),
    }
}

fn atomic_replace(path: &Path, encoded: &[u8]) -> Result<(), DkgKeystoreError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
                return Err(DkgKeystoreError::NotRegularFile(path.to_path_buf()))
            }
        }
        Err(error) if error.kind() == ErrorKind::NotFound => return atomic_write_new(path, encoded),
        Err(error) => return Err(DkgKeystoreError::Filesystem(error.to_string())),
    }
    let mut temporary = write_temporary(path, encoded)?;
    fs::rename(&temporary.path, path)
        .map_err(|error| DkgKeystoreError::Filesystem(error.to_string()))?;
    temporary.committed = true;
    sync_parent(path)
}

struct TemporaryFile {
    path: PathBuf,
    committed: bool,
}

impl Drop for TemporaryFile {
    fn drop(&mut self) {
        if !self.committed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn write_temporary(path: &Path, encoded: &[u8]) -> Result<TemporaryFile, DkgKeystoreError> {
    let parent = path.parent().expect("resolved target has a parent");
    let filename =
        path.file_name().and_then(|name| name.to_str()).ok_or(DkgKeystoreError::InvalidPath)?;
    for _ in 0..16 {
        let mut suffix = [0_u8; 8];
        OsRng
            .try_fill_bytes(&mut suffix)
            .map_err(|error| DkgKeystoreError::Entropy(error.to_string()))?;
        let temporary_path =
            parent.join(format!(".{filename}.tmp-{}-{}", std::process::id(), hex::encode(suffix)));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        match options.open(&temporary_path) {
            Ok(mut file) => {
                let temporary = TemporaryFile { path: temporary_path, committed: false };
                file.write_all(encoded)
                    .map_err(|error| DkgKeystoreError::Filesystem(error.to_string()))?;
                file.sync_all().map_err(|error| DkgKeystoreError::Filesystem(error.to_string()))?;
                return Ok(temporary)
            }
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
            Err(error) => return Err(DkgKeystoreError::Filesystem(error.to_string())),
        }
    }
    Err(DkgKeystoreError::TemporaryFileCollision)
}

#[cfg(unix)]
fn sync_parent(path: &Path) -> Result<(), DkgKeystoreError> {
    File::open(path.parent().expect("resolved target has a parent"))
        .and_then(|directory| directory.sync_all())
        .map_err(|error| DkgKeystoreError::Filesystem(error.to_string()))
}

#[cfg(not(unix))]
fn sync_parent(_path: &Path) -> Result<(), DkgKeystoreError> {
    Ok(())
}

/// Failure to encrypt, validate, or atomically persist a Neo X DKG state file.
#[derive(Debug, Error)]
pub enum DkgKeystoreError {
    /// Empty passwords provide no protection.
    #[error("Neo X DKG keystore password cannot be empty")]
    EmptyPassword,
    /// The target must have a filename under an existing directory.
    #[error("invalid Neo X DKG keystore path")]
    InvalidPath,
    /// New-store creation never overwrites an existing entry.
    #[error("Neo X DKG keystore target already exists: {0}")]
    TargetAlreadyExists(PathBuf),
    /// Symlinks, directories, devices, and sockets are rejected.
    #[error("Neo X DKG keystore is not a regular file: {0}")]
    NotRegularFile(PathBuf),
    /// Secret state must not be readable by group or other users.
    #[error("insecure Neo X DKG keystore permissions {0:o}, expected no group/other bits")]
    InsecurePermissions(u32),
    /// Encrypted input is bounded before JSON parsing and KDF work.
    #[error("Neo X DKG keystore is too large: {0} bytes")]
    FileTooLarge(u64),
    /// Filesystem operation failed.
    #[error("Neo X DKG keystore filesystem error: {0}")]
    Filesystem(String),
    /// OS randomness failed.
    #[error("failed to obtain Neo X DKG keystore entropy: {0}")]
    Entropy(String),
    /// Scrypt failed to derive the encryption key.
    #[error("Neo X DKG keystore key derivation failed")]
    KeyDerivation,
    /// AES-256-GCM encryption failed.
    #[error("Neo X DKG keystore encryption failed")]
    Encryption,
    /// Wrong password and modified ciphertext are intentionally indistinguishable.
    #[error("Neo X DKG keystore authentication failed")]
    Authentication,
    /// Encrypted envelope JSON could not be encoded or parsed.
    #[error("invalid Neo X DKG keystore envelope: {0}")]
    EnvelopeEncoding(String),
    /// Plaintext state JSON could not be encoded or parsed.
    #[error("invalid Neo X DKG keystore state encoding: {0}")]
    StateEncoding(String),
    /// Envelope algorithms or fields are not the pinned version.
    #[error("invalid Neo X DKG keystore envelope: {0}")]
    InvalidEnvelope(&'static str),
    /// Encrypted envelope versions require explicit migration.
    #[error("unsupported Neo X DKG keystore envelope version {0}")]
    UnsupportedEnvelopeVersion(u16),
    /// Plaintext schema versions require explicit migration.
    #[error("unsupported Neo X DKG state version {0}")]
    UnsupportedStateVersion(u16),
    /// Decrypted state violated a state-machine invariant.
    #[error("invalid Neo X DKG keystore state: {0}")]
    InvalidState(&'static str),
    /// Decrypted secret material failed canonical validation.
    #[error(transparent)]
    State(#[from] DkgStateError),
    /// Random temporary-name collisions exceeded the bounded retry count.
    #[error("failed to allocate a unique Neo X DKG keystore temporary file")]
    TemporaryFileCollision,
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::U256;

    fn message_key(value: u8) -> DkgMessagePrivateKey {
        let mut encoded = [0_u8; 32];
        encoded[31] = value;
        DkgMessagePrivateKey::new(encoded).unwrap()
    }

    #[test]
    fn encrypted_roundtrip_preserves_pending_state_and_rejects_wrong_password() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("validator-dkg.json");
        let password = b"correct horse battery staple";
        let mut store = DkgKeyStore::new(message_key(3));
        store.on_share_period_start(false);
        store.prepare_share(U256::from(47_763)).unwrap();
        let expected = PersistedStore::from(&store);

        store.save_encrypted(&path, password).unwrap();
        let encoded = fs::read_to_string(&path).unwrap();
        assert!(!encoded.contains("message_private_key"));
        assert!(!encoded.contains(&hex::encode(store.message_private_key.as_bytes())));
        assert!(encoded.contains(KEYSTORE_FORMAT));
        #[cfg(unix)]
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);

        let restored = DkgKeyStore::load_encrypted(&path, password).unwrap();
        let actual = PersistedStore::from(&restored);
        assert!(expected == actual);
        assert_eq!(restored.message_public_key(), store.message_public_key());
        assert!(restored.is_sharing());
        assert!(matches!(
            DkgKeyStore::load_encrypted(&path, b"wrong password"),
            Err(DkgKeystoreError::Authentication)
        ));
        assert!(matches!(
            DkgKeyStore::create_encrypted(&path, password),
            Err(DkgKeystoreError::TargetAlreadyExists(_))
        ));

        #[cfg(unix)]
        {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
            assert!(matches!(
                DkgKeyStore::load_encrypted(&path, password),
                Err(DkgKeystoreError::InsecurePermissions(0o640))
            ));
        }
    }

    #[test]
    fn atomic_writes_never_overwrite_on_create_and_leave_no_temporary_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.json");
        atomic_write_new(&path, b"first").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"first");
        assert!(matches!(
            atomic_write_new(&path, b"forbidden"),
            Err(DkgKeystoreError::TargetAlreadyExists(existing)) if existing == path
        ));
        assert_eq!(fs::read(&path).unwrap(), b"first");

        atomic_replace(&path, b"second").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"second");
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
        #[cfg(unix)]
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn decrypted_state_is_validated_before_construction() {
        let store = DkgKeyStore::new(message_key(7));
        let mut snapshot = PersistedStore::from(&store);
        snapshot.message_private_key = [0_u8; 32];
        assert!(matches!(
            snapshot.restore(),
            Err(DkgKeystoreError::State(DkgStateError::InvalidMessagePrivateKey))
        ));

        let mut snapshot = PersistedStore::from(&store);
        snapshot.schema_version = 2;
        assert!(matches!(snapshot.restore(), Err(DkgKeystoreError::UnsupportedStateVersion(2))));

        let mut snapshot = PersistedStore::from(&store);
        snapshot.round = 1;
        assert!(matches!(
            snapshot.restore(),
            Err(DkgKeystoreError::InvalidState("a settled round requires the current key group"))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn load_rejects_symlinks() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target");
        let link = directory.path().join("link");
        fs::write(&target, b"ciphertext").unwrap();
        symlink(&target, &link).unwrap();
        assert!(matches!(
            read_private_regular_file(&link),
            Err(DkgKeystoreError::NotRegularFile(existing)) if existing == link
        ));
    }
}
