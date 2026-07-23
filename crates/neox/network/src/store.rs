//! Persistent block-indexed storage for Neo X blob sidecars.

use crate::{BeaconBlobSidecar, BeaconMessageId, BeaconVersion, Blobs, MAX_MESSAGE_SIZE};
use alloy_primitives::B256;
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};
use thiserror::Error;

const STORE_MAGIC: &[u8; 8] = b"NEOXSCAR";
const STORE_VERSION: u8 = 1;
const STORE_HEADER_LEN: usize = STORE_MAGIC.len() + 1;
static TEMP_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// An append-only, block-hash-indexed sidecar store used by the Neo X beacon protocol.
///
/// This is intentionally separate from Reth's transaction-pool blob store: pool blobs are removed
/// after finalization, while Neo X must continue serving finalized block sidecars to beacon peers.
#[derive(Debug, Clone)]
pub struct NeoXSidecarStore {
    root: Arc<PathBuf>,
}

impl NeoXSidecarStore {
    /// Opens (or creates) a persistent sidecar store at `root`.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, SidecarStoreError> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        Ok(Self { root: Arc::new(root) })
    }

    /// Returns the store root.
    pub fn root(&self) -> &Path {
        self.root.as_ref()
    }

    /// Returns whether a complete sidecar vector is stored for `block_hash`.
    ///
    /// [`Self::insert`] writes to a temporary file and atomically renames it into place, so a
    /// present block file is always complete; checking existence avoids reading and
    /// RLP-decoding the whole (up to ~10 MiB) sidecar file just to answer a boolean.
    pub fn contains(&self, block_hash: B256) -> Result<bool, SidecarStoreError> {
        Ok(self.block_path(block_hash).try_exists()?)
    }

    /// Loads the complete sidecar vector for `block_hash`.
    pub fn get(
        &self,
        block_hash: B256,
    ) -> Result<Option<Vec<BeaconBlobSidecar>>, SidecarStoreError> {
        let path = self.block_path(block_hash);
        let mut file = match OpenOptions::new().read(true).open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let length = usize::try_from(file.metadata()?.len())
            .map_err(|_| SidecarStoreError::Oversized(usize::MAX))?;
        if length > STORE_HEADER_LEN + MAX_MESSAGE_SIZE {
            return Err(SidecarStoreError::Oversized(length));
        }
        let mut bytes = Vec::with_capacity(length);
        file.read_to_end(&mut bytes)?;
        decode_store_file(&bytes).map(Some)
    }

    /// Atomically persists the complete sidecar vector for a finalized block.
    pub fn insert(
        &self,
        block_hash: B256,
        sidecars: Vec<BeaconBlobSidecar>,
    ) -> Result<(), SidecarStoreError> {
        let bytes = encode_store_file(sidecars)?;
        let path = self.block_path(block_hash);
        let parent = path.parent().expect("block sidecar path always has a parent");
        fs::create_dir_all(parent)?;

        let sequence = TEMP_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temp_path =
            parent.join(format!(".{}.{}.{}.tmp", block_hash, std::process::id(), sequence));
        let write_result = (|| -> Result<(), SidecarStoreError> {
            let mut file = OpenOptions::new().create_new(true).write(true).open(&temp_path)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            fs::rename(&temp_path, &path)?;
            if let Ok(directory) = OpenOptions::new().read(true).open(parent) {
                directory.sync_all()?;
            }
            Ok(())
        })();
        if write_result.is_err() {
            let _ = fs::remove_file(&temp_path);
        }
        write_result
    }

    fn block_path(&self, block_hash: B256) -> PathBuf {
        let hash = block_hash.to_string();
        let hash = hash.strip_prefix("0x").unwrap_or(&hash);
        self.root.join(&hash[..2]).join(format!("{hash}.rlp"))
    }
}

fn encode_store_file(sidecars: Vec<BeaconBlobSidecar>) -> Result<Vec<u8>, SidecarStoreError> {
    let frame = Blobs { request_id: 0, sidecars }.encoded(BeaconVersion::V2);
    if frame.len() > MAX_MESSAGE_SIZE {
        return Err(SidecarStoreError::Oversized(frame.len()));
    }
    let mut bytes = Vec::with_capacity(STORE_HEADER_LEN + frame.len());
    bytes.extend_from_slice(STORE_MAGIC);
    bytes.push(STORE_VERSION);
    bytes.extend_from_slice(&frame);
    Ok(bytes)
}

fn decode_store_file(bytes: &[u8]) -> Result<Vec<BeaconBlobSidecar>, SidecarStoreError> {
    if bytes.len() < STORE_HEADER_LEN + 1 || &bytes[..STORE_MAGIC.len()] != STORE_MAGIC {
        return Err(SidecarStoreError::InvalidFormat("missing Neo X sidecar store magic"));
    }
    if bytes[STORE_MAGIC.len()] != STORE_VERSION {
        return Err(SidecarStoreError::UnsupportedVersion(bytes[STORE_MAGIC.len()]));
    }
    let frame = &bytes[STORE_HEADER_LEN..];
    if frame[0] != BeaconMessageId::Blobs as u8 {
        return Err(SidecarStoreError::InvalidFormat("stored payload is not a Blobs packet"));
    }
    let response = Blobs::decode(BeaconVersion::V2, &frame[1..])?;
    if response.request_id != 0 {
        return Err(SidecarStoreError::InvalidFormat("stored Blobs request id is not zero"));
    }
    Ok(response.sidecars)
}

/// Persistent sidecar store error.
#[derive(Debug, Error)]
pub enum SidecarStoreError {
    /// Filesystem operation failed.
    #[error("sidecar store I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Stored RLP is malformed.
    #[error("invalid stored sidecar RLP: {0}")]
    Rlp(#[from] alloy_rlp::Error),
    /// A sidecar vector exceeds the Neo X beacon packet limit.
    #[error("sidecar payload is too large: {0} bytes")]
    Oversized(usize),
    /// Store schema is not supported by this node.
    #[error("unsupported sidecar store version {0}")]
    UnsupportedVersion(u8),
    /// Store file has an invalid envelope.
    #[error("invalid sidecar store file: {0}")]
    InvalidFormat(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_eips::{eip4844::BlobTransactionSidecar, eip7594::BlobTransactionSidecarEip7594};

    #[test]
    fn persists_both_sidecar_versions_by_block_hash() {
        let directory = tempfile::tempdir().unwrap();
        let store = NeoXSidecarStore::open(directory.path()).unwrap();
        let hash = B256::repeat_byte(0x42);
        let sidecars = vec![
            BeaconBlobSidecar::Eip4844(BlobTransactionSidecar::default()),
            BeaconBlobSidecar::Eip7594(BlobTransactionSidecarEip7594::default()),
        ];

        assert!(!store.contains(hash).unwrap());
        store.insert(hash, sidecars.clone()).unwrap();
        assert!(store.contains(hash).unwrap());
        assert_eq!(store.get(hash).unwrap(), Some(sidecars));
        assert_eq!(store.get(B256::repeat_byte(0x24)).unwrap(), None);
    }

    #[test]
    fn rejects_corrupt_store_files() {
        let error = decode_store_file(b"not-a-sidecar").unwrap_err();
        assert!(matches!(error, SidecarStoreError::InvalidFormat(_)));

        let mut future = Vec::from(STORE_MAGIC.as_slice());
        future.push(STORE_VERSION + 1);
        future.push(BeaconMessageId::Blobs as u8);
        assert!(matches!(
            decode_store_file(&future),
            Err(SidecarStoreError::UnsupportedVersion(2))
        ));
    }
}
