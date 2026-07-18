//! Sandboxed process client for Neo X's gnark DKG prover compatibility helper.

use crate::{DkgGroth16Proof, NEOX_DKG_MESSAGE_LEN};
use alloy_primitives::{hex, Address, Bytes, B256, U256};
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    path::PathBuf,
    process::{ExitStatus, Stdio},
    time::Duration,
};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    process::{Child, Command},
    time::timeout,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

const PROVER_PROTOCOL_VERSION: u8 = 1;
const MAX_PROVER_STDOUT_BYTES: usize = 256 * 1024;
const MAX_PROVER_STDERR_BYTES: usize = 16 * 1024;
const DEFAULT_PROVER_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const BLS12_381_SCALAR_MODULUS: [u8; 32] =
    hex!("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");

/// External prover configuration and process boundary.
#[derive(Debug, Clone)]
pub struct DkgProver {
    executable: PathBuf,
    artifacts: Option<DkgProverArtifacts>,
    timeout: Duration,
}

impl DkgProver {
    /// Configures a helper executable for proofless ZK-v0 encryption.
    pub fn new(executable: impl Into<PathBuf>) -> Result<Self, DkgProverError> {
        let executable = validate_file("prover executable", executable.into())?;
        Ok(Self { executable, artifacts: None, timeout: DEFAULT_PROVER_TIMEOUT })
    }

    /// Installs the pinned one-, two-, and seven-message ZK-v1 proof artifacts.
    pub fn with_artifacts(mut self, artifacts: DkgProverArtifacts) -> Self {
        self.artifacts = Some(artifacts);
        self
    }

    /// Overrides the whole-process deadline, including artifact loading and proof generation.
    pub fn with_timeout(mut self, timeout: Duration) -> Result<Self, DkgProverError> {
        if timeout.is_zero() {
            return Err(DkgProverError::ZeroTimeout)
        }
        self.timeout = timeout;
        Ok(self)
    }

    /// Encrypts DKG shares and optionally generates the exact committed Groth16 contract proof.
    pub async fn prepare(
        &self,
        sender: Address,
        zk_version: u64,
        public_keys: &[[u8; 65]],
        shares: &[DkgShareScalar],
    ) -> Result<DkgProverOutput, DkgProverError> {
        if public_keys.len() != shares.len() {
            return Err(DkgProverError::InputCountMismatch {
                public_keys: public_keys.len(),
                shares: shares.len(),
            })
        }
        if !matches!(shares.len(), 1 | 2 | 7) {
            return Err(DkgProverError::UnsupportedMessageCount(shares.len()))
        }
        if !matches!(zk_version, 0 | 1) {
            return Err(DkgProverError::UnsupportedZkVersion(zk_version))
        }

        let artifacts = match zk_version {
            0 => None,
            1 => Some(
                self.artifacts
                    .as_ref()
                    .ok_or(DkgProverError::MissingArtifacts)?
                    .for_message_count(shares.len())?,
            ),
            _ => unreachable!("ZK version checked above"),
        };
        let public_keys = public_keys.iter().map(hex::encode_prefixed).collect::<Vec<_>>();
        let mut encoded_shares =
            shares.iter().map(|share| hex::encode_prefixed(share.as_bytes())).collect::<Vec<_>>();
        let request = ProverRequest {
            protocol_version: PROVER_PROTOCOL_VERSION,
            zk_version,
            sender: sender.to_string(),
            public_keys: &public_keys,
            shares: &encoded_shares,
            r1cs_path: artifacts.map(|artifact| artifact.r1cs_path.to_string_lossy()),
            r1cs_sha256: artifacts.map(|artifact| artifact.r1cs_sha256.to_string()),
            proving_key_path: artifacts.map(|artifact| artifact.proving_key_path.to_string_lossy()),
            proving_key_sha256: artifacts.map(|artifact| artifact.proving_key_sha256.to_string()),
        };
        let encoded = serde_json::to_vec(&request)
            .map_err(|error| DkgProverError::RequestEncoding(error.to_string()));
        encoded_shares.zeroize();
        let mut encoded = encoded?;

        let result = self.invoke(&encoded).await;
        encoded.zeroize();
        let output = result?;
        decode_output(zk_version, shares.len(), output)
    }

    async fn invoke(&self, request: &[u8]) -> Result<RawProverOutput, DkgProverError> {
        let mut command = Command::new(&self.executable);
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .env_clear();
        let child = command.spawn().map_err(|error| DkgProverError::Spawn(error.to_string()))?;
        timeout(self.timeout, run_child(child, request))
            .await
            .map_err(|_| DkgProverError::Timeout(self.timeout))?
    }
}

/// Pinned circuit and proving key for one DKG message count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DkgProofArtifact {
    r1cs_path: PathBuf,
    r1cs_sha256: B256,
    proving_key_path: PathBuf,
    proving_key_sha256: B256,
}

impl DkgProofArtifact {
    /// Validates regular absolute artifact paths and stores their expected SHA-256 digests.
    pub fn new(
        r1cs_path: impl Into<PathBuf>,
        r1cs_sha256: B256,
        proving_key_path: impl Into<PathBuf>,
        proving_key_sha256: B256,
    ) -> Result<Self, DkgProverError> {
        Ok(Self {
            r1cs_path: validate_file("R1CS", r1cs_path.into())?,
            r1cs_sha256,
            proving_key_path: validate_file("proving key", proving_key_path.into())?,
            proving_key_sha256,
        })
    }
}

/// Pinned proof artifacts for every message count deployed by Neo X.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DkgProverArtifacts {
    one: DkgProofArtifact,
    two: DkgProofArtifact,
    seven: DkgProofArtifact,
}

impl DkgProverArtifacts {
    /// Creates the complete one-, two-, and seven-message artifact set.
    pub const fn new(
        one: DkgProofArtifact,
        two: DkgProofArtifact,
        seven: DkgProofArtifact,
    ) -> Self {
        Self { one, two, seven }
    }

    const fn for_message_count(&self, count: usize) -> Result<&DkgProofArtifact, DkgProverError> {
        match count {
            1 => Ok(&self.one),
            2 => Ok(&self.two),
            7 => Ok(&self.seven),
            count => Err(DkgProverError::UnsupportedMessageCount(count)),
        }
    }
}

/// Canonical nonzero BLS12-381 scalar held as secret DKG material.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DkgShareScalar([u8; 32]);

impl DkgShareScalar {
    /// Validates the big-endian scalar encoding without reducing it modulo the field.
    pub fn new(encoded: [u8; 32]) -> Result<Self, DkgProverError> {
        if encoded.iter().all(|byte| *byte == 0) || encoded >= BLS12_381_SCALAR_MODULUS {
            return Err(DkgProverError::InvalidShareScalar)
        }
        Ok(Self(encoded))
    }

    /// Returns the canonical big-endian scalar bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for DkgShareScalar {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DkgShareScalar([REDACTED])")
    }
}

/// Validated prover result ready for `DkgContractCall::abi_encode`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DkgProverOutput {
    /// Contract-compatible encrypted share messages in input order.
    pub messages: Vec<Bytes>,
    /// ZK-v1 proof coordinates, absent for ZK-v0.
    pub proof: Option<DkgGroth16Proof>,
}

#[derive(Debug, Serialize)]
struct ProverRequest<'a> {
    protocol_version: u8,
    zk_version: u64,
    sender: String,
    public_keys: &'a [String],
    shares: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    r1cs_path: Option<std::borrow::Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    r1cs_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    proving_key_path: Option<std::borrow::Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    proving_key_sha256: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProverResponse {
    protocol_version: u8,
    messages: Vec<String>,
    proof: Option<ProverProof>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProverProof {
    proof: [String; 8],
    commitments: [String; 2],
    commitment_pok: [String; 2],
}

#[derive(Debug)]
struct RawProverOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

async fn run_child(mut child: Child, request: &[u8]) -> Result<RawProverOutput, DkgProverError> {
    let mut stdin = child.stdin.take().ok_or(DkgProverError::MissingPipe("stdin"))?;
    let stdout = child.stdout.take().ok_or(DkgProverError::MissingPipe("stdout"))?;
    let stderr = child.stderr.take().ok_or(DkgProverError::MissingPipe("stderr"))?;
    stdin.write_all(request).await.map_err(|error| DkgProverError::Write(error.to_string()))?;
    stdin.shutdown().await.map_err(|error| DkgProverError::Write(error.to_string()))?;
    drop(stdin);

    let stdout_task = tokio::spawn(read_limited(stdout, MAX_PROVER_STDOUT_BYTES));
    let stderr_task = tokio::spawn(read_limited(stderr, MAX_PROVER_STDERR_BYTES));
    let status = child.wait().await.map_err(|error| DkgProverError::Wait(error.to_string()))?;
    let stdout = stdout_task
        .await
        .map_err(|error| DkgProverError::Read(error.to_string()))?
        .map_err(|error| DkgProverError::Read(error.to_string()))?;
    let stderr = stderr_task
        .await
        .map_err(|error| DkgProverError::Read(error.to_string()))?
        .map_err(|error| DkgProverError::Read(error.to_string()))?;
    Ok(RawProverOutput { status, stdout, stderr })
}

async fn read_limited(reader: impl AsyncRead + Unpin, limit: usize) -> std::io::Result<Vec<u8>> {
    let mut output = Vec::new();
    reader.take((limit + 1) as u64).read_to_end(&mut output).await?;
    Ok(output)
}

fn decode_output(
    zk_version: u64,
    message_count: usize,
    output: RawProverOutput,
) -> Result<DkgProverOutput, DkgProverError> {
    if output.stdout.len() > MAX_PROVER_STDOUT_BYTES {
        return Err(DkgProverError::OutputTooLarge("stdout"))
    }
    if output.stderr.len() > MAX_PROVER_STDERR_BYTES {
        return Err(DkgProverError::OutputTooLarge("stderr"))
    }
    if !output.status.success() {
        let message = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        return Err(DkgProverError::Failed {
            code: output.status.code(),
            message: (!message.is_empty()).then_some(message),
        })
    }

    let response: ProverResponse = serde_json::from_slice(&output.stdout)
        .map_err(|error| DkgProverError::ResponseDecoding(error.to_string()))?;
    if response.protocol_version != PROVER_PROTOCOL_VERSION {
        return Err(DkgProverError::ProtocolVersion(response.protocol_version))
    }
    if response.messages.len() != message_count {
        return Err(DkgProverError::ResponseMessageCount {
            expected: message_count,
            actual: response.messages.len(),
        })
    }
    let messages = response
        .messages
        .iter()
        .enumerate()
        .map(|(index, encoded)| {
            decode_fixed_hex::<{ NEOX_DKG_MESSAGE_LEN }>("message", index, encoded)
                .map(|message| Bytes::copy_from_slice(&message))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let proof = match (zk_version, response.proof) {
        (0, None) => None,
        (0, Some(_)) => return Err(DkgProverError::UnexpectedProof),
        (1, None) => return Err(DkgProverError::MissingProof),
        (1, Some(proof)) => Some(DkgGroth16Proof {
            proof: decode_u256_array("proof", &proof.proof)?,
            commitments: decode_u256_array("commitment", &proof.commitments)?,
            commitment_pok: decode_u256_array("commitment POK", &proof.commitment_pok)?,
        }),
        (version, _) => return Err(DkgProverError::UnsupportedZkVersion(version)),
    };
    Ok(DkgProverOutput { messages, proof })
}

fn decode_u256_array<const N: usize>(
    name: &'static str,
    encoded: &[String; N],
) -> Result<[U256; N], DkgProverError> {
    let mut result = [U256::ZERO; N];
    for (index, value) in encoded.iter().enumerate() {
        result[index] = U256::from_be_bytes(decode_fixed_hex::<32>(name, index, value)?);
    }
    Ok(result)
}

fn decode_fixed_hex<const N: usize>(
    name: &'static str,
    index: usize,
    encoded: &str,
) -> Result<[u8; N], DkgProverError> {
    let raw = encoded.strip_prefix("0x").unwrap_or(encoded);
    if raw.len() != N * 2 {
        return Err(DkgProverError::InvalidHexLength { name, index, expected: N })
    }
    let mut result = [0_u8; N];
    hex::decode_to_slice(raw, &mut result)
        .map_err(|_| DkgProverError::InvalidHex { name, index })?;
    Ok(result)
}

fn validate_file(name: &'static str, path: PathBuf) -> Result<PathBuf, DkgProverError> {
    if !path.is_absolute() {
        return Err(DkgProverError::RelativePath { name, path })
    }
    let metadata = path.metadata().map_err(|error| DkgProverError::File {
        name,
        path: path.clone(),
        error: error.to_string(),
    })?;
    if !metadata.is_file() {
        return Err(DkgProverError::NotFile { name, path })
    }
    Ok(path)
}

/// Failure to validate inputs, invoke the compatibility helper, or decode its response.
#[derive(Debug, Error)]
pub enum DkgProverError {
    /// Configured paths are independent of the node's working directory.
    #[error("Neo X DKG {name} path must be absolute: {path}")]
    RelativePath {
        /// Configured component.
        name: &'static str,
        /// Rejected relative path.
        path: PathBuf,
    },
    /// A configured helper or proof artifact could not be inspected.
    #[error("failed to inspect Neo X DKG {name} at {path}: {error}")]
    File {
        /// Configured component.
        name: &'static str,
        /// Path being inspected.
        path: PathBuf,
        /// Filesystem failure.
        error: String,
    },
    /// Only regular files can be executed or parsed as proof artifacts.
    #[error("Neo X DKG {name} is not a regular file: {path}")]
    NotFile {
        /// Configured component.
        name: &'static str,
        /// Rejected path.
        path: PathBuf,
    },
    /// A zero deadline would make every invocation fail immediately.
    #[error("Neo X DKG prover timeout must be nonzero")]
    ZeroTimeout,
    /// Public encryption keys and secret shares have a one-to-one relationship.
    #[error("Neo X DKG prover input mismatch: {public_keys} public keys, {shares} shares")]
    InputCountMismatch {
        /// Public-key count.
        public_keys: usize,
        /// Secret-share count.
        shares: usize,
    },
    /// Neo X deploys circuits only for one, two, and seven messages.
    #[error("unsupported Neo X DKG prover message count {0}")]
    UnsupportedMessageCount(usize),
    /// Only the deployed ZK-v0 and ZK-v1 protocols are supported.
    #[error("unsupported Neo X DKG ZK version {0}")]
    UnsupportedZkVersion(u64),
    /// ZK-v1 cannot operate without all three pinned circuit/key pairs.
    #[error("Neo X DKG ZK-v1 prover artifacts are not configured")]
    MissingArtifacts,
    /// DKG material must not be silently reduced modulo the scalar field.
    #[error("invalid canonical Neo X DKG share scalar")]
    InvalidShareScalar,
    /// JSON request serialization failed before process creation.
    #[error("failed to encode Neo X DKG prover request: {0}")]
    RequestEncoding(String),
    /// The helper could not be started.
    #[error("failed to spawn Neo X DKG prover: {0}")]
    Spawn(String),
    /// The helper process did not expose a configured standard-I/O pipe.
    #[error("Neo X DKG prover has no {0} pipe")]
    MissingPipe(&'static str),
    /// Secret request bytes could not be delivered to the helper.
    #[error("failed to write Neo X DKG prover request: {0}")]
    Write(String),
    /// Process completion failed.
    #[error("failed to wait for Neo X DKG prover: {0}")]
    Wait(String),
    /// Captured process output could not be read.
    #[error("failed to read Neo X DKG prover output: {0}")]
    Read(String),
    /// The configured whole-process deadline elapsed.
    #[error("Neo X DKG prover exceeded its {0:?} timeout")]
    Timeout(Duration),
    /// Captured output exceeded its defensive allocation ceiling.
    #[error("Neo X DKG prover {0} exceeded its output limit")]
    OutputTooLarge(&'static str),
    /// The helper returned a nonzero process status.
    #[error("Neo X DKG prover failed with status {code:?}: {message:?}")]
    Failed {
        /// Platform process exit code, if available.
        code: Option<i32>,
        /// Bounded helper error output.
        message: Option<String>,
    },
    /// Successful stdout was not one strict response object.
    #[error("failed to decode Neo X DKG prover response: {0}")]
    ResponseDecoding(String),
    /// Client and helper protocol versions must match exactly.
    #[error("unsupported Neo X DKG prover protocol version {0}")]
    ProtocolVersion(u8),
    /// The helper must preserve one message for every input share.
    #[error("Neo X DKG prover returned {actual} messages, expected {expected}")]
    ResponseMessageCount {
        /// Input share count.
        expected: usize,
        /// Returned message count.
        actual: usize,
    },
    /// One fixed-size response field had a different encoded length.
    #[error("invalid Neo X DKG prover {name} {index} length: expected {expected} bytes")]
    InvalidHexLength {
        /// Response field kind.
        name: &'static str,
        /// Field array position.
        index: usize,
        /// Required decoded byte length.
        expected: usize,
    },
    /// One response field was not hexadecimal.
    #[error("invalid hexadecimal Neo X DKG prover {name} {index}")]
    InvalidHex {
        /// Response field kind.
        name: &'static str,
        /// Field array position.
        index: usize,
    },
    /// ZK-v0 must not return proof coordinates.
    #[error("Neo X DKG ZK-v0 prover unexpectedly returned a proof")]
    UnexpectedProof,
    /// ZK-v1 must return proof coordinates.
    #[error("Neo X DKG ZK-v1 prover did not return a proof")]
    MissingProof,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn success_output(zk_version: u64, message_count: usize) -> RawProverOutput {
        let message = hex::encode_prefixed([0x11; NEOX_DKG_MESSAGE_LEN]);
        let proof = (zk_version == 1).then(|| ProverProof {
            proof: core::array::from_fn(|index| format!("0x{:064x}", index + 1)),
            commitments: core::array::from_fn(|index| format!("0x{:064x}", index + 9)),
            commitment_pok: core::array::from_fn(|index| format!("0x{:064x}", index + 11)),
        });
        let response = ProverResponseForTest {
            protocol_version: PROVER_PROTOCOL_VERSION,
            messages: vec![message; message_count],
            proof,
        };
        RawProverOutput {
            status: success_status(),
            stdout: serde_json::to_vec(&response).unwrap(),
            stderr: Vec::new(),
        }
    }

    #[derive(Serialize)]
    struct ProverResponseForTest {
        protocol_version: u8,
        messages: Vec<String>,
        proof: Option<ProverProof>,
    }

    impl Serialize for ProverProof {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            #[derive(Serialize)]
            struct SerializableProof<'a> {
                proof: &'a [String; 8],
                commitments: &'a [String; 2],
                commitment_pok: &'a [String; 2],
            }
            SerializableProof {
                proof: &self.proof,
                commitments: &self.commitments,
                commitment_pok: &self.commitment_pok,
            }
            .serialize(serializer)
        }
    }

    #[cfg(unix)]
    fn success_status() -> ExitStatus {
        use std::os::unix::process::ExitStatusExt;
        ExitStatus::from_raw(0)
    }

    #[cfg(windows)]
    fn success_status() -> ExitStatus {
        use std::os::windows::process::ExitStatusExt;
        ExitStatus::from_raw(0)
    }

    #[test]
    fn validates_and_redacts_share_scalars() {
        let mut one = [0_u8; 32];
        one[31] = 1;
        let share = DkgShareScalar::new(one).unwrap();
        assert_eq!(share.as_bytes(), &one);
        assert_eq!(format!("{share:?}"), "DkgShareScalar([REDACTED])");
        assert!(matches!(DkgShareScalar::new([0_u8; 32]), Err(DkgProverError::InvalidShareScalar)));
        assert!(matches!(
            DkgShareScalar::new(BLS12_381_SCALAR_MODULUS),
            Err(DkgProverError::InvalidShareScalar)
        ));
    }

    #[test]
    fn decodes_strict_v0_and_v1_responses() {
        let v0 = decode_output(0, 7, success_output(0, 7)).unwrap();
        assert_eq!(v0.messages.len(), 7);
        assert!(v0.proof.is_none());

        let v1 = decode_output(1, 2, success_output(1, 2)).unwrap();
        assert_eq!(v1.messages.len(), 2);
        let proof = v1.proof.unwrap();
        assert_eq!(proof.proof[0], U256::from(1));
        assert_eq!(proof.commitments, [U256::from(9), U256::from(10)]);
        assert_eq!(proof.commitment_pok, [U256::from(11), U256::from(12)]);
    }

    #[test]
    fn rejects_response_shape_and_proof_version_confusion() {
        assert!(matches!(
            decode_output(0, 7, success_output(0, 2)),
            Err(DkgProverError::ResponseMessageCount { expected: 7, actual: 2 })
        ));
        assert!(matches!(
            decode_output(1, 7, success_output(0, 7)),
            Err(DkgProverError::MissingProof)
        ));
        assert!(matches!(
            decode_output(0, 7, success_output(1, 7)),
            Err(DkgProverError::UnexpectedProof)
        ));
    }

    #[test]
    fn validates_absolute_regular_paths_and_timeout() {
        let executable = std::env::current_exe().unwrap();
        let prover = DkgProver::new(&executable).unwrap();
        assert!(matches!(prover.with_timeout(Duration::ZERO), Err(DkgProverError::ZeroTimeout)));
        assert!(matches!(
            DkgProver::new(Path::new("relative-helper")),
            Err(DkgProverError::RelativePath { .. })
        ));
        let one = DkgProofArtifact::new(
            &executable,
            B256::repeat_byte(1),
            &executable,
            B256::repeat_byte(2),
        )
        .unwrap();
        let two = DkgProofArtifact::new(
            &executable,
            B256::repeat_byte(3),
            &executable,
            B256::repeat_byte(4),
        )
        .unwrap();
        let seven = DkgProofArtifact::new(
            &executable,
            B256::repeat_byte(5),
            &executable,
            B256::repeat_byte(6),
        )
        .unwrap();
        let artifacts = DkgProverArtifacts::new(one, two, seven);
        assert_eq!(artifacts.for_message_count(1).unwrap().r1cs_sha256, B256::repeat_byte(1));
        assert_eq!(artifacts.for_message_count(2).unwrap().r1cs_sha256, B256::repeat_byte(3));
        assert_eq!(artifacts.for_message_count(7).unwrap().r1cs_sha256, B256::repeat_byte(5));
    }
}
