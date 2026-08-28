//! Sandboxed process client for Neo X's gnark DKG prover compatibility helper.

use crate::{DkgContractMethod, DkgGroth16Proof, NEOX_DKG_MESSAGE_LEN};
use alloy_primitives::{hex, Address, Bytes, B256, U256};
use serde::{Deserialize, Serialize};
#[cfg(target_os = "linux")]
use std::{
    ffi::CString,
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    os::{
        fd::{AsRawFd, FromRawFd, RawFd},
        unix::ffi::OsStrExt,
    },
    path::{Component, Path},
    sync::Arc,
};
use std::{
    fmt,
    path::PathBuf,
    process::{ExitStatus, Stdio},
    time::Duration,
};
use thiserror::Error;
#[cfg(target_os = "linux")]
use tokio::sync::oneshot;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    process::{Child, Command},
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const PROVER_PROTOCOL_VERSION: u8 = 1;
const MAX_PROVER_STDOUT_BYTES: usize = 256 * 1024;
const MAX_PROVER_STDERR_BYTES: usize = 16 * 1024;
const DEFAULT_PROVER_TIMEOUT: Duration = Duration::from_secs(30 * 60);
#[cfg(target_os = "linux")]
const MAX_PROVER_EXECUTABLE_BYTES: u64 = 512 * 1024 * 1024;
#[cfg(target_os = "linux")]
const PROVER_EXIT_POLL_INTERVAL: Duration = Duration::from_millis(10);
const BLS12_381_SCALAR_MODULUS: [u8; 32] =
    hex!("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");

/// External prover configuration and process boundary.
#[derive(Debug, Clone)]
pub struct DkgProver {
    executable: TrustedExecutable,
    artifacts: Option<DkgProverArtifacts>,
    timeout: Duration,
}

impl DkgProver {
    /// Configures a helper executable for proofless ZK-v0 encryption.
    pub fn new(executable: impl Into<PathBuf>) -> Result<Self, DkgProverError> {
        let executable = TrustedExecutable::new(executable.into())?;
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
            return Err(DkgProverError::ZeroTimeout);
        }
        self.timeout = timeout;
        Ok(self)
    }

    /// Encrypts DKG shares and optionally generates the exact committed Groth16 contract proof.
    pub async fn prepare(
        &self,
        sender: Address,
        method: DkgContractMethod,
        zk_version: u64,
        public_keys: &[[u8; 65]],
        shares: &[DkgShareScalar],
    ) -> Result<DkgProverOutput, DkgProverError> {
        if public_keys.len() != shares.len() {
            return Err(DkgProverError::InputCountMismatch {
                public_keys: public_keys.len(),
                shares: shares.len(),
            });
        }
        if !matches!(zk_version, 0 | 1) {
            return Err(DkgProverError::UnsupportedZkVersion(zk_version));
        }
        validate_message_count(method, zk_version, shares.len())?;

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
        let encoded_shares = Zeroizing::new(
            shares.iter().map(|share| hex::encode_prefixed(share.as_bytes())).collect::<Vec<_>>(),
        );
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
        let encoded = Zeroizing::new(
            serde_json::to_vec(&request)
                .map_err(|error| DkgProverError::RequestEncoding(error.to_string()))?,
        );
        // The serialized request is the only copy needed across the process boundary. Drop the
        // per-share JSON strings before awaiting the potentially long-running prover so a second
        // plaintext copy is not retained for the whole timeout window.
        drop(request);
        drop(encoded_shares);

        let output = self.invoke(&encoded).await?;
        decode_output(zk_version, shares.len(), output)
    }

    async fn invoke(&self, request: &[u8]) -> Result<RawProverOutput, DkgProverError> {
        #[cfg(target_os = "linux")]
        {
            self.invoke_linux_supervised(request, ProverSupervisorProbe::default()).await
        }
        #[cfg(not(target_os = "linux"))]
        {
            let mut command = self.executable.command()?;
            command
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true)
                .env_clear()
                .current_dir("/");
            let child =
                command.spawn().map_err(|error| DkgProverError::Spawn(error.to_string()))?;
            match tokio::time::timeout(self.timeout, run_child(child, request)).await {
                Ok(result) => result,
                Err(_) => Err(DkgProverError::Timeout(self.timeout)),
            }
        }
    }

    #[cfg(target_os = "linux")]
    async fn invoke_linux_supervised(
        &self,
        request: &[u8],
        probe: ProverSupervisorProbe,
    ) -> Result<RawProverOutput, DkgProverError> {
        let mut command = self.executable.command()?;
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .env_clear()
            .current_dir("/");
        let mut child =
            command.spawn().map_err(|error| DkgProverError::Spawn(error.to_string()))?;
        let child_pid = match child.id().filter(|pid| *pid > 1) {
            Some(child_pid) => child_pid,
            None => {
                let kill_error = child.start_kill().err();
                let wait_error = child.wait().await.err();
                let mut errors = vec!["spawned prover child has no valid PID".to_owned()];
                if let Some(error) = kill_error {
                    errors.push(format!("leader kill failed: {error}"));
                }
                if let Some(error) = wait_error {
                    errors.push(format!("leader wait failed: {error}"));
                }
                return Err(DkgProverError::ProcessGroupCleanup(errors.join("; ")))
            }
        };

        // The supervisor owns every lifecycle-sensitive resource. If the invoking future is
        // aborted during a reorg, dropping `cancellation` only signals this task; it does not drop
        // the child, waitid observer, or pipe readers before structured cleanup completes.
        let request = Zeroizing::new(request.to_vec());
        let (cancellation_sender, cancellation_receiver) = oneshot::channel();
        let mut cancellation = ProverCancellation::new(cancellation_sender);
        // Construct the guard before spawning so even a runtime shutdown that drops the supervisor
        // before its first poll still signals the complete process group.
        let child = ProverChildOwner::new(child, child_pid);
        let supervisor = tokio::spawn(supervise_linux_child(
            child,
            child_pid,
            request,
            self.timeout,
            cancellation_receiver,
            probe,
        ));
        let result = supervisor.await;
        cancellation.disarm();
        result.map_err(|error| {
            DkgProverError::ProcessGroupCleanup(format!("prover supervisor task failed: {error}"))
        })?
    }
}

const fn validate_message_count(
    method: DkgContractMethod,
    zk_version: u64,
    count: usize,
) -> Result<(), DkgProverError> {
    if count == 0 || count > 256 {
        return Err(DkgProverError::UnsupportedMessageCount(count));
    }
    if zk_version == 1 {
        let supported = match method {
            DkgContractMethod::Share |
            DkgContractMethod::Reshare |
            DkgContractMethod::ReshareRecovered => count == 7,
            DkgContractMethod::Recover => matches!(count, 1 | 2),
        };
        if !supported {
            return Err(DkgProverError::UnsupportedMessageCount(count));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
struct ProverCancellation {
    sender: Option<oneshot::Sender<()>>,
}

#[cfg(target_os = "linux")]
impl ProverCancellation {
    const fn new(sender: oneshot::Sender<()>) -> Self {
        Self { sender: Some(sender) }
    }

    fn disarm(&mut self) {
        self.sender = None;
    }
}

#[cfg(target_os = "linux")]
impl Drop for ProverCancellation {
    fn drop(&mut self) {
        if let Some(sender) = self.sender.take() {
            let _ = sender.send(());
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Default)]
struct ProverSupervisorProbe {
    started: Option<oneshot::Sender<u32>>,
    completed: Option<oneshot::Sender<bool>>,
}

#[cfg(target_os = "linux")]
impl ProverSupervisorProbe {
    fn notify_started(&mut self, child_pid: u32) {
        if let Some(started) = self.started.take() {
            let _ = started.send(child_pid);
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct ProverProcessGroup {
    process_group: Option<libc::pid_t>,
}

#[cfg(target_os = "linux")]
impl ProverProcessGroup {
    fn new(child_pid: u32) -> Self {
        debug_assert!(child_pid > 1);
        Self { process_group: Some(child_pid as libc::pid_t) }
    }

    fn kill(&self) -> io::Result<()> {
        if let Some(process_group) = self.process_group {
            loop {
                // Negative pid targets the dedicated process group created in the pre-exec hook.
                let result = unsafe { libc::kill(-process_group, libc::SIGKILL) };
                if result == 0 {
                    break
                }
                let error = io::Error::last_os_error();
                // ESRCH means the direct child and every descendant already exited. Every other
                // failure is security-relevant and leaves the guard armed for a Drop retry.
                if error.raw_os_error() == Some(libc::ESRCH) {
                    break
                }
                if error.kind() == io::ErrorKind::Interrupted {
                    continue
                }
                return Err(error)
            }
        }
        Ok(())
    }

    const fn disarm(&mut self) {
        self.process_group = None;
    }
}

#[cfg(target_os = "linux")]
impl Drop for ProverProcessGroup {
    fn drop(&mut self) {
        let _ = self.kill();
    }
}

#[cfg(target_os = "linux")]
struct ProverChildOwner {
    process_group: ProverProcessGroup,
    child: Child,
}

#[cfg(target_os = "linux")]
impl ProverChildOwner {
    fn new(child: Child, child_pid: u32) -> Self {
        Self { process_group: ProverProcessGroup::new(child_pid), child }
    }
}

#[cfg(target_os = "linux")]
impl Drop for ProverChildOwner {
    fn drop(&mut self) {
        // This owner is captured as one future field. Its explicit Drop runs before either field
        // is released, so an unpolled or abruptly dropped supervisor still kills the group while
        // the direct child pins its numeric PGID.
        let _ = self.process_group.kill();
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
struct TrustedExecutable {
    snapshot: Arc<File>,
}

#[cfg(target_os = "linux")]
impl TrustedExecutable {
    fn new(source: PathBuf) -> Result<Self, DkgProverError> {
        let executable =
            open_trusted_file("prover executable", &source, TrustedFileKind::Executable)?;
        let snapshot = snapshot_executable(executable, &source)?;
        Ok(Self { snapshot: Arc::new(snapshot) })
    }

    fn command(&self) -> Result<Command, DkgProverError> {
        let executable_fd = self.snapshot.as_raw_fd();
        let proc_path = PathBuf::from(format!("/proc/self/fd/{executable_fd}"));
        if !Path::new("/proc/self/fd").is_dir() {
            return Err(DkgProverError::Sandbox(
                "Linux /proc/self/fd is required for sealed prover execution".to_owned(),
            ));
        }

        let mut command = Command::new(proc_path);
        // SAFETY: the closure calls only async-signal-safe syscalls and does not allocate. It marks
        // the sealed executable descriptor as inherited before Command performs execve.
        unsafe {
            command.pre_exec(move || harden_prover_child(executable_fd));
        }
        Ok(command)
    }
}

#[cfg(not(target_os = "linux"))]
#[derive(Debug, Clone)]
struct TrustedExecutable;

#[cfg(not(target_os = "linux"))]
impl TrustedExecutable {
    fn new(_source: PathBuf) -> Result<Self, DkgProverError> {
        Err(DkgProverError::UnsupportedPlatform)
    }

    const fn command(&self) -> Result<Command, DkgProverError> {
        Err(DkgProverError::UnsupportedPlatform)
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TrustedFileKind {
    Directory,
    Regular,
    Executable,
}

#[cfg(target_os = "linux")]
fn open_trusted_file(
    name: &'static str,
    path: &Path,
    kind: TrustedFileKind,
) -> Result<File, DkgProverError> {
    if !path.is_absolute() {
        return Err(DkgProverError::RelativePath { name, path: path.to_path_buf() });
    }

    let mut names = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(value) => names.push(value),
            _ => return Err(DkgProverError::UnsafePath { name, path: path.to_path_buf() }),
        }
    }
    if names.is_empty() {
        return Err(DkgProverError::NotFile { name, path: path.to_path_buf() });
    }

    let root = CString::new("/").expect("static root path has no NUL");
    // SAFETY: root is a valid C string and the returned descriptor is owned immediately.
    let root_fd = unsafe { libc::open(root.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if root_fd < 0 {
        return Err(path_io_error(name, Path::new("/"), io::Error::last_os_error()));
    }
    // SAFETY: open returned a new owned descriptor.
    let mut directory = unsafe { File::from_raw_fd(root_fd) };
    validate_trusted_metadata(name, Path::new("/"), &directory, TrustedFileKind::Directory)?;

    let mut resolved = PathBuf::from("/");
    for (index, component) in names.iter().enumerate() {
        resolved.push(component);
        let is_last = index + 1 == names.len();
        let expected = if is_last { kind } else { TrustedFileKind::Directory };
        let flags = match expected {
            TrustedFileKind::Directory => libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            TrustedFileKind::Regular | TrustedFileKind::Executable => {
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK
            }
        };
        let component = CString::new(component.as_bytes())
            .map_err(|_| DkgProverError::UnsafePath { name, path: resolved.clone() })?;
        // SAFETY: directory and component are valid; the new descriptor is owned immediately.
        let fd = unsafe { libc::openat(directory.as_raw_fd(), component.as_ptr(), flags) };
        if fd < 0 {
            return Err(path_io_error(name, &resolved, io::Error::last_os_error()));
        }
        // SAFETY: openat returned a new owned descriptor.
        let opened = unsafe { File::from_raw_fd(fd) };
        validate_trusted_metadata(name, &resolved, &opened, expected)?;
        if is_last {
            return Ok(opened);
        }
        directory = opened;
    }
    unreachable!("an absolute non-root path has at least one component")
}

#[cfg(target_os = "linux")]
fn path_io_error(name: &'static str, path: &Path, error: io::Error) -> DkgProverError {
    if error.raw_os_error() == Some(libc::ELOOP) {
        DkgProverError::Symlink { name, path: path.to_path_buf() }
    } else {
        DkgProverError::File { name, path: path.to_path_buf(), error: error.to_string() }
    }
}

#[cfg(target_os = "linux")]
fn validate_trusted_metadata(
    name: &'static str,
    path: &Path,
    file: &File,
    expected: TrustedFileKind,
) -> Result<(), DkgProverError> {
    use std::os::unix::fs::MetadataExt;

    let metadata = file.metadata().map_err(|error| path_io_error(name, path, error))?;
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(DkgProverError::Symlink { name, path: path.to_path_buf() });
    }
    let expected_type = match expected {
        TrustedFileKind::Directory => file_type.is_dir(),
        TrustedFileKind::Regular | TrustedFileKind::Executable => file_type.is_file(),
    };
    if !expected_type {
        return Err(DkgProverError::NotFile { name, path: path.to_path_buf() });
    }

    // Files owned by the node account or root are trusted. Shared writes are accepted only for a
    // root-owned sticky directory (for example /tmp). In particular, do not infer that a group is
    // private from NSS membership: primary-group users and POSIX ACL entries are not reliably
    // listed there. Every child entry is still opened relative to the anchored descriptor.
    let effective_uid = unsafe { libc::geteuid() };
    if metadata.uid() != 0 && metadata.uid() != effective_uid {
        return Err(DkgProverError::UntrustedOwner {
            name,
            path: path.to_path_buf(),
            owner: metadata.uid(),
        });
    }
    let mode = metadata.mode();
    let shared_writable = mode & 0o022 != 0;
    let trusted_sticky_directory =
        expected == TrustedFileKind::Directory && metadata.uid() == 0 && mode & libc::S_ISVTX != 0;
    let has_special_file_bits = expected != TrustedFileKind::Directory && mode & 0o7000 != 0;
    if (shared_writable && !trusted_sticky_directory) || has_special_file_bits {
        return Err(DkgProverError::UnsafePermissions {
            name,
            path: path.to_path_buf(),
            mode: mode & 0o7777,
        });
    }
    if expected == TrustedFileKind::Executable && !can_execute(&metadata) {
        return Err(DkgProverError::NotExecutable { path: path.to_path_buf() });
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn can_execute(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    let mode = metadata.mode();
    let effective_uid = unsafe { libc::geteuid() };
    if effective_uid == 0 {
        return mode & 0o111 != 0;
    }
    if metadata.uid() == effective_uid {
        return mode & 0o100 != 0;
    }

    let effective_gid = unsafe { libc::getegid() };
    if metadata.gid() == effective_gid {
        return mode & 0o010 != 0;
    }
    // SAFETY: a null first call queries the required count; the second writes into allocated space.
    let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if count > 0 {
        let mut groups = vec![0; count as usize];
        let actual = unsafe { libc::getgroups(count, groups.as_mut_ptr()) };
        if actual >= 0 && groups[..actual as usize].contains(&metadata.gid()) {
            return mode & 0o010 != 0;
        }
    }
    mode & 0o001 != 0
}

#[cfg(target_os = "linux")]
#[derive(Debug, PartialEq, Eq)]
struct FileFingerprint {
    device: u64,
    inode: u64,
    length: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

#[cfg(target_os = "linux")]
impl FileFingerprint {
    fn read(file: &File, path: &Path) -> Result<Self, DkgProverError> {
        use std::os::unix::fs::MetadataExt;

        let metadata = file.metadata().map_err(|error| DkgProverError::File {
            name: "prover executable",
            path: path.to_path_buf(),
            error: error.to_string(),
        })?;
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            length: metadata.size(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        })
    }
}

#[cfg(target_os = "linux")]
fn snapshot_executable(mut source: File, path: &Path) -> Result<File, DkgProverError> {
    let before = FileFingerprint::read(&source, path)?;
    if before.length == 0 || before.length > MAX_PROVER_EXECUTABLE_BYTES {
        return Err(DkgProverError::ExecutableSize {
            path: path.to_path_buf(),
            size: before.length,
            maximum: MAX_PROVER_EXECUTABLE_BYTES,
        });
    }

    let name = CString::new("neox-dkg-prover").expect("static memfd name has no NUL");
    let flags = libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING | libc::MFD_EXEC;
    // SAFETY: name is valid and the returned descriptor is owned immediately.
    let fd = unsafe { libc::memfd_create(name.as_ptr(), flags) };
    let fd = if fd < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) {
        // MFD_EXEC was added in Linux 6.3. Older kernels still create executable memfds by default.
        unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) }
    } else {
        fd
    };
    if fd < 0 {
        return Err(DkgProverError::Sandbox(io::Error::last_os_error().to_string()));
    }
    // SAFETY: memfd_create returned a new owned descriptor.
    let mut snapshot = unsafe { File::from_raw_fd(fd) };
    source.seek(SeekFrom::Start(0)).map_err(|error| DkgProverError::Snapshot(error.to_string()))?;
    let copied = {
        let mut limited = (&mut source).take(MAX_PROVER_EXECUTABLE_BYTES + 1);
        io::copy(&mut limited, &mut snapshot)
            .map_err(|error| DkgProverError::Snapshot(error.to_string()))?
    };
    let after = FileFingerprint::read(&source, path)?;
    if before != after || copied != before.length {
        return Err(DkgProverError::ExecutableChanged { path: path.to_path_buf() });
    }
    snapshot.flush().map_err(|error| DkgProverError::Snapshot(error.to_string()))?;
    validate_native_static_elf(&mut snapshot, path, copied)?;
    snapshot
        .seek(SeekFrom::Start(0))
        .map_err(|error| DkgProverError::Snapshot(error.to_string()))?;

    // SAFETY: snapshot is an owned descriptor; permissions are set before seals become immutable.
    if unsafe { libc::fchmod(snapshot.as_raw_fd(), 0o500) } != 0 {
        return Err(DkgProverError::Sandbox(io::Error::last_os_error().to_string()));
    }
    let portable_seals =
        libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    let strongest_seals = portable_seals | libc::F_SEAL_FUTURE_WRITE | libc::F_SEAL_EXEC;
    // SAFETY: fcntl operates on the private memfd and does not retain pointers.
    if unsafe { libc::fcntl(snapshot.as_raw_fd(), libc::F_ADD_SEALS, strongest_seals) } != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINVAL) ||
            unsafe { libc::fcntl(snapshot.as_raw_fd(), libc::F_ADD_SEALS, portable_seals) } != 0
        {
            return Err(DkgProverError::Sandbox(io::Error::last_os_error().to_string()));
        }
    }
    if snapshot.as_raw_fd() < 3 {
        // SAFETY: fcntl returns a new descriptor with close-on-exec set; File takes sole ownership.
        let fd = unsafe { libc::fcntl(snapshot.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
        if fd < 0 {
            return Err(DkgProverError::Sandbox(io::Error::last_os_error().to_string()));
        }
        // SAFETY: F_DUPFD_CLOEXEC returned a new owned descriptor.
        snapshot = unsafe { File::from_raw_fd(fd) };
    }
    Ok(snapshot)
}

#[cfg(target_os = "linux")]
fn validate_native_static_elf(
    executable: &mut File,
    path: &Path,
    length: u64,
) -> Result<(), DkgProverError> {
    const ELF64_HEADER_LEN: usize = 64;
    const ELF64_PROGRAM_HEADER_LEN: usize = 56;
    const ET_EXEC: u16 = 2;
    const ET_DYN: u16 = 3;
    const PT_LOAD: u32 = 1;
    const PT_INTERP: u32 = 3;

    let invalid =
        |reason| DkgProverError::InvalidExecutableFormat { path: path.to_path_buf(), reason };
    if length < ELF64_HEADER_LEN as u64 {
        return Err(invalid("file is shorter than an ELF64 header"));
    }

    let mut header = [0_u8; ELF64_HEADER_LEN];
    executable
        .seek(SeekFrom::Start(0))
        .and_then(|_| executable.read_exact(&mut header))
        .map_err(|error| DkgProverError::Snapshot(error.to_string()))?;
    if header[..4] != *b"\x7fELF" {
        return Err(invalid("missing ELF magic"));
    }
    if header[4] != 2 {
        return Err(invalid("ELF class is not 64-bit"));
    }
    if header[5] != 1 {
        return Err(invalid("ELF byte order is not little endian"));
    }
    if header[6] != 1 {
        return Err(invalid("invalid ELF identification version"));
    }

    let object_type = u16::from_le_bytes(header[16..18].try_into().expect("fixed ELF field"));
    if !matches!(object_type, ET_EXEC | ET_DYN) {
        return Err(invalid("ELF object is not executable"));
    }
    let machine = u16::from_le_bytes(header[18..20].try_into().expect("fixed ELF field"));
    if machine != native_elf_machine() {
        return Err(invalid("ELF machine does not match the node architecture"));
    }
    let version = u32::from_le_bytes(header[20..24].try_into().expect("fixed ELF field"));
    if version != 1 {
        return Err(invalid("invalid ELF version"));
    }
    let header_size = u16::from_le_bytes(header[52..54].try_into().expect("fixed ELF field"));
    if header_size as usize != ELF64_HEADER_LEN {
        return Err(invalid("invalid ELF64 header size"));
    }
    let program_offset = u64::from_le_bytes(header[32..40].try_into().expect("fixed ELF field"));
    let program_entry_size =
        u16::from_le_bytes(header[54..56].try_into().expect("fixed ELF field"));
    let program_count = u16::from_le_bytes(header[56..58].try_into().expect("fixed ELF field"));
    if program_entry_size as usize != ELF64_PROGRAM_HEADER_LEN ||
        program_count == 0 ||
        program_count == u16::MAX
    {
        return Err(invalid("invalid ELF64 program-header size or count"));
    }
    let program_table_len = u64::from(program_entry_size)
        .checked_mul(u64::from(program_count))
        .ok_or_else(|| invalid("ELF64 program-header table overflows"))?;
    let program_table_end = program_offset
        .checked_add(program_table_len)
        .filter(|end| *end <= length)
        .ok_or_else(|| invalid("ELF64 program-header table exceeds executable bounds"))?;
    debug_assert!(program_table_end <= length);

    let mut has_load_segment = false;
    let mut program_header = [0_u8; ELF64_PROGRAM_HEADER_LEN];
    for index in 0..program_count {
        let entry_offset = program_offset
            .checked_add(u64::from(index) * u64::from(program_entry_size))
            .ok_or_else(|| invalid("ELF64 program-header offset overflows"))?;
        executable
            .seek(SeekFrom::Start(entry_offset))
            .and_then(|_| executable.read_exact(&mut program_header))
            .map_err(|error| DkgProverError::Snapshot(error.to_string()))?;
        let segment_type =
            u32::from_le_bytes(program_header[..4].try_into().expect("fixed ELF field"));
        if segment_type == PT_INTERP {
            return Err(invalid("ELF contains a PT_INTERP dynamic-loader segment"));
        }
        has_load_segment |= segment_type == PT_LOAD;

        let segment_offset =
            u64::from_le_bytes(program_header[8..16].try_into().expect("fixed ELF field"));
        let segment_length =
            u64::from_le_bytes(program_header[32..40].try_into().expect("fixed ELF field"));
        if segment_length != 0 &&
            segment_offset.checked_add(segment_length).is_none_or(|end| end > length)
        {
            return Err(invalid("ELF program segment exceeds executable bounds"));
        }
    }
    if !has_load_segment {
        return Err(invalid("ELF has no loadable segment"));
    }
    Ok(())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const fn native_elf_machine() -> u16 {
    62
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const fn native_elf_machine() -> u16 {
    183
}

#[cfg(all(target_os = "linux", target_arch = "riscv64"))]
const fn native_elf_machine() -> u16 {
    243
}

#[cfg(target_os = "linux")]
fn harden_prover_child(executable_fd: RawFd) -> io::Result<()> {
    let core_limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: all calls operate on process-local state and valid scalar arguments.
    unsafe {
        if libc::setpgid(0, 0) != 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::setrlimit(libc::RLIMIT_CORE, &raw const core_limit) != 0 {
            return Err(io::Error::last_os_error());
        }
        libc::umask(0o077);
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(io::Error::last_os_error());
        }

        // Prevent unrelated descriptors from crossing the exec boundary. Fail closed when the
        // kernel cannot atomically mark the complete descriptor range close-on-exec.
        let result =
            libc::syscall(libc::SYS_close_range, 3_u32, u32::MAX, libc::CLOSE_RANGE_CLOEXEC);
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        let descriptor_flags = libc::fcntl(executable_fd, libc::F_GETFD);
        if descriptor_flags < 0 ||
            libc::fcntl(executable_fd, libc::F_SETFD, descriptor_flags & !libc::FD_CLOEXEC) != 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    install_prover_seccomp_filter()
}

#[cfg(target_os = "linux")]
fn install_prover_seccomp_filter() -> io::Result<()> {
    const DENIED: &[libc::c_long] = &[
        libc::SYS_socket,
        libc::SYS_socketpair,
        libc::SYS_connect,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_accept,
        libc::SYS_accept4,
        libc::SYS_sendto,
        libc::SYS_recvfrom,
        libc::SYS_sendmsg,
        libc::SYS_recvmsg,
        libc::SYS_sendmmsg,
        libc::SYS_recvmmsg,
        libc::SYS_shutdown,
        libc::SYS_getsockname,
        libc::SYS_getpeername,
        libc::SYS_setsockopt,
        libc::SYS_getsockopt,
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
        libc::SYS_bpf,
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_pidfd_getfd,
        libc::SYS_keyctl,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_move_mount,
        libc::SYS_open_tree,
        libc::SYS_fsopen,
        libc::SYS_fsmount,
        libc::SYS_fspick,
        libc::SYS_mount_setattr,
        libc::SYS_setns,
        libc::SYS_unshare,
        libc::SYS_setpgid,
        libc::SYS_setsid,
    ];
    const PREFIX: usize = if cfg!(target_arch = "x86_64") { 5 } else { 4 };
    const FILTER_LEN: usize = PREFIX + DENIED.len() + 2;
    let mut filter =
        [bpf_statement(libc::BPF_RET | libc::BPF_K, libc::SECCOMP_RET_ALLOW); FILTER_LEN];
    let mut cursor = 0;
    filter[cursor] = bpf_statement(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, 4);
    cursor += 1;
    filter[cursor] = bpf_jump(libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K, audit_arch(), 1, 0);
    cursor += 1;
    filter[cursor] = bpf_statement(libc::BPF_RET | libc::BPF_K, libc::SECCOMP_RET_KILL_PROCESS);
    cursor += 1;
    filter[cursor] = bpf_statement(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, 0);
    cursor += 1;
    if cfg!(target_arch = "x86_64") {
        filter[cursor] = bpf_jump(
            libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K,
            0x4000_0000,
            (DENIED.len() + 1) as u8,
            0,
        );
        cursor += 1;
    }
    for (index, syscall) in DENIED.iter().enumerate() {
        filter[cursor] = bpf_jump(
            libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
            *syscall as u32,
            (DENIED.len() - index) as u8,
            0,
        );
        cursor += 1;
    }
    filter[cursor] = bpf_statement(libc::BPF_RET | libc::BPF_K, libc::SECCOMP_RET_ALLOW);
    cursor += 1;
    filter[cursor] =
        bpf_statement(libc::BPF_RET | libc::BPF_K, libc::SECCOMP_RET_ERRNO | libc::EPERM as u32);

    let mut program = libc::sock_fprog { len: filter.len() as u16, filter: filter.as_mut_ptr() };
    // SAFETY: program points to a stack array that remains alive for the syscall duration.
    let result = unsafe {
        libc::syscall(libc::SYS_seccomp, libc::SECCOMP_SET_MODE_FILTER, 0, &raw mut program)
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
const fn bpf_statement(code: u32, value: u32) -> libc::sock_filter {
    libc::sock_filter { code: code as u16, jt: 0, jf: 0, k: value }
}

#[cfg(target_os = "linux")]
const fn bpf_jump(code: u32, value: u32, jump_true: u8, jump_false: u8) -> libc::sock_filter {
    libc::sock_filter { code: code as u16, jt: jump_true, jf: jump_false, k: value }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const fn audit_arch() -> u32 {
    0xc000_003e
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const fn audit_arch() -> u32 {
    0xc000_00b7
}

#[cfg(all(target_os = "linux", target_arch = "riscv64"))]
const fn audit_arch() -> u32 {
    0xc000_00f3
}

#[cfg(all(
    target_os = "linux",
    not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "riscv64"))
))]
compile_error!("sealed Neo X DKG prover execution is not implemented for this Linux architecture");

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
            return Err(DkgProverError::InvalidShareScalar);
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

#[cfg(not(target_os = "linux"))]
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

#[cfg(target_os = "linux")]
enum CapturedProverOutput {
    Data(Vec<u8>),
    TooLarge,
    Failed(String),
}

#[cfg(target_os = "linux")]
struct ProverOutputReader {
    name: &'static str,
    limit: usize,
    task: Option<tokio::task::JoinHandle<io::Result<Vec<u8>>>>,
    result: Option<CapturedProverOutput>,
}

#[cfg(target_os = "linux")]
impl ProverOutputReader {
    fn new(
        name: &'static str,
        reader: impl AsyncRead + Send + Unpin + 'static,
        limit: usize,
    ) -> Self {
        Self { name, limit, task: Some(tokio::spawn(read_limited(reader, limit))), result: None }
    }

    const fn is_pending(&self) -> bool {
        self.task.is_some()
    }

    async fn observe(&mut self) -> Result<(), DkgProverError> {
        let joined = self.task.as_mut().expect("only pending reader tasks are observed").await;
        self.task = None;
        self.result = Some(match joined {
            Ok(Ok(output)) if output.len() > self.limit => CapturedProverOutput::TooLarge,
            Ok(Ok(output)) => CapturedProverOutput::Data(output),
            Ok(Err(error)) => CapturedProverOutput::Failed(error.to_string()),
            Err(error) => CapturedProverOutput::Failed(error.to_string()),
        });
        self.check()
    }

    fn check(&self) -> Result<(), DkgProverError> {
        match self.result.as_ref() {
            Some(CapturedProverOutput::Data(_)) | None => Ok(()),
            Some(CapturedProverOutput::TooLarge) => Err(DkgProverError::OutputTooLarge(self.name)),
            Some(CapturedProverOutput::Failed(error)) => Err(DkgProverError::Read(error.clone())),
        }
    }

    async fn finish(&mut self) -> Result<Vec<u8>, DkgProverError> {
        if self.is_pending() {
            let _ = self.observe().await;
        }
        match self.result.take().expect("finished reader task recorded its result") {
            CapturedProverOutput::Data(output) => Ok(output),
            CapturedProverOutput::TooLarge => Err(DkgProverError::OutputTooLarge(self.name)),
            CapturedProverOutput::Failed(error) => Err(DkgProverError::Read(error)),
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for ProverOutputReader {
    fn drop(&mut self) {
        if let Some(task) = self.task.as_ref() {
            task.abort();
        }
    }
}

#[cfg(target_os = "linux")]
struct ProverExitObserver {
    task: Option<tokio::task::JoinHandle<io::Result<()>>>,
    result: Option<Result<(), String>>,
}

#[cfg(target_os = "linux")]
impl ProverExitObserver {
    fn new(child_pid: u32) -> Self {
        Self { task: Some(tokio::spawn(wait_child_exit_without_reaping(child_pid))), result: None }
    }

    const fn is_pending(&self) -> bool {
        self.task.is_some()
    }

    async fn observe(&mut self) -> Result<(), DkgProverError> {
        let joined = self.task.as_mut().expect("only a pending exit observer is awaited").await;
        self.task = None;
        self.result = Some(match joined {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(error.to_string()),
            Err(error) => Err(error.to_string()),
        });
        self.check()
    }

    fn check(&self) -> Result<(), DkgProverError> {
        match self.result.as_ref() {
            Some(Ok(())) | None => Ok(()),
            Some(Err(error)) => Err(DkgProverError::Wait(error.clone())),
        }
    }

    async fn finish(&mut self) -> Result<(), DkgProverError> {
        if self.is_pending() {
            let _ = self.observe().await;
        }
        self.check()
    }
}

#[cfg(target_os = "linux")]
impl Drop for ProverExitObserver {
    fn drop(&mut self) {
        if let Some(task) = self.task.as_ref() {
            task.abort();
        }
    }
}

#[cfg(target_os = "linux")]
struct ProverChildController {
    stdin: Option<tokio::process::ChildStdin>,
    stdout: Option<ProverOutputReader>,
    stderr: Option<ProverOutputReader>,
    exit: ProverExitObserver,
    initialization_error: Option<DkgProverError>,
}

#[cfg(target_os = "linux")]
impl ProverChildController {
    fn new(child: &mut Child, child_pid: u32) -> Self {
        let stdin = child.stdin.take();
        let stdout = child
            .stdout
            .take()
            .map(|stdout| ProverOutputReader::new("stdout", stdout, MAX_PROVER_STDOUT_BYTES));
        let stderr = child
            .stderr
            .take()
            .map(|stderr| ProverOutputReader::new("stderr", stderr, MAX_PROVER_STDERR_BYTES));
        let initialization_error = if stdin.is_none() {
            Some(DkgProverError::MissingPipe("stdin"))
        } else if stdout.is_none() {
            Some(DkgProverError::MissingPipe("stdout"))
        } else if stderr.is_none() {
            Some(DkgProverError::MissingPipe("stderr"))
        } else {
            None
        };
        Self {
            stdin,
            stdout,
            stderr,
            exit: ProverExitObserver::new(child_pid),
            initialization_error,
        }
    }
}

#[cfg(target_os = "linux")]
async fn supervise_linux_child(
    mut child: ProverChildOwner,
    child_pid: u32,
    request: Zeroizing<Vec<u8>>,
    timeout: Duration,
    mut cancellation: oneshot::Receiver<()>,
    mut probe: ProverSupervisorProbe,
) -> Result<RawProverOutput, DkgProverError> {
    let mut controller = ProverChildController::new(&mut child.child, child_pid);
    probe.notify_started(child_pid);

    let execution =
        run_child_until_exit(&mut controller, &request, timeout, &mut cancellation).await;
    // Erase the owned request before potentially waiting on pipe cleanup. The write future has
    // already completed or been dropped by `run_child_until_exit` at this point.
    drop(request);
    let cleanup =
        finish_linux_child(&mut child.child, &mut child.process_group, &mut controller).await;
    probe.notify_completed(&cleanup, &controller);

    // Lifecycle failures take precedence because a non-ESRCH group-kill error means descendants
    // may still hold secret material. Otherwise retain the original execution/timeout error before
    // considering captured-output failures, exactly as the non-cancelled path did.
    if let Some(error) = cleanup.lifecycle_error {
        return Err(error)
    }
    execution?;
    let status = cleanup.status.expect("successful cleanup reaped the prover leader");
    Ok(RawProverOutput { status, stdout: cleanup.stdout?, stderr: cleanup.stderr? })
}

#[cfg(target_os = "linux")]
async fn run_child_until_exit(
    controller: &mut ProverChildController,
    request: &[u8],
    timeout: Duration,
    cancellation: &mut oneshot::Receiver<()>,
) -> Result<(), DkgProverError> {
    if let Some(error) = controller.initialization_error.take() {
        return Err(error)
    }

    let ProverChildController { stdin, stdout, stderr, exit, .. } = controller;
    let mut stdin = stdin.take().expect("initialization checked the prover stdin pipe");
    let stdout = stdout.as_mut().expect("initialization checked the prover stdout pipe");
    let stderr = stderr.as_mut().expect("initialization checked the prover stderr pipe");
    let write_request = async move {
        stdin.write_all(request).await.map_err(|error| DkgProverError::Write(error.to_string()))?;
        stdin.shutdown().await.map_err(|error| DkgProverError::Write(error.to_string()))
    };
    tokio::pin!(write_request);
    let deadline = tokio::time::sleep(timeout);
    tokio::pin!(deadline);
    let mut request_written = false;

    loop {
        let stdout_pending = stdout.is_pending();
        let stderr_pending = stderr.is_pending();
        let exit_pending = exit.is_pending();
        tokio::select! {
            result = &mut write_request, if !request_written => {
                result?;
                request_written = true;
            }
            result = stdout.observe(), if stdout_pending => {
                result?;
            }
            result = stderr.observe(), if stderr_pending => {
                result?;
            }
            result = exit.observe(), if exit_pending => {
                result?;
                return Ok(())
            }
            _ = &mut *cancellation => return Err(DkgProverError::Cancelled),
            _ = &mut deadline => return Err(DkgProverError::Timeout(timeout)),
        }
    }
}

#[cfg(target_os = "linux")]
struct LinuxChildCleanup {
    lifecycle_error: Option<DkgProverError>,
    status: Option<ExitStatus>,
    stdout: Result<Vec<u8>, DkgProverError>,
    stderr: Result<Vec<u8>, DkgProverError>,
}

#[cfg(target_os = "linux")]
impl ProverSupervisorProbe {
    fn notify_completed(
        &mut self,
        cleanup: &LinuxChildCleanup,
        controller: &ProverChildController,
    ) {
        if let Some(completed) = self.completed.take() {
            let readers_joined =
                controller.stdout.as_ref().is_some_and(|reader| !reader.is_pending()) &&
                    controller.stderr.as_ref().is_some_and(|reader| !reader.is_pending());
            let structured_cleanup_completed = cleanup.lifecycle_error.is_none() &&
                cleanup.status.is_some() &&
                !controller.exit.is_pending() &&
                readers_joined;
            let _ = completed.send(structured_cleanup_completed);
        }
    }
}

#[cfg(target_os = "linux")]
async fn finish_linux_child(
    child: &mut Child,
    process_group: &mut ProverProcessGroup,
    controller: &mut ProverChildController,
) -> LinuxChildCleanup {
    let mut lifecycle_errors = Vec::new();

    // The leader has deliberately not been reaped. Its PID therefore still pins the numeric PGID
    // while the negative-PID signal terminates both it and every descendant that retained a pipe.
    if let Err(error) = process_group.kill() {
        lifecycle_errors.push(format!("process-group kill failed: {error}"));
        if let Err(error) = child.start_kill() {
            lifecycle_errors.push(format!("leader kill fallback failed: {error}"));
        }
        // Reaping the leader here would release the numeric PGID even though descendants may still
        // retain prover secrets. Leave the guard armed for its Drop retry and let `kill_on_drop`
        // handle the direct child; completed invocations take the explicit-reap path below.
        let message = lifecycle_errors.join("; ");
        return LinuxChildCleanup {
            lifecycle_error: Some(DkgProverError::ProcessGroupCleanup(message)),
            status: None,
            stdout: Err(DkgProverError::ProcessGroupCleanup(
                "stdout unavailable after process-group kill failure".to_owned(),
            )),
            stderr: Err(DkgProverError::ProcessGroupCleanup(
                "stderr unavailable after process-group kill failure".to_owned(),
            )),
        }
    }
    if let Err(error) = controller.exit.finish().await {
        lifecycle_errors.push(format!("exit observation failed: {error}"));
    }

    // Never retain an armed numeric PGID after reaping its leader: that number may be reused.
    process_group.disarm();
    let status = match child.wait().await {
        Ok(status) => Some(status),
        Err(error) => {
            lifecycle_errors.push(format!("leader wait failed: {error}"));
            None
        }
    };

    // Join both readers independently. A failure in one must not detach or skip the other.
    let stdout = match controller.stdout.as_mut() {
        Some(stdout) => stdout.finish().await,
        None => Err(DkgProverError::MissingPipe("stdout")),
    };
    let stderr = match controller.stderr.as_mut() {
        Some(stderr) => stderr.finish().await,
        None => Err(DkgProverError::MissingPipe("stderr")),
    };
    let lifecycle_error = (!lifecycle_errors.is_empty())
        .then(|| DkgProverError::ProcessGroupCleanup(lifecycle_errors.join("; ")));
    LinuxChildCleanup { lifecycle_error, status, stdout, stderr }
}

#[cfg(target_os = "linux")]
async fn wait_child_exit_without_reaping(child_pid: u32) -> io::Result<()> {
    loop {
        let mut information = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
        // SAFETY: `information` is writable storage for waitid and the PID belongs to the freshly
        // spawned direct child. WNOWAIT pins its status/PID; WNOHANG keeps this task abortable.
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                child_pid as libc::id_t,
                information.as_mut_ptr(),
                libc::WEXITED | libc::WNOWAIT | libc::WNOHANG,
            )
        };
        if result == 0 {
            // SAFETY: a successful waitid initialized the siginfo storage. Linux reports si_pid=0
            // when WNOHANG finds no waitable state change.
            let observed_pid = unsafe { information.assume_init().si_pid() };
            if observed_pid == child_pid as libc::pid_t {
                return Ok(())
            }
            if observed_pid != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("waitid observed unexpected child PID {observed_pid}"),
                ))
            }
        } else {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error)
            }
        }
        tokio::time::sleep(PROVER_EXIT_POLL_INTERVAL).await;
    }
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
        return Err(DkgProverError::OutputTooLarge("stdout"));
    }
    if output.stderr.len() > MAX_PROVER_STDERR_BYTES {
        return Err(DkgProverError::OutputTooLarge("stderr"));
    }
    if !output.status.success() {
        let message = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        return Err(DkgProverError::Failed {
            code: output.status.code(),
            message: (!message.is_empty()).then_some(message),
        });
    }

    let response: ProverResponse = serde_json::from_slice(&output.stdout)
        .map_err(|error| DkgProverError::ResponseDecoding(error.to_string()))?;
    if response.protocol_version != PROVER_PROTOCOL_VERSION {
        return Err(DkgProverError::ProtocolVersion(response.protocol_version));
    }
    if response.messages.len() != message_count {
        return Err(DkgProverError::ResponseMessageCount {
            expected: message_count,
            actual: response.messages.len(),
        });
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
        return Err(DkgProverError::InvalidHexLength { name, index, expected: N });
    }
    let mut result = [0_u8; N];
    hex::decode_to_slice(raw, &mut result)
        .map_err(|_| DkgProverError::InvalidHex { name, index })?;
    Ok(result)
}

fn validate_file(name: &'static str, path: PathBuf) -> Result<PathBuf, DkgProverError> {
    if !path.is_absolute() {
        return Err(DkgProverError::RelativePath { name, path });
    }

    #[cfg(target_os = "linux")]
    {
        open_trusted_file(name, &path, TrustedFileKind::Regular)?;
    }
    #[cfg(not(target_os = "linux"))]
    {
        let metadata = path.symlink_metadata().map_err(|error| DkgProverError::File {
            name,
            path: path.clone(),
            error: error.to_string(),
        })?;
        if metadata.file_type().is_symlink() {
            return Err(DkgProverError::Symlink { name, path });
        }
        if !metadata.is_file() {
            return Err(DkgProverError::NotFile { name, path });
        }
    }
    Ok(path)
}

/// Failure to validate inputs, invoke the compatibility helper, or decode its response.
#[derive(Debug, Error)]
pub enum DkgProverError {
    /// Sealed executable snapshots are currently enforced only by the Linux implementation.
    #[error("secure Neo X DKG prover execution requires Linux")]
    UnsupportedPlatform,
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
    /// Symlinks are rejected for every configured path component.
    #[error("Neo X DKG {name} path contains a symlink: {path}")]
    Symlink {
        /// Configured component.
        name: &'static str,
        /// Rejected path component.
        path: PathBuf,
    },
    /// Dot and parent traversal components are not accepted at a trust boundary.
    #[error("Neo X DKG {name} path is not a direct absolute path: {path}")]
    UnsafePath {
        /// Configured component.
        name: &'static str,
        /// Rejected path.
        path: PathBuf,
    },
    /// Configured files and directories must be owned by root or the node account.
    #[error("Neo X DKG {name} has untrusted owner uid {owner}: {path}")]
    UntrustedOwner {
        /// Configured component.
        name: &'static str,
        /// Rejected path component.
        path: PathBuf,
        /// Filesystem owner uid.
        owner: u32,
    },
    /// Shared writable and special-mode files cannot cross the secret process boundary.
    #[error("Neo X DKG {name} has unsafe mode {mode:#06o}: {path}")]
    UnsafePermissions {
        /// Configured component.
        name: &'static str,
        /// Rejected path component.
        path: PathBuf,
        /// Permission and special-mode bits.
        mode: u32,
    },
    /// A configured prover must be executable by the current node account.
    #[error("Neo X DKG prover is not executable by the node account: {path}")]
    NotExecutable {
        /// Rejected executable path.
        path: PathBuf,
    },
    /// Empty and unreasonably large helpers are not copied into executable memory.
    #[error("Neo X DKG prover executable size {size} is outside 1..={maximum} bytes: {path}")]
    ExecutableSize {
        /// Rejected executable path.
        path: PathBuf,
        /// Observed byte length.
        size: u64,
        /// Defensive byte ceiling.
        maximum: u64,
    },
    /// The executable changed while its immutable snapshot was being constructed.
    #[error("Neo X DKG prover executable changed during validation: {path}")]
    ExecutableChanged {
        /// Rejected executable path.
        path: PathBuf,
    },
    /// Only native, static, directly executable ELF64 helpers cross the secret boundary.
    #[error("Neo X DKG prover is not a native static ELF64 executable: {path}: {reason}")]
    InvalidExecutableFormat {
        /// Rejected executable path.
        path: PathBuf,
        /// Structural incompatibility detected in the sealed snapshot.
        reason: &'static str,
    },
    /// Reading or writing the private executable snapshot failed.
    #[error("failed to snapshot Neo X DKG prover executable: {0}")]
    Snapshot(String),
    /// The operating-system process sandbox could not be installed.
    #[error("failed to install Neo X DKG prover sandbox: {0}")]
    Sandbox(String),
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
    /// Neo X ZK-v0 supports every deployed committee size; ZK-v1 circuits cover one/two recovery
    /// messages and seven full share/reshare contributions.
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
    /// The helper or one of its descendants could not be terminated securely.
    #[error("failed to clean up Neo X DKG prover process group: {0}")]
    ProcessGroupCleanup(String),
    /// Captured process output could not be read.
    #[error("failed to read Neo X DKG prover output: {0}")]
    Read(String),
    /// The invoking task was dropped and requested structured process cleanup.
    #[error("Neo X DKG prover invocation was cancelled")]
    Cancelled,
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
    #[cfg(target_os = "linux")]
    use std::{
        fs,
        os::unix::fs::{DirBuilderExt, PermissionsExt},
        sync::atomic::{AtomicU64, Ordering},
    };

    #[test]
    fn message_count_gates_match_the_geth_circuit_set() {
        assert!(validate_message_count(DkgContractMethod::Share, 0, 4).is_ok());
        assert!(matches!(
            validate_message_count(DkgContractMethod::Share, 1, 4),
            Err(DkgProverError::UnsupportedMessageCount(4))
        ));
        assert!(validate_message_count(DkgContractMethod::Share, 1, 7).is_ok());
        assert!(matches!(
            validate_message_count(DkgContractMethod::Share, 1, 1),
            Err(DkgProverError::UnsupportedMessageCount(1))
        ));
        assert!(validate_message_count(DkgContractMethod::Recover, 1, 2).is_ok());
        assert!(matches!(
            validate_message_count(DkgContractMethod::Recover, 1, 4),
            Err(DkgProverError::UnsupportedMessageCount(4))
        ));
        assert!(validate_message_count(DkgContractMethod::Recover, 0, 4).is_ok());
    }

    #[cfg(target_os = "linux")]
    static TEST_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    #[cfg(target_os = "linux")]
    struct TestDirectory(PathBuf);

    #[cfg(target_os = "linux")]
    impl TestDirectory {
        fn new() -> Self {
            loop {
                let sequence = TEST_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
                let path = PathBuf::from(format!(
                    "/tmp/neox-dkg-prover-test-{}-{sequence}",
                    std::process::id()
                ));
                let mut builder = fs::DirBuilder::new();
                builder.mode(0o700);
                match builder.create(&path) {
                    Ok(()) => return Self(path),
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(error) => panic!("failed to create private test directory: {error}"),
                }
            }
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[cfg(target_os = "linux")]
    fn copy_with_mode(source: impl AsRef<Path>, destination: &Path, mode: u32) {
        fs::copy(source, destination).unwrap();
        fs::set_permissions(destination, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[cfg(target_os = "linux")]
    fn static_test_executable(exit_status: u8) -> Vec<u8> {
        #[cfg(target_arch = "x86_64")]
        let code = match exit_status {
            0 => &[0xb8, 0x3c, 0, 0, 0, 0x31, 0xff, 0x0f, 0x05][..],
            1 => &[0xb8, 0x3c, 0, 0, 0, 0xbf, 1, 0, 0, 0, 0x0f, 0x05][..],
            _ => panic!("test fixture supports only success and failure"),
        };
        #[cfg(target_arch = "aarch64")]
        let code = match exit_status {
            0 => &[0x00, 0x00, 0x80, 0xd2, 0xa8, 0x0b, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4][..],
            1 => &[0x20, 0x00, 0x80, 0xd2, 0xa8, 0x0b, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4][..],
            _ => panic!("test fixture supports only success and failure"),
        };
        #[cfg(target_arch = "riscv64")]
        let code = match exit_status {
            0 => &[0x13, 0x05, 0x00, 0x00, 0x93, 0x08, 0xd0, 0x05, 0x73, 0x00, 0x00, 0x00][..],
            1 => &[0x13, 0x05, 0x10, 0x00, 0x93, 0x08, 0xd0, 0x05, 0x73, 0x00, 0x00, 0x00][..],
            _ => panic!("test fixture supports only success and failure"),
        };

        static_test_elf(code)
    }

    #[cfg(target_os = "linux")]
    fn static_test_elf(code: &[u8]) -> Vec<u8> {
        const ELF64_HEADER_LEN: usize = 64;
        const ELF64_PROGRAM_HEADER_LEN: usize = 56;
        const IMAGE_BASE: u64 = 0x40_0000;

        let code_offset = ELF64_HEADER_LEN + ELF64_PROGRAM_HEADER_LEN;
        let image_len = code_offset + code.len();
        let mut elf = vec![0_u8; image_len];
        elf[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        elf[16..18].copy_from_slice(&2_u16.to_le_bytes());
        elf[18..20].copy_from_slice(&native_elf_machine().to_le_bytes());
        elf[20..24].copy_from_slice(&1_u32.to_le_bytes());
        elf[24..32].copy_from_slice(&(IMAGE_BASE + code_offset as u64).to_le_bytes());
        elf[32..40].copy_from_slice(&(ELF64_HEADER_LEN as u64).to_le_bytes());
        elf[52..54].copy_from_slice(&(ELF64_HEADER_LEN as u16).to_le_bytes());
        elf[54..56].copy_from_slice(&(ELF64_PROGRAM_HEADER_LEN as u16).to_le_bytes());
        elf[56..58].copy_from_slice(&1_u16.to_le_bytes());

        let program = &mut elf[ELF64_HEADER_LEN..code_offset];
        program[..4].copy_from_slice(&1_u32.to_le_bytes());
        program[4..8].copy_from_slice(&5_u32.to_le_bytes());
        program[16..24].copy_from_slice(&IMAGE_BASE.to_le_bytes());
        program[24..32].copy_from_slice(&IMAGE_BASE.to_le_bytes());
        program[32..40].copy_from_slice(&(image_len as u64).to_le_bytes());
        program[40..48].copy_from_slice(&(image_len as u64).to_le_bytes());
        program[48..56].copy_from_slice(&0x1000_u64.to_le_bytes());
        elf[code_offset..].copy_from_slice(code);
        elf
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn forking_static_test_executable(exit_status: u8) -> Vec<u8> {
        assert!(exit_status <= 1, "test fixture supports only success and failure");
        // fork(), write the child PID from the direct parent, then leave the descendant with all
        // stdio closed. The runtime must kill that descendant even though the direct child exits
        // and all pipe readers have already observed EOF.
        let code = [
            0xb8,
            0x39,
            0,
            0,
            0, // mov eax, fork
            0x0f,
            0x05, // syscall
            0x85,
            0xc0, // test eax, eax
            0x74,
            0x25, // je child
            0x50, // push rax
            0x48,
            0x89,
            0xe6, // mov rsi, rsp
            0xba,
            0x04,
            0,
            0,
            0, // mov edx, 4
            0xbf,
            0x01,
            0,
            0,
            0, // mov edi, stdout
            0xb8,
            0x01,
            0,
            0,
            0, // mov eax, write
            0x0f,
            0x05, // syscall
            0x48,
            0x83,
            0xc4,
            0x08, // add rsp, 8
            0xb8,
            0x3c,
            0,
            0,
            0, // mov eax, exit
            0xbf,
            exit_status,
            0,
            0,
            0, // mov edi, exit_status
            0x0f,
            0x05, // syscall
            0x31,
            0xff, // child: xor edi, edi
            0xb8,
            0x03,
            0,
            0,
            0, // mov eax, close
            0x0f,
            0x05, // syscall
            0xff,
            0xc7, // inc edi
            0xb8,
            0x03,
            0,
            0,
            0,
            0x0f,
            0x05,
            0xff,
            0xc7, // inc edi
            0xb8,
            0x03,
            0,
            0,
            0,
            0x0f,
            0x05,
            0xb8,
            0x22,
            0,
            0,
            0, // pause
            0x0f,
            0x05,
            0xeb,
            0xf7, // loop on pause
        ];
        static_test_elf(&code)
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn timeout_forking_static_test_executable() -> Vec<u8> {
        // The direct child writes its descendant PID, then both processes retain every stdio pipe
        // and pause forever. Deadline cleanup must kill the whole group before joining readers.
        let code = [
            0xb8, 0x39, 0, 0, 0, // mov eax, fork
            0x0f, 0x05, // syscall
            0x85, 0xc0, // test eax, eax
            0x74, 0x19, // je pause
            0x50, // push rax
            0x48, 0x89, 0xe6, // mov rsi, rsp
            0xba, 0x04, 0, 0, 0, // mov edx, 4
            0xbf, 0x01, 0, 0, 0, // mov edi, stdout
            0xb8, 0x01, 0, 0, 0, // mov eax, write
            0x0f, 0x05, // syscall
            0x48, 0x83, 0xc4, 0x08, // add rsp, 8
            0xb8, 0x22, 0, 0, 0, // pause: mov eax, pause
            0x0f, 0x05, 0xeb, 0xf7, // syscall; loop on pause
        ];
        static_test_elf(&code)
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn output_flooding_static_test_executable() -> Vec<u8> {
        // Write more than the stdout cap without waiting for EOF, then exit. The reader task must
        // notify the controller as soon as it consumes limit+1 bytes.
        let code = [
            0x45, 0x31, 0xe4, // xor r12d, r12d
            0x50, // push rax
            0xb8, 0x01, 0, 0, 0, // loop: mov eax, write
            0xbf, 0x01, 0, 0, 0, // mov edi, stdout
            0x48, 0x89, 0xe6, // mov rsi, rsp
            0xba, 0x08, 0, 0, 0, // mov edx, 8
            0x0f, 0x05, // syscall
            0x41, 0xff, 0xc4, // inc r12d
            0x41, 0x81, 0xfc, 0x00, 0x90, 0, 0, // cmp r12d, 0x9000
            0x7c, 0xe0, // jl loop
            0xb8, 0x3c, 0, 0, 0, // mov eax, exit
            0x31, 0xff, // xor edi, edi
            0x0f, 0x05, // syscall
        ];
        static_test_elf(&code)
    }

    #[cfg(target_os = "linux")]
    fn write_static_test_executable(path: &Path, exit_status: u8) {
        fs::write(path, static_test_executable(exit_status)).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[cfg(target_os = "linux")]
    fn spawn_test_prover(prover: &DkgProver) -> Child {
        let mut command = prover.executable.command().unwrap();
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .env_clear()
            .current_dir("/");
        command.spawn().unwrap()
    }

    #[cfg(target_os = "linux")]
    async fn run_test_prover_lifecycle(
        prover: &DkgProver,
        timeout: Duration,
    ) -> (u32, Result<(), DkgProverError>, LinuxChildCleanup, ProverChildController) {
        let mut child = spawn_test_prover(prover);
        let child_pid = child.id().unwrap();
        let mut process_group = ProverProcessGroup::new(child_pid);
        let mut controller = ProverChildController::new(&mut child, child_pid);
        let (_cancellation_sender, mut cancellation_receiver) = oneshot::channel();
        let execution =
            run_child_until_exit(&mut controller, &[], timeout, &mut cancellation_receiver).await;
        let cleanup = finish_linux_child(&mut child, &mut process_group, &mut controller).await;
        (child_pid, execution, cleanup, controller)
    }

    #[cfg(target_os = "linux")]
    fn process_is_running(pid: libc::pid_t) -> bool {
        fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|stat| {
                stat.rsplit_once(") ").map(|(_, rest)| {
                    rest.starts_with('R') ||
                        rest.starts_with('S') ||
                        rest.starts_with('D') ||
                        rest.starts_with('I')
                })
            })
            .unwrap_or(false)
    }

    #[cfg(target_os = "linux")]
    async fn assert_process_not_running(pid: libc::pid_t) {
        for _ in 0..100 {
            if !process_is_running(pid) {
                return
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("prover process {pid} survived process-group cleanup");
    }

    #[cfg(target_os = "linux")]
    async fn wait_for_direct_descendant(leader: libc::pid_t) -> libc::pid_t {
        let children = format!("/proc/{leader}/task/{leader}/children");
        for _ in 0..100 {
            if let Ok(contents) = fs::read_to_string(&children) &&
                let Some(descendant) =
                    contents.split_whitespace().find_map(|pid| pid.parse().ok())
            {
                return descendant
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("prover leader {leader} did not create its test descendant");
    }

    #[cfg(target_os = "linux")]
    fn assert_controller_tasks_joined(controller: &ProverChildController) {
        assert!(!controller.exit.is_pending(), "waitid observer was left detached");
        assert!(
            controller.stdout.as_ref().is_some_and(|reader| !reader.is_pending()),
            "stdout reader was left detached"
        );
        assert!(
            controller.stderr.as_ref().is_some_and(|reader| !reader.is_pending()),
            "stderr reader was left detached"
        );
    }

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

    /// The helper decodes with `DisallowUnknownFields` and rejects a ZK-v0 request that carries any
    /// artifact field, so a rename or a stray `Some` on this side compiles and passes every unit
    /// test while failing only against the real prover, mid-round. Pin the exact wire form: the
    /// field names the helper's tags expect, the checksummed sender and `0x` hex its
    /// `decodeFixedHex` accepts, and the omission of all four artifact fields for ZK-v0.
    #[test]
    fn pins_request_wire_format() {
        let public_keys = vec![hex::encode_prefixed([0x04; 65])];
        let shares = vec![hex::encode_prefixed([0x22; 32])];
        let sender = Address::with_last_byte(0xab);

        let v0 = ProverRequest {
            protocol_version: PROVER_PROTOCOL_VERSION,
            zk_version: 0,
            sender: sender.to_string(),
            public_keys: &public_keys,
            shares: &shares,
            r1cs_path: None,
            r1cs_sha256: None,
            proving_key_path: None,
            proving_key_sha256: None,
        };
        // Key order is not pinned: `to_value` sorts into a map, and the helper's decoder is
        // order-insensitive. The name set and the omissions are what the two sides must agree on.
        let encoded = serde_json::to_value(&v0).unwrap();
        let object = encoded.as_object().unwrap();
        assert_eq!(
            object.keys().map(String::as_str).collect::<Vec<_>>(),
            ["protocol_version", "public_keys", "sender", "shares", "zk_version"]
        );
        assert_eq!(object["protocol_version"], serde_json::json!(1));
        assert_eq!(object["zk_version"], serde_json::json!(0));
        // EIP-55 checksummed; Go's hex decoder is case-insensitive after the 0x is trimmed.
        assert_eq!(object["sender"], serde_json::json!(sender.to_checksum(None)));
        assert_eq!(object["shares"][0].as_str().unwrap().len(), 2 + 64);
        assert_eq!(object["public_keys"][0].as_str().unwrap().len(), 2 + 130);

        let v1 = ProverRequest {
            zk_version: 1,
            r1cs_path: Some("/artifacts/one.r1cs".into()),
            r1cs_sha256: Some(B256::repeat_byte(0x33).to_string()),
            proving_key_path: Some("/artifacts/one.pk".into()),
            proving_key_sha256: Some(B256::repeat_byte(0x44).to_string()),
            ..v0
        };
        let encoded = serde_json::to_value(&v1).unwrap();
        assert_eq!(
            encoded.as_object().unwrap().keys().map(String::as_str).collect::<Vec<_>>(),
            [
                "protocol_version",
                "proving_key_path",
                "proving_key_sha256",
                "public_keys",
                "r1cs_path",
                "r1cs_sha256",
                "sender",
                "shares",
                "zk_version"
            ]
        );
        assert_eq!(encoded["r1cs_path"], serde_json::json!("/artifacts/one.r1cs"));
        assert_eq!(encoded["r1cs_sha256"].as_str().unwrap().len(), 2 + 64);
        assert_eq!(encoded["proving_key_sha256"].as_str().unwrap().len(), 2 + 64);
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
        #[cfg(target_os = "linux")]
        let test_directory = TestDirectory::new();
        #[cfg(target_os = "linux")]
        let executable = {
            let path = test_directory.path().join("prover");
            write_static_test_executable(&path, 0);
            path
        };
        #[cfg(not(target_os = "linux"))]
        let executable = std::env::current_exe().unwrap();

        #[cfg(target_os = "linux")]
        let prover = DkgProver::new(&executable).unwrap();
        #[cfg(not(target_os = "linux"))]
        let prover = DkgProver::new(&executable).unwrap_err();
        #[cfg(target_os = "linux")]
        assert!(matches!(prover.with_timeout(Duration::ZERO), Err(DkgProverError::ZeroTimeout)));
        #[cfg(not(target_os = "linux"))]
        assert!(matches!(prover, DkgProverError::UnsupportedPlatform));
        assert!(matches!(
            DkgProver::new(Path::new("relative-helper")),
            Err(DkgProverError::RelativePath { .. } | DkgProverError::UnsupportedPlatform)
        ));

        #[cfg(target_os = "linux")]
        let artifact = {
            let path = test_directory.path().join("artifact");
            fs::write(&path, b"artifact").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            path
        };
        #[cfg(not(target_os = "linux"))]
        let artifact = executable;
        let one =
            DkgProofArtifact::new(&artifact, B256::repeat_byte(1), &artifact, B256::repeat_byte(2))
                .unwrap();
        let two =
            DkgProofArtifact::new(&artifact, B256::repeat_byte(3), &artifact, B256::repeat_byte(4))
                .unwrap();
        let seven =
            DkgProofArtifact::new(&artifact, B256::repeat_byte(5), &artifact, B256::repeat_byte(6))
                .unwrap();
        let artifacts = DkgProverArtifacts::new(one, two, seven);
        assert_eq!(artifacts.for_message_count(1).unwrap().r1cs_sha256, B256::repeat_byte(1));
        assert_eq!(artifacts.for_message_count(2).unwrap().r1cs_sha256, B256::repeat_byte(3));
        assert_eq!(artifacts.for_message_count(7).unwrap().r1cs_sha256, B256::repeat_byte(5));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn rejects_symlinked_executable_and_path_component() {
        use std::os::unix::fs::symlink;

        let test_directory = TestDirectory::new();
        let executable = test_directory.path().join("prover");
        copy_with_mode("/bin/true", &executable, 0o700);

        let linked_executable = test_directory.path().join("linked-prover");
        symlink(&executable, &linked_executable).unwrap();
        assert!(matches!(DkgProver::new(&linked_executable), Err(DkgProverError::Symlink { .. })));

        let real_directory = test_directory.path().join("real");
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700).create(&real_directory).unwrap();
        let nested_executable = real_directory.join("prover");
        copy_with_mode("/bin/true", &nested_executable, 0o700);
        let linked_directory = test_directory.path().join("linked-directory");
        symlink(&real_directory, &linked_directory).unwrap();
        assert!(matches!(
            DkgProver::new(linked_directory.join("prover")),
            Err(DkgProverError::Symlink { .. })
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn rejects_world_writable_non_sticky_path_component() {
        let test_directory = TestDirectory::new();
        let unsafe_directory = test_directory.path().join("shared");
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o702).create(&unsafe_directory).unwrap();
        fs::set_permissions(&unsafe_directory, fs::Permissions::from_mode(0o702)).unwrap();
        let executable = unsafe_directory.join("prover");
        copy_with_mode("/bin/true", &executable, 0o700);
        assert!(matches!(
            DkgProver::new(executable),
            Err(DkgProverError::UnsafePermissions { .. })
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn rejects_non_static_or_malformed_executable_formats() {
        let test_directory = TestDirectory::new();

        let script = test_directory.path().join("script");
        fs::write(&script, b"#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(
            DkgProver::new(script),
            Err(DkgProverError::InvalidExecutableFormat { .. })
        ));

        let interpreter = test_directory.path().join("interpreter");
        let mut bytes = static_test_executable(0);
        bytes[64..68].copy_from_slice(&3_u32.to_le_bytes());
        fs::write(&interpreter, bytes).unwrap();
        fs::set_permissions(&interpreter, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(
            DkgProver::new(interpreter),
            Err(DkgProverError::InvalidExecutableFormat { .. })
        ));

        let wrong_machine = test_directory.path().join("wrong-machine");
        let mut bytes = static_test_executable(0);
        bytes[18..20].copy_from_slice(&0_u16.to_le_bytes());
        fs::write(&wrong_machine, bytes).unwrap();
        fs::set_permissions(&wrong_machine, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(
            DkgProver::new(wrong_machine),
            Err(DkgProverError::InvalidExecutableFormat { .. })
        ));

        let malformed_table = test_directory.path().join("malformed-table");
        let mut bytes = static_test_executable(0);
        bytes[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
        fs::write(&malformed_table, bytes).unwrap();
        fs::set_permissions(&malformed_table, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(
            DkgProver::new(malformed_table),
            Err(DkgProverError::InvalidExecutableFormat { .. })
        ));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn executes_sealed_snapshot_after_path_replacement() {
        let test_directory = TestDirectory::new();
        let executable = test_directory.path().join("prover");
        write_static_test_executable(&executable, 0);
        let prover = DkgProver::new(&executable).unwrap();

        let original_path = test_directory.path().join("original-prover");
        fs::rename(&executable, original_path).unwrap();
        write_static_test_executable(&executable, 1);

        let original = prover.invoke(&[]).await.unwrap();
        assert!(original.status.success(), "sealed original executable was not invoked");
        let replacement = DkgProver::new(&executable).unwrap().invoke(&[]).await.unwrap();
        assert!(!replacement.status.success(), "replacement executable did not run");
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[tokio::test]
    async fn kills_forked_descendant_after_successful_direct_exit() {
        let test_directory = TestDirectory::new();
        let executable = test_directory.path().join("forking-prover");
        fs::write(&executable, forking_static_test_executable(0)).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let prover = DkgProver::new(&executable).unwrap();

        let output = prover.invoke(&[]).await.unwrap();
        assert!(output.status.success(), "direct prover child was spuriously failed");
        assert_eq!(output.stdout.len(), 4, "forking fixture did not report its descendant");
        let descendant = i32::from_ne_bytes(output.stdout[..4].try_into().unwrap());
        assert!(descendant > 1);
        assert_process_not_running(descendant).await;
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[tokio::test]
    async fn preserves_nonzero_direct_status_while_killing_descendant() {
        let test_directory = TestDirectory::new();
        let executable = test_directory.path().join("failing-forking-prover");
        fs::write(&executable, forking_static_test_executable(1)).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let output = DkgProver::new(&executable).unwrap().invoke(&[]).await.unwrap();

        assert_eq!(output.status.code(), Some(1), "group cleanup replaced the direct exit status");
        assert_eq!(output.stdout.len(), 4, "forking fixture did not report its descendant");
        let descendant = i32::from_ne_bytes(output.stdout[..4].try_into().unwrap());
        assert_process_not_running(descendant).await;
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[tokio::test]
    async fn unpolled_supervisor_kills_group_before_releasing_child() {
        let test_directory = TestDirectory::new();
        let executable = test_directory.path().join("unpolled-forking-prover");
        fs::write(&executable, timeout_forking_static_test_executable()).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let prover = DkgProver::new(&executable).unwrap();
        let child = spawn_test_prover(&prover);
        let leader = child.id().unwrap();
        let (_cancellation_sender, cancellation_receiver) = oneshot::channel();

        let supervisor = supervise_linux_child(
            ProverChildOwner::new(child, leader),
            leader,
            Zeroizing::new(Vec::new()),
            Duration::from_secs(1),
            cancellation_receiver,
            ProverSupervisorProbe::default(),
        );
        let descendant = wait_for_direct_descendant(leader as libc::pid_t).await;
        drop(supervisor);

        assert_process_not_running(leader as libc::pid_t).await;
        assert_process_not_running(descendant).await;
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[tokio::test]
    async fn cancelled_invocation_supervises_group_kill_reap_and_reader_joins() {
        let test_directory = TestDirectory::new();
        let executable = test_directory.path().join("cancelled-forking-prover");
        fs::write(&executable, timeout_forking_static_test_executable()).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let prover = DkgProver::new(&executable).unwrap();
        let (started_sender, started_receiver) = oneshot::channel();
        let (completed_sender, completed_receiver) = oneshot::channel();
        let probe = ProverSupervisorProbe {
            started: Some(started_sender),
            completed: Some(completed_sender),
        };

        let invocation =
            tokio::spawn(async move { prover.invoke_linux_supervised(&[], probe).await });
        let leader = tokio::time::timeout(Duration::from_secs(2), started_receiver)
            .await
            .expect("prover supervisor did not start")
            .expect("prover supervisor dropped its start signal");
        let descendant = wait_for_direct_descendant(leader as libc::pid_t).await;

        invocation.abort();
        assert!(invocation.await.unwrap_err().is_cancelled());
        let completion = tokio::time::timeout(Duration::from_secs(2), completed_receiver)
            .await
            .expect("cancelled prover supervisor did not complete cleanup")
            .expect("cancelled prover supervisor dropped its completion signal");

        assert!(completion, "cancelled prover did not complete structured cleanup");
        assert!(!Path::new(&format!("/proc/{leader}")).exists(), "leader remains a zombie");
        assert_process_not_running(descendant).await;
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[tokio::test]
    async fn timeout_kills_forked_descendant_holding_stdio_and_joins_tasks() {
        let test_directory = TestDirectory::new();
        let executable = test_directory.path().join("timeout-forking-prover");
        fs::write(&executable, timeout_forking_static_test_executable()).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let prover = DkgProver::new(&executable).unwrap();
        let timeout = Duration::from_millis(50);

        let (leader, execution, cleanup, controller) =
            run_test_prover_lifecycle(&prover, timeout).await;
        assert!(matches!(execution, Err(DkgProverError::Timeout(actual)) if actual == timeout));
        assert!(cleanup.lifecycle_error.is_none(), "cleanup failed after timeout");
        assert!(cleanup.status.is_some(), "direct prover leader was not explicitly reaped");
        let stdout = cleanup.stdout.unwrap();
        assert_eq!(stdout.len(), 4, "timeout fixture did not report its descendant");
        cleanup.stderr.unwrap();
        let descendant = i32::from_ne_bytes(stdout[..4].try_into().unwrap());
        assert!(descendant > 1);
        assert!(!Path::new(&format!("/proc/{leader}")).exists(), "direct leader remains a zombie");
        assert_process_not_running(descendant).await;
        assert_controller_tasks_joined(&controller);
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[tokio::test]
    async fn output_cap_stops_prover_before_deadline_and_joins_tasks() {
        let test_directory = TestDirectory::new();
        let executable = test_directory.path().join("output-flooding-prover");
        fs::write(&executable, output_flooding_static_test_executable()).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let prover = DkgProver::new(&executable).unwrap();
        let timeout = Duration::from_secs(5);
        let started = tokio::time::Instant::now();

        let (leader, execution, cleanup, controller) =
            run_test_prover_lifecycle(&prover, timeout).await;
        assert!(started.elapsed() < Duration::from_secs(1), "output limit waited for the deadline");
        assert!(
            matches!(execution, Err(DkgProverError::OutputTooLarge("stdout"))) ||
                matches!(cleanup.stdout, Err(DkgProverError::OutputTooLarge("stdout"))),
            "stdout overflow was not classified"
        );
        assert!(cleanup.lifecycle_error.is_none(), "cleanup failed after stdout overflow");
        assert!(cleanup.status.is_some(), "direct prover leader was not explicitly reaped");
        cleanup.stderr.unwrap();
        assert!(!Path::new(&format!("/proc/{leader}")).exists(), "direct leader remains a zombie");
        assert_controller_tasks_joined(&controller);
    }
}
