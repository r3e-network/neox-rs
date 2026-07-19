//! One-shot encrypted Neo X Geth Anti-MEV keystore migration utility.

use alloy_primitives::Address;
use clap::Parser;
use reth_neox_antimev::DkgKeyStore;
use std::{
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

const MAX_PASSWORD_FILE_BYTES: u64 = 4 * 1024;

#[derive(Debug, Parser)]
#[command(about = "Migrate an encrypted Neo X Geth Anti-MEV keystore into Reth format")]
struct Arguments {
    /// Existing private regular EIP-2335 v4 Geth Anti-MEV keystore.
    #[arg(long, value_name = "FILE")]
    source: PathBuf,
    /// Mode-0600 file containing the Geth keystore password.
    #[arg(long, value_name = "FILE")]
    source_password_file: PathBuf,
    /// New Reth AES-256-GCM DKG keystore; the path must not already exist.
    #[arg(long, value_name = "FILE")]
    destination: PathBuf,
    /// Mode-0600 file containing the new Reth keystore password.
    #[arg(long, value_name = "FILE")]
    destination_password_file: PathBuf,
    /// Validator address that must match the identity embedded in the Geth state.
    #[arg(long)]
    validator: Address,
}

fn main() {
    if let Err(error) = run(Arguments::parse()) {
        eprintln!("Error: {error:?}");
        std::process::exit(1);
    }
}

fn run(arguments: Arguments) -> eyre::Result<()> {
    let source_password = read_password_file(&arguments.source_password_file)?;
    let destination_password = read_password_file(&arguments.destination_password_file)?;
    let store = DkgKeyStore::import_geth_encrypted_for_validator(
        &arguments.source,
        &source_password,
        &arguments.destination,
        &destination_password,
        arguments.validator,
    )?;
    println!(
        "Migrated Neo X DKG keystore: validator={}, round={}, message_public_key={}",
        arguments.validator,
        store.round(),
        alloy_primitives::hex::encode_prefixed(store.message_public_key())
    );
    Ok(())
}

fn read_password_file(path: &Path) -> eyre::Result<Zeroizing<Vec<u8>>> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        eyre::eyre!("failed to inspect password file {}: {error}", path.display())
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        eyre::bail!("refusing non-regular password file {}", path.display())
    }
    #[cfg(unix)]
    {
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            eyre::bail!("password file {} has mode {mode:o}; expected mode 0600", path.display())
        }
    }
    if metadata.len() == 0 || metadata.len() > MAX_PASSWORD_FILE_BYTES {
        eyre::bail!(
            "password file {} must contain between 1 and {MAX_PASSWORD_FILE_BYTES} bytes",
            path.display()
        )
    }
    let file = File::open(path)
        .map_err(|error| eyre::eyre!("failed to read password file {}: {error}", path.display()))?;
    let mut password = Zeroizing::new(Vec::with_capacity(metadata.len() as usize));
    file.take(MAX_PASSWORD_FILE_BYTES + 1)
        .read_to_end(&mut password)
        .map_err(|error| eyre::eyre!("failed to read password file {}: {error}", path.display()))?;
    if password.last() == Some(&b'\n') {
        password.pop();
        if password.last() == Some(&b'\r') {
            password.pop();
        }
    }
    if password.is_empty() {
        eyre::bail!("password file {} contains an empty password", path.display())
    }
    Ok(password)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn password_file_is_private_bounded_and_newline_trimmed() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("password");
        fs::write(&path, b"migration password\r\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_password_file(&path).unwrap().as_slice(), b"migration password");

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_password_file(&path).unwrap_err().to_string().contains("mode 0600"));
    }
}
