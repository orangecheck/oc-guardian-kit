//! Download + verify + install the upstream `fedimintd` binary.
//!
//! The kit composes with upstream rather than forking the protocol. For
//! the Fly deploy path the Docker image bundles a pinned `fedimintd` at
//! build time (see Dockerfile), so `install` is primarily for bare-metal
//! operators provisioning their own box.
//!
//! Security: a guardian binary is consensus-critical, so we NEVER install
//! an unverified download. Each supported version pins the release
//! asset URL + its SHA-256; install refuses any version not in the
//! pinned manifest, and aborts if the downloaded bytes don't match.

use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use sha2::{Digest, Sha256};
use tracing::info;

/// A pinned, verified release asset for the linux-x86_64 target (the
/// Docker image + the standard Fly machine arch).
#[derive(Clone, Copy, Debug)]
pub struct PinnedRelease {
    pub version: &'static str,
    pub url: &'static str,
    /// Lowercase hex SHA-256 of the downloaded artifact.
    pub sha256_hex: &'static str,
}

/// The pinned manifest. Each entry is added deliberately, with its
/// SHA-256 verified out-of-band against the upstream signed release,
/// before it ships here. An empty/incomplete entry means that version
/// is not yet installable via the kit — `install` errors clearly rather
/// than fetching something unverified.
///
/// (Hashes are pinned per release in the release PR; the Fly image's
/// bundled fedimintd is the validated production path.)
pub const PINNED_RELEASES: &[PinnedRelease] = &[
    // Example shape — replace url/sha256 with the verified upstream
    // release artifact when pinning a version:
    // PinnedRelease {
    //     version: "0.7.2",
    //     url: "https://github.com/fedimint/fedimint/releases/download/v0.7.2/fedimintd-x86_64-unknown-linux-gnu",
    //     sha256_hex: "<verified-sha256>",
    // },
];

fn lookup(version: &str) -> Option<&'static PinnedRelease> {
    PINNED_RELEASES.iter().find(|r| r.version == version)
}

/// Compute the lowercase-hex SHA-256 of a byte slice.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// Verify downloaded bytes against the expected hex digest. Constant-ish
/// comparison is unnecessary (the expected value is public), but we
/// compare the full digests.
pub fn verify_sha256(bytes: &[u8], expected_hex: &str) -> Result<()> {
    let got = sha256_hex(bytes);
    if got.eq_ignore_ascii_case(expected_hex) {
        Ok(())
    } else {
        bail!("sha256 mismatch · expected {expected_hex}, got {got} · refusing to install")
    }
}

/// Install path for the fedimintd binary, given a bin dir.
pub fn bin_path(bin_dir: &Path) -> PathBuf {
    bin_dir.join("fedimintd")
}

/// Download + verify + install. Errors (without writing anything) if the
/// version isn't pinned or the hash doesn't match.
pub fn install_to(version: &str, bin_dir: &Path) -> Result<PathBuf> {
    let pin = lookup(version).ok_or_else(|| {
        anyhow!(
            "fedimintd {version} is not in the kit's pinned-release manifest · \
             pin its verified SHA-256 in install::PINNED_RELEASES first (the Fly image \
             bundles a pinned fedimintd; bare-metal installs require an explicit pin)"
        )
    })?;

    info!(version, url = pin.url, "downloading fedimintd release");
    let mut bytes = Vec::new();
    ureq::get(pin.url)
        .call()
        .with_context(|| format!("fetching {}", pin.url))?
        .into_reader()
        .take(512 * 1024 * 1024) // 512 MiB ceiling
        .read_to_end(&mut bytes)
        .context("reading release body")?;

    verify_sha256(&bytes, pin.sha256_hex)?;

    std::fs::create_dir_all(bin_dir).with_context(|| format!("creating {}", bin_dir.display()))?;
    let path = bin_path(bin_dir);
    std::fs::write(&path, &bytes).with_context(|| format!("writing {}", path.display()))?;
    set_executable(&path)?;
    info!(path = %path.display(), "fedimintd installed + verified");
    Ok(path)
}

#[cfg(unix)]
fn set_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms).context("chmod +x fedimintd")
}

#[cfg(not(unix))]
fn set_executable(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_is_correct() {
        // Known vector: sha256("abc").
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn verify_accepts_match_case_insensitive() {
        let h = sha256_hex(b"guardian");
        assert!(verify_sha256(b"guardian", &h).is_ok());
        assert!(verify_sha256(b"guardian", &h.to_uppercase()).is_ok());
    }

    #[test]
    fn verify_rejects_mismatch() {
        assert!(verify_sha256(b"guardian", &sha256_hex(b"tampered")).is_err());
    }

    #[test]
    fn unpinned_version_errors_without_download() {
        // No pinned releases by default → any version is refused, and the
        // error names the manifest so the operator knows what to do.
        let dir = std::env::temp_dir().join("oc-fedimint-test-bin");
        let err = install_to("99.99.99", &dir).unwrap_err().to_string();
        assert!(err.contains("PINNED_RELEASES"), "got: {err}");
        assert!(
            !bin_path(&dir).exists(),
            "must not write an unverified binary"
        );
    }

    #[test]
    fn bin_path_is_under_bin_dir() {
        assert_eq!(
            bin_path(Path::new("/opt/oc/bin")),
            PathBuf::from("/opt/oc/bin/fedimintd")
        );
    }
}
