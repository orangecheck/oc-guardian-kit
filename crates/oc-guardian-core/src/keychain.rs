//! OS keychain-backed signer for the operator's Ed25519 identity.
//!
//! The private key bytes live in the operator's OS keychain
//! (Keychain Access on macOS, libsecret/gnome-keyring/KWallet on
//! Linux, Credential Vault on Windows). The kit reads the bytes
//! when it needs to produce a signature and never persists them
//! anywhere else.
//!
//! This is the v0.1 default backend. v0.2+ adds first-class support
//! for hardware tokens (YubiKey FIDO2, Ledger, browser passkeys via
//! WebAuthn) where the private key never leaves the token at all —
//! the OS keychain is a software-only baseline that works everywhere.
//!
//! Service name: `io.ochk.oc-guardian`. Account: the operator
//! identifier (e.g. `op-3f7a8b2e...`). One operator key per kit
//! installation; switching identities means deleting the existing
//! keychain entry first.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use keyring::Entry;
use rand::{rngs::OsRng, RngCore};

use crate::config::{read_kit_config, resolve_dir};
use crate::identity::{OperatorPubKey, Signer};

const SERVICE: &str = "io.ochk.oc-guardian";

/// Generate a new operator identity, persist the private key to the
/// OS keychain under `service=io.ochk.oc-guardian, account=<id>`,
/// and return the keychain-backed signer plus its derived identifier.
///
/// Refuses to overwrite an existing entry — the caller is expected
/// to have checked, or to surface a clear "operator already
/// initialized" error.
pub fn generate_and_persist() -> Result<KeychainSigner> {
    // ed25519-dalek 2.1's `generate` requires the `rand_core` feature
    // wired through; cleaner to generate 32 random bytes via OsRng
    // and feed them to from_bytes. Same security; fewer features.
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    let signing = SigningKey::from_bytes(&secret);
    let verifying = signing.verifying_key();
    let pubkey = OperatorPubKey(verifying.to_bytes());
    let id = pubkey.to_id();

    let entry = Entry::new(SERVICE, &id.0)
        .with_context(|| format!("opening keychain entry for {}", id.0))?;

    // Refuse to overwrite — surface a clear error to the operator.
    if let Ok(_existing) = entry.get_password() {
        anyhow::bail!(
            "operator identity {} already exists in the OS keychain. \
             Delete it first if you intend to rotate.",
            id.0
        );
    }

    let priv_hex = hex::encode(signing.to_bytes());
    entry
        .set_password(&priv_hex)
        .with_context(|| format!("writing operator key to keychain ({})", id.0))?;

    Ok(KeychainSigner {
        id_account: id.0,
        pubkey,
    })
}

/// Load an existing operator identity from the keychain by its
/// identifier. Returns Ok(None) if no entry is bound to that
/// identifier; Err on keychain access failures.
pub fn load(operator_id: &str) -> Result<Option<KeychainSigner>> {
    let entry = Entry::new(SERVICE, operator_id)
        .with_context(|| format!("opening keychain entry for {operator_id}"))?;
    let priv_hex = match entry.get_password() {
        Ok(s) => s,
        Err(keyring::Error::NoEntry) => return Ok(None),
        Err(e) => return Err(e).context("reading operator key from keychain"),
    };
    let bytes = hex::decode(&priv_hex).context("operator key is not hex")?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("operator key is not 32 bytes"))?;
    let signing = SigningKey::from_bytes(&arr);
    let verifying = signing.verifying_key();
    Ok(Some(KeychainSigner {
        id_account: operator_id.to_string(),
        pubkey: OperatorPubKey(verifying.to_bytes()),
    }))
}

/// Delete the operator's keychain entry. Used when the operator
/// rotates identities or when the kit is uninstalled.
pub fn delete(operator_id: &str) -> Result<()> {
    let entry = Entry::new(SERVICE, operator_id)
        .with_context(|| format!("opening keychain entry for {operator_id}"))?;
    match entry.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(e).context("deleting operator key from keychain"),
    }
}

/// Concrete `Signer` impl backed by the OS keychain. Implements the
/// `Signer` trait declared in `identity.rs` so action envelopes can
/// be signed without the rest of the kit caring how.
pub struct KeychainSigner {
    id_account: String,
    pubkey: OperatorPubKey,
}

impl Signer for KeychainSigner {
    fn pubkey(&self) -> OperatorPubKey {
        self.pubkey
    }

    fn sign(&self, message: &[u8]) -> Result<[u8; 64]> {
        let entry = Entry::new(SERVICE, &self.id_account)
            .with_context(|| format!("opening keychain entry for {}", self.id_account))?;
        let priv_hex = entry
            .get_password()
            .context("reading operator key from keychain")?;
        let bytes = hex::decode(&priv_hex).context("operator key is not hex")?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("operator key is not 32 bytes"))?;
        let signing = SigningKey::from_bytes(&arr);
        Ok(signing.sign(message).to_bytes())
    }
}

/// A signer over a key the process is handed rather than one in the OS
/// keychain: a hosted guardian's attestation key, delegated by the seat's
/// operator and passed in as `OC_ATTEST_KEY_HEX`. It signs liveness reports
/// only; the operator key never reaches a hosted machine.
pub struct StaticSigner {
    signing: SigningKey,
}

impl StaticSigner {
    pub fn from_hex(private_hex: &str) -> Result<Self> {
        let bytes = hex::decode(private_hex.trim()).context("attestation key is not hex")?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("attestation key is not 32 bytes"))?;
        Ok(Self {
            signing: SigningKey::from_bytes(&arr),
        })
    }
}

impl Signer for StaticSigner {
    fn pubkey(&self) -> OperatorPubKey {
        OperatorPubKey(self.signing.verifying_key().to_bytes())
    }

    fn sign(&self, message: &[u8]) -> Result<[u8; 64]> {
        Ok(self.signing.sign(message).to_bytes())
    }
}

/// The operator's signer: the key file `init --key-file` recorded, else
/// the OS keychain entry. Ok(None) when neither holds a key.
pub fn load_signer(operator_id: &str) -> Result<Option<Box<dyn Signer>>> {
    let cfg = read_kit_config(&resolve_dir(None)?)?.unwrap_or_default();
    if let Some(path) = cfg.key_file {
        return Ok(Some(Box::new(FileSigner::load(Path::new(&path))?)));
    }
    Ok(load(operator_id)?.map(|s| Box::new(s) as Box<dyn Signer>))
}

/// A signer over an operator key kept in a file, for a machine with no OS
/// keychain (a headless server). The file is the key: anyone who can read
/// it can sign as the operator, so `init` only makes one when asked to.
pub struct FileSigner {
    path: PathBuf,
    pubkey: OperatorPubKey,
}

impl FileSigner {
    /// Generate a key into `path` (mode 0600). Refuses to overwrite.
    pub fn generate(path: &Path) -> Result<Self> {
        if path.exists() {
            anyhow::bail!(
                "{} already exists · refusing to overwrite an operator key",
                path.display()
            );
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        write_private(path, &hex::encode(secret))?;
        Self::load(path)
    }

    pub fn load(path: &Path) -> Result<Self> {
        let signing = read_key_file(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            pubkey: OperatorPubKey(signing.verifying_key().to_bytes()),
        })
    }
}

impl Signer for FileSigner {
    fn pubkey(&self) -> OperatorPubKey {
        self.pubkey
    }

    fn sign(&self, message: &[u8]) -> Result<[u8; 64]> {
        Ok(read_key_file(&self.path)?.sign(message).to_bytes())
    }
}

fn read_key_file(path: &Path) -> Result<SigningKey> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading operator key file {}", path.display()))?;
    let bytes = hex::decode(text.trim()).context("operator key file is not hex")?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("operator key file is not 32 bytes"))?;
    Ok(SigningKey::from_bytes(&arr))
}

#[cfg(unix)]
fn write_private(path: &Path, contents: &str) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    f.write_all(contents.as_bytes())
        .with_context(|| format!("writing {}", path.display()))
}

#[cfg(not(unix))]
fn write_private(path: &Path, contents: &str) -> Result<()> {
    std::fs::write(path, contents).with_context(|| format!("writing {}", path.display()))
}

/// Verify an Ed25519 signature against a public key. Convenience
/// wrapper around `ed25519_dalek::VerifyingKey::verify_strict` so
/// callers don't have to care about the underlying crypto crate.
pub fn verify(pubkey: &OperatorPubKey, message: &[u8], sig: &[u8; 64]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(&pubkey.0) else {
        return false;
    };
    let sig = ed25519_dalek::Signature::from_bytes(sig);
    vk.verify_strict(message, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_key_is_private_signs_and_is_never_overwritten() {
        let dir = std::env::temp_dir().join(format!("oc-kit-keyfile-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("operator.key");
        let signer = FileSigner::generate(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let sig = signer.sign(b"msg").unwrap();
        assert!(verify(&signer.pubkey(), b"msg", &sig));
        assert_eq!(FileSigner::load(&path).unwrap().pubkey(), signer.pubkey());
        assert!(FileSigner::generate(&path).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
