//! Operator identity primitives.
//!
//! An operator's identity is an Ed25519 key pair. The **public key**
//! is published with the OC operator registry, embedded in charters
//! the operator signs, and used by federations + the portal as the
//! operator's stable identifier across lifecycle stages.
//!
//! The **private key** never appears in this crate's runtime. It
//! lives behind a hardware-token boundary the kit does not cross:
//!
//!   - `os-keychain` (default): backed by the OS passkey store. On
//!     macOS this is Keychain Access + Touch ID/Face ID; on Linux
//!     it's libsecret + GNOME-keyring or KWallet; on Windows it's
//!     Windows Hello.
//!   - `yubikey`: FIDO2 with `hmac-secret` extension; signing
//!     requires user touch.
//!   - `ledger`: Ledger Nano signing app.
//!   - `passkey`: cross-platform WebAuthn passkey.
//!
//! Each backend exposes the same `Signer` interface. The kit asks
//! for a signature; the backend prompts the operator's hardware;
//! the signature returns to the kit. The private key is never
//! materialized into kit memory.

use serde::{Deserialize, Serialize};

/// 32-byte Ed25519 public key in raw form. We keep it as a byte
/// array rather than a `VerifyingKey` so this struct can be cheaply
/// serialized + persisted; verification re-imports as needed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct OperatorPubKey(pub [u8; 32]);

/// Operator identifier — first 16 bytes of `sha256(pubkey)`,
/// hex-encoded with a `op-` prefix. Stable across rotations: a key
/// rotation produces a new pubkey AND a new identifier; the old
/// identifier is preserved in the operator's audit log + the
/// federation's records.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct OperatorId(pub String);

impl OperatorPubKey {
    pub fn to_id(&self) -> OperatorId {
        use sha2::{Digest, Sha256};
        let h = Sha256::digest(self.0);
        OperatorId(format!("op-{}", hex::encode(&h[..16])))
    }
}

/// Hardware-token backend selector. Maps the CLI `--hsm` flag to a
/// signing-implementation strategy.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum HsmBackend {
    OsKeychain,
    Yubikey,
    Ledger,
    Passkey,
}

impl HsmBackend {
    pub fn from_flag(s: &str) -> anyhow::Result<Self> {
        Ok(match s {
            "os-keychain" => Self::OsKeychain,
            "yubikey" => Self::Yubikey,
            "ledger" => Self::Ledger,
            "passkey" => Self::Passkey,
            other => anyhow::bail!("unknown --hsm value: {other}"),
        })
    }
}

/// The kit's view of a signer. Concrete implementations live in
/// per-backend modules and are not surfaced here — the kit asks for
/// a signature and gets one, without learning anything about how
/// the backend produced it.
pub trait Signer {
    fn pubkey(&self) -> OperatorPubKey;
    fn sign(&self, message: &[u8]) -> anyhow::Result<[u8; 64]>;
}
