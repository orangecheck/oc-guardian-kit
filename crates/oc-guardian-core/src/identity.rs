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

use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};

/// 32-byte Ed25519 public key in raw form. We keep it as a byte
/// array rather than a `VerifyingKey` so this struct can be cheaply
/// persisted; verification re-imports as needed.
///
/// **Wire format:** hex-encoded 64-character string. Cleaner for
/// humans reading envelopes and consistent with how the rest of the
/// OC family serializes public-key bytes (see `oc-attest-protocol`
/// envelopes). Internal Rust callers still see `[u8; 32]`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct OperatorPubKey(pub [u8; 32]);

impl Serialize for OperatorPubKey {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for OperatorPubKey {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        let bytes = hex::decode(&s).map_err(D::Error::custom)?;
        let arr: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
            D::Error::custom(format!("expected 32 bytes, got {}", v.len()))
        })?;
        Ok(OperatorPubKey(arr))
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pubkey_serializes_as_64_hex_chars() {
        // Full 32-byte key must produce exactly 64 hex chars wrapped in quotes.
        let k = OperatorPubKey([0xab; 32]);
        let json = serde_json::to_string(&k).unwrap();
        assert_eq!(json.len(), 66, "expected 64 hex + 2 quotes, got {json}");
        assert_eq!(json, format!("\"{}\"", "ab".repeat(32)));
    }

    #[test]
    fn to_id_is_op_plus_32_hex() {
        // op-<hex(sha256(pubkey)[..16])> → "op-" + 32 hex chars.
        let id = OperatorPubKey([0xab; 32]).to_id();
        assert!(id.0.starts_with("op-"));
        assert_eq!(id.0.len(), 3 + 32, "op- + 32 hex; got {}", id.0);
    }

    #[test]
    fn to_id_matches_portal_cross_language_vector() {
        // CROSS-LANGUAGE PARITY: me.ochk.io derives the same operator_id from a
        // pubkey (oc-me-web operator-identity-store.ts deriveOperatorIdFromPubkeyHex
        // + browser-key.ts). Both sides pin this exact pubkey→id mapping; if the
        // kit and portal ever disagree, browser-key flows would mis-attribute.
        // pubkey = the ed25519-dalek attestation test pubkey.
        let pk: [u8; 32] =
            hex::decode("8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c")
                .unwrap()
                .try_into()
                .unwrap();
        assert_eq!(
            OperatorPubKey(pk).to_id().0,
            "op-34750f98bd59fcfc946da45aaabe933b"
        );
    }

    #[test]
    fn pubkey_deserializes_back_to_same_bytes() {
        let original = OperatorPubKey([
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
            0xcc, 0xdd, 0xee, 0xff,
        ]);
        let json = serde_json::to_string(&original).unwrap();
        let parsed: OperatorPubKey = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.0, original.0);
    }

    #[test]
    fn pubkey_rejects_wrong_length() {
        // 30 hex chars = 15 bytes, not 32 · must fail.
        let err = serde_json::from_str::<OperatorPubKey>(&format!("\"{}\"", "ab".repeat(15)))
            .unwrap_err()
            .to_string();
        assert!(err.contains("expected 32 bytes"), "got: {err}");
    }

    #[test]
    fn pubkey_rejects_non_hex() {
        let err = serde_json::from_str::<OperatorPubKey>("\"zzzz\"")
            .unwrap_err()
            .to_string();
        assert!(err.to_lowercase().contains("invalid"), "got: {err}");
    }

    #[test]
    fn operator_id_is_deterministic_from_pubkey() {
        // Same pubkey · same id, every time. The kit + me-web both
        // derive op-id from sha256(pubkey)[..16]; drift here would
        // make every accepted operator's id rotate on rebuild.
        let k = OperatorPubKey([0x42; 32]);
        let id1 = k.to_id();
        let id2 = k.to_id();
        assert_eq!(id1, id2);
        assert!(id1.0.starts_with("op-"));
        // "op-" + 32 hex chars
        assert_eq!(id1.0.len(), 3 + 32);
    }

    #[test]
    fn operator_id_differs_for_different_pubkeys() {
        let a = OperatorPubKey([0x42; 32]).to_id();
        let b = OperatorPubKey([0x43; 32]).to_id();
        assert_ne!(a, b);
    }

    #[test]
    fn hsm_backend_parses_known_flags() {
        assert!(matches!(
            HsmBackend::from_flag("os-keychain").unwrap(),
            HsmBackend::OsKeychain
        ));
        assert!(matches!(
            HsmBackend::from_flag("yubikey").unwrap(),
            HsmBackend::Yubikey
        ));
        assert!(matches!(
            HsmBackend::from_flag("ledger").unwrap(),
            HsmBackend::Ledger
        ));
        assert!(matches!(
            HsmBackend::from_flag("passkey").unwrap(),
            HsmBackend::Passkey
        ));
    }

    #[test]
    fn hsm_backend_rejects_unknown_flag() {
        // No silent fallback — an unknown flag must surface as an error
        // so the operator sees the typo rather than getting the wrong
        // signing backend.
        let err = HsmBackend::from_flag("plaintext-key")
            .unwrap_err()
            .to_string();
        assert!(err.contains("unknown --hsm"), "got: {err}");
    }
}
