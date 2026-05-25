//! Federation → portal settlement events (the bridge's signing primitive).
//!
//! Fedimint has no native federation-signed settlement webhook, so a
//! companion bridge service — holding an operator/gateway-controlled key —
//! observes federation state (via fedimint-clientd) and emits OC-defined
//! settlement events signed by that key, each referencing Fedimint-native
//! primitives (operation_id, payment_hash/preimage, txid, gateway pubkey).
//! The portal verifies the signature against the federation's published
//! `settlement_pubkey` and mirrors the settled state. OC holds no funds.
//!
//! This module is the SIGNING half: the event types + canonical bytes +
//! `sign`. The observation half (polling fedimint-clientd, mapping its
//! responses into these events) is validated against a live federation and
//! lives in the bridge binary, not here.
//!
//! Canonical bytes = `serde_json::to_vec(&event)` in field-declaration order
//! — byte-identical to the portal's `canonicalSettlementBytes`
//! (oc-me-web src/lib/envelope/canonical.ts). Pinned by a cross-language
//! parity vector in tests. Full contract: oc-me-web/SETTLEMENT-CONTRACT.md.

use anyhow::{Context, Result};
use oc_guardian_core::identity::Signer;
use serde::{Deserialize, Serialize};

/// What settled. Serializes to the dotted strings the portal switches on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SettlementKind {
    #[serde(rename = "escrow.deposit")]
    EscrowDeposit,
    #[serde(rename = "escrow.rebate")]
    EscrowRebate,
    #[serde(rename = "escrow.refund")]
    EscrowRefund,
    #[serde(rename = "platform.accrual")]
    PlatformAccrual,
    #[serde(rename = "distribution.settled")]
    DistributionSettled,
    #[serde(rename = "operator.payout")]
    OperatorPayout,
    #[serde(rename = "adjustment")]
    Adjustment,
}

/// Direction of the settled value relative to federation custody.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    /// Into federation custody (deposits).
    #[serde(rename = "in")]
    In,
    /// Paid out of federation custody (distributions, payouts).
    #[serde(rename = "out")]
    Out,
}

/// The signed body. **Field order here IS the canonical signing order** —
/// it must match the portal's `canonicalSettlementBytes` exactly. `Option`
/// fields serialize as `null` (serde default), never omitted.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SettlementEvent {
    pub kind: SettlementKind,
    pub federation_slug: String,
    /// Fedimint native operation handle — also the portal idempotency key.
    pub operation_id: String,
    pub amount_sats: u64,
    pub direction: Direction,
    /// Unix seconds.
    pub settled_at: u64,

    // native anchors (presence depends on rail/kind)
    pub payment_hash: Option<String>,
    pub preimage: Option<String>,
    pub txid: Option<String>,
    pub gateway_pubkey: Option<String>,

    // targets (presence depends on kind)
    pub project_key: Option<String>,
    pub user_address: Option<String>,
    pub payout_binding_id: Option<String>,
    pub distribution_id: Option<String>,
    pub operator_id: Option<String>,
    pub destination: Option<String>,

    pub note: Option<String>,
}

/// The wire envelope the bridge POSTs to `/api/webhook/federation-settle`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedSettlement {
    pub event: SettlementEvent,
    /// Hex Ed25519 public key (32 bytes) — the federation's settlement key.
    pub pubkey_hex: String,
    /// Hex Ed25519 signature (64 bytes) over `serde_json::to_vec(&event)`.
    pub sig_hex: String,
}

/// The exact bytes the bridge signs (and the portal re-derives to verify).
pub fn canonical_bytes(event: &SettlementEvent) -> Result<Vec<u8>> {
    serde_json::to_vec(event).context("serializing settlement event")
}

/// Sign a settlement event with the federation settlement key. Returns the
/// wire form. The signing key lives under operator/federation control; OC
/// cannot produce this signature.
pub fn sign(event: &SettlementEvent, signer: &dyn Signer) -> Result<SignedSettlement> {
    let bytes = canonical_bytes(event)?;
    let sig = signer.sign(&bytes).context("signing settlement event")?;
    Ok(SignedSettlement {
        event: event.clone(),
        pubkey_hex: hex::encode(signer.pubkey().0),
        sig_hex: hex::encode(sig),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use oc_guardian_core::identity::OperatorPubKey;

    /// Deterministic real-Ed25519 signer over a fixed seed, for the
    /// cross-language vector (mirrors the portal's @noble verifier).
    struct FixedSigner {
        sk: ed25519_dalek::SigningKey,
    }
    impl FixedSigner {
        fn new() -> Self {
            Self {
                sk: ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]),
            }
        }
    }
    impl Signer for FixedSigner {
        fn pubkey(&self) -> OperatorPubKey {
            OperatorPubKey(self.sk.verifying_key().to_bytes())
        }
        fn sign(&self, message: &[u8]) -> Result<[u8; 64]> {
            use ed25519_dalek::Signer as _;
            Ok(self.sk.sign(message).to_bytes())
        }
    }

    /// CROSS-LANGUAGE PARITY VECTOR. The portal
    /// (oc-me-web src/lib/envelope/canonical.ts → canonicalSettlementBytes)
    /// asserts canonicalSettlementBytes(fixture) decodes to this exact string
    /// AND that the dalek signature below verifies under @noble. If field
    /// order / escaping / null-handling drifts on either side, both fail CI.
    const PARITY_VECTOR: &str = r#"{"kind":"escrow.deposit","federation_slug":"oc-me-v1","operation_id":"op-fixture-1","amount_sats":100000,"direction":"in","settled_at":1779408000,"payment_hash":null,"preimage":null,"txid":null,"gateway_pubkey":null,"project_key":"pk-fixture","user_address":null,"payout_binding_id":null,"distribution_id":null,"operator_id":null,"destination":null,"note":null}"#;

    fn fixture() -> SettlementEvent {
        SettlementEvent {
            kind: SettlementKind::EscrowDeposit,
            federation_slug: "oc-me-v1".to_string(),
            operation_id: "op-fixture-1".to_string(),
            amount_sats: 100_000,
            direction: Direction::In,
            settled_at: 1_779_408_000,
            payment_hash: None,
            preimage: None,
            txid: None,
            gateway_pubkey: None,
            project_key: Some("pk-fixture".to_string()),
            user_address: None,
            payout_binding_id: None,
            distribution_id: None,
            operator_id: None,
            destination: None,
            note: None,
        }
    }

    #[test]
    fn canonical_bytes_match_cross_language_vector() {
        let s = String::from_utf8(canonical_bytes(&fixture()).unwrap()).unwrap();
        assert_eq!(
            s, PARITY_VECTOR,
            "serde_json output drifted from the portal vector"
        );
    }

    #[test]
    fn kind_and_direction_serialize_to_dotted_lowercase() {
        assert_eq!(
            serde_json::to_string(&SettlementKind::DistributionSettled).unwrap(),
            "\"distribution.settled\""
        );
        assert_eq!(serde_json::to_string(&Direction::Out).unwrap(), "\"out\"");
    }

    #[test]
    fn option_some_serializes_as_value_not_omitted() {
        let mut e = fixture();
        e.preimage = Some("ab".repeat(32));
        let s = String::from_utf8(canonical_bytes(&e).unwrap()).unwrap();
        assert!(s.contains(&format!("\"preimage\":\"{}\"", "ab".repeat(32))));
    }

    #[test]
    fn sign_is_deterministic_and_emits_the_cross_language_signature() {
        let signer = FixedSigner::new();
        let a = sign(&fixture(), &signer).unwrap();
        let b = sign(&fixture(), &signer).unwrap();
        assert_eq!(
            a.sig_hex, b.sig_hex,
            "Ed25519 is deterministic for a fixed key+msg"
        );
        // These two hex strings are asserted verbatim in the portal test
        // (oc-me-web federation-settlement.test.ts) — a real dalek signature
        // the @noble verifier must accept. Changing them means the vector
        // moved; update both sides.
        assert_eq!(
            a.pubkey_hex,
            "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c"
        );
        assert_eq!(
            a.sig_hex,
            "c6d8dd32146024fcff0cd5fc289678d06c900af0f16a5ece957d2fbd37e03040c308d4bf5b90c64931915b27c62258d1f6ef380df1571fc9d55405841384180e"
        );
    }
}
