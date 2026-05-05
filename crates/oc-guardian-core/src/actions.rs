//! Signed action envelopes.
//!
//! Every action that produces or applies authority — a join request,
//! a charter signature, a payout claim, a portal-bridge command —
//! is wrapped in an `ActionEnvelope`. The envelope is canonicalized,
//! hashed, and signed by the operator's hardware key. The receiver
//! verifies the signature against the operator's registered pubkey
//! before acting.
//!
//! Replay protection: each envelope carries a monotonic per-action
//! nonce + an absolute expiration timestamp. Receivers persist
//! `last_seen_nonce[action_type]` and reject any envelope whose nonce
//! does not strictly exceed the last seen value, or whose expiration
//! has passed.
//!
//! Action allowlist: the guardian's local config declares which
//! action types the operator key is authorized to sign. New action
//! types require explicit operator opt-in via the bridge subcommand.
//! This is the confused-deputy mitigation: a hostile portal cannot
//! escalate by inventing new action types.

use serde::{Deserialize, Serialize};

use crate::identity::OperatorPubKey;

/// Action types the kit understands. New variants require explicit
/// opt-in by the operator on each guardian that should accept them.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ActionType {
    /// Operator applies to the OC guardian operator program.
    ProgramApply,
    /// Operator joins a specific federation.
    FederationJoin,
    /// Operator leaves a specific federation.
    FederationLeave,
    /// Operator signs a federation charter.
    CharterSign,
    /// Operator coordinates exit-handoff to a replacement guardian.
    ExitHandoff,
    /// Operator claims accrued payouts.
    PayoutsClaim,
    /// Operator publishes an incident alert.
    AlertPublish,
    /// Operator authorizes a portal-bridge command (each portal-
    /// originated command is wrapped in this envelope and signed by
    /// the operator before the kit applies it).
    BridgeCommand,
}

/// Outer envelope. Receivers verify `sig_hex` against `pubkey` over
/// the CBOR canonical encoding of `payload`.
///
/// Hex-encoded signature is on the wire so envelopes survive JSON
/// transports, copy-paste, and human review without base64 ambiguity.
/// 128 hex chars = 64 raw bytes for Ed25519.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActionEnvelope {
    pub payload: ActionPayload,
    pub pubkey: OperatorPubKey,
    /// Hex-encoded 64-byte Ed25519 signature.
    pub sig_hex: String,
}

/// Inner signed payload. `params` is action-type-specific JSON; the
/// guardian dispatches on `action` to interpret it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActionPayload {
    pub action: ActionType,
    pub params: serde_json::Value,
    /// Monotonic nonce per `action`. Receivers reject equal-or-lower
    /// nonces seen previously.
    pub nonce: u64,
    /// Absolute expiration (Unix epoch seconds). Past-due envelopes
    /// are rejected even if signature + nonce are valid.
    pub expires_at: i64,
    /// Federation slug the action is scoped to (or None for
    /// federation-independent actions like ProgramApply).
    pub federation: Option<String>,
}

/// Reviewer-issued acceptance envelope. Asymmetric counterpart to
/// `ActionEnvelope` — sent in the OC→operator direction (an applicant
/// receives this in reply to a successful program-apply submission).
/// The reviewer signs over `serde_json::to_vec(&payload)` with their
/// Ed25519 key; the kit verifies against the public key published at
/// `me.ochk.io/.well-known/oc-operator-reviewer.json` (or against a
/// pinned `--reviewer-pubkey-hex` flag for fully-offline verification).
///
/// Field order in `AcceptancePayload` is load-bearing — it must match
/// the TypeScript signer's `reencodePayload` ordering exactly, since
/// signature verification depends on byte-identical canonicalization.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AcceptanceEnvelope {
    pub payload: AcceptancePayload,
    pub reviewer_kid: String,
    /// Hex-encoded 64-byte Ed25519 signature.
    pub sig_hex: String,
}

/// Inner signed payload. Mirrors `src/lib/operator/acceptance.ts` in
/// `oc-me-web` field-for-field, in field-declaration order.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AcceptancePayload {
    /// Always the literal `"program-accept"`.
    pub action: String,
    pub application_id: String,
    pub operator_id: String,
    /// Hex of the operator's Ed25519 public key (32 bytes = 64 hex).
    /// The applicant verifies this matches their local pubkey before
    /// trusting the acceptance.
    pub operator_pubkey: String,
    pub accepted_at_unix: i64,
    pub reviewer_note: Option<String>,
    pub federation_slug: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};

    /// AcceptancePayload field order is load-bearing — me-web's
    /// `reencodePayload` re-builds the payload object in this exact
    /// order before signing. If field order drifts here, every
    /// existing acceptance envelope stops verifying.
    #[test]
    fn acceptance_payload_serializes_in_field_declaration_order() {
        let p = AcceptancePayload {
            action: "program-accept".into(),
            application_id: "app_x".into(),
            operator_id: "op-aa".into(),
            operator_pubkey: "bb".into(),
            accepted_at_unix: 1714867200,
            reviewer_note: Some("ok".into()),
            federation_slug: Some("oc-me-v1".into()),
        };
        let json = serde_json::to_string(&p).unwrap();
        assert_eq!(
            json,
            r#"{"action":"program-accept","application_id":"app_x","operator_id":"op-aa","operator_pubkey":"bb","accepted_at_unix":1714867200,"reviewer_note":"ok","federation_slug":"oc-me-v1"}"#
        );
    }

    #[test]
    fn acceptance_envelope_round_trips_under_ed25519() {
        // Reviewer key.
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let verifying_key: VerifyingKey = signing_key.verifying_key();

        let payload = AcceptancePayload {
            action: "program-accept".into(),
            application_id: "app_round".into(),
            operator_id: "op-ff".into(),
            operator_pubkey: "ee".into(),
            accepted_at_unix: 1714867200,
            reviewer_note: None,
            federation_slug: Some("oc-me-v1".into()),
        };
        let canon = serde_json::to_vec(&payload).unwrap();
        let sig = signing_key.sign(&canon);

        // Verify against the canonical encoding.
        verifying_key.verify(&canon, &sig).unwrap();

        // Tamper detection.
        let mut tampered = payload.clone();
        tampered.reviewer_note = Some("after-the-fact note".into());
        let canon2 = serde_json::to_vec(&tampered).unwrap();
        assert!(verifying_key.verify(&canon2, &sig).is_err());
    }
}

/// Verification error categories. Returned by receivers; surfaced to
/// the operator as actionable diagnostics.
#[derive(Debug, thiserror::Error)]
pub enum ActionError {
    #[error("signature does not verify against operator pubkey")]
    BadSignature,
    #[error("nonce {got} not strictly greater than last seen {last_seen}")]
    StaleNonce { got: u64, last_seen: u64 },
    #[error("envelope expired at {expires_at} (now {now})")]
    Expired { expires_at: i64, now: i64 },
    #[error("action type {0:?} not in operator's allowlist")]
    NotAllowed(ActionType),
    #[error("operator pubkey not in registry")]
    UnknownOperator,
}
