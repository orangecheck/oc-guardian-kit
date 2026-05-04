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
