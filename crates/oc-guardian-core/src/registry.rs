//! OC operator registry — the canonical mapping of `operator_pubkey`
//! → operator metadata. Used by federations + the portal to resolve
//! operator identities at the program-membership layer.
//!
//! The registry is published as a signed JSON document at
//! `https://ochk.io/.well-known/oc-guardian-operators.json`, signed
//! by the OC release key. Federations cache locally; consumers
//! verify the signature offline. **The registry is read-only from
//! every party except OC's signing key — no party (including the
//! portal) can add, remove, or modify entries without producing a
//! valid signed document under the OC release key.**
//!
//! Operators register by submitting a signed application envelope.
//! OC reviewers run the program's vetting workflow; on acceptance,
//! the operator's pubkey is added to the next published registry
//! revision. Removal happens via the same mechanism (signed revision
//! omitting the operator).
//!
//! Operators who want to verify their inclusion can run:
//!
//! ```sh
//! oc-guardian register verify
//! ```
//!
//! …which fetches the latest registry, verifies the signature,
//! and confirms the operator's pubkey is present.

use serde::{Deserialize, Serialize};

use crate::identity::OperatorPubKey;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegistryEntry {
    pub pubkey: OperatorPubKey,
    pub display_handle: String,
    pub joined_at: String,
    pub jurisdiction: String,
    /// Public contact channel — Nostr npub, email, or HTTPS endpoint
    /// the operator publishes signed status payloads at.
    pub public_channel: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Registry {
    pub revision: u64,
    pub published_at: String,
    pub operators: Vec<RegistryEntry>,
    /// Ed25519 signature over the canonicalized `(revision,
    /// published_at, operators)` tuple, produced by the OC release
    /// key. Verifiers fetch the OC release pubkey from
    /// `https://ochk.io/.well-known/oc-release-pubkey.txt`.
    pub sig_hex: String,
}
