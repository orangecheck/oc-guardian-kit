//! HTTP client for the OC me.ochk.io portal API.
//!
//! The kit reaches the portal for three reasons:
//!
//!   1. Read-only fetches against public endpoints (charter meta,
//!      federation directory, per-federation deep view, operator
//!      marketplace). These are CORS-open at the portal layer and
//!      need no authentication.
//!   2. Submitting hardware-key-signed envelopes (charter sign,
//!      payout claim, alert publish, exit handoff). The envelope
//!      itself carries the authorization · the portal verifies the
//!      Ed25519 signature against the operator's published pubkey
//!      before accepting.
//!   3. Verifying acceptance envelopes the portal issues back to the
//!      operator (via `oc-guardian apply verify-acceptance`).
//!
//! Sync by design · the kit is a CLI; no tokio runtime needed.
//! `ureq` with rustls-only TLS keeps the binary reproducible (no
//! per-host openssl linkage variance).

use anyhow::{anyhow, Context, Result};
use serde::{de::DeserializeOwned, Serialize};
use std::time::Duration;
use tracing::debug;

use crate::actions::ActionEnvelope;

/// Default portal base. Operators can override via the
/// `OC_PORTAL_BASE` env var or the per-command `--portal` flag for
/// preview deploys / staging / local dev.
pub const DEFAULT_PORTAL_BASE: &str = "https://me.ochk.io";

/// Reasonable timeout for portal calls. Operator-signed actions and
/// transparency fetches are all short-lived; anything longer than
/// 15s is degenerate.
pub const PORTAL_TIMEOUT_SECS: u64 = 15;

/// A small wrapper around the ureq agent so callers don't have to
/// re-thread timeout / user-agent / base-url on every call.
#[derive(Clone, Debug)]
pub struct PortalClient {
    base: String,
    agent: ureq::Agent,
}

impl PortalClient {
    /// Build a client against a specific base URL. Use
    /// `PortalClient::default()` for `me.ochk.io`.
    pub fn new(base: impl Into<String>) -> Self {
        let base = base.into();
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(PORTAL_TIMEOUT_SECS))
            .user_agent(&format!("oc-guardian-kit/{}", env!("CARGO_PKG_VERSION")))
            .build();
        Self { base, agent }
    }

    /// Build a client from environment override or default. The
    /// CLI passes `--portal <URL>` to override per-invocation; the
    /// `OC_PORTAL_BASE` env var lets ops set it once for a shell
    /// session. Falls through to `DEFAULT_PORTAL_BASE`.
    pub fn from_env(override_url: Option<&str>) -> Self {
        if let Some(url) = override_url {
            return Self::new(url);
        }
        let base = std::env::var("OC_PORTAL_BASE").unwrap_or_else(|_| DEFAULT_PORTAL_BASE.into());
        Self::new(base)
    }

    fn url(&self, path: &str) -> String {
        if path.starts_with('/') {
            format!("{}{}", self.base.trim_end_matches('/'), path)
        } else {
            format!("{}/{}", self.base.trim_end_matches('/'), path)
        }
    }

    /// GET an endpoint and deserialize the JSON body. Returns
    /// PortalError::Status on non-2xx; PortalError::Transport on
    /// connection/TLS/timeout; PortalError::Parse on body shape
    /// mismatch.
    pub fn get_json<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let url = self.url(path);
        debug!(%url, "portal-client GET");
        match self.agent.get(&url).call() {
            Ok(response) => {
                let body: T = response
                    .into_json()
                    .with_context(|| format!("decoding JSON response from {url}"))?;
                Ok(body)
            }
            Err(ureq::Error::Status(code, response)) => {
                let body = response.into_string().unwrap_or_default();
                Err(anyhow!("{url} returned HTTP {code}: {body}"))
            }
            Err(e) => Err(anyhow!("portal transport error · {url}: {e}")),
        }
    }

    /// POST a JSON body and deserialize the response body. Used for
    /// signed-envelope submissions (charter-sign, payout-claim,
    /// alert-publish, etc.).
    pub fn post_json<T: DeserializeOwned, B: Serialize>(&self, path: &str, body: &B) -> Result<T> {
        let url = self.url(path);
        debug!(%url, "portal-client POST");
        match self.agent.post(&url).send_json(serde_json::to_value(body)?) {
            Ok(response) => {
                let parsed: T = response
                    .into_json()
                    .with_context(|| format!("decoding JSON response from {url}"))?;
                Ok(parsed)
            }
            Err(ureq::Error::Status(code, response)) => {
                let body = response.into_string().unwrap_or_default();
                Err(anyhow!("{url} returned HTTP {code}: {body}"))
            }
            Err(e) => Err(anyhow!("portal transport error · {url}: {e}")),
        }
    }

    /// Convenience · submit an ActionEnvelope to its destination endpoint.
    /// Returns the portal's response body parsed as T. The path is
    /// caller-supplied because each action type lands at a distinct
    /// endpoint (charter → /api/operator/charter, payouts →
    /// /api/operator/payouts/claim, etc.).
    pub fn submit_envelope<T: DeserializeOwned>(
        &self,
        path: &str,
        envelope: &ActionEnvelope,
    ) -> Result<T> {
        self.post_json(path, envelope)
    }
}

impl Default for PortalClient {
    fn default() -> Self {
        Self::new(DEFAULT_PORTAL_BASE)
    }
}

/// Charter meta as returned by /api/operator/charter?federation=X.
/// Mirrors src/lib/operator/charter.ts in oc-me-web field-for-field.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct CharterMeta {
    pub federation_slug: String,
    pub charter_hash: String,
    pub charter_version: String,
    pub charter_url: String,
    pub published_at: String,
}

/// Existing charter signature as returned by /api/operator/charter.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct CharterSignature {
    pub federation_slug: String,
    pub operator_id: String,
    pub operator_pubkey: String,
    pub charter_hash: String,
    pub charter_version: String,
    pub signed_at: String,
    pub sig_hex: String,
    pub received_at: String,
}

/// GET /api/operator/charter?federation=<slug> response shape.
#[derive(Clone, Debug, serde::Deserialize)]
pub struct CharterFetchResponse {
    pub ok: bool,
    pub meta: CharterMeta,
    #[serde(default)]
    pub signatures: Vec<CharterSignature>,
}

/// Public federation row as returned by /api/public/federations/[slug].
/// Subset of fields · we only need what the kit-side commands surface.
#[derive(Clone, Debug, serde::Deserialize)]
pub struct PublicFederation {
    pub slug: String,
    pub name: String,
    pub status: String,
    pub threshold: String,
    pub target_guardian_count: u32,
    #[serde(default)]
    pub bootstrap_mode: bool,
    pub charter_hash: Option<String>,
    pub last_attestation_at: Option<String>,
    #[serde(default)]
    pub seats: Vec<PublicSeat>,
}

#[derive(Clone, Debug, serde::Deserialize)]
pub struct PublicSeat {
    pub index: u32,
    pub operator_pubkey: String,
    pub assigned_at: String,
}

/// Wrapper around the /api/public/federations/[slug] response.
#[derive(Clone, Debug, serde::Deserialize)]
pub struct PublicFederationResponse {
    pub ok: bool,
    pub federation: PublicFederation,
}

/// Wrapper around the GET /api/federations directory list response.
#[derive(Clone, Debug, serde::Deserialize)]
pub struct FederationsListResponse {
    #[serde(default)]
    pub ok: bool,
    #[serde(default)]
    pub federations: Vec<PublicFederation>,
}

/// An accepted operator as returned by the public GET /api/operator/registry.
/// Anonymized: operator_id (sha256-derived) + pubkey hex only.
#[derive(Clone, Debug, serde::Deserialize)]
pub struct RegistryOperator {
    pub operator_id: String,
    pub pubkey: String,
}

/// Wrapper around GET /api/operator/registry (public · no auth).
#[derive(Clone, Debug, serde::Deserialize)]
pub struct OperatorRegistryResponse {
    #[serde(default)]
    pub ok: bool,
    #[serde(default)]
    pub operators: Vec<RegistryOperator>,
    #[serde(default)]
    pub count: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_join_handles_leading_slash() {
        let c = PortalClient::new("https://me.ochk.io");
        assert_eq!(c.url("/api/foo"), "https://me.ochk.io/api/foo");
    }

    #[test]
    fn url_join_handles_missing_leading_slash() {
        let c = PortalClient::new("https://me.ochk.io");
        assert_eq!(c.url("api/foo"), "https://me.ochk.io/api/foo");
    }

    #[test]
    fn url_join_strips_trailing_slash_from_base() {
        let c = PortalClient::new("https://me.ochk.io/");
        assert_eq!(c.url("/api/foo"), "https://me.ochk.io/api/foo");
    }

    #[test]
    fn from_env_with_override_wins() {
        let c = PortalClient::from_env(Some("https://staging.ochk.io"));
        assert_eq!(c.base, "https://staging.ochk.io");
    }

    #[test]
    fn default_points_at_production() {
        let c = PortalClient::default();
        assert_eq!(c.base, DEFAULT_PORTAL_BASE);
    }

    #[test]
    fn charter_meta_deserializes_minimal_shape() {
        let json = r#"{
            "federation_slug": "oc-me-v1",
            "charter_hash": "abc123",
            "charter_version": "v1.0.0",
            "charter_url": "https://docs.ochk.io/charter",
            "published_at": "2026-05-06T00:00:00.000Z"
        }"#;
        let m: CharterMeta = serde_json::from_str(json).unwrap();
        assert_eq!(m.federation_slug, "oc-me-v1");
        assert_eq!(m.charter_version, "v1.0.0");
    }

    #[test]
    fn charter_fetch_response_handles_empty_signatures() {
        let json = r#"{
            "ok": true,
            "meta": {
                "federation_slug": "oc-me-v1",
                "charter_hash": "abc",
                "charter_version": "v1.0.0",
                "charter_url": "https://example.com",
                "published_at": "2026-05-12T00:00:00Z"
            }
        }"#;
        let r: CharterFetchResponse = serde_json::from_str(json).unwrap();
        assert!(r.ok);
        assert!(r.signatures.is_empty());
    }

    #[test]
    fn public_federation_handles_missing_optional_fields() {
        let json = r#"{
            "slug": "oc-me-v1",
            "name": "OC-Me v1",
            "status": "recruiting",
            "threshold": "3-of-4",
            "target_guardian_count": 4,
            "charter_hash": null,
            "last_attestation_at": null
        }"#;
        let f: PublicFederation = serde_json::from_str(json).unwrap();
        assert!(!f.bootstrap_mode);
        assert!(f.seats.is_empty());
        assert!(f.charter_hash.is_none());
    }
}
