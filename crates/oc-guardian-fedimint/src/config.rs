//! Map the OC-injected machine environment to a concrete `fedimintd`
//! runtime configuration.
//!
//! `provisionHosted` (oc-me-web/src/lib/hosting) creates the Fly machine
//! and injects:
//!   OC_OPERATOR_ID, OC_OPERATOR_PUBKEY_HEX, OC_FEDERATION_SLUG,
//!   OC_HOSTED_REQUEST_ID, OC_ATTESTATION_POST_URL
//! and exposes ports 9000 (P2P) + 9001 (consensus API) over Fly TLS.
//!
//! This module turns that into the `FM_*` environment `fedimintd`
//! actually reads, plus the data dir and the operator-identity context
//! the attestation needs. It is a pure transform (no I/O), so the whole
//! wiring is unit-tested without a running daemon.

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{anyhow, Result};

/// Default ports — must match the Fly service ports in
/// oc-me-web/src/lib/hosting/fly.ts (9000 P2P, 9001 API).
pub const DEFAULT_P2P_PORT: u16 = 9000;
pub const DEFAULT_API_PORT: u16 = 9001;
/// Guardian setup UI / DKG-coordination bind. Not exposed publicly by
/// Fly; reached over the machine's private network during the ceremony.
pub const DEFAULT_UI_PORT: u16 = 8175;

/// fedimintd's Bitcoin data source. fedimintd MANDATES one (it refuses
/// to start without `--bitcoind-url` or `--esplora-url`); the federation
/// watches the chain through it. Esplora is the zero-infra default
/// (no bitcoind to run); bitcoind is for operators running their own node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BitcoinBackend {
    /// `FM_ESPLORA_URL` — e.g. https://mempool.space/api.
    Esplora { url: String },
    /// `FM_BITCOIND_URL` (+ optional username/password).
    Bitcoind {
        url: String,
        username: Option<String>,
        password: Option<String>,
    },
}

/// A fully-resolved fedimintd runtime, derived from the machine env.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FedimintdRuntime {
    /// `FM_DATA_DIR` — persistent consensus state. On Fly this is the
    /// mounted volume.
    pub data_dir: PathBuf,
    /// Public hostname the federation peers + clients reach this guardian
    /// at (e.g. `<app>.fly.dev`).
    pub public_host: String,
    pub p2p_port: u16,
    pub api_port: u16,
    pub ui_port: u16,
    /// `FM_BITCOIN_NETWORK` — `bitcoin` (mainnet) for production.
    pub bitcoin_network: String,
    /// The mandatory Bitcoin data source.
    pub bitcoin_backend: BitcoinBackend,
    /// Operator identity (for the attestation + audit context).
    pub operator_id: String,
    pub operator_pubkey_hex: String,
    pub federation_slug: String,
    pub hosted_request_id: Option<String>,
    /// Where to POST the operator-signed runtime attestation. None
    /// disables attestation (e.g. local dev).
    pub attestation_post_url: Option<String>,
}

impl FedimintdRuntime {
    /// Resolve from the process environment.
    pub fn from_env() -> Result<Self> {
        Self::from_vars(|k| std::env::var(k).ok())
    }

    /// Resolve from an arbitrary variable lookup — the testable core.
    pub fn from_vars(get: impl Fn(&str) -> Option<String>) -> Result<Self> {
        let require = |k: &str| -> Result<String> {
            get(k)
                .filter(|v| !v.is_empty())
                .ok_or_else(|| anyhow!("required env var {k} is not set"))
        };
        let port = |k: &str, default: u16| -> Result<u16> {
            match get(k) {
                Some(v) if !v.is_empty() => v
                    .parse::<u16>()
                    .map_err(|_| anyhow!("{k}={v} is not a valid port")),
                _ => Ok(default),
            }
        };

        // Public host: explicit override, else derive from Fly's
        // FLY_APP_NAME (<app>.fly.dev). Required — peers need a routable
        // address for the federation invite.
        let public_host = match get("OC_PUBLIC_HOST").filter(|v| !v.is_empty()) {
            Some(h) => h,
            None => {
                let app = get("FLY_APP_NAME")
                    .filter(|v| !v.is_empty())
                    .ok_or_else(|| anyhow!("set OC_PUBLIC_HOST or run on Fly (FLY_APP_NAME)"))?;
                format!("{app}.fly.dev")
            }
        };

        let data_dir = get("FM_DATA_DIR")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/data/fedimintd"));

        // Bitcoin backend · fedimintd refuses to start without one. Prefer
        // an explicit bitcoind URL; else an Esplora URL. Required.
        let nonempty = |k: &str| get(k).filter(|v| !v.is_empty());
        let bitcoin_backend = if let Some(url) = nonempty("OC_BITCOIND_URL") {
            BitcoinBackend::Bitcoind {
                url,
                username: nonempty("OC_BITCOIND_USERNAME"),
                password: nonempty("OC_BITCOIND_PASSWORD"),
            }
        } else if let Some(url) = nonempty("OC_ESPLORA_URL") {
            BitcoinBackend::Esplora { url }
        } else {
            return Err(anyhow!(
                "fedimintd needs a Bitcoin backend · set OC_ESPLORA_URL (e.g. \
                 https://mempool.space/api) or OC_BITCOIND_URL (+ OC_BITCOIND_USERNAME/PASSWORD)"
            ));
        };

        Ok(Self {
            data_dir,
            public_host,
            p2p_port: port("OC_P2P_PORT", DEFAULT_P2P_PORT)?,
            api_port: port("OC_API_PORT", DEFAULT_API_PORT)?,
            ui_port: port("OC_UI_PORT", DEFAULT_UI_PORT)?,
            // Production default is mainnet; override via OC_BITCOIN_NETWORK
            // (bitcoin | testnet | signet | regtest).
            bitcoin_network: nonempty("OC_BITCOIN_NETWORK")
                .unwrap_or_else(|| "bitcoin".to_string()),
            bitcoin_backend,
            operator_id: require("OC_OPERATOR_ID")?,
            operator_pubkey_hex: require("OC_OPERATOR_PUBKEY_HEX")?,
            federation_slug: require("OC_FEDERATION_SLUG")?,
            hosted_request_id: get("OC_HOSTED_REQUEST_ID").filter(|v| !v.is_empty()),
            attestation_post_url: get("OC_ATTESTATION_POST_URL").filter(|v| !v.is_empty()),
        })
    }

    /// The public P2P URL peers dial during/after DKG.
    pub fn p2p_url(&self) -> String {
        format!("fedimint://{}:{}", self.public_host, self.p2p_port)
    }

    /// The public WebSocket consensus-API URL clients use. Fly terminates
    /// TLS on the exposed port, so this is `wss`.
    pub fn api_url(&self) -> String {
        format!("wss://{}:{}", self.public_host, self.api_port)
    }

    /// The `FM_*` environment `fedimintd` reads, as an ordered map
    /// (BTreeMap → deterministic for tests + logs). Binds listen on all
    /// interfaces inside the machine; the public URLs carry the routable
    /// host Fly assigns.
    pub fn fedimintd_env(&self) -> BTreeMap<String, String> {
        let mut env = BTreeMap::new();
        env.insert("FM_DATA_DIR".into(), self.data_dir.display().to_string());
        env.insert("FM_BIND_P2P".into(), format!("0.0.0.0:{}", self.p2p_port));
        env.insert("FM_BIND_API".into(), format!("0.0.0.0:{}", self.api_port));
        env.insert("FM_BIND_UI".into(), format!("0.0.0.0:{}", self.ui_port));
        env.insert("FM_P2P_URL".into(), self.p2p_url());
        env.insert("FM_API_URL".into(), self.api_url());
        env.insert("FM_BITCOIN_NETWORK".into(), self.bitcoin_network.clone());
        // Bitcoin backend — fedimintd mandates one.
        match &self.bitcoin_backend {
            BitcoinBackend::Esplora { url } => {
                env.insert("FM_ESPLORA_URL".into(), url.clone());
            }
            BitcoinBackend::Bitcoind {
                url,
                username,
                password,
            } => {
                env.insert("FM_BITCOIND_URL".into(), url.clone());
                if let Some(u) = username {
                    env.insert("FM_BITCOIND_USERNAME".into(), u.clone());
                }
                if let Some(p) = password {
                    env.insert("FM_BITCOIND_PASSWORD".into(), p.clone());
                }
            }
        }
        env
    }

    /// Local consensus-API base for health checks (the daemon binds all
    /// interfaces; we probe loopback).
    pub fn local_api_base(&self) -> String {
        format!("http://127.0.0.1:{}", self.api_port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn base() -> HashMap<String, String> {
        HashMap::from([
            ("OC_OPERATOR_ID".to_string(), "op-abc123".to_string()),
            ("OC_OPERATOR_PUBKEY_HEX".to_string(), "deadbeef".to_string()),
            ("OC_FEDERATION_SLUG".to_string(), "oc-me-v1".to_string()),
            ("FLY_APP_NAME".to_string(), "oc-guardian-xyz".to_string()),
            (
                "OC_ESPLORA_URL".to_string(),
                "https://mempool.space/api".to_string(),
            ),
        ])
    }

    fn rt(map: &HashMap<String, String>) -> FedimintdRuntime {
        FedimintdRuntime::from_vars(|k| map.get(k).cloned()).unwrap()
    }

    #[test]
    fn derives_public_host_from_fly_app_name() {
        let r = rt(&base());
        assert_eq!(r.public_host, "oc-guardian-xyz.fly.dev");
        assert_eq!(r.p2p_url(), "fedimint://oc-guardian-xyz.fly.dev:9000");
        assert_eq!(r.api_url(), "wss://oc-guardian-xyz.fly.dev:9001");
    }

    #[test]
    fn explicit_public_host_overrides_fly() {
        let mut m = base();
        m.insert("OC_PUBLIC_HOST".into(), "guardian.example.com".into());
        assert_eq!(rt(&m).public_host, "guardian.example.com");
    }

    #[test]
    fn defaults_match_fly_service_ports() {
        let r = rt(&base());
        assert_eq!(r.p2p_port, DEFAULT_P2P_PORT);
        assert_eq!(r.api_port, DEFAULT_API_PORT);
        let env = r.fedimintd_env();
        assert_eq!(env.get("FM_BIND_P2P").unwrap(), "0.0.0.0:9000");
        assert_eq!(env.get("FM_BIND_API").unwrap(), "0.0.0.0:9001");
        assert_eq!(env.get("FM_BIND_UI").unwrap(), "0.0.0.0:8175");
        assert_eq!(env.get("FM_DATA_DIR").unwrap(), "/data/fedimintd");
    }

    #[test]
    fn bitcoin_backend_required() {
        let mut m = base();
        m.remove("OC_ESPLORA_URL");
        let err = FedimintdRuntime::from_vars(|k| m.get(k).cloned())
            .unwrap_err()
            .to_string();
        assert!(err.contains("Bitcoin backend"), "got: {err}");
    }

    #[test]
    fn esplora_backend_maps_to_fm_env_and_mainnet_default() {
        let env = rt(&base()).fedimintd_env();
        assert_eq!(
            env.get("FM_ESPLORA_URL").unwrap(),
            "https://mempool.space/api"
        );
        assert_eq!(env.get("FM_BITCOIN_NETWORK").unwrap(), "bitcoin");
        assert!(!env.contains_key("FM_BITCOIND_URL"));
    }

    #[test]
    fn bitcoind_backend_with_creds_overrides_esplora() {
        let mut m = base();
        m.insert("OC_BITCOIND_URL".into(), "http://127.0.0.1:8332".into());
        m.insert("OC_BITCOIND_USERNAME".into(), "rpcuser".into());
        m.insert("OC_BITCOIND_PASSWORD".into(), "rpcpass".into());
        m.insert("OC_BITCOIN_NETWORK".into(), "signet".into());
        let env = rt(&m).fedimintd_env();
        assert_eq!(env.get("FM_BITCOIND_URL").unwrap(), "http://127.0.0.1:8332");
        assert_eq!(env.get("FM_BITCOIND_USERNAME").unwrap(), "rpcuser");
        assert_eq!(env.get("FM_BITCOIND_PASSWORD").unwrap(), "rpcpass");
        assert_eq!(env.get("FM_BITCOIN_NETWORK").unwrap(), "signet");
        // bitcoind takes precedence; no esplora var emitted.
        assert!(!env.contains_key("FM_ESPLORA_URL"));
    }

    #[test]
    fn ports_are_overridable() {
        let mut m = base();
        m.insert("OC_P2P_PORT".into(), "7000".into());
        m.insert("OC_API_PORT".into(), "7001".into());
        let r = rt(&m);
        assert_eq!(r.p2p_port, 7000);
        assert_eq!(r.api_url(), "wss://oc-guardian-xyz.fly.dev:7001");
    }

    #[test]
    fn missing_required_var_errors() {
        let mut m = base();
        m.remove("OC_OPERATOR_ID");
        assert!(FedimintdRuntime::from_vars(|k| m.get(k).cloned()).is_err());
    }

    #[test]
    fn missing_host_source_errors() {
        let mut m = base();
        m.remove("FLY_APP_NAME");
        assert!(FedimintdRuntime::from_vars(|k| m.get(k).cloned()).is_err());
    }

    #[test]
    fn bad_port_errors() {
        let mut m = base();
        m.insert("OC_P2P_PORT".into(), "not-a-port".into());
        assert!(FedimintdRuntime::from_vars(|k| m.get(k).cloned()).is_err());
    }

    #[test]
    fn attestation_url_optional() {
        let r = rt(&base());
        assert!(r.attestation_post_url.is_none());
        let mut m = base();
        m.insert(
            "OC_ATTESTATION_POST_URL".into(),
            "https://me.ochk.io/api/operator/attestation".into(),
        );
        assert_eq!(
            rt(&m).attestation_post_url.unwrap(),
            "https://me.ochk.io/api/operator/attestation"
        );
    }
}
