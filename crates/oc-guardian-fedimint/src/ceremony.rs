//! DKG ceremony orchestration.
//!
//! Grounded in how fedimintd 0.11.1 ACTUALLY runs DKG: it is driven
//! through the guardian setup Web UI (`--bind-ui` / FM_BIND_UI). There is
//! no stable programmatic `fedimintd dkg` CLI — guardians coordinate the
//! distributed key generation through the setup UI, after which fedimintd
//! transitions from "setup" to a running federation exposing the
//! consensus API. So the kit's job here is to orchestrate AROUND that real
//! flow, not to fake a DKG it can't drive headlessly:
//!
//!   start    · persist the ceremony intent (peers + setup code) and print
//!              how to reach the setup UI to complete DKG.
//!   status   · detect the phase — consensus API answering ⇒ DKG complete
//!              + federation running; otherwise still in setup.
//!   finalize · once the API answers, record completion + point at the
//!              invite (the setup UI surfaces it post-DKG).
//!
//! The phase detection (API up ⇒ running) is real + reused from `status`.
//! The setup UI binds to a machine-private port (not exposed by Fly), so
//! operators reach it via `fly proxy`.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::config::FedimintdRuntime;
use crate::status as daemon_status;

/// Persisted ceremony intent · lives at `<data_dir>/oc-ceremony.json`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CeremonyState {
    pub federation_slug: String,
    /// Peer guardian URLs supplied to `ceremony start`.
    pub peers: Vec<String>,
    /// The federation organizer's setup code.
    pub setup_code: String,
    pub started_at_unix: u64,
    /// Set by `finalize` once the consensus API is answering.
    pub finalized_at_unix: Option<u64>,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn state_path(rt: &FedimintdRuntime) -> PathBuf {
    rt.data_dir.join("oc-ceremony.json")
}

/// Parse the comma-separated `--peers` value into a clean list.
pub fn parse_peers(peers: &str) -> Vec<String> {
    peers
        .split(',')
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect()
}

/// `fly proxy` guidance for reaching the machine-private setup UI.
pub fn setup_ui_hint(rt: &FedimintdRuntime) -> String {
    format!(
        "the setup UI binds 0.0.0.0:{ui} inside the machine (not exposed by Fly). \
         Reach it with:  fly proxy {ui}:{ui} -a <app>   then open http://localhost:{ui}",
        ui = rt.ui_port
    )
}

fn read_state(rt: &FedimintdRuntime) -> Result<Option<CeremonyState>> {
    let path = state_path(rt);
    match std::fs::read_to_string(&path) {
        Ok(s) => Ok(Some(
            serde_json::from_str(&s).with_context(|| format!("parsing {}", path.display()))?,
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

fn write_state(rt: &FedimintdRuntime, state: &CeremonyState) -> Result<()> {
    std::fs::create_dir_all(&rt.data_dir)
        .with_context(|| format!("creating {}", rt.data_dir.display()))?;
    let path = state_path(rt);
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(state).context("encoding ceremony state")?,
    )
    .with_context(|| format!("writing {}", path.display()))
}

/// `ceremony start` · record the intent + print how to complete DKG.
pub fn start(peers: String, setup_code: String) -> Result<()> {
    let rt = FedimintdRuntime::from_env().context("resolving runtime from env")?;
    let state = CeremonyState {
        federation_slug: rt.federation_slug.clone(),
        peers: parse_peers(&peers),
        setup_code,
        started_at_unix: now_unix(),
        finalized_at_unix: None,
    };
    write_state(&rt, &state)?;
    info!(
        federation = %rt.federation_slug,
        peers = state.peers.len(),
        "ceremony intent recorded"
    );
    println!();
    println!("  ceremony started for federation {}", rt.federation_slug);
    println!("    peers      {}", state.peers.len());
    println!("    p2p url    {}", rt.p2p_url());
    println!("    api url    {}", rt.api_url());
    println!();
    println!("  DKG runs through the fedimintd setup UI:");
    println!("    {}", setup_ui_hint(&rt));
    println!();
    println!("  enter the setup code + peer URLs there to run DKG, then:");
    println!("    oc-guardian ceremony status      # poll until the federation is running");
    println!("    oc-guardian ceremony finalize    # record completion + get the invite");
    println!();
    Ok(())
}

/// `ceremony status` · detect setup vs running from the consensus API.
pub fn status() -> Result<()> {
    let rt = FedimintdRuntime::from_env().context("resolving runtime from env")?;
    let running = daemon_status::api_up(&rt);
    let state = read_state(&rt)?;
    println!();
    match &state {
        Some(s) => {
            println!("  ceremony · federation {}", s.federation_slug);
            println!("    peers          {}", s.peers.len());
            println!(
                "    finalized      {}",
                s.finalized_at_unix.map(|_| "yes").unwrap_or("no")
            );
        }
        None => println!("  no recorded ceremony · run `oc-guardian ceremony start` first"),
    }
    if running {
        println!("    phase          RUNNING · consensus API is answering (DKG complete)");
    } else {
        println!("    phase          SETUP · DKG not complete — finish it in the setup UI");
        println!("    {}", setup_ui_hint(&rt));
    }
    println!();
    Ok(())
}

/// `ceremony finalize` · once the API answers, record completion.
pub fn finalize() -> Result<()> {
    let rt = FedimintdRuntime::from_env().context("resolving runtime from env")?;
    if !daemon_status::api_up(&rt) {
        anyhow::bail!(
            "DKG is not complete · the consensus API at {} is not answering yet. \
             Finish the ceremony in the setup UI ({}), then re-run finalize.",
            rt.api_url(),
            setup_ui_hint(&rt)
        );
    }
    if let Some(mut state) = read_state(&rt)? {
        state.finalized_at_unix = Some(now_unix());
        write_state(&rt, &state)?;
    }
    println!();
    println!(
        "  ✓ DKG complete · federation {} is running",
        rt.federation_slug
    );
    println!("    api url   {}", rt.api_url());
    println!("    p2p url   {}", rt.p2p_url());
    println!();
    println!("  the federation invite code is shown in the setup UI on completion:");
    println!("    {}", setup_ui_hint(&rt));
    println!("  publish it via the portal so clients can join.");
    println!();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn rt() -> FedimintdRuntime {
        let m = HashMap::from([
            ("OC_OPERATOR_ID".to_string(), "op-test".to_string()),
            ("OC_OPERATOR_PUBKEY_HEX".to_string(), "aa".to_string()),
            ("OC_FEDERATION_SLUG".to_string(), "oc-me-v1".to_string()),
            ("OC_PUBLIC_HOST".to_string(), "g.example.com".to_string()),
            (
                "OC_ESPLORA_URL".to_string(),
                "https://mempool.space/api".to_string(),
            ),
        ]);
        FedimintdRuntime::from_vars(|k| m.get(k).cloned()).unwrap()
    }

    #[test]
    fn parses_peer_list() {
        assert_eq!(
            parse_peers(" fedimint://a:9000 , fedimint://b:9000 ,, "),
            vec!["fedimint://a:9000", "fedimint://b:9000"]
        );
        assert!(parse_peers("").is_empty());
    }

    #[test]
    fn setup_ui_hint_names_the_ui_port_and_fly_proxy() {
        let h = setup_ui_hint(&rt());
        assert!(h.contains("8175"));
        assert!(h.contains("fly proxy"));
    }

    #[test]
    fn ceremony_state_roundtrips() {
        let s = CeremonyState {
            federation_slug: "oc-me-v1".into(),
            peers: vec!["fedimint://a:9000".into()],
            setup_code: "abc".into(),
            started_at_unix: 1_700_000_000,
            finalized_at_unix: None,
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: CeremonyState = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn state_path_is_under_data_dir() {
        assert_eq!(state_path(&rt()), rt().data_dir.join("oc-ceremony.json"));
    }
}
