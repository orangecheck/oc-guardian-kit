//! Liveness / status of the wrapped fedimintd daemon.

use std::time::Duration;

use anyhow::{Context, Result};
use tracing::info;

use crate::config::FedimintdRuntime;
use crate::run::probe_version;
use crate::run::resolve_binary;

/// Is fedimintd's consensus API answering on loopback? Any HTTP response
/// (even an upgrade-required / 4xx) means the port is bound + serving;
/// only a connection failure counts as down. Short timeout so callers
/// (the attestation ticker) never block.
pub fn api_up(rt: &FedimintdRuntime) -> bool {
    let url = rt.local_api_base();
    let resp = ureq::get(&url).timeout(Duration::from_secs(3)).call();
    match resp {
        Ok(_) => true,
        // Reached the server but it returned an HTTP error → still "up".
        Err(ureq::Error::Status(_, _)) => true,
        // Transport error (connection refused, timeout) → down.
        Err(_) => false,
    }
}

/// CLI entrypoint: print the daemon's status.
pub fn report() -> Result<()> {
    let rt = FedimintdRuntime::from_env().context("resolving runtime from env")?;
    let bin = resolve_binary("");
    let version = probe_version(&bin);
    let up = api_up(&rt);
    info!(
        federation = %rt.federation_slug,
        operator = %rt.operator_id,
        version,
        api = %rt.api_url(),
        up,
        "fedimintd status"
    );
    println!(
        "fedimintd · federation={} · version={} · api={} · up={}",
        rt.federation_slug,
        version,
        rt.api_url(),
        up
    );
    Ok(())
}
