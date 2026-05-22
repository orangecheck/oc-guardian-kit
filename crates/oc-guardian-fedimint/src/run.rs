//! Launch + supervise the wrapped `fedimintd` daemon.
//!
//! This is the guardian's main process on the Fly machine: it resolves
//! the runtime config from the injected env, starts `fedimintd` with the
//! mapped `FM_*` variables, restarts it with backoff if it dies, and
//! emits operator-signed attestations on an interval.

use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use tracing::{error, info, warn};

use crate::attest;
use crate::config::FedimintdRuntime;
use crate::status;

/// How often the supervisor emits a runtime attestation.
const ATTEST_INTERVAL: Duration = Duration::from_secs(300);
/// Restart backoff bounds.
const BACKOFF_MIN: Duration = Duration::from_secs(2);
const BACKOFF_MAX: Duration = Duration::from_secs(60);

/// Resolve the fedimintd binary from an optional hint. An explicit
/// non-empty path is used as-is; otherwise we rely on `fedimintd` being
/// on PATH (the Docker image installs it there).
pub fn resolve_binary(hint: &str) -> PathBuf {
    let h = hint.trim();
    if h.is_empty() || h == "auto" {
        PathBuf::from("fedimintd")
    } else {
        PathBuf::from(h)
    }
}

/// Build the spawn command for fedimintd with the mapped FM_* env. Pure
/// (no spawn) so the wiring is unit-testable.
pub fn build_command(rt: &FedimintdRuntime, bin: &PathBuf) -> Command {
    let mut cmd = Command::new(bin);
    for (k, v) in rt.fedimintd_env() {
        cmd.env(k, v);
    }
    cmd
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Best-effort version probe: `fedimintd --version`. Returns "unknown"
/// if the binary can't be run or doesn't print a recognizable version.
pub fn probe_version(bin: &PathBuf) -> String {
    match Command::new(bin).arg("--version").output() {
        Ok(out) if out.status.success() => {
            let s = String::from_utf8_lossy(&out.stdout);
            s.split_whitespace()
                .last()
                .unwrap_or("unknown")
                .trim()
                .to_string()
        }
        _ => "unknown".to_string(),
    }
}

/// Entrypoint: supervise fedimintd forever. `bin_hint` is the optional
/// `--config` value from the CLI (treated as a fedimintd binary path
/// override; empty → resolve from PATH).
pub fn run(bin_hint: String) -> Result<()> {
    let rt = FedimintdRuntime::from_env().context("resolving fedimintd runtime from env")?;
    std::fs::create_dir_all(&rt.data_dir)
        .with_context(|| format!("creating data dir {}", rt.data_dir.display()))?;
    let bin = resolve_binary(&bin_hint);
    let version = probe_version(&bin);
    info!(
        bin = %bin.display(),
        version,
        federation = %rt.federation_slug,
        p2p = %rt.p2p_url(),
        api = %rt.api_url(),
        "starting guardian · supervising fedimintd"
    );

    // Attestation ticker on a background thread · operator-signed, no TEE.
    spawn_attestation_ticker(rt.clone(), version.clone());

    let mut backoff = BACKOFF_MIN;
    loop {
        match spawn_once(&rt, &bin) {
            Ok(mut child) => {
                backoff = BACKOFF_MIN; // a clean start resets backoff
                let exit = child.wait().context("waiting on fedimintd")?;
                error!(?exit, "fedimintd exited · restarting after backoff");
            }
            Err(e) => {
                error!(error = %e, "failed to spawn fedimintd · retrying after backoff");
            }
        }
        std::thread::sleep(backoff);
        backoff = (backoff * 2).min(BACKOFF_MAX);
    }
}

fn spawn_once(rt: &FedimintdRuntime, bin: &PathBuf) -> Result<Child> {
    build_command(rt, bin)
        .spawn()
        .with_context(|| format!("spawning {}", bin.display()))
}

fn spawn_attestation_ticker(rt: FedimintdRuntime, version: String) {
    std::thread::spawn(move || {
        // First report: starting. Then transition to running once the API
        // answers, and re-emit on the interval.
        if let Err(e) = attest::emit(&rt, &version, "starting", now_unix()) {
            warn!(error = %e, "initial attestation failed");
        }
        loop {
            std::thread::sleep(ATTEST_INTERVAL);
            let status = if status::api_up(&rt) {
                "running"
            } else {
                "starting"
            };
            if let Err(e) = attest::emit(&rt, &version, status, now_unix()) {
                warn!(error = %e, "periodic attestation failed");
            }
        }
    });
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
        ]);
        FedimintdRuntime::from_vars(|k| m.get(k).cloned()).unwrap()
    }

    #[test]
    fn resolve_binary_defaults_to_path() {
        assert_eq!(resolve_binary(""), PathBuf::from("fedimintd"));
        assert_eq!(resolve_binary("auto"), PathBuf::from("fedimintd"));
        assert_eq!(
            resolve_binary("/opt/fedimintd"),
            PathBuf::from("/opt/fedimintd")
        );
    }

    #[test]
    fn build_command_maps_fm_env() {
        let r = rt();
        let bin = PathBuf::from("fedimintd");
        let cmd = build_command(&r, &bin);
        let envs: HashMap<String, String> = cmd
            .get_envs()
            .filter_map(|(k, v)| {
                Some((
                    k.to_string_lossy().into_owned(),
                    v?.to_string_lossy().into_owned(),
                ))
            })
            .collect();
        assert_eq!(envs.get("FM_BIND_P2P").unwrap(), "0.0.0.0:9000");
        assert_eq!(envs.get("FM_BIND_API").unwrap(), "0.0.0.0:9001");
        assert_eq!(
            envs.get("FM_P2P_URL").unwrap(),
            "fedimint://g.example.com:9000"
        );
        assert_eq!(cmd.get_program().to_string_lossy(), "fedimintd");
    }
}
