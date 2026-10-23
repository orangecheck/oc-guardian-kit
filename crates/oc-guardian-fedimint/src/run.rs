//! Launch + supervise the wrapped `fedimintd` daemon.
//!
//! This is the guardian's main process on the Fly machine: it resolves
//! the runtime config from the injected env, starts `fedimintd` with the
//! mapped `FM_*` variables, restarts it with backoff if it dies, and
//! emits operator-signed attestations on an interval.

use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use tracing::{error, info, warn};

use crate::attest;
use crate::ceremony::ensure_local_params;
use crate::config::{is_loopback_bind, FedimintdRuntime, SetupPassword};
use crate::gate;
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

/// What an un-set-up guardian exposes. Until DKG writes its config,
/// fedimintd's setup API answers on the API bind and the setup UI on the
/// UI bind, and the first caller of `set_local_params` sets the password.
pub fn setup_exposure(rt: &FedimintdRuntime) -> Vec<String> {
    if rt.is_set_up() {
        return Vec::new();
    }
    let mut open = Vec::new();
    if !is_loopback_bind(&rt.bind_api) {
        open.push(format!("the setup API on {}", rt.bind_api));
    }
    if !is_loopback_bind(&rt.bind_ui) {
        open.push(format!("the setup UI on {}", rt.bind_ui));
    }
    open
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
pub fn run(bin_hint: String, allow_public_setup: bool) -> Result<()> {
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

    if let Some(pw) = rt.setup_password.as_ref().filter(|_| !rt.is_set_up()) {
        // Attestations carry on through setup.
        spawn_attestation_ticker(rt.clone(), version.clone());
        setup_behind_gate(&rt, &bin, pw)?;
        return supervise(&rt, &bin);
    }

    let open = setup_exposure(&rt);
    if !open.is_empty() {
        if !allow_public_setup {
            bail!(
                "this guardian is not set up yet, and {} would be reachable from other machines, \
                 where the first caller to set local params sets its password. Set \
                 OC_GUARDIAN_SETUP_PASSWORD (the setup gate), or bind the API and UI to 127.0.0.1 \
                 until DKG is done, or pass --allow-public-setup and run `oc-guardian ceremony \
                 start` straight away",
                open.join(" and ")
            );
        }
        warn!(
            "--allow-public-setup · this guardian is not set up yet, and {} can be reached from \
             other machines. The first caller to set local params sets the guardian's password: \
             set them now, with `oc-guardian ceremony start` on this machine",
            open.join(" and ")
        );
    }

    // Attestation ticker on a background thread · operator-signed, no TEE.
    spawn_attestation_ticker(rt.clone(), version.clone());
    supervise(&rt, &bin)
}

/// Run fedimintd with the configured binds, restarting it with backoff.
fn supervise(rt: &FedimintdRuntime, bin: &PathBuf) -> Result<()> {
    let mut backoff = BACKOFF_MIN;
    loop {
        match spawn_once(rt, bin) {
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

/// Until DKG writes the consensus config: fedimintd's API and UI on
/// loopback, and the setup gate on the public API bind. fedimintd forgets
/// local params when it restarts, so the gate holds across every restart.
/// Returns once the guardian is set up, with fedimintd stopped.
fn setup_behind_gate(rt: &FedimintdRuntime, bin: &PathBuf, pw: &SetupPassword) -> Result<()> {
    let mut local = rt.clone();
    local.bind_api = format!("127.0.0.1:{}", gate::free_loopback_port()?);
    local.bind_ui = format!("127.0.0.1:{}", rt.ui_port);
    let internal = local.local_api_base();
    // With OC_GUARDIAN_NAME the kit sets local params itself, and the gate
    // answers "starting" until it has.
    let gate = gate::start(
        &rt.bind_api,
        internal.clone(),
        pw.0.clone(),
        rt.local_params.is_none(),
    )?;
    info!(
        public = %rt.bind_api,
        internal = %local.bind_api,
        "not set up yet · fedimintd's API is on loopback, and the setup gate answers {} for it",
        rt.bind_api
    );
    let mut child: Option<Child> = None;
    let mut backoff = BACKOFF_MIN;
    let mut params_set = false;
    while !rt.is_set_up() {
        let exited = match child.as_mut() {
            None => true,
            Some(c) => c.try_wait().context("checking on fedimintd")?.is_some(),
        };
        if exited {
            if child.is_some() {
                warn!("fedimintd exited during setup · it forgets its local params and comes back with a new setup code (the gate still asks for the setup password)");
                std::thread::sleep(backoff);
                backoff = (backoff * 2).min(BACKOFF_MAX);
            }
            if rt.local_params.is_some() {
                gate.set_ready(false);
                params_set = false;
            }
            child = match spawn_once(&local, bin) {
                Ok(c) => Some(c),
                Err(e) => {
                    error!(error = %e, "failed to spawn fedimintd · retrying");
                    None
                }
            };
        }
        if let (Some(params), false) = (rt.local_params.as_ref(), params_set) {
            match ensure_local_params(&internal, &rt.data_dir, &rt.federation_slug, params, &pw.0) {
                Ok(fresh) => {
                    params_set = true;
                    gate.set_ready(true);
                    if fresh {
                        info!(name = %params.name, "local params set · this seat has a new setup code; the gate is open to the setup password");
                    } else {
                        info!("local params are this seat's own · the gate is open to the setup password");
                    }
                }
                Err(e) if e.to_string().contains("did not answer") => {}
                Err(e) => {
                    error!(error = %e, "local params could not be set · the gate stays closed")
                }
            }
            std::thread::sleep(Duration::from_millis(250));
            continue;
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    if let Some(mut c) = child {
        let _ = c.kill();
        let _ = c.wait();
    }
    gate.stop();
    info!("DKG is done · closing the setup gate and giving fedimintd the public API bind");
    Ok(())
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
            (
                "OC_ESPLORA_URL".to_string(),
                "https://mempool.space/api".to_string(),
            ),
            ("OC_BITCOIN_NETWORK".to_string(), "signet".to_string()),
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

    #[test]
    fn an_un_set_up_guardian_says_which_setup_surfaces_are_reachable() {
        let dir = std::env::temp_dir().join(format!("oc-kit-exposure-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut r = rt();
        r.data_dir = dir.clone();
        // Defaults: the API binds all interfaces, the UI loopback.
        assert_eq!(setup_exposure(&r), vec!["the setup API on 0.0.0.0:9001"]);
        r.bind_ui = "0.0.0.0:8175".into();
        assert_eq!(setup_exposure(&r).len(), 2);
        r.bind_api = "127.0.0.1:9001".into();
        r.bind_ui = "127.0.0.1:8175".into();
        assert!(setup_exposure(&r).is_empty());
        // Once set up, nothing is open to claim.
        r.bind_api = "0.0.0.0:9001".into();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("consensus.json"), "{}").unwrap();
        assert!(setup_exposure(&r).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
