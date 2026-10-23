//! DKG ceremony, driven through fedimintd 0.11's setup API on this machine.
//!
//! fedimintd 0.11 sets a federation up in four steps, the same ones its
//! setup UI and the portal take:
//!
//!   start    · `set_local_params`: this guardian's name and password (the
//!              leader also names the federation and its size). Returns
//!              this guardian's setup code, to send to the other guardians.
//!   add-peer · `add_peer_setup_code`, once for every other guardian's code.
//!   dkg      · `start_dkg`, on every guardian once all codes are in.
//!   finalize · once `setup_status` reports consensus running, fetch the
//!              invite code.
//!
//! The kit calls the API over this machine's own address for it, so the
//! password never crosses the network. Until `start` has run, whoever
//! reaches the setup API first sets the password: run it as soon as the
//! guardian boots.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tracing::info;

use crate::config::FedimintdRuntime;
use crate::status::{self, Phase};

/// Persisted ceremony progress · lives at `<data_dir>/oc-ceremony.json`.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CeremonyState {
    pub federation_slug: String,
    /// This guardian's name, as set with `start`.
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub leader: bool,
    /// This guardian's own setup code, returned by `set_local_params`.
    #[serde(default)]
    pub setup_code: String,
    /// The names fedimintd returned for each peer code added.
    #[serde(default)]
    pub peers: Vec<String>,
    pub started_at_unix: u64,
    #[serde(default)]
    pub dkg_started_at_unix: Option<u64>,
    /// Set by `finalize` once consensus is running.
    pub finalized_at_unix: Option<u64>,
    #[serde(default)]
    pub invite_code: Option<String>,
}

/// What `start` sends as `set_local_params`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalParams {
    pub name: String,
    /// The leader's federation name and size; `None` on every other guardian.
    pub federation: Option<(String, u32)>,
}

impl LocalParams {
    pub fn new(
        name: String,
        leader: bool,
        federation_name: Option<String>,
        federation_size: Option<u32>,
    ) -> Result<Self> {
        if name.trim().is_empty() {
            bail!("--name is required");
        }
        let federation = match (leader, federation_name, federation_size) {
            (true, Some(n), Some(s)) if !n.trim().is_empty() && s >= 1 => Some((n, s)),
            (true, _, _) => {
                bail!("the leader also sets --federation-name and --federation-size")
            }
            (false, None, None) => None,
            (false, _, _) => {
                bail!("--federation-name and --federation-size are for the leader (--leader)")
            }
        };
        Ok(Self { name, federation })
    }

    fn to_json(&self) -> Value {
        let mut v = json!({ "name": self.name });
        if let Some((n, s)) = &self.federation {
            v["federation_name"] = json!(n);
            v["federation_size"] = json!(s);
        }
        v
    }
}

/// The guardian password: `--password-file`, else `FM_PASSWORD` (the
/// variable fedimint-cli reads). Never printed.
pub fn read_password(password_file: Option<&str>) -> Result<String> {
    let pw = match password_file {
        Some(path) => std::fs::read_to_string(path)
            .with_context(|| format!("reading the password file {path}"))?
            .trim_end_matches(['\r', '\n'])
            .to_string(),
        None => std::env::var("FM_PASSWORD").map_err(|_| {
            anyhow!("give the guardian password with --password-file or FM_PASSWORD")
        })?,
    };
    if pw.is_empty() {
        bail!("the guardian password is empty");
    }
    Ok(pw)
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn state_path(data_dir: &Path) -> PathBuf {
    data_dir.join("oc-ceremony.json")
}

fn read_state(data_dir: &Path) -> Result<Option<CeremonyState>> {
    let path = state_path(data_dir);
    match std::fs::read_to_string(&path) {
        Ok(s) => Ok(Some(
            serde_json::from_str(&s).with_context(|| format!("parsing {}", path.display()))?,
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

fn write_state(data_dir: &Path, state: &CeremonyState) -> Result<()> {
    std::fs::create_dir_all(data_dir)
        .with_context(|| format!("creating {}", data_dir.display()))?;
    let path = state_path(data_dir);
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(state).context("encoding ceremony state")?,
    )
    .with_context(|| format!("writing {}", path.display()))
}

/// `start` against an API base: set local params, record the setup code.
pub fn start_at(
    base: &str,
    data_dir: &Path,
    slug: &str,
    params: &LocalParams,
    password: &str,
) -> Result<CeremonyState> {
    let code = status::rpc(base, "set_local_params", params.to_json(), Some(password))
        .map_err(|e| anyhow!("{e}"))?;
    let setup_code = code
        .as_str()
        .ok_or_else(|| anyhow!("set_local_params did not return a setup code"))?
        .to_string();
    let state = CeremonyState {
        federation_slug: slug.to_string(),
        name: params.name.clone(),
        leader: params.federation.is_some(),
        setup_code,
        started_at_unix: now_unix(),
        ..Default::default()
    };
    write_state(data_dir, &state)?;
    Ok(state)
}

/// `add-peer` against an API base: add each code, record the peer names.
pub fn add_peers_at(
    base: &str,
    data_dir: &Path,
    codes: &[String],
    password: &str,
) -> Result<Vec<String>> {
    let mut state =
        read_state(data_dir)?.ok_or_else(|| anyhow!("run `oc-guardian ceremony start` first"))?;
    let mut names = Vec::new();
    for code in codes {
        let name = status::rpc(
            base,
            "add_peer_setup_code",
            json!(code.trim()),
            Some(password),
        )
        .map_err(|e| anyhow!("{e}"))?;
        let name = name.as_str().unwrap_or("(unnamed)").to_string();
        if !state.peers.contains(&name) {
            state.peers.push(name.clone());
        }
        names.push(name);
    }
    write_state(data_dir, &state)?;
    Ok(names)
}

/// `dkg` against an API base.
pub fn start_dkg_at(base: &str, data_dir: &Path, password: &str) -> Result<()> {
    status::rpc(base, "start_dkg", Value::Null, Some(password)).map_err(|e| anyhow!("{e}"))?;
    if let Some(mut state) = read_state(data_dir)? {
        state.dkg_started_at_unix = Some(now_unix());
        write_state(data_dir, &state)?;
    }
    Ok(())
}

/// `finalize` against an API base: only once consensus is running.
pub fn finalize_at(base: &str, data_dir: &Path) -> Result<String> {
    let phase = status::phase_at(base)?;
    if phase != Phase::ConsensusRunning {
        bail!("DKG is not complete · {}", phase.describe());
    }
    let invite = status::rpc(base, "invite_code", Value::Null, None)
        .map_err(|e| anyhow!("{e}"))?
        .as_str()
        .ok_or_else(|| anyhow!("invite_code did not return a code"))?
        .to_string();
    if let Some(mut state) = read_state(data_dir)? {
        state.finalized_at_unix = Some(now_unix());
        state.invite_code = Some(invite.clone());
        write_state(data_dir, &state)?;
    }
    Ok(invite)
}

fn runtime() -> Result<FedimintdRuntime> {
    FedimintdRuntime::from_env().context("resolving runtime from env")
}

/// `ceremony start`
pub fn start(params: LocalParams, password_file: Option<String>) -> Result<()> {
    let rt = runtime()?;
    let password = read_password(password_file.as_deref())?;
    let state = start_at(
        &rt.local_api_base(),
        &rt.data_dir,
        &rt.federation_slug,
        &params,
        &password,
    )?;
    info!(federation = %rt.federation_slug, leader = state.leader, "local params set");
    println!();
    println!(
        "  local params set for {} · this guardian's password is now the one you gave",
        state.name
    );
    println!();
    println!("  your setup code (send it to each other guardian):");
    println!("    {}", state.setup_code);
    println!();
    println!("  then, with every other guardian's code:");
    println!("    oc-guardian ceremony add-peer --code <code> [--code <code> …]");
    println!("    oc-guardian ceremony dkg");
    println!();
    Ok(())
}

/// `ceremony add-peer`
pub fn add_peer(codes: Vec<String>, password_file: Option<String>) -> Result<()> {
    let rt = runtime()?;
    let password = read_password(password_file.as_deref())?;
    let names = add_peers_at(&rt.local_api_base(), &rt.data_dir, &codes, &password)?;
    for n in names {
        println!("  added peer {n}");
    }
    Ok(())
}

/// `ceremony dkg`
pub fn dkg(password_file: Option<String>) -> Result<()> {
    let rt = runtime()?;
    let password = read_password(password_file.as_deref())?;
    start_dkg_at(&rt.local_api_base(), &rt.data_dir, &password)?;
    println!("  DKG started · run `oc-guardian ceremony status` until it says RUNNING");
    Ok(())
}

/// `ceremony status` · the phase fedimintd reports, plus recorded progress.
pub fn status() -> Result<()> {
    let rt = runtime()?;
    let phase = status::phase(&rt)?;
    println!();
    match read_state(&rt.data_dir)? {
        Some(s) => {
            println!("  ceremony · federation {}", s.federation_slug);
            println!(
                "    guardian       {}{}",
                s.name,
                if s.leader { " (leader)" } else { "" }
            );
            println!("    peers added    {}", s.peers.len());
            println!(
                "    dkg started    {}",
                s.dkg_started_at_unix.map(|_| "yes").unwrap_or("no")
            );
            println!(
                "    finalized      {}",
                s.finalized_at_unix.map(|_| "yes").unwrap_or("no")
            );
        }
        None => println!("  no recorded ceremony · run `oc-guardian ceremony start` first"),
    }
    println!("    phase          {}", phase.describe());
    println!();
    Ok(())
}

/// `ceremony finalize` · once consensus is running, record it and print the invite.
pub fn finalize() -> Result<()> {
    let rt = runtime()?;
    let invite = finalize_at(&rt.local_api_base(), &rt.data_dir)?;
    println!();
    println!(
        "  DKG complete · federation {} is running",
        rt.federation_slug
    );
    println!("    api url   {}", rt.api_url());
    println!("    p2p url   {}", rt.p2p_url());
    println!("    invite    {invite}");
    println!();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status::stub::{error, result, serve};

    fn temp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("oc-kit-ceremony-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn local_params_follow_fedimint_0_11() {
        let leader = LocalParams::new("g0".into(), true, Some("fed".into()), Some(4)).unwrap();
        assert_eq!(
            leader.to_json(),
            json!({"name":"g0","federation_name":"fed","federation_size":4})
        );
        let peer = LocalParams::new("g1".into(), false, None, None).unwrap();
        assert_eq!(peer.to_json(), json!({"name":"g1"}));
        assert!(LocalParams::new("g0".into(), true, None, Some(4)).is_err());
        assert!(LocalParams::new("g1".into(), false, Some("fed".into()), None).is_err());
        assert!(LocalParams::new(" ".into(), false, None, None).is_err());
    }

    #[test]
    fn start_sets_local_params_with_the_password_and_records_the_code() {
        let s = serve(Box::new(|_, m, _| match m {
            "set_local_params" => result(json!("fedimint-code-g0")),
            _ => error("unexpected"),
        }));
        let dir = temp_dir("start");
        let p = LocalParams::new("g0".into(), true, Some("fed".into()), Some(4)).unwrap();
        let st = start_at(&s.base, &dir, "fed", &p, "pw").unwrap();
        assert_eq!(st.setup_code, "fedimint-code-g0");
        assert!(st.leader);
        assert_eq!(read_state(&dir).unwrap().unwrap(), st);
        let calls = s.calls.lock().unwrap();
        assert_eq!(calls[0].1["auth"], json!("pw"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn start_fails_when_someone_else_already_set_local_params() {
        let s = serve(Box::new(|_, _, _| {
            error("Local parameters have already been set")
        }));
        let dir = temp_dir("taken");
        let p = LocalParams::new("g0".into(), false, None, None).unwrap();
        let err = start_at(&s.base, &dir, "fed", &p, "pw")
            .unwrap_err()
            .to_string();
        assert!(err.contains("already been set"), "got: {err}");
        assert!(read_state(&dir).unwrap().is_none());
    }

    #[test]
    fn add_peer_adds_every_code_and_dkg_starts() {
        let s = serve(Box::new(|_, m, j| match m {
            "set_local_params" => result(json!("own")),
            "add_peer_setup_code" => {
                let code = j["params"][0]["params"].as_str().unwrap().to_string();
                result(json!(format!("name-of-{code}")))
            }
            "start_dkg" => result(Value::Null),
            _ => error("unexpected"),
        }));
        let dir = temp_dir("peers");
        let p = LocalParams::new("g1".into(), false, None, None).unwrap();
        start_at(&s.base, &dir, "fed", &p, "pw").unwrap();
        let names = add_peers_at(&s.base, &dir, &["a".into(), " b ".into()], "pw").unwrap();
        assert_eq!(names, vec!["name-of-a", "name-of-b"]);
        start_dkg_at(&s.base, &dir, "pw").unwrap();
        let st = read_state(&dir).unwrap().unwrap();
        assert_eq!(st.peers, vec!["name-of-a", "name-of-b"]);
        assert!(st.dkg_started_at_unix.is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn finalize_refuses_while_fedimintd_is_still_in_setup() {
        // fedimintd during setup: any HTTP reply, but not consensus.
        let s = serve(Box::new(|verb, m, _| match (verb, m) {
            ("GET", _) => (405, String::new()),
            (_, "setup_status") => result(json!("SharingConnectionCodes")),
            _ => error("unexpected"),
        }));
        let err = finalize_at(&s.base, &temp_dir("final-setup"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("not complete"), "got: {err}");
    }

    #[test]
    fn finalize_records_the_invite_once_consensus_is_running() {
        let s = serve(Box::new(|_, m, _| match m {
            "setup_status" => result(json!("ConsensusIsRunning")),
            "invite_code" => result(json!("fed11invite")),
            _ => error("unexpected"),
        }));
        let dir = temp_dir("final");
        write_state(
            &dir,
            &CeremonyState {
                federation_slug: "fed".into(),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(finalize_at(&s.base, &dir).unwrap(), "fed11invite");
        let st = read_state(&dir).unwrap().unwrap();
        assert_eq!(st.invite_code.as_deref(), Some("fed11invite"));
        assert!(st.finalized_at_unix.is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_password_comes_from_a_file_without_its_newline() {
        let dir = temp_dir("pw");
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("pw");
        std::fs::write(&f, "s3cret\n").unwrap();
        assert_eq!(read_password(Some(f.to_str().unwrap())).unwrap(), "s3cret");
        std::fs::write(&f, "\n").unwrap();
        assert!(read_password(Some(f.to_str().unwrap())).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
