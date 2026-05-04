//! Operator-local config dir layout.
//!
//! Resolves to `$XDG_CONFIG_HOME/oc-guardian/` on Linux/BSD,
//! `~/Library/Application Support/oc-guardian/` on macOS, and
//! `%APPDATA%\oc-guardian\` on Windows. Files in this dir are NOT
//! sensitive — they hold the operator's pubkey, identifier, and
//! kit configuration. The private key lives in the OS keychain
//! (see `keychain.rs`).
//!
//! Files:
//!
//!   operator.pub  — hex-encoded Ed25519 public key (32 bytes)
//!   operator.id   — operator identifier (op-<sha256-of-pubkey>)
//!   kit.toml      — non-secret kit settings (HSM backend choice,
//!                   bridge enabled flag, action allowlist)

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::identity::{HsmBackend, OperatorId, OperatorPubKey};

const DIR_NAME: &str = "oc-guardian";

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct KitConfig {
    /// Hardware backend selected at `init` time. Determines which
    /// signing path the kit uses for subsequent commands. Defaults
    /// to `os-keychain`.
    pub hsm_backend: Option<String>,
    /// Optional portal bridge state. Disabled by default; operators
    /// opt in via `oc-guardian bridge enable`.
    pub bridge: BridgeConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct BridgeConfig {
    pub enabled: bool,
    /// Allowlist of action types the operator has consented to
    /// authorize via the portal bridge. New action types require
    /// explicit `oc-guardian bridge allow <action>`.
    pub allowed_actions: Vec<String>,
}

/// Resolve the operator's config dir. Honors `--config-dir` override
/// passed by the CLI; otherwise falls back to the platform default.
pub fn resolve_dir(override_path: Option<&str>) -> Result<PathBuf> {
    if let Some(p) = override_path {
        return Ok(PathBuf::from(p));
    }
    let base = dirs::config_dir().context("could not locate user config dir")?;
    Ok(base.join(DIR_NAME))
}

pub fn ensure_dir(dir: &Path) -> Result<()> {
    if !dir.exists() {
        fs::create_dir_all(dir)
            .with_context(|| format!("creating config dir {}", dir.display()))?;
    }
    Ok(())
}

pub fn write_pubkey(dir: &Path, pubkey: &OperatorPubKey) -> Result<PathBuf> {
    let path = dir.join("operator.pub");
    let hex = format!("{}\n", hex::encode(pubkey.0));
    fs::write(&path, hex).with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}

pub fn write_id(dir: &Path, id: &OperatorId) -> Result<PathBuf> {
    let path = dir.join("operator.id");
    let line = format!("{}\n", id.0);
    fs::write(&path, line).with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}

pub fn write_kit_config(dir: &Path, cfg: &KitConfig) -> Result<PathBuf> {
    // Use JSON instead of TOML so the file is parseable without an
    // extra crate; can switch to TOML in v0.2 when other settings
    // benefit from the format.
    let path = dir.join("kit.json");
    let body = serde_json::to_string_pretty(cfg).context("serializing kit config")?;
    fs::write(&path, body).with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}

pub fn read_kit_config(dir: &Path) -> Result<Option<KitConfig>> {
    let path = dir.join("kit.json");
    match fs::read_to_string(&path) {
        Ok(s) => Ok(Some(serde_json::from_str(&s).context("parsing kit.json")?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).context("reading kit.json"),
    }
}

pub fn read_id(dir: &Path) -> Result<Option<OperatorId>> {
    let path = dir.join("operator.id");
    match fs::read_to_string(&path) {
        Ok(s) => Ok(Some(OperatorId(s.trim().to_string()))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).context("reading operator.id"),
    }
}

/// Marker type returned by `init` so the CLI can pretty-print all
/// outputs in one block.
pub struct InitOutcome {
    pub config_dir: PathBuf,
    pub pubkey_path: PathBuf,
    pub id_path: PathBuf,
    pub kit_config_path: PathBuf,
    pub operator_id: OperatorId,
    pub pubkey_hex: String,
    pub hsm_backend: HsmBackend,
}
