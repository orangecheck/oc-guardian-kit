//! `oc-guardian-fedimint` — wraps the upstream `fedimintd` binary
//! lifecycle: download + verify signed releases, launch + supervise the
//! daemon with the OC-injected runtime config, and emit operator-signed
//! runtime attestations.
//!
//! Composes with upstream rather than reimplementing — the kit's job is
//! to orchestrate operator-side, not to fork the protocol.
//!
//! Deploy path (Fly): `provisionHosted` creates the machine + injects
//! `OC_OPERATOR_ID / OC_OPERATOR_PUBKEY_HEX / OC_FEDERATION_SLUG /
//! OC_ATTESTATION_POST_URL` and exposes ports 9000 (P2P) + 9001 (API).
//! The Docker image's entrypoint is `oc-guardian fedimintd run`, which
//! maps that env to `FM_*` and supervises a bundled, pinned fedimintd.
//!
//! Attestation is OPERATOR-signed, not TEE-based: §1A's load-bearing
//! property is operator-key control + diversity, so OC cannot forge a
//! guardian's attestation and an un-attested box is visibly un-attested.

pub mod attest;
pub mod config;
pub mod install;
pub mod run;
pub mod status;

use std::path::PathBuf;

use anyhow::Result;

/// Library version, from Cargo.toml.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// CLI entrypoint · download + verify + install a pinned fedimintd
/// release into the standard bin dir (`<FM_DATA_DIR>/../bin`, or
/// `/usr/local/bin` when the runtime env isn't resolvable).
pub fn install(version: String) -> Result<()> {
    let bin_dir = config::FedimintdRuntime::from_env()
        .ok()
        .and_then(|rt| rt.data_dir.parent().map(|p| p.join("bin")))
        .unwrap_or_else(|| PathBuf::from("/usr/local/bin"));
    let path = install::install_to(&version, &bin_dir)?;
    println!("installed fedimintd {version} → {}", path.display());
    Ok(())
}

/// CLI entrypoint · launch + supervise fedimintd (the guardian's main
/// process). `config` is an optional fedimintd-binary path override.
pub fn run(config: String) -> Result<()> {
    run::run(config)
}

/// CLI entrypoint · print the wrapped daemon's status.
pub fn status() -> Result<()> {
    status::report()
}
