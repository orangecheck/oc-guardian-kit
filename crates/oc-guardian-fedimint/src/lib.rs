//! `oc-guardian-fedimint` — wraps the upstream `fedimintd` binary
//! lifecycle. Downloads + verifies signed releases, manages the
//! daemon, exposes status.
//!
//! Composes with upstream rather than reimplementing — the kit's job
//! is to orchestrate operator-side, not to fork the protocol.
//!
//! Release verification: each fedimintd release tag is PGP-signed by
//! the upstream maintainers. The kit fetches the release tarball +
//! its `.asc` signature, verifies against a pinned set of upstream
//! release pubkeys, then installs.
//!
//! v0.1.0 ships stubs. v0.2.0 lights up `install` + `run` against
//! real fedimintd binaries.

use anyhow::Result;
use tracing::info;

pub fn install(version: String) -> Result<()> {
    info!("fedimintd install ({version}): stub — v0.2.0 wires upstream release verification");
    Ok(())
}

pub fn run(config: String) -> Result<()> {
    info!("fedimintd run ({config}): stub — v0.2.0 launches the wrapped daemon");
    Ok(())
}

pub fn status() -> Result<()> {
    info!("fedimintd status: stub — v0.2.0 reports daemon health + peer view");
    Ok(())
}
