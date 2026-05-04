//! Federation charter primitives — fetch, canonicalize, hash, sign,
//! publish.
//!
//! The charter is the human-readable document a federation publishes
//! disclosing its guardians, threshold, operational commitments, and
//! exit clause. Operators sign the charter to ratify their guardian
//! seat. Consumers verify the charter against its hash before
//! depositing into the federation.
//!
//! Canonical form: RFC 8785 JSON canonicalization for the structured
//! metadata block + UTF-8 normalization (NFC) of the prose body.
//! SHA-256 of the canonical bytes is the charter hash.
//!
//! v0.1.0 ships stubs. v0.2.0 lights up the full sign + publish flow.

use anyhow::Result;
use tracing::info;

pub fn fetch(slug: String) -> Result<()> {
    info!("charter fetch ({slug}): stub — v0.2.0 fetches from federation coordinator");
    Ok(())
}

pub fn sign(file: String, hsm: String) -> Result<()> {
    info!("charter sign ({file}, hsm={hsm}): stub — v0.2.0 produces a signed charter envelope");
    Ok(())
}

pub fn publish(file: String, transport: String) -> Result<()> {
    info!(
        "charter publish ({file}, transport={transport}): stub — v0.2.0 broadcasts the signature"
    );
    Ok(())
}
