//! `oc-guardian-portal-bridge` — optional subsystem that bridges the
//! operator portal at `guardian.ochk.io` into the operator's running
//! kit. **Disabled by default.**
//!
//! Architecture:
//!
//!   1. Portal sends an *action request* to the operator's local
//!      kit. The request is itself signed by the portal's release
//!      key, so the kit can prove it came from the published portal
//!      build (not a spoof). But this is provenance only — not
//!      authority.
//!
//!   2. Kit displays the request to the operator (CLI prompt,
//!      desktop notification, or embedded web UI — operator's
//!      choice).
//!
//!   3. Operator decides. If approved, operator's hardware token
//!      signs an `ActionEnvelope` carrying the request's payload.
//!      The kit's signature is what actually authorizes the action.
//!
//!   4. Kit applies the action locally OR publishes the
//!      operator-signed envelope outward (to peers, federations,
//!      the registry — wherever the action targets).
//!
//! The portal never produces the operator's signature. The bridge's
//! only authority is "request" — it cannot apply, push, or sign on
//! behalf of the operator. A compromised portal can spam approval
//! requests; it cannot move funds or change federation state.
//!
//! Each enabled action type requires explicit operator opt-in via
//! `oc-guardian bridge allow <action>`. The default state is
//! "bridge disabled, no actions allowed." Operators ratchet up
//! permissions only when they understand each action's effect.

use anyhow::Result;
use tracing::info;

pub fn enable() -> Result<()> {
    info!("bridge enable: stub — v0.2.0 subscribes to portal action requests");
    Ok(())
}

pub fn allow(action: String) -> Result<()> {
    info!("bridge allow ({action}): stub — v0.2.0 adds the action to the local allowlist");
    Ok(())
}

pub fn disable() -> Result<()> {
    info!("bridge disable: stub — v0.2.0 unsubscribes; guardian operation unaffected");
    Ok(())
}

pub fn status() -> Result<()> {
    info!("bridge status: stub — v0.2.0 prints subscription state + allowlist");
    Ok(())
}
