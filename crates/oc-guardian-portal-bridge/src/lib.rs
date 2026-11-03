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
//!
//! **Not built yet.** The functions below change nothing and say so: the
//! portal cannot send this kit an action request. An operator runs each
//! action with its own `oc-guardian` command instead.

use anyhow::Result;
use tracing::info;

pub fn enable() -> Result<()> {
    info!("bridge enable: not built yet, so nothing changed: the portal cannot send this kit action requests. Run each action with its own oc-guardian command (`oc-guardian --help` lists them).");
    Ok(())
}

pub fn allow(action: String) -> Result<()> {
    info!("bridge allow ({action}): not built yet, so no allowlist was written and the portal can request nothing. Run the action with its own oc-guardian command.");
    Ok(())
}

pub fn disable() -> Result<()> {
    info!("bridge disable: not built yet, so there was nothing to turn off. Guardian operation is unaffected.");
    Ok(())
}

pub fn status() -> Result<()> {
    info!("bridge status: not built yet. The portal cannot send this kit action requests, and no action is allowed.");
    Ok(())
}
