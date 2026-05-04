//! Lifecycle command implementations.
//!
//! Each function here corresponds to a CLI subcommand and a row in
//! BYPASS.md. The pattern is consistent: take CLI args, prepare a
//! signed envelope (or other side-effecting operation), present any
//! signing challenges to the operator's hardware, route the result.
//!
//! v0.1.0 ships these as stubs with operator-visible "not yet
//! implemented · v0.2 target" output. Each subsequent point release
//! lights up one more lifecycle stage end-to-end. The architecture
//! (signed envelopes, replay protection, allowlist, hardware-token-
//! backed signing) is what's settled in v0.1.0 — implementation is
//! mechanical from there.

use anyhow::Result;
use tracing::info;

macro_rules! todo_command {
    ($name:expr) => {{
        info!(
            "{}: not yet implemented in v0.1.0 — see BYPASS.md or run \
             `oc-guardian {} --help`. Architecture for this command is \
             described in GUARDIAN-PROGRAM-DESIGN.md (workspace root).",
            $name, $name
        );
        Ok(())
    }};
}

pub fn init(_hsm: String, _config_dir: Option<String>) -> Result<()> {
    todo_command!("init")
}

pub fn apply_prepare(_out: String, _questionnaire: Option<String>, _hsm: String) -> Result<()> {
    todo_command!("apply prepare")
}

pub fn apply_verify_acceptance(_file: String) -> Result<()> {
    todo_command!("apply verify-acceptance")
}

pub fn register(_transport: String) -> Result<()> {
    todo_command!("register")
}

pub fn federations_list() -> Result<()> {
    todo_command!("federations list")
}

pub fn federations_join(_slug: String, _transport: String) -> Result<()> {
    todo_command!("federations join")
}

pub fn federations_leave(_slug: String) -> Result<()> {
    todo_command!("federations leave")
}

pub fn ceremony_start(_peers: String, _setup_code: String) -> Result<()> {
    todo_command!("ceremony start")
}

pub fn ceremony_status() -> Result<()> {
    todo_command!("ceremony status")
}

pub fn ceremony_finalize() -> Result<()> {
    todo_command!("ceremony finalize")
}

pub fn status() -> Result<()> {
    todo_command!("status")
}

pub fn alerts_subscribe(_federation: String) -> Result<()> {
    todo_command!("alerts subscribe")
}

pub fn alerts_post(_federation: String, _severity: String, _body: String) -> Result<()> {
    todo_command!("alerts post")
}

pub fn payouts_list(_federation: String) -> Result<()> {
    todo_command!("payouts list")
}

pub fn payouts_claim(_federation: String, _to: String) -> Result<()> {
    todo_command!("payouts claim")
}

pub fn audit_log(_since: String) -> Result<()> {
    todo_command!("audit log")
}

pub fn audit_export(_out: String) -> Result<()> {
    todo_command!("audit export")
}

pub fn exit_handoff(_federation: String, _replacement: String, _effective_date: String) -> Result<()> {
    todo_command!("exit-handoff")
}

pub fn portal_forget() -> Result<()> {
    todo_command!("portal forget")
}

pub fn verify_status() -> Result<()> {
    todo_command!("verify-status")
}
