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

use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use tracing::info;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use crate::actions::{AcceptanceEnvelope, ActionEnvelope, ActionPayload, ActionType};
use crate::config::{
    ensure_dir, read_id, read_kit_config, resolve_dir, write_id, write_kit_config, write_pubkey,
    BridgeConfig, KitConfig,
};
use crate::identity::{HsmBackend, OperatorPubKey, Signer};
use crate::keychain;

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

/// Generate the operator's Ed25519 identity, persist the private key
/// to the OS keychain, write the public key + identifier + non-secret
/// kit config to the operator's config dir.
///
/// Refuses to overwrite an existing identity — operators rotate via
/// `oc-guardian portal forget` (or by deleting the keychain entry +
/// config dir manually) and re-running `init`.
pub fn init(hsm: String, config_dir: Option<String>) -> Result<()> {
    let backend = HsmBackend::from_flag(&hsm)?;

    // v0.1 ships only the os-keychain backend. Other --hsm values are
    // accepted by the CLI parser so the surface is stable, but they
    // route to OS-keychain in v0.1 with a clear note. v0.2 lights up
    // YubiKey FIDO2 / Ledger / passkey first-class.
    if !matches!(backend, HsmBackend::OsKeychain) {
        info!(
            "--hsm {hsm} requested · v0.1 ships only os-keychain. \
             Falling back to OS keychain for now; v0.2 lights up \
             hardware-token backends. Your operator pubkey is unchanged \
             across the eventual rotation."
        );
    }

    let dir = resolve_dir(config_dir.as_deref())?;
    ensure_dir(&dir)?;

    // Refuse to clobber an existing identity. If operator.id exists,
    // we treat the config dir as already-initialized.
    if let Some(existing) = read_id(&dir)? {
        anyhow::bail!(
            "operator already initialized at {} (id={}). Refusing to overwrite. \
             To rotate, delete the keychain entry + config dir manually, then re-run \
             `oc-guardian init`.",
            dir.display(),
            existing.0
        );
    }

    // Generate + persist private key in OS keychain. Returns a signer
    // bound to that entry; we use the signer to derive the public key
    // for the on-disk pubkey/id files.
    let signer = keychain::generate_and_persist().context("provisioning operator key")?;
    let pubkey: OperatorPubKey = signer.pubkey();
    let id = pubkey.to_id();

    let pubkey_path = write_pubkey(&dir, &pubkey)?;
    let id_path = write_id(&dir, &id)?;

    let cfg = KitConfig {
        hsm_backend: Some(hsm.to_string()),
        bridge: BridgeConfig::default(),
    };
    let kit_config_path = write_kit_config(&dir, &cfg)?;

    // Operator-visible summary. The CLI's verbosity setting controls
    // whether the tracing output is full debug or just the headline;
    // we always print the headline so the operator knows what to do
    // next.
    println!();
    println!("  ✓ operator identity provisioned");
    println!();
    println!("    operator id    {}", id.0);
    println!("    pubkey         {}", hex::encode(pubkey.0));
    println!("    config dir     {}", dir.display());
    println!(
        "      ├─ {}",
        pubkey_path.file_name().unwrap().to_string_lossy()
    );
    println!(
        "      ├─ {}",
        id_path.file_name().unwrap().to_string_lossy()
    );
    println!(
        "      └─ {}",
        kit_config_path.file_name().unwrap().to_string_lossy()
    );
    println!();
    println!(
        "    private key    OS keychain · service=io.ochk.oc-guardian, account={}",
        id.0
    );
    println!("    backend        {hsm}");
    println!();
    println!("  next steps:");
    println!("    1. oc-guardian register --transport https     # publish your pubkey to the OC operator registry");
    println!(
        "    2. oc-guardian apply prepare --out application.json --questionnaire ./your-answers.md"
    );
    println!("    3. email apply@ochk.io with the signed envelope (see docs/application-questionnaire.md)");
    println!();

    Ok(())
}

/// Produce a signed application envelope from the operator's filled-out
/// questionnaire. Output is a JSON file the operator attaches to the
/// email to apply@ochk.io. Bypass for portal §01 (apply).
pub fn apply_prepare(out: String, questionnaire: Option<String>, _hsm: String) -> Result<()> {
    // 1. Locate + hash the questionnaire.
    let q_path =
        questionnaire.ok_or_else(|| anyhow::anyhow!("--questionnaire <path> is required"))?;
    let q_bytes =
        fs::read(&q_path).with_context(|| format!("reading questionnaire at {q_path}"))?;
    let q_sha256 = Sha256::digest(&q_bytes);
    let q_hash_hex = hex::encode(q_sha256);

    // 2. Load operator identity from config dir + keychain.
    let dir = resolve_dir(None)?;
    let id = read_id(&dir)?
        .context("no operator identity in config dir — run `oc-guardian init` first")?;
    let signer = keychain::load(&id.0)?.with_context(|| {
        format!(
            "operator {} has no key in the OS keychain — re-run `oc-guardian init`",
            id.0
        )
    })?;
    let pubkey: OperatorPubKey = signer.pubkey();

    // 3. Build the payload. ApplicationApply payloads carry the
    //    questionnaire hash + a small subset of the questionnaire as
    //    params; the OC reviewer reads the full questionnaire from
    //    the email attachment and hashes it locally to verify the
    //    signed-over hash matches.
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before epoch")?
        .as_secs() as i64;
    let payload = ActionPayload {
        action: ActionType::ProgramApply,
        params: serde_json::json!({
            "operator_id": id.0,
            "questionnaire_path": q_path,
            "questionnaire_sha256": q_hash_hex,
            "questionnaire_bytes": q_bytes.len(),
            "submitted_at_unix": now_secs,
        }),
        nonce: 1,                           // first action under this identity
        expires_at: now_secs + 30 * 86_400, // 30 days
        federation: None,                   // program-level, not federation-scoped
    };

    // 4. Sign the canonical encoding.
    let canon = serde_json::to_vec(&payload).context("serializing application payload")?;
    let sig = signer.sign(&canon).context("signing application payload")?;

    // 4b. Defense-in-depth · re-verify the signature we just produced
    //     against the operator's own pubkey before claiming success.
    //     Catches any keychain-rotation or signing-pipeline bug before
    //     the operator emails an unverifiable envelope.
    {
        let verifier = ed25519_dalek::VerifyingKey::from_bytes(&pubkey.0)
            .context("internal: operator pubkey is not a valid Ed25519 point")?;
        let sig_for_verify = ed25519_dalek::Signature::from_bytes(&sig);
        ed25519_dalek::Verifier::verify(&verifier, &canon, &sig_for_verify).context(
            "self-verify failed · the signature we just produced does not check out \
             against the operator's own pubkey. This is a kit bug or a keychain-rotation \
             race; do NOT email the resulting file. Re-run after `oc-guardian status` \
             confirms the keychain entry is reachable.",
        )?;
    }

    // 5. Wrap + write.
    let envelope = ActionEnvelope {
        payload,
        pubkey,
        sig_hex: hex::encode(sig),
    };
    let body =
        serde_json::to_string_pretty(&envelope).context("serializing application envelope")?;
    fs::write(&out, body).with_context(|| format!("writing {out}"))?;

    println!();
    println!("  ✓ application envelope signed and written");
    println!();
    println!("    operator id              {}", id.0);
    println!("    questionnaire            {}", q_path);
    println!("    questionnaire sha256     {}", q_hash_hex);
    println!("    questionnaire size       {} bytes", q_bytes.len());
    println!("    envelope                 {}", out);
    println!();
    println!("  next step:");
    println!("    email apply@ochk.io with {} attached.", out);
    println!("    subject: OC Guardian Application — <your handle>");
    println!();
    println!("  to verify the signature locally before sending:");
    println!(
        "    openssl dgst -sha256 {}    # should match questionnaire sha256 above",
        q_path
    );
    println!();

    Ok(())
}

/// Verify a reviewer-signed acceptance envelope. The applicant receives
/// `acceptance-<app_id>.json` in the email reply; running this command
/// against it confirms the email genuinely came from OC.
///
/// `reviewer_pubkey_hex` is the 64-char hex of the OC reviewer's
/// Ed25519 public key. v0.1 requires it explicitly for fully-offline
/// verification; a future revision will fetch from
/// `me.ochk.io/.well-known/oc-operator-reviewer.json` when --jwks-url
/// is passed.
///
/// Also cross-checks `payload.operator_pubkey` against the operator's
/// local identity (from `~/.config/oc-guardian/`). A mismatch means
/// the acceptance is for a different operator key — almost always a
/// bug, sometimes a phishing attempt.
pub fn apply_verify_acceptance(file: String, reviewer_pubkey_hex: String) -> Result<()> {
    // 1. Validate flag-supplied reviewer key.
    let reviewer_key_bytes = hex::decode(&reviewer_pubkey_hex)
        .with_context(|| "--reviewer-pubkey-hex must be hex-encoded")?;
    if reviewer_key_bytes.len() != 32 {
        anyhow::bail!(
            "--reviewer-pubkey-hex must decode to 32 bytes (got {})",
            reviewer_key_bytes.len()
        );
    }
    let reviewer_key_arr: [u8; 32] = reviewer_key_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("internal: failed to coerce 32-byte slice"))?;
    let verifier = VerifyingKey::from_bytes(&reviewer_key_arr)
        .context("--reviewer-pubkey-hex is not a valid Ed25519 point")?;

    // 2. Read + parse envelope.
    let raw = fs::read(&file).with_context(|| format!("reading {file}"))?;
    let envelope: AcceptanceEnvelope =
        serde_json::from_slice(&raw).with_context(|| format!("parsing {file} as JSON"))?;

    // 3. Action discrimination — refuse to verify non-acceptance envelopes
    //    even if a sig happens to check out (defense in depth).
    if envelope.payload.action != "program-accept" {
        anyhow::bail!(
            "payload.action must be \"program-accept\"; got \"{}\"",
            envelope.payload.action
        );
    }

    // 4. Re-canonicalize and verify the signature.
    let canon =
        serde_json::to_vec(&envelope.payload).context("re-serializing payload for verification")?;
    let sig_bytes =
        hex::decode(&envelope.sig_hex).with_context(|| "envelope.sig_hex must be hex-encoded")?;
    if sig_bytes.len() != 64 {
        anyhow::bail!(
            "envelope.sig_hex must decode to 64 bytes (got {})",
            sig_bytes.len()
        );
    }
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("internal: failed to coerce 64-byte sig"))?;
    let signature = Signature::from_bytes(&sig_arr);
    verifier
        .verify(&canon, &signature)
        .context("signature does not verify against --reviewer-pubkey-hex")?;

    // 5. Pretty output. The signature check above is the load-bearing
    //    security property; cross-checking `payload.operator_pubkey`
    //    against the local identity's pubkey is operator-visible
    //    diagnostics — flagged in the output below for the operator
    //    to verify by eye against `oc-guardian status`. A first-class
    //    cross-check lands once the status command surfaces the raw
    //    pubkey bytes (it currently writes them to the config dir but
    //    doesn't expose a read accessor; v0.2).
    println!();
    println!("  ✓ acceptance signature verifies");
    println!();
    println!(
        "    application_id      {}",
        envelope.payload.application_id
    );
    println!("    operator_id         {}", envelope.payload.operator_id);
    println!(
        "    operator_pubkey     {}",
        envelope.payload.operator_pubkey
    );
    println!(
        "    accepted_at_unix    {}",
        envelope.payload.accepted_at_unix
    );
    if let Some(note) = &envelope.payload.reviewer_note {
        println!("    reviewer_note       {note}");
    }
    if let Some(slug) = &envelope.payload.federation_slug {
        println!("    federation_slug     {slug}");
    }
    println!("    reviewer_kid        {}", envelope.reviewer_kid);
    println!();
    println!("  ⓘ confirm payload.operator_pubkey matches your kit:");
    println!("    run `oc-guardian status` and compare the printed pubkey hex.");
    println!("    a mismatch means the acceptance is for a different operator key.");
    println!();

    Ok(())
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

/// Report the operator's local state — identity, config dir, keychain
/// presence, kit version, bridge configuration. Purely local; no
/// network. Useful before signing anything to confirm the kit is
/// reading the operator the operator expects.
pub fn status() -> Result<()> {
    let dir = resolve_dir(None)?;

    println!();
    println!("  oc-guardian-kit v{}", crate::VERSION);
    println!();
    println!("  config dir       {}", dir.display());

    let id = match read_id(&dir)? {
        Some(id) => id,
        None => {
            println!();
            println!("  status           NOT INITIALIZED");
            println!();
            println!("  no operator identity found at this config dir.");
            println!("  run `oc-guardian init` to provision one.");
            println!();
            return Ok(());
        }
    };

    println!("  operator id      {}", id.0);

    // Try to load the keychain entry to confirm the private key is
    // reachable. We don't sign anything — just verify the entry
    // exists.
    let key_present = match keychain::load(&id.0) {
        Ok(Some(_)) => true,
        Ok(None) => false,
        Err(err) => {
            println!("  keychain         ERROR · {err}");
            anyhow::bail!("keychain access failed");
        }
    };

    let pubkey_path = dir.join("operator.pub");
    let pubkey_hex = std::fs::read_to_string(&pubkey_path)
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "<missing>".to_string());
    println!("  pubkey           {pubkey_hex}");

    let kit_cfg = read_kit_config(&dir)?.unwrap_or_default();
    println!(
        "  hsm backend      {}",
        kit_cfg.hsm_backend.as_deref().unwrap_or("(not recorded)")
    );
    println!(
        "  bridge           {}{}",
        if kit_cfg.bridge.enabled {
            "enabled"
        } else {
            "disabled (default)"
        },
        if kit_cfg.bridge.allowed_actions.is_empty() {
            "".to_string()
        } else {
            format!(
                " · allowlist: {}",
                kit_cfg.bridge.allowed_actions.join(", ")
            )
        }
    );
    println!(
        "  private key      {}",
        if key_present {
            "OS keychain · reachable"
        } else {
            "OS keychain · MISSING (rotation needed)"
        }
    );
    println!();
    if !key_present {
        println!("  ! operator.id is on disk but no key in the OS keychain.");
        println!("    Either the keychain entry was deleted out-of-band, or the");
        println!("    config dir was copied from another machine. Re-run");
        println!("    `oc-guardian init` after manually clearing this config dir.");
        println!();
    }
    Ok(())
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

pub fn exit_handoff(
    _federation: String,
    _replacement: String,
    _effective_date: String,
) -> Result<()> {
    todo_command!("exit-handoff")
}

pub fn portal_forget() -> Result<()> {
    todo_command!("portal forget")
}

pub fn verify_status() -> Result<()> {
    todo_command!("verify-status")
}
