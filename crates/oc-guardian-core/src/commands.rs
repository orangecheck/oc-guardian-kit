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

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use crate::actions::{envelope_id, AcceptanceEnvelope, ActionEnvelope, ActionPayload, ActionType};
use crate::config::{
    ensure_dir, read_id, read_kit_config, resolve_dir, write_id, write_kit_config, write_pubkey,
    BridgeConfig, KitConfig,
};
use crate::identity::{HsmBackend, OperatorPubKey, Signer};
use crate::keychain;

/// Generate the operator's Ed25519 identity, persist the private key
/// to the OS keychain, write the public key + identifier + non-secret
/// kit config to the operator's config dir.
///
/// Refuses to overwrite an existing identity — operators rotate via
/// `oc-guardian portal forget` (or by deleting the keychain entry +
/// config dir manually) and re-running `init`.
pub fn init(hsm: String, key_file: Option<String>) -> Result<()> {
    let backend = HsmBackend::from_flag(&hsm)?;

    // Only the OS keychain (or, when asked for, a key file) is built.
    // Other --hsm values are accepted so the surface is stable, and use
    // the OS keychain.
    if !matches!(backend, HsmBackend::OsKeychain) && key_file.is_none() {
        println!("  note: --hsm {hsm} is not built yet · the key goes in the OS keychain instead");
    }

    let dir = resolve_dir()?;
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

    // Generate + persist the private key: the OS keychain, or the key
    // file the operator asked for. The signer gives the public key for the
    // on-disk pubkey/id files.
    let (pubkey, key_location): (OperatorPubKey, String) = match &key_file {
        Some(path) => {
            let signer = keychain::FileSigner::generate(std::path::Path::new(path))
                .context("provisioning operator key file")?;
            (signer.pubkey(), format!("file {path} (mode 0600)"))
        }
        None => {
            let signer = keychain::generate_and_persist().context(
                "provisioning operator key · on a machine without an OS keychain, use --key-file <path>",
            )?;
            let pubkey = signer.pubkey();
            (
                pubkey,
                format!(
                    "OS keychain · service=io.ochk.oc-guardian, account={}",
                    pubkey.to_id().0
                ),
            )
        }
    };
    let id = pubkey.to_id();

    let pubkey_path = write_pubkey(&dir, &pubkey)?;
    let id_path = write_id(&dir, &id)?;

    let cfg = KitConfig {
        hsm_backend: Some(if key_file.is_some() {
            "file".to_string()
        } else {
            hsm.to_string()
        }),
        key_file: key_file.clone(),
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
    println!("    private key    {key_location}");
    println!();
    if key_file.is_some() {
        println!("  warning: the operator key is stored unencrypted in that file. Anyone who can");
        println!("  read it can sign as you. Keep it on this machine only, readable by you only,");
        println!("  and use the OS keychain on any machine that has one.");
        println!();
    }
    println!("  next steps:");
    println!("    1. oc-guardian register --transport https     # publish your pubkey to the OC operator registry");
    println!(
        "    2. oc-guardian apply prepare --out application.json --questionnaire ./your-answers.md"
    );
    println!("    3. email apply@ochk.io with the signed envelope (see docs/application-questionnaire.md)");
    println!();

    Ok(())
}

/// The signed params of an application: who applies, and the questionnaire's hash and size,
/// never where the file sits on this machine.
fn application_params(
    operator_id: &str,
    q_sha256_hex: &str,
    q_bytes: usize,
    now_secs: i64,
) -> serde_json::Value {
    serde_json::json!({
        "operator_id": operator_id,
        "questionnaire_sha256": q_sha256_hex,
        "questionnaire_bytes": q_bytes,
        "submitted_at_unix": now_secs,
    })
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
    let dir = resolve_dir()?;
    let id = read_id(&dir)?
        .context("no operator identity in config dir — run `oc-guardian init` first")?;
    let signer = keychain::load_signer(&id.0)?.with_context(|| {
        format!(
            "operator {} has no key in the OS keychain or a key file — re-run `oc-guardian init`",
            id.0
        )
    })?;
    let pubkey: OperatorPubKey = signer.pubkey();

    // 3. Build the payload. The OC reviewer reads the full questionnaire
    //    from the email attachment and hashes it locally to verify the
    //    signed-over hash matches.
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before epoch")?
        .as_secs() as i64;
    let payload = ActionPayload {
        action: ActionType::ProgramApply,
        params: application_params(&id.0, &q_hash_hex, q_bytes.len(), now_secs),
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

// ── Shared helpers for the signed-envelope + portal commands ─────────

/// Load the operator identity + keychain signer, or a clear error.
fn load_operator() -> Result<(crate::identity::OperatorId, Box<dyn Signer>)> {
    let dir = resolve_dir()?;
    let id = read_id(&dir)?.context("no operator identity — run `oc-guardian init` first")?;
    let signer = keychain::load_signer(&id.0)?.with_context(|| {
        format!(
            "operator {} has no key in the OS keychain or a key file — re-run `oc-guardian init`",
            id.0
        )
    })?;
    Ok((id, signer))
}

/// Build + sign an `ActionEnvelope`. The nonce is unix-seconds (monotonic
/// per run); the portal rejects equal-or-lower nonces it has seen.
fn build_signed_envelope(
    signer: &dyn Signer,
    action: ActionType,
    params: serde_json::Value,
    federation: Option<String>,
) -> Result<ActionEnvelope> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before epoch")?
        .as_secs();
    sign_envelope_at(signer, action, params, federation, now, 30 * 86_400)
}

/// Sign an `ActionEnvelope` dated `now_secs` that expires `valid_secs` later.
fn sign_envelope_at(
    signer: &dyn Signer,
    action: ActionType,
    params: serde_json::Value,
    federation: Option<String>,
    now_secs: u64,
    valid_secs: u64,
) -> Result<ActionEnvelope> {
    let payload = ActionPayload {
        action,
        params,
        nonce: now_secs,
        expires_at: (now_secs + valid_secs) as i64,
        federation,
    };
    let canon = serde_json::to_vec(&payload).context("serializing action payload")?;
    let sig = signer.sign(&canon).context("signing action payload")?;
    Ok(ActionEnvelope {
        payload,
        pubkey: signer.pubkey(),
        sig_hex: hex::encode(sig),
    })
}

/// Write a signed envelope to disk + print portal-submission guidance.
/// The operator endpoints are session-gated (the kit is not signed-in), so
/// the kit's job is to PRODUCE the hardware-signed envelope; the operator
/// submits it via the signed-in ochk.app surface — same pattern as
/// `charter sign`. `notes` print after the upload line.
fn write_envelope(
    env: &ActionEnvelope,
    out: &str,
    what: &str,
    page: &str,
    notes: &[String],
) -> Result<()> {
    let json = serde_json::to_vec_pretty(env).context("encoding envelope")?;
    fs::write(out, &json).with_context(|| format!("writing {out}"))?;
    println!();
    println!("  ✓ signed {what} envelope written to {out}");
    println!("    it carries your operator key's signature · OC cannot forge it.");
    println!("    upload it at {page}, signed in to your ochk.app account.");
    for note in notes {
        println!("    {note}");
    }
    println!();
    Ok(())
}

/// `oc-guardian register` · the operator registry is public; check whether
/// this operator's pubkey is published in it (i.e. accepted into the
/// program), and report. Registration itself happens via the apply →
/// accept flow, not a self-publish.
pub fn register(_transport: String) -> Result<()> {
    use crate::portal_client::{OperatorRegistryResponse, PortalClient};
    let (id, signer) = load_operator()?;
    let my_pubkey = hex::encode(signer.pubkey().0);
    let client = PortalClient::from_env(None);
    let resp: OperatorRegistryResponse = client
        .get_json("/api/operator/registry")
        .context("fetching the operator registry")?;
    let listed = resp
        .operators
        .iter()
        .any(|o| o.pubkey.eq_ignore_ascii_case(&my_pubkey));
    println!();
    println!("  operator {}", id.0);
    println!("    pubkey    {my_pubkey}");
    println!("    registry  {} accepted operators", resp.count);
    if listed {
        println!("    status    ✓ your pubkey is in the OC operator registry (accepted)");
    } else {
        println!("    status    ✗ not yet in the registry");
        println!("    → run `oc-guardian apply prepare` + email apply@ochk.io; once accepted,");
        println!("      your pubkey is published here for federations to include in a charter.");
    }
    println!();
    Ok(())
}

pub fn federations_list() -> Result<()> {
    use crate::portal_client::{FederationsListResponse, PortalClient};
    let client = PortalClient::from_env(None);
    let resp: FederationsListResponse = client
        .get_json("/api/federations")
        .context("fetching the federation directory from the portal")?;
    if resp.federations.is_empty() {
        println!("no federations in the directory yet.");
        return Ok(());
    }
    println!("federations ({}):", resp.federations.len());
    println!();
    for f in &resp.federations {
        println!(
            "  {:<18} {:<10} thr {:<7} target {}{}",
            f.slug,
            f.status,
            f.threshold,
            f.target_guardian_count,
            if f.bootstrap_mode {
                " · bootstrap"
            } else {
                ""
            }
        );
        println!("    {}", f.name);
    }
    println!();
    println!("  join one with:  oc-guardian federations join <slug>");
    Ok(())
}

/// `oc-guardian federations join` · joining a federation isn't a single
/// envelope — it's a seat assignment (admin) + a charter ratification.
/// Point the operator at the real path rather than POST to a non-endpoint.
pub fn federations_join(slug: String, _transport: String) -> Result<()> {
    println!();
    println!("  joining federation {slug}:");
    println!("    1. an OC admin assigns you a guardian seat (after your application is accepted)");
    println!("    2. ratify the charter — that IS your join:");
    println!("         oc-guardian charter sign {slug}");
    println!("         oc-guardian charter publish --file charter-sig.json");
    println!("    3. run DKG with your peers:  oc-guardian ceremony start --name <name> …");
    println!();
    Ok(())
}

/// `oc-guardian federations leave` · a clean exit from a threshold
/// federation is an exit-handoff to a successor, not a unilateral leave.
pub fn federations_leave(slug: String) -> Result<()> {
    println!();
    println!("  leaving federation {slug} is an exit-handoff to a replacement guardian:");
    println!(
        "    oc-guardian exit-handoff --federation {slug} --replacement <pubkey> --effective-date <YYYY-MM-DD>"
    );
    println!("  (a threshold federation needs a successor before you step down.)");
    println!();
    Ok(())
}

// The DKG ceremony now lives in oc-guardian-fedimint::ceremony (it needs
// the fedimintd runtime + setup-UI phase detection). The CLI dispatches
// `ceremony *` straight there.

/// Report the operator's local state — identity, config dir, keychain
/// presence, kit version, bridge configuration. Purely local; no
/// network. Useful before signing anything to confirm the kit is
/// reading the operator the operator expects.
pub fn status() -> Result<()> {
    let dir = resolve_dir()?;

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
    let key_present = match keychain::load_signer(&id.0) {
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
    let store = match &kit_cfg.key_file {
        Some(path) => format!("key file {path}"),
        None => "OS keychain".to_string(),
    };
    println!(
        "  private key      {store} · {}",
        if key_present {
            "reachable"
        } else {
            "MISSING (rotation needed)"
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

/// Format unix seconds as ISO-8601 UTC (`YYYY-MM-DDTHH:MM:SSZ`) via the
/// civil-from-days algorithm — no chrono dep. Used for incident
/// `occurred_at`, which the portal validates with `Date.parse`.
fn iso8601_utc(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // days since 1970-01-01 → civil (y, m, d) · Howard Hinnant's algorithm.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let mut y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    if m <= 2 {
        y += 1;
    }
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// `oc-guardian alerts subscribe` · there is no alert feed yet; point the
/// operator at the published incidents rather than fake a subscription.
pub fn alerts_subscribe(federation: String) -> Result<()> {
    println!();
    println!("  the kit has no alert feed for {federation} yet (the portal bridge is not built).");
    println!("  published incidents are visible at ochk.app/me/operator/incidents");
    println!("  and the public /federations timeline.");
    println!();
    Ok(())
}

/// `oc-guardian alerts post` · produce a hardware-signed incident envelope
/// (severity/title/body) for publication to the federation's channel.
pub fn alerts_post(federation: String, severity: String, body: String) -> Result<()> {
    let (id, signer) = load_operator()?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before epoch")?
        .as_secs();
    let title: String = body.chars().take(120).collect();
    let params = serde_json::json!({
        "operator_id": id.0,
        "federation_slug": federation,
        "occurred_at": iso8601_utc(now),
        "severity": severity,
        "title": title,
        "body": body,
        "tags": [],
    });
    let env = build_signed_envelope(
        signer.as_ref(),
        ActionType::AlertPublish,
        params,
        Some(federation),
    )?;
    write_envelope(
        &env,
        "incident.json",
        "incident",
        "ochk.app/me/operator/incidents",
        &[],
    )
}

/// `oc-guardian payouts list` · accrued-payout figures are session-gated
/// at the portal; the kit produces the signed CLAIM envelope locally.
pub fn payouts_list(federation: String) -> Result<()> {
    let (id, _signer) = load_operator()?;
    println!();
    println!("  payouts · operator {} · federation {federation}", id.0);
    println!("    accrued figures are session-gated — view them signed-in at");
    println!("    ochk.app/me/operator/payouts. To withdraw, produce a signed claim:");
    println!(
        "      oc-guardian payouts claim {federation} --to <you@wallet.example> [--amount <sats>]"
    );
    println!();
    Ok(())
}

/// `oc-guardian payouts claim` · produce a hardware-signed `payouts-claim`
/// envelope directing accrued payouts to a Lightning address.
pub fn payouts_claim(federation: String, to: String, amount: Option<u64>) -> Result<()> {
    let (id, signer) = load_operator()?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before epoch")?
        .as_secs();
    let params = payouts_claim_params(&id.0, &federation, &to, amount, now)?;
    let env = build_signed_envelope(
        signer.as_ref(),
        ActionType::PayoutsClaim,
        params,
        Some(federation),
    )?;
    write_envelope(
        &env,
        "payouts-claim.json",
        "payouts-claim",
        "ochk.app/me/operator/payouts",
        &[],
    )
}

/// The claim's signed params. The portal requires `signed_at`, and refused
/// every claim the kit made without it. A payout is paid over Lightning, so
/// the destination is a Lightning address; an on-chain address could never
/// be paid.
fn payouts_claim_params(
    operator_id: &str,
    federation: &str,
    to: &str,
    amount: Option<u64>,
    now_secs: u64,
) -> Result<serde_json::Value> {
    let to = to.trim();
    let looks_like_ln_address = to
        .split_once('@')
        .is_some_and(|(user, domain)| !user.is_empty() && domain.contains('.'));
    if !looks_like_ln_address {
        anyhow::bail!("--to must be a Lightning address (you@wallet.example); payouts are paid over Lightning");
    }
    if amount == Some(0) {
        anyhow::bail!("--amount must be above zero, or omitted to claim the whole balance");
    }
    let mut params = serde_json::json!({
        "operator_id": operator_id,
        "destination": to,
        "federation_slug": federation,
        "signed_at": iso8601_utc(now_secs),
    });
    if let Some(sats) = amount {
        params["amount_sats"] = serde_json::json!(sats);
    }
    Ok(params)
}

/// Local signed-envelope filenames the kit recognizes as its action trail.
fn local_envelope_files() -> Result<Vec<std::path::PathBuf>> {
    let dir = std::env::current_dir().context("resolving cwd")?;
    let mut out = Vec::new();
    if let Ok(rd) = fs::read_dir(&dir) {
        for entry in rd.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let is_envelope = name.ends_with(".json")
                && [
                    "charter",
                    "payouts",
                    "exit",
                    "incident",
                    "application",
                    "ceremony",
                    "handover",
                ]
                .iter()
                .any(|k| name.contains(k));
            if is_envelope {
                out.push(entry.path());
            }
        }
    }
    out.sort();
    Ok(out)
}

/// `oc-guardian audit log` · the kit's local action trail is the set of
/// signed envelopes it has produced; the authoritative cross-operator log
/// is the portal's session-gated /me/admin/audit. (`--since` reserved for
/// when the kit keeps a timestamped local log.)
pub fn audit_log(_since: String) -> Result<()> {
    let files = local_envelope_files()?;
    println!();
    println!("  local signed-envelope trail:");
    if files.is_empty() {
        println!("    (none in cwd — produce one with `charter sign`, `payouts claim`, …)");
    } else {
        for f in &files {
            println!(
                "    {}",
                f.file_name().unwrap_or_default().to_string_lossy()
            );
        }
    }
    println!("  authoritative audit log · ochk.app/me/admin/audit (signed-in).");
    println!();
    Ok(())
}

/// `oc-guardian audit export` · bundle the local signed envelopes into one
/// JSON array for archival / handoff.
pub fn audit_export(out: String) -> Result<()> {
    let files = local_envelope_files()?;
    let mut bundle = Vec::new();
    for f in &files {
        let bytes = fs::read(f).with_context(|| format!("reading {}", f.display()))?;
        let value: serde_json::Value =
            serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", f.display()))?;
        bundle.push(serde_json::json!({
            "file": f.file_name().unwrap_or_default().to_string_lossy(),
            "envelope": value,
        }));
    }
    fs::write(
        &out,
        serde_json::to_vec_pretty(&bundle).context("encoding bundle")?,
    )
    .with_context(|| format!("writing {out}"))?;
    println!();
    println!("  ✓ exported {} signed envelope(s) → {out}", bundle.len());
    println!();
    Ok(())
}

/// `oc-guardian exit-handoff` · produce a hardware-signed `exit-handoff`
/// envelope announcing the operator's intent to hand their seat to a
/// replacement guardian, effective a given date.
/// Derive a successor's operator_id from their Ed25519 pubkey hex, using the
/// kit-canonical `OperatorPubKey::to_id`. Returns None if the replacement
/// string isn't a valid 32-byte hex pubkey (then it stays in the reason text).
fn successor_operator_id_from(pubkey_hex: &str) -> Option<String> {
    let bytes = hex::decode(pubkey_hex.trim()).ok()?;
    let arr: [u8; 32] = bytes.try_into().ok()?;
    Some(OperatorPubKey(arr).to_id().0)
}

pub fn exit_handoff(federation: String, replacement: String, effective_date: String) -> Result<()> {
    let (id, signer) = load_operator()?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before epoch")?
        .as_secs();
    // Portal-canonical exit-handoff params (matches oc-me-web
    // validateExitHandoffEnvelope): operator_id, federation_slug, signed_at
    // (REQUIRED — the portal 422s without it), reason, and an optional
    // successor_operator_id. The human-readable effective date stays in reason.
    let mut params = serde_json::json!({
        "operator_id": id.0,
        "federation_slug": federation,
        "signed_at": iso8601_utc(now),
        "reason": format!("exit-handoff to {replacement}, effective {effective_date}"),
    });
    // If the replacement is a valid pubkey, include the structured successor
    // (kit ↔ portal operator_id derivations are pinned identical).
    if let Some(succ) = successor_operator_id_from(&replacement) {
        params["successor_operator_id"] = serde_json::Value::String(succ);
    }
    let env = build_signed_envelope(
        signer.as_ref(),
        ActionType::ExitHandoff,
        params,
        Some(federation.clone()),
    )?;
    write_envelope(
        &env,
        "exit-handoff.json",
        "exit-handoff",
        &format!("ochk.app/me/operator/federations/{federation}"),
        &[],
    )
}

/// `oc-guardian exit-ratify` · countersign another guardian's exit. The exit
/// is ratified once the guardians staying reach the charter threshold. The
/// envelope names a recent block (height and hash from any explorer), so it
/// cannot have been signed long before it is posted.
pub fn exit_ratify(
    federation: String,
    exit_id: String,
    block_height: u64,
    block_hash: String,
    note: Option<String>,
) -> Result<()> {
    let (id, signer) = load_operator()?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before epoch")?
        .as_secs();
    let params = exit_ratify_params(
        &id.0,
        &federation,
        &exit_id,
        block_height,
        &block_hash,
        note,
        now,
    )?;
    let env = build_signed_envelope(
        signer.as_ref(),
        ActionType::ExitRatify,
        params,
        Some(federation.clone()),
    )?;
    write_envelope(
        &env,
        "exit-ratify.json",
        "exit-ratify",
        &format!("ochk.app/me/operator/federations/{federation}"),
        &[],
    )
}

/// The longest a delegation may run, as the portal caps it.
pub const ATTEST_DELEGATION_MAX_DAYS: u64 = 366;

/// A seat operator's permission for another key to sign the seat's liveness
/// attestations: how a guardian on hosted hardware, which never holds the
/// operator key, attests at all. The portal's `AttestDelegation`, field for
/// field.
#[derive(Debug, serde::Serialize)]
pub struct AttestDelegation {
    pub federation_slug: String,
    pub seat_index: u32,
    pub operator_pubkey: String,
    pub attest_pubkey: String,
    pub not_after: u64,
    pub block_height: u64,
    pub block_hash: String,
    pub sig: String,
}

/// The bytes a delegation signs. oc-me-web `canonicalDelegationBytes`, line
/// for line; the cross-language test below pins it.
fn attest_delegation_bytes(
    federation_slug: &str,
    seat_index: u32,
    operator_pubkey: &str,
    attest_pubkey: &str,
    not_after: u64,
    block_height: u64,
    block_hash: &str,
) -> Vec<u8> {
    [
        "oc-me/attest-delegation/v1".to_string(),
        format!(
            "federation_slug: {}:{}",
            federation_slug.len(),
            federation_slug
        ),
        format!("seat_index: {seat_index}"),
        format!("operator_pubkey: {operator_pubkey}"),
        format!("attest_pubkey: {attest_pubkey}"),
        format!("not_after: {not_after}"),
        format!("block_height: {block_height}"),
        format!("block_hash: {block_hash}"),
    ]
    .join("\n")
    .into_bytes()
}

fn hex64(value: &str, flag: &str) -> Result<String> {
    let v = value.trim().to_lowercase();
    if v.len() != 64 || !v.bytes().all(|b| b.is_ascii_hexdigit()) {
        anyhow::bail!("{flag} must be 64 hex characters");
    }
    Ok(v)
}

/// Sign a delegation with the seat operator's key. Pure apart from the
/// signer, so the test can pin it against the portal's own signer.
#[allow(clippy::too_many_arguments)]
fn sign_attest_delegation(
    signer: &dyn Signer,
    federation_slug: &str,
    seat_index: u32,
    attest_pubkey: &str,
    days: u64,
    block_height: u64,
    block_hash: &str,
    now_secs: u64,
) -> Result<AttestDelegation> {
    if !federation_slug.is_ascii() || federation_slug.is_empty() {
        anyhow::bail!("--federation must be a federation slug");
    }
    if days == 0 || days > ATTEST_DELEGATION_MAX_DAYS {
        anyhow::bail!("--days must be between 1 and {ATTEST_DELEGATION_MAX_DAYS}");
    }
    let attest_pubkey = hex64(attest_pubkey, "--attest-pubkey")?;
    let block_hash = hex64(block_hash, "--block-hash")?;
    let operator_pubkey = hex::encode(signer.pubkey().0);
    let not_after = now_secs + days * 86_400;
    let bytes = attest_delegation_bytes(
        federation_slug,
        seat_index,
        &operator_pubkey,
        &attest_pubkey,
        not_after,
        block_height,
        &block_hash,
    );
    let sig = signer.sign(&bytes).context("signing the delegation")?;
    Ok(AttestDelegation {
        federation_slug: federation_slug.to_string(),
        seat_index,
        operator_pubkey,
        attest_pubkey,
        not_after,
        block_height,
        block_hash,
        sig: hex::encode(sig),
    })
}

/// `oc-guardian attest-delegate` · let a hosted guardian's own key sign this
/// seat's liveness attestations, until `--days` from now. The key signs
/// liveness and nothing else; the charter, payouts, exits and votes still
/// take the operator key. Its pubkey is on the seat's hosted status at
/// ochk.app. Names a recent block, which the portal checks.
#[allow(clippy::too_many_arguments)]
pub fn attest_delegate(
    federation: String,
    seat_index: u32,
    attest_pubkey: String,
    days: u64,
    block_height: u64,
    block_hash: String,
    out: String,
) -> Result<()> {
    let (_id, signer) = load_operator()?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before epoch")?
        .as_secs();
    let delegation = sign_attest_delegation(
        signer.as_ref(),
        &federation,
        seat_index,
        &attest_pubkey,
        days,
        block_height,
        &block_hash,
        now,
    )?;
    let json = serde_json::to_vec_pretty(&serde_json::json!({ "delegation": delegation }))
        .context("encoding delegation")?;
    fs::write(&out, &json).with_context(|| format!("writing {out}"))?;
    println!();
    println!("  ✓ signed attest delegation written to {out}");
    println!(
        "    seat {seat_index} of {federation} · key {} · until {}",
        delegation.attest_pubkey,
        iso8601_utc(delegation.not_after)
    );
    println!("    upload it at ochk.app/me/operator/federations/{federation}, signed in to the");
    println!("    account your key is bound to (oc-guardian bind). Revoke it from the seat's");
    println!("    hosted status there.");
    println!();
    Ok(())
}

/// A bind claim: proof that whoever binds this operator key to an ochk.app
/// account holds it. The account and a recent block are inside the signed
/// bytes, so it cannot be replayed to another account or kept for later.
#[derive(Debug, serde::Serialize)]
struct BindClaim {
    did_oc: String,
    operator_pubkey: String,
    block_height: u64,
    block_hash: String,
    sig: String,
}

/// The bytes a bind claim signs. oc-me-web `canonicalBindClaimBytes`, line
/// for line; the cross-language test below pins it.
fn bind_claim_bytes(
    did_oc: &str,
    operator_pubkey: &str,
    block_height: u64,
    block_hash: &str,
) -> Vec<u8> {
    [
        "oc-me/operator-bind/v1".to_string(),
        format!("did_oc: {}:{}", did_oc.len(), did_oc),
        format!("operator_pubkey: {operator_pubkey}"),
        format!("block_height: {block_height}"),
        format!("block_hash: {block_hash}"),
    ]
    .join("\n")
    .into_bytes()
}

fn sign_bind_claim(
    signer: &dyn Signer,
    did_oc: &str,
    block_height: u64,
    block_hash: &str,
) -> Result<BindClaim> {
    let well_formed = did_oc.strip_prefix("did:oc:").is_some_and(|id| {
        !id.is_empty()
            && id.len() <= 64
            && id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    });
    if !well_formed {
        anyhow::bail!(
            "--did must be your ochk.app account's id (did:oc:…), as ochk.app/me/operator shows it"
        );
    }
    let block_hash = hex64(block_hash, "--block-hash")?;
    let operator_pubkey = hex::encode(signer.pubkey().0);
    let bytes = bind_claim_bytes(did_oc, &operator_pubkey, block_height, &block_hash);
    let sig = signer.sign(&bytes).context("signing the bind claim")?;
    Ok(BindClaim {
        did_oc: did_oc.to_string(),
        operator_pubkey,
        block_height,
        block_hash,
        sig: hex::encode(sig),
    })
}

/// `oc-guardian bind` · bind this operator key to an ochk.app account, for a
/// key that never enters a browser. Writes the body ochk.app/me/operator
/// uploads; payouts, exits and attest delegations then accept what this key
/// signs from that account.
pub fn bind(did_oc: String, block_height: u64, block_hash: String, out: String) -> Result<()> {
    let (id, signer) = load_operator()?;
    let claim = sign_bind_claim(signer.as_ref(), &did_oc, block_height, &block_hash)?;
    let body = serde_json::json!({
        "pubkey": claim.operator_pubkey,
        "operator_id": id.0,
        "bind_claim": claim,
    });
    let json = serde_json::to_vec_pretty(&body).context("encoding the bind claim")?;
    fs::write(&out, &json).with_context(|| format!("writing {out}"))?;
    println!();
    println!("  ✓ signed bind claim written to {out}");
    println!("    binds operator {} to {did_oc}", id.0);
    println!("    upload it at ochk.app/me/operator, signed in to that account,");
    println!("    within 6 blocks (about an hour) of block {block_height}.");
    println!();
    Ok(())
}

/// How long a handover offer stands unless `--valid-days` says otherwise.
pub const HANDOVER_OFFER_DEFAULT_DAYS: u64 = 7;
/// The longest `--valid-days` takes; the portal refuses expiries past 31 days.
pub const HANDOVER_OFFER_MAX_DAYS: u64 = 30;
/// An acceptance is uploaded right after it is signed.
const HANDOVER_ACCEPT_DAYS: u64 = 1;

fn handover_slug(federation: &str) -> Result<&str> {
    let slug = federation.trim();
    if slug.is_empty() || !slug.is_ascii() {
        anyhow::bail!("--federation must be a federation slug");
    }
    Ok(slug)
}

/// The creator's offer of `federation` to the operator key `to`. The portal's
/// `validateHandoverEnvelope`, field for field.
fn handover_offer_envelope(
    signer: &dyn Signer,
    federation: &str,
    to: &str,
    valid_days: u64,
    now_secs: u64,
) -> Result<ActionEnvelope> {
    let slug = handover_slug(federation)?;
    let me = signer.pubkey().to_id().0;
    let to = to.trim();
    if !to.starts_with("op-") || to.len() == 3 {
        anyhow::bail!("--to must be the operator id (op-…) of the key taking the federation on");
    }
    if to == me {
        anyhow::bail!("--to is your own operator id; name the operator taking the federation on");
    }
    if !(1..=HANDOVER_OFFER_MAX_DAYS).contains(&valid_days) {
        anyhow::bail!("--valid-days must be between 1 and {HANDOVER_OFFER_MAX_DAYS}");
    }
    let params = serde_json::json!({
        "operator_id": me,
        "federation_slug": slug,
        "to_operator_id": to,
        "offered_at": iso8601_utc(now_secs),
    });
    sign_envelope_at(
        signer,
        ActionType::CreatorHandoverOffer,
        params,
        Some(slug.to_string()),
        now_secs,
        valid_days * 86_400,
    )
}

/// The named operator's acceptance of the offer whose id is `offer_id`.
fn handover_accept_envelope(
    signer: &dyn Signer,
    federation: &str,
    offer_id: &str,
    now_secs: u64,
) -> Result<ActionEnvelope> {
    let slug = handover_slug(federation)?;
    let offer_id = hex64(offer_id, "--offer")?;
    let params = serde_json::json!({
        "operator_id": signer.pubkey().to_id().0,
        "federation_slug": slug,
        "offer_id": offer_id,
        "accepted_at": iso8601_utc(now_secs),
    });
    sign_envelope_at(
        signer,
        ActionType::CreatorHandoverAccept,
        params,
        Some(slug.to_string()),
        now_secs,
        HANDOVER_ACCEPT_DAYS * 86_400,
    )
}

/// `oc-guardian federation handover offer` · the creator offers their
/// federation to another operator key, which accepts it from its own account.
/// Prints the offer's id, which the acceptance signs.
pub fn federation_handover_offer(
    federation: String,
    to: String,
    valid_days: u64,
    out: String,
) -> Result<()> {
    let (_id, signer) = load_operator()?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before epoch")?
        .as_secs();
    let env = handover_offer_envelope(signer.as_ref(), &federation, &to, valid_days, now)?;
    let offer_id = envelope_id(&env).context("computing the offer id")?;
    let slug = federation.trim();
    write_envelope(
        &env,
        &out,
        "creator-handover-offer",
        &format!("https://ochk.app/me/operator/federations/{slug}#handover"),
        &[format!("offer id: {offer_id}")],
    )
}

/// `oc-guardian federation handover accept` · the operator an offer names
/// takes the federation on. The offer's id is on ochk.app/me/operator/handovers.
pub fn federation_handover_accept(federation: String, offer: String, out: String) -> Result<()> {
    let (_id, signer) = load_operator()?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before epoch")?
        .as_secs();
    let env = handover_accept_envelope(signer.as_ref(), &federation, &offer, now)?;
    write_envelope(
        &env,
        &out,
        "creator-handover-accept",
        "https://ochk.app/me/operator/handovers",
        &[],
    )
}

fn exit_ratify_params(
    operator_id: &str,
    federation: &str,
    exit_id: &str,
    block_height: u64,
    block_hash: &str,
    note: Option<String>,
    now_secs: u64,
) -> Result<serde_json::Value> {
    let block_hash = block_hash.trim().to_lowercase();
    if block_hash.len() != 64 || !block_hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        anyhow::bail!("--block-hash must be a 64-hex block hash");
    }
    let mut params = serde_json::json!({
        "exit_id": exit_id,
        "federation_slug": federation,
        "ratifier_operator_id": operator_id,
        "signed_at": iso8601_utc(now_secs),
        "block_height": block_height,
        "block_hash": block_hash,
    });
    if let Some(note) = note {
        params["note"] = serde_json::Value::String(note);
    }
    Ok(params)
}

/// `oc-guardian portal forget` · wipe local operator state — the keychain
/// key + the config dir. Irreversible; re-init to start fresh.
pub fn portal_forget() -> Result<()> {
    let dir = resolve_dir()?;
    let id = read_id(&dir)?;
    if let Some(id) = &id {
        let _ = keychain::delete(&id.0); // best-effort; dir removal is the source of truth
    }
    if dir.exists() {
        fs::remove_dir_all(&dir).with_context(|| format!("removing {}", dir.display()))?;
    }
    println!();
    println!("  ✓ forgot local operator state");
    println!("    removed config dir {}", dir.display());
    if id.is_some() {
        println!("    removed keychain key");
    }
    println!("  re-run `oc-guardian init` to start fresh.");
    println!();
    Ok(())
}

/// `oc-guardian verify-status` · confirm local setup + whether this
/// operator's pubkey is accepted (published in the public registry).
pub fn verify_status() -> Result<()> {
    use crate::portal_client::{OperatorRegistryResponse, PortalClient};
    let (id, signer) = load_operator()?;
    let my_pubkey = hex::encode(signer.pubkey().0);
    let client = PortalClient::from_env(None);
    let resp: OperatorRegistryResponse = client
        .get_json("/api/operator/registry")
        .context("fetching the operator registry")?;
    let accepted = resp
        .operators
        .iter()
        .any(|o| o.pubkey.eq_ignore_ascii_case(&my_pubkey));
    println!();
    println!("  verify · operator {}", id.0);
    println!("    local key       ✓ present in keychain");
    println!("    pubkey          {my_pubkey}");
    println!(
        "    program status  {}",
        if accepted {
            "✓ ACCEPTED (in OC registry)"
        } else {
            "✗ not yet accepted — apply via `oc-guardian apply prepare`"
        }
    );
    println!();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_application_signs_the_questionnaire_hash_and_size_and_no_local_path() {
        let p = application_params("op-1", &"ab".repeat(32), 1234, 0);
        let keys: Vec<&str> = p.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            [
                "operator_id",
                "questionnaire_bytes",
                "questionnaire_sha256",
                "submitted_at_unix"
            ]
        );
        assert_eq!(p["questionnaire_bytes"], 1234);
    }

    #[test]
    fn payouts_claim_carries_signed_at_and_a_lightning_destination() {
        let p = payouts_claim_params("op-1", "oc-mutiny-v1", "op@wallet.example", Some(2100), 0)
            .unwrap();
        assert_eq!(p["signed_at"], "1970-01-01T00:00:00Z");
        assert_eq!(p["destination"], "op@wallet.example");
        assert_eq!(p["amount_sats"], 2100);
        let whole = payouts_claim_params("op-1", "f", "op@wallet.example", None, 0).unwrap();
        assert!(whole.get("amount_sats").is_none());
        assert!(payouts_claim_params("op-1", "f", "bc1qexample", None, 0).is_err());
        assert!(payouts_claim_params("op-1", "f", "op@wallet.example", Some(0), 0).is_err());
    }

    /// Produced by oc-me-web's `signAttestDelegation` with the same key and
    /// fields; the portal verified it. A drift in either side's bytes breaks it.
    #[test]
    fn attest_delegation_matches_the_portals_signer() {
        let signer = keychain::StaticSigner::from_hex(&"07".repeat(32)).unwrap();
        let machine = keychain::StaticSigner::from_hex(&"08".repeat(32)).unwrap();
        let attest = hex::encode(machine.pubkey().0);
        let now = 1_800_000_000 - 30 * 86_400;
        let d = sign_attest_delegation(
            &signer,
            "oc-mutiny-v1",
            2,
            &attest.to_uppercase(),
            30,
            900_000,
            &"AB".repeat(32),
            now,
        )
        .unwrap();
        assert_eq!(
            d.operator_pubkey,
            "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c"
        );
        assert_eq!(
            d.attest_pubkey,
            "1398f62c6d1a457c51ba6a4b5f3dbd2f69fca93216218dc8997e416bd17d93ca"
        );
        assert_eq!(d.not_after, 1_800_000_000);
        assert_eq!(d.block_hash, "ab".repeat(32));
        assert_eq!(
            d.sig,
            "126436c597704b1a4daed8576d18d02869311e4397d21cc425a871bed46c906d\
             8db2845b46916aa9dba44cf5676f2d3dd1d2055c42a937568d60d6bb63fd7208"
        );
    }

    #[test]
    fn attest_delegation_refuses_what_the_portal_would() {
        let signer = keychain::StaticSigner::from_hex(&"07".repeat(32)).unwrap();
        let key = "11".repeat(32);
        let hash = "ab".repeat(32);
        assert!(sign_attest_delegation(&signer, "f", 0, &key, 367, 1, &hash, 0).is_err());
        assert!(sign_attest_delegation(&signer, "f", 0, &key, 0, 1, &hash, 0).is_err());
        assert!(sign_attest_delegation(&signer, "f", 0, "zz", 30, 1, &hash, 0).is_err());
        assert!(sign_attest_delegation(&signer, "f", 0, &key, 30, 1, "zz", 0).is_err());
        assert!(sign_attest_delegation(&signer, "", 0, &key, 30, 1, &hash, 0).is_err());
        assert!(sign_attest_delegation(&signer, "f", 0, &key, 366, 1, &hash, 0).is_ok());
    }

    /// Signed with the same key and fields as oc-me-web's
    /// `canonicalBindClaimBytes`; its `verifyBindClaim` accepted that claim.
    /// A drift in either side's bytes breaks it.
    #[test]
    fn bind_claim_matches_the_portals_verifier() {
        let signer = keychain::StaticSigner::from_hex(&"07".repeat(32)).unwrap();
        let did = format!("did:oc:{}", "ab".repeat(16));
        let c = sign_bind_claim(&signer, &did, 900_000, &"AB".repeat(32)).unwrap();
        assert_eq!(
            c.operator_pubkey,
            "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c"
        );
        assert_eq!(c.block_hash, "ab".repeat(32));
        assert_eq!(
            c.sig,
            "ef8f4c6e08f690efee3d1e3bbc0e016b3633680c0ec6be67138778ec4d85ffbe\
             30bf9d45a0ee00b1a5a62412318e6973da602982da76032469b261a936fe6909"
        );
    }

    #[test]
    fn bind_claim_refuses_what_the_portal_would() {
        let signer = keychain::StaticSigner::from_hex(&"07".repeat(32)).unwrap();
        let hash = "ab".repeat(32);
        for did in [
            "",
            "did:oc:",
            "oc:abc",
            "did:oc:ABC",
            "did:oc:ab\ncd",
            "did:key:abc",
        ] {
            assert!(sign_bind_claim(&signer, did, 1, &hash).is_err(), "{did:?}");
        }
        assert!(sign_bind_claim(&signer, "did:oc:ab12", 1, "zz").is_err());
        assert!(sign_bind_claim(&signer, "did:oc:ab12", 1, &hash).is_ok());
    }

    /// Write the envelope as the command does, read the file back, and check
    /// its signature over the payload's bytes under the file's own pubkey.
    fn written_and_verified(env: &ActionEnvelope, name: &str) -> ActionEnvelope {
        let path = std::env::temp_dir().join(format!("{name}-{}.json", std::process::id()));
        let out = path.to_str().unwrap();
        write_envelope(env, out, name, "https://ochk.app/me/operator", &[]).unwrap();
        let read: ActionEnvelope = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        fs::remove_file(&path).unwrap();
        let sig: [u8; 64] = hex::decode(&read.sig_hex).unwrap().try_into().unwrap();
        let bytes = serde_json::to_vec(&read.payload).unwrap();
        assert!(keychain::verify(&read.pubkey, &bytes, &sig), "{name}");
        read
    }

    #[test]
    fn handover_offer_is_what_the_portal_checks() {
        let creator = keychain::StaticSigner::from_hex(&"07".repeat(32)).unwrap();
        let to = keychain::StaticSigner::from_hex(&"08".repeat(32))
            .unwrap()
            .pubkey()
            .to_id()
            .0;
        let now = 1_779_408_000;
        let env = handover_offer_envelope(&creator, " oc-mutiny-v1 ", &to, 7, now).unwrap();
        let env = written_and_verified(&env, "creator-handover-offer");
        assert_eq!(env.pubkey, creator.pubkey());
        assert_eq!(env.payload.action, ActionType::CreatorHandoverOffer);
        assert_eq!(env.payload.federation.as_deref(), Some("oc-mutiny-v1"));
        assert_eq!(
            env.payload.params,
            serde_json::json!({
                "operator_id": creator.pubkey().to_id().0,
                "federation_slug": "oc-mutiny-v1",
                "to_operator_id": to,
                "offered_at": "2026-05-22T00:00:00Z",
            })
        );
        assert_eq!(env.payload.nonce, now);
        assert_eq!(env.payload.expires_at, (now + 7 * 86_400) as i64);
        let longest = handover_offer_envelope(&creator, "f", &to, 30, now).unwrap();
        assert_eq!(longest.payload.expires_at, (now + 30 * 86_400) as i64);
    }

    #[test]
    fn handover_accept_is_what_the_portal_checks() {
        let recipient = keychain::StaticSigner::from_hex(&"08".repeat(32)).unwrap();
        let now = 1_779_408_000 + 13 * 3600 + 45 * 60 + 7;
        let offer = "AB".repeat(32);
        let env = handover_accept_envelope(&recipient, "oc-mutiny-v1", &offer, now).unwrap();
        let env = written_and_verified(&env, "creator-handover-accept");
        assert_eq!(env.pubkey, recipient.pubkey());
        assert_eq!(env.payload.action, ActionType::CreatorHandoverAccept);
        assert_eq!(env.payload.federation.as_deref(), Some("oc-mutiny-v1"));
        assert_eq!(
            env.payload.params,
            serde_json::json!({
                "operator_id": recipient.pubkey().to_id().0,
                "federation_slug": "oc-mutiny-v1",
                "offer_id": "ab".repeat(32),
                "accepted_at": "2026-05-22T13:45:07Z",
            })
        );
        assert_eq!(env.payload.expires_at, (now + 86_400) as i64);
    }

    #[test]
    fn handover_refuses_what_the_portal_would() {
        let signer = keychain::StaticSigner::from_hex(&"07".repeat(32)).unwrap();
        let me = signer.pubkey().to_id().0;
        let to = format!("op-{}", "ab".repeat(16));
        for (slug, to, days) in [
            ("", to.as_str(), 7),
            ("  ", to.as_str(), 7),
            ("f", "ab12", 7),
            ("f", "op-", 7),
            ("f", me.as_str(), 7),
            ("f", to.as_str(), 0),
            ("f", to.as_str(), 31),
        ] {
            assert!(
                handover_offer_envelope(&signer, slug, to, days, 0).is_err(),
                "{slug:?} {to:?} {days}"
            );
        }
        assert!(handover_offer_envelope(&signer, "f", &to, 1, 0).is_ok());
        let offer = "ab".repeat(32);
        for (slug, offer) in [
            ("", offer.clone()),
            ("f", "ab".repeat(31)),
            ("f", "zz".repeat(32)),
            ("f", format!("{offer}00")),
        ] {
            assert!(
                handover_accept_envelope(&signer, slug, &offer, 0).is_err(),
                "{slug:?} {offer:?}"
            );
        }
        assert!(handover_accept_envelope(&signer, "f", &offer, 0).is_ok());
    }

    #[test]
    fn exit_ratify_names_a_block_the_portal_checks() {
        let p = exit_ratify_params(
            "op-2",
            "oc-mutiny-v1",
            "exit_1",
            900_000,
            &"AB".repeat(32),
            None,
            0,
        )
        .unwrap();
        assert_eq!(p["block_height"], 900_000);
        assert_eq!(p["block_hash"], "ab".repeat(32));
        assert_eq!(p["ratifier_operator_id"], "op-2");
        assert!(p.get("note").is_none());
        assert!(exit_ratify_params("op-2", "f", "e", 1, "zz", None, 0).is_err());
    }

    #[test]
    fn iso8601_utc_epoch() {
        assert_eq!(iso8601_utc(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn iso8601_utc_known_instant() {
        // 2026-05-22T00:00:00Z = 1_779_408_000
        assert_eq!(iso8601_utc(1_779_408_000), "2026-05-22T00:00:00Z");
    }

    #[test]
    fn iso8601_utc_carries_time_of_day() {
        // 2026-05-22T13:45:07Z
        assert_eq!(
            iso8601_utc(1_779_408_000 + 13 * 3600 + 45 * 60 + 7),
            "2026-05-22T13:45:07Z"
        );
    }
}
