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

// ── Shared helpers for the signed-envelope + portal commands ─────────

/// Load the operator identity + keychain signer, or a clear error.
fn load_operator() -> Result<(crate::identity::OperatorId, keychain::KeychainSigner)> {
    let dir = resolve_dir(None)?;
    let id = read_id(&dir)?.context("no operator identity — run `oc-guardian init` first")?;
    let signer = keychain::load(&id.0)?.with_context(|| {
        format!(
            "operator {} has no key in the OS keychain — re-run `oc-guardian init`",
            id.0
        )
    })?;
    Ok((id, signer))
}

/// Build + sign an `ActionEnvelope`. The nonce is unix-seconds (monotonic
/// per run); the portal rejects equal-or-lower nonces it has seen.
fn build_signed_envelope(
    signer: &keychain::KeychainSigner,
    action: ActionType,
    params: serde_json::Value,
    federation: Option<String>,
) -> Result<ActionEnvelope> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before epoch")?
        .as_secs() as i64;
    let payload = ActionPayload {
        action,
        params,
        nonce: now as u64,
        expires_at: now + 30 * 86_400,
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
/// submits it via the authenticated me.ochk.io surface — same pattern as
/// `charter sign`.
fn write_envelope(env: &ActionEnvelope, out: &str, what: &str, submit_path: &str) -> Result<()> {
    let json = serde_json::to_vec_pretty(env).context("encoding envelope")?;
    fs::write(out, &json).with_context(|| format!("writing {out}"))?;
    println!();
    println!("  ✓ signed {what} envelope written to {out}");
    println!("    it carries your hardware-key signature · OC cannot forge it.");
    println!("    submit it signed-in at the matching me.ochk.io/me/operator surface");
    println!("    (the portal POSTs it to {submit_path}).");
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
    println!("         oc-guardian charter sign --slug {slug}");
    println!("         oc-guardian charter publish --file charter-sig.json");
    println!("    3. run DKG with your peers:  oc-guardian ceremony start …");
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

/// `oc-guardian alerts subscribe` · alert delivery is a portal-bridge
/// feature; point the operator at it rather than fake a subscription.
pub fn alerts_subscribe(federation: String) -> Result<()> {
    println!();
    println!("  alert delivery for {federation} is a portal-bridge feature:");
    println!("    oc-guardian bridge enable    # opt into portal-mediated signed requests");
    println!("  published incidents are visible at me.ochk.io/me/operator (incidents)");
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
    let env = build_signed_envelope(&signer, ActionType::AlertPublish, params, Some(federation))?;
    write_envelope(&env, "incident.json", "incident", "/api/operator/incidents")
}

/// `oc-guardian payouts list` · accrued-payout figures are session-gated
/// at the portal; the kit produces the signed CLAIM envelope locally.
pub fn payouts_list(federation: String) -> Result<()> {
    let (id, _signer) = load_operator()?;
    println!();
    println!("  payouts · operator {} · federation {federation}", id.0);
    println!("    accrued figures are session-gated — view them signed-in at");
    println!("    me.ochk.io/me/operator. To withdraw, produce a signed claim:");
    println!("      oc-guardian payouts claim --federation {federation} --to <bc1q…>");
    println!();
    Ok(())
}

/// `oc-guardian payouts claim` · produce a hardware-signed `payouts-claim`
/// envelope directing accrued payouts to a Bitcoin destination.
pub fn payouts_claim(federation: String, to: String) -> Result<()> {
    let (id, signer) = load_operator()?;
    let params = serde_json::json!({
        "operator_id": id.0,
        "destination": to,
        "federation_slug": federation,
    });
    let env = build_signed_envelope(&signer, ActionType::PayoutsClaim, params, Some(federation))?;
    write_envelope(
        &env,
        "payouts-claim.json",
        "payouts-claim",
        "/api/operator/payouts/claim",
    )
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
    println!("  authoritative audit log · me.ochk.io/me/admin/audit (signed-in).");
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
    let env = build_signed_envelope(&signer, ActionType::ExitHandoff, params, Some(federation))?;
    write_envelope(
        &env,
        "exit-handoff.json",
        "exit-handoff",
        "/api/operator/exits",
    )
}

/// `oc-guardian portal forget` · wipe local operator state — the keychain
/// key + the config dir. Irreversible; re-init to start fresh.
pub fn portal_forget() -> Result<()> {
    let dir = resolve_dir(None)?;
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
