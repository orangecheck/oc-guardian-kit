//! Federation charter primitives — fetch, hash, sign, publish.
//!
//! The charter is the artifact a federation publishes disclosing its
//! guardians, threshold, operational commitments, and exit clause.
//! Operators sign the charter's SHA-256 to ratify their guardian seat.
//! Consumers verify the charter against its hash before depositing
//! into the federation.
//!
//! Canonical form: the federation's `/api/operator/charter` endpoint
//! returns the canonical hash + version + URL. The kit fetches that,
//! produces a hardware-key-signed `ActionEnvelope` (action:
//! charter-sign), and either writes it to disk for review (default)
//! or publishes it back to the portal.
//!
//! This crate implements the kit-side of BYPASS.md §06 (charter
//! fetch / sign / publish).
//!
//! ```text
//! oc-guardian charter fetch <slug>          # see what would be signed
//! oc-guardian charter sign --slug <slug>    # produce charter-sig.json
//! oc-guardian charter publish --file <path> # POST to portal
//! ```

use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use oc_guardian_core::actions::{ActionEnvelope, ActionPayload, ActionType};
use oc_guardian_core::config::{read_id, resolve_dir};
use oc_guardian_core::identity::Signer;
use oc_guardian_core::keychain;
use oc_guardian_core::portal_client::{CharterFetchResponse, PortalClient};
use tracing::{info, warn};

/// Replay-protection horizon for charter-sign envelopes. The portal
/// rejects envelopes older than this; choose a window that lets the
/// operator review locally before submitting but still bounds the
/// replay attack surface.
const ENVELOPE_TTL_SECS: i64 = 60 * 60; // 1 hour

/// `oc-guardian charter fetch <slug>` · read the canonical charter
/// meta from the portal and print it. Read-only · no operator key
/// involved. The output is what `sign` would commit to.
pub fn fetch(slug: String) -> Result<()> {
    let client = PortalClient::from_env(None);
    let path = format!("/api/operator/charter?federation={}", url_encode(&slug));
    let resp: CharterFetchResponse = client
        .get_json(&path)
        .with_context(|| format!("fetching charter meta for federation {slug}"))?;
    println!("federation : {}", resp.meta.federation_slug);
    println!("version    : {}", resp.meta.charter_version);
    println!("hash       : {}", resp.meta.charter_hash);
    println!("canonical  : {}", resp.meta.charter_url);
    println!("published  : {}", resp.meta.published_at);
    println!("ratifications: {}", resp.signatures.len());
    if resp.meta.charter_version.contains("placeholder") {
        warn!(
            "the canonical charter for {} is a placeholder · OC has not published \
             the formal charter document at docs.ochk.io/charter yet. Signing is \
             still possible against this hash, but operators typically wait for \
             the formal document.",
            resp.meta.federation_slug
        );
    }
    Ok(())
}

/// `oc-guardian charter sign --slug <slug> --out <path>` · fetch the
/// canonical charter meta, produce a charter-sign `ActionEnvelope`
/// signed with the operator's hardware-backed key, write the envelope
/// JSON to disk. Idempotent · re-running produces a fresh envelope
/// with a new nonce.
///
/// Bytes signed · the canonical serialization of `ActionPayload`
/// (action=charter-sign, params containing federation_slug +
/// operator_id + charter_hash + charter_version + signed_at, nonce,
/// expires_at, federation=Some(slug)). Same wire format the portal's
/// `recordCharterSignature` validator already accepts.
pub fn sign(slug: String, out: String, hsm: String) -> Result<()> {
    // 1. Resolve operator identity from kit config.
    let config_dir = resolve_dir(None)?;
    let id = read_id(&config_dir)
        .context("read operator id from config")?
        .ok_or_else(|| anyhow!("no operator id on disk · run `oc-guardian init` first"))?;

    info!(
        "signing charter for federation `{}` as operator `{}` (hsm={hsm})",
        slug, id.0
    );

    // 2. Fetch canonical charter meta so we commit to whatever the
    //    portal currently publishes. Reduces "you signed the wrong
    //    version" foot-guns.
    let client = PortalClient::from_env(None);
    let path = format!("/api/operator/charter?federation={}", url_encode(&slug));
    let meta_resp: CharterFetchResponse = client
        .get_json(&path)
        .with_context(|| format!("fetching charter meta for federation {slug}"))?;
    let meta = meta_resp.meta;

    if meta.charter_version.contains("placeholder") {
        warn!(
            "signing against placeholder charter for `{}` · OC has not published \
             the formal charter at docs.ochk.io/charter yet. Re-sign after publication.",
            slug
        );
    }

    // 3. Load the operator keychain signer. The private bytes never
    //    leave the KeychainSigner; we get a `sign(&[u8])` API only.
    let signer = keychain::load(&id.0)
        .context("read operator key from keychain")?
        .ok_or_else(|| {
            anyhow!(
                "no keychain entry for operator id `{}` · run `oc-guardian init` or rotate \
                 to repair drift between config and keychain.",
                id.0
            )
        })?;
    let pubkey = signer.pubkey();

    // 4. Build the inner payload + outer envelope.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before UNIX epoch")?
        .as_secs();
    let signed_at = format!(
        "{}.000Z",
        iso8601_from_unix(now as i64).context("format signed_at timestamp")?
    );
    let payload = ActionPayload {
        action: ActionType::CharterSign,
        params: serde_json::json!({
            "federation_slug": slug,
            "operator_id": id.0,
            "charter_hash": meta.charter_hash,
            "charter_version": meta.charter_version,
            "signed_at": signed_at,
        }),
        nonce: now,
        expires_at: (now as i64) + ENVELOPE_TTL_SECS,
        federation: Some(slug.clone()),
    };

    let canonical = serde_json::to_vec(&payload).context("canonicalize payload")?;
    let sig_bytes = signer.sign(&canonical).context("sign canonical bytes")?;
    let envelope = ActionEnvelope {
        payload,
        pubkey,
        sig_hex: hex::encode(sig_bytes),
    };

    // 5. Self-verify before writing. Catches keychain corruption /
    //    local crypto regressions before the portal sees a bad sig.
    let canonical_check = serde_json::to_vec(&envelope.payload).context("re-canonicalize")?;
    debug_assert_eq!(canonical, canonical_check, "canonicalization not stable");
    if !keychain::verify(&envelope.pubkey, &canonical, &sig_bytes) {
        return Err(anyhow!(
            "self-verify failed · the signature this kit just produced does NOT verify \
             against the local pubkey. Likely a keychain drift or a hex encoding bug. \
             Re-run `oc-guardian init` if this persists."
        ));
    }

    // 6. Write to disk. Use pretty-printed JSON · this file may be
    //    eyeballed by operators reviewing before publish.
    let out_path = Path::new(&out);
    if let Some(parent) = out_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).with_context(|| format!("create parent dir for {out}"))?;
        }
    }
    let json = serde_json::to_string_pretty(&envelope).context("serialize envelope")?;
    fs::write(out_path, &json).with_context(|| format!("write envelope to {out}"))?;

    println!("charter ratification envelope written to {out}");
    println!("federation : {slug}");
    println!("hash       : {}", envelope.payload.params["charter_hash"]);
    println!(
        "version    : {}",
        envelope.payload.params["charter_version"]
    );
    println!("operator   : {}", id.0);
    println!("expires_at : {}", envelope.payload.expires_at);
    println!();
    println!("review the envelope, then publish with:");
    println!("  oc-guardian charter publish --file {out}");
    Ok(())
}

/// `oc-guardian charter publish --file <path>` · read a previously-
/// signed charter envelope and POST it to the portal. Idempotent at
/// the portal layer · re-publishing the same envelope returns the
/// same signature row.
pub fn publish(file: String, transport: String) -> Result<()> {
    if transport != "https" {
        return Err(anyhow!(
            "transport `{transport}` not yet supported · v0.2 ships `https` only"
        ));
    }
    let raw = fs::read_to_string(&file).with_context(|| format!("read envelope file {file}"))?;
    let envelope: ActionEnvelope =
        serde_json::from_str(&raw).context("parse envelope · not a valid ActionEnvelope JSON")?;
    if !matches!(envelope.payload.action, ActionType::CharterSign) {
        return Err(anyhow!(
            "envelope action is `{:?}`, expected `charter-sign`",
            envelope.payload.action
        ));
    }

    info!(
        "publishing charter signature to portal (federation={:?}, nonce={})",
        envelope.payload.federation, envelope.payload.nonce
    );

    let client = PortalClient::from_env(None);
    let response: serde_json::Value = client
        .submit_envelope("/api/operator/charter", &envelope)
        .with_context(|| format!("POST envelope from {file}"))?;
    println!("portal accepted the signature");
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

/// Minimal URL-component encoder · `slug` is `[a-z0-9-]` by federation
/// convention; we percent-encode anything outside that to be safe
/// against operator typos. Hand-rolled to avoid pulling in `url` for
/// a 3-line helper.
fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Format a Unix-seconds timestamp as ISO-8601 (`YYYY-MM-DDTHH:MM:SS`).
/// Caller appends fractional / timezone suffix.
///
/// Hand-rolled to avoid pulling in chrono/time for a kit binary that
/// just needs a stable ISO-8601 prefix on charter envelopes.
/// Supports the 1970-2099 range, which covers any realistic kit
/// deploy without complicating Gregorian calendar edge cases.
fn iso8601_from_unix(unix_secs: i64) -> Result<String> {
    if unix_secs < 0 {
        return Err(anyhow!("negative timestamps not supported"));
    }
    let secs_in_day: i64 = 86_400;
    let days_since_epoch = unix_secs / secs_in_day;
    let remainder_secs = unix_secs % secs_in_day;
    let h = remainder_secs / 3600;
    let m = (remainder_secs % 3600) / 60;
    let sec = remainder_secs % 60;
    let (year, month, day) = days_to_ymd(days_since_epoch);
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{sec:02}"
    ))
}

/// Convert days-since-Unix-epoch to (year, month, day) in the
/// Gregorian calendar.
fn days_to_ymd(mut days: i64) -> (i64, u32, u32) {
    let mut year = 1970i64;
    loop {
        let len = if is_leap_year(year) { 366 } else { 365 };
        if days < len {
            break;
        }
        days -= len;
        year += 1;
    }
    let month_lengths: [i64; 12] = if is_leap_year(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut month: u32 = 0;
    for (i, len) in month_lengths.iter().enumerate() {
        if days < *len {
            month = (i as u32) + 1;
            break;
        }
        days -= *len;
    }
    (year, month, (days as u32) + 1)
}

fn is_leap_year(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_encode_alpha_numeric_passthrough() {
        assert_eq!(url_encode("oc-me-v1"), "oc-me-v1");
        assert_eq!(url_encode("a1.b2_c3-d4~e5"), "a1.b2_c3-d4~e5");
    }

    #[test]
    fn url_encode_special_chars_percent_encoded() {
        assert_eq!(url_encode("a/b"), "a%2Fb");
        assert_eq!(url_encode("hello world"), "hello%20world");
        assert_eq!(url_encode("=&?"), "%3D%26%3F");
    }

    #[test]
    fn is_leap_year_matches_gregorian() {
        assert!(is_leap_year(2000));
        assert!(!is_leap_year(1900));
        assert!(is_leap_year(2024));
        assert!(!is_leap_year(2026));
        assert!(is_leap_year(2028));
    }

    #[test]
    fn iso8601_from_unix_epoch_renders_correctly() {
        assert_eq!(iso8601_from_unix(0).unwrap(), "1970-01-01T00:00:00");
    }

    #[test]
    fn iso8601_from_unix_specific_date_renders_correctly() {
        // 2026-05-12T13:00:00Z · day 20585 from epoch · 20585*86400 + 13*3600 = 1778590800
        assert_eq!(
            iso8601_from_unix(1_778_590_800).unwrap(),
            "2026-05-12T13:00:00"
        );
    }

    #[test]
    fn iso8601_from_unix_handles_leap_year_feb29() {
        // 2024-02-29T00:00:00Z = 1709164800
        assert_eq!(
            iso8601_from_unix(1_709_164_800).unwrap(),
            "2024-02-29T00:00:00"
        );
    }

    #[test]
    fn iso8601_from_unix_rejects_negative_timestamps() {
        assert!(iso8601_from_unix(-1).is_err());
    }

    #[test]
    fn days_to_ymd_first_day_of_year_2024() {
        let (y, m, d) = days_to_ymd(19_723);
        assert_eq!((y, m, d), (2024, 1, 1));
    }

    #[test]
    fn days_to_ymd_mid_year_2026() {
        let (y, m, d) = days_to_ymd(20_585);
        assert_eq!((y, m, d), (2026, 5, 12));
    }
}
