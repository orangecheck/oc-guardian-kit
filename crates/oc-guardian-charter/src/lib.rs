//! Federation charter primitives — fetch, hash, sign, publish.
//!
//! The charter is the artifact a federation publishes disclosing its
//! guardians, threshold, operational commitments, and exit clause.
//! Operators sign an envelope naming the charter's SHA-256 to ratify
//! their guardian seat.
//! Consumers verify the charter against its hash before depositing
//! into the federation.
//!
//! Canonical form: the federation's `/api/operator/charter` endpoint
//! returns the charter's hash, version, URL and exact text. The kit hashes
//! that text itself, signs an `ActionEnvelope` (action: charter-sign)
//! with the operator key only when it matches the hash the portal names,
//! and writes it to disk. The operator uploads it on the federation's page
//! at ochk.app, signed in to the account the key is bound to.
//!
//! This crate implements the kit-side of BYPASS.md §06 (charter
//! fetch / sign / publish).
//!
//! ```text
//! oc-guardian charter fetch <slug>          # see what would be signed
//! oc-guardian charter sign <slug>           # produce charter-sig.json
//! oc-guardian charter publish --file <path> # POST, no session: refused
//! ```

use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use oc_guardian_core::actions::{ActionEnvelope, ActionPayload, ActionType};
use oc_guardian_core::commands::printable;
use oc_guardian_core::config::{read_id, resolve_dir};
use oc_guardian_core::identity::Signer;
use oc_guardian_core::keychain;
use oc_guardian_core::portal_client::{CharterFetchResponse, CharterMeta, PortalClient};
use sha2::{Digest, Sha256};
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
    print!("{}", fetch_summary(&slug, &resp));
    if resp.meta.is_some() {
        if let Err(e) = charter_to_sign(&slug, resp.meta) {
            warn!("{e}. Do not sign it.");
        }
    }
    Ok(())
}

/// What `charter fetch` prints. The count is every signature the portal has
/// recorded for the federation, superseded versions included, so it is not a
/// ratification count.
fn fetch_summary(slug: &str, resp: &CharterFetchResponse) -> String {
    let Some(m) = &resp.meta else {
        return format!(
            "federation : {slug}\n\
             no charter published for {slug}\n\
             signatures recorded: {}\n",
            resp.signatures.len()
        );
    };
    let mut out = [
        format!("federation : {}", m.federation_slug),
        format!("version    : {}", m.charter_version),
        format!("hash       : {}", m.charter_hash),
        format!("canonical  : {}", m.charter_url),
        format!("published  : {}", m.published_at),
        format!("signatures recorded: {}", resp.signatures.len()),
    ]
    .join("\n");
    out.push('\n');
    out
}

/// The charter `sign` may commit to, or why there is none: the portal
/// publishes no charter for the federation (`meta: null`), an older portal
/// sent its "v0-pending" stand-in, which carries oc-me-v1's hash, or the text
/// it serves is not the text the hash names.
fn charter_to_sign(slug: &str, meta: Option<CharterMeta>) -> Result<CharterMeta> {
    let meta = meta.ok_or_else(|| {
        anyhow!(
            "no charter published for `{slug}`, so there is nothing to ratify. A federation \
             you create gets its charter when its seats are assigned; the OC-managed oc-me-v1 \
             charter is at ochk.io/docs/federation/oc-me-v1"
        )
    })?;
    if meta.charter_version.contains("placeholder") || meta.charter_version.contains("pending") {
        return Err(anyhow!(
            "the meta for `{slug}` reports version `{}`, the stand-in an older portal sent \
             for a federation with no charter, not a real charter. Verify the slug and \
             re-run. The OC-managed oc-me-v1 charter is at ochk.io/docs/federation/oc-me-v1",
            meta.charter_version
        ));
    }
    if meta.federation_slug != slug {
        return Err(anyhow!(
            "the portal answered for `{slug}` with the charter of `{}`",
            printable(&meta.federation_slug)
        ));
    }
    let text = meta.canonical_text.as_deref().ok_or_else(|| {
        anyhow!(
            "the portal serves no text for `{slug}`'s charter {}, so its hash cannot be \
             checked here. A charter stored before the portal kept its text serves none; \
             it gets one when a seat change republishes it",
            printable(&meta.charter_version)
        )
    })?;
    let digest = hex::encode(Sha256::digest(text.as_bytes()));
    if digest != meta.charter_hash.to_ascii_lowercase() {
        return Err(anyhow!(
            "the charter text the portal serves for `{slug}` hashes to {digest}, not the {} \
             it names",
            printable(&meta.charter_hash)
        ));
    }
    Ok(meta)
}

/// The charter-sign envelope the portal's charter route takes: the hash and
/// version of `meta`, the operator id of the key that signs, dated `now` and
/// valid for an hour.
fn charter_envelope(signer: &dyn Signer, meta: &CharterMeta, now: u64) -> Result<ActionEnvelope> {
    let signed_at = format!(
        "{}.000Z",
        iso8601_from_unix(now as i64).context("format signed_at timestamp")?
    );
    let payload = ActionPayload {
        action: ActionType::CharterSign,
        params: serde_json::json!({
            "federation_slug": meta.federation_slug,
            "operator_id": signer.pubkey().to_id().0,
            "charter_hash": meta.charter_hash,
            "charter_version": meta.charter_version,
            "signed_at": signed_at,
        }),
        nonce: now,
        expires_at: (now as i64) + ENVELOPE_TTL_SECS,
        federation: Some(meta.federation_slug.clone()),
    };
    let canonical = serde_json::to_vec(&payload).context("canonicalize payload")?;
    let sig: [u8; 64] = signer.sign(&canonical).context("sign canonical bytes")?;
    // A key store that signs with another key than the one it names is caught here, not at
    // the portal.
    if !keychain::verify(&signer.pubkey(), &canonical, &sig) {
        return Err(anyhow!(
            "the signature does not verify under this operator's key {}. Re-run \
             `oc-guardian init` if this persists",
            hex::encode(signer.pubkey().0)
        ));
    }
    Ok(ActionEnvelope {
        payload,
        pubkey: signer.pubkey(),
        sig_hex: hex::encode(sig),
    })
}

/// `oc-guardian charter sign <slug> --out <path>` · fetch the
/// canonical charter meta, produce a charter-sign `ActionEnvelope`
/// signed with the operator key, write the envelope
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
    let config_dir = resolve_dir()?;
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
    let meta = charter_to_sign(&slug, meta_resp.meta).context("refusing to sign")?;

    // 3. Load the operator signer (OS keychain, or the key file `init
    //    --key-file` recorded). We get a `sign(&[u8])` API only.
    let signer = keychain::load_signer(&id.0)
        .context("read operator key")?
        .ok_or_else(|| {
            anyhow!(
                "no key for operator id `{}` in the OS keychain or a key file · run \
                 `oc-guardian init` or rotate to repair drift between config and key.",
                id.0
            )
        })?;

    // 4. Sign, and check the signature under the key before writing it.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before UNIX epoch")?
        .as_secs();
    let envelope = charter_envelope(signer.as_ref(), &meta, now)?;

    // 5. Write to disk. Pretty-printed: the operator may read it before uploading.
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
    println!(
        "hash       : {} (the text served hashes to it)",
        meta.charter_hash
    );
    println!("version    : {}", meta.charter_version);
    println!(
        "operator   : {}",
        envelope.payload.params["operator_id"]
            .as_str()
            .unwrap_or_default()
    );
    println!("expires_at : {}", envelope.payload.expires_at);
    println!();
    println!("upload it at ochk.app/me/operator/federations/{slug}, signed in to the account");
    println!("this key is bound to (oc-guardian bind), within the hour.");
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

    fn oc_me_v1() -> CharterMeta {
        CharterMeta {
            federation_slug: "oc-me-v1".into(),
            charter_hash: "5fcb".into(),
            charter_version: "v1.1.0".into(),
            charter_url: "https://ochk.io/docs/federation/oc-me-v1".into(),
            published_at: "2026-10-31T00:00:00.000Z".into(),
            canonical_text: None,
        }
    }

    /// A charter as the portal serves it, with the text its hash names.
    fn served(slug: &str, text: &str) -> CharterMeta {
        use sha2::{Digest, Sha256};
        CharterMeta {
            federation_slug: slug.into(),
            charter_hash: hex::encode(Sha256::digest(text.as_bytes())),
            canonical_text: Some(text.into()),
            ..oc_me_v1()
        }
    }

    const TEXT: &str = "# Kit fixture charter\nversion: v1.3.0\nthreshold: 3-of-4\n";

    // One signature over a superseded version: recorded, not a ratification.
    fn old_signature() -> oc_guardian_core::portal_client::CharterSignature {
        oc_guardian_core::portal_client::CharterSignature {
            federation_slug: "oc-me-v1".into(),
            operator_id: "op-cf6d365829055b25".into(),
            operator_pubkey: "ab".repeat(32),
            charter_hash: "58f5".into(),
            charter_version: "v1.0.0".into(),
            signed_at: "2026-05-21T04:53:53.042Z".into(),
            sig_hex: "cd".repeat(64),
            received_at: "2026-05-21T04:53:53.042Z".into(),
        }
    }

    #[test]
    fn fetch_summary_counts_signatures_recorded_not_ratifications() {
        let resp = CharterFetchResponse {
            ok: true,
            meta: Some(oc_me_v1()),
            signatures: vec![old_signature()],
        };
        assert_eq!(
            fetch_summary("oc-me-v1", &resp),
            "federation : oc-me-v1\n\
             version    : v1.1.0\n\
             hash       : 5fcb\n\
             canonical  : https://ochk.io/docs/federation/oc-me-v1\n\
             published  : 2026-10-31T00:00:00.000Z\n\
             signatures recorded: 1\n"
        );
    }

    #[test]
    fn fetch_summary_says_when_no_charter_is_published() {
        let resp = CharterFetchResponse {
            ok: true,
            meta: None,
            signatures: vec![old_signature()],
        };
        assert_eq!(
            fetch_summary("oc-testnet-v1", &resp),
            "federation : oc-testnet-v1\n\
             no charter published for oc-testnet-v1\n\
             signatures recorded: 1\n"
        );
    }

    #[test]
    fn sign_refuses_a_federation_with_no_charter() {
        let err = charter_to_sign("oc-testnet-v1", None).unwrap_err();
        assert!(
            err.to_string()
                .starts_with("no charter published for `oc-testnet-v1`"),
            "{err}"
        );
    }

    #[test]
    fn sign_refuses_an_older_portals_stand_in() {
        let stand_in = CharterMeta {
            federation_slug: "oc-testnet-v1".into(),
            charter_version: "v0-pending".into(),
            ..oc_me_v1()
        };
        let err = charter_to_sign("oc-testnet-v1", Some(stand_in)).unwrap_err();
        assert!(err.to_string().contains("`v0-pending`"), "{err}");
    }

    #[test]
    fn sign_takes_a_charter_whose_text_hashes_to_its_hash() {
        let meta = served("oc-me-v1", TEXT);
        let hash = meta.charter_hash.clone();
        assert_eq!(
            charter_to_sign("oc-me-v1", Some(meta))
                .unwrap()
                .charter_hash,
            hash
        );
    }

    #[test]
    fn sign_refuses_a_charter_whose_text_does_not_hash_to_its_hash() {
        let meta = CharterMeta {
            charter_hash: served("oc-me-v1", "another text").charter_hash,
            ..served("oc-me-v1", TEXT)
        };
        let err = charter_to_sign("oc-me-v1", Some(meta)).unwrap_err();
        assert!(err.to_string().contains("hashes to"), "{err}");
    }

    #[test]
    fn sign_refuses_a_charter_that_serves_no_text() {
        let meta = CharterMeta {
            canonical_text: None,
            ..served("oc-me-v1", TEXT)
        };
        let err = charter_to_sign("oc-me-v1", Some(meta)).unwrap_err();
        assert!(err.to_string().contains("serves no text"), "{err}");
    }

    #[test]
    fn sign_refuses_another_federations_charter() {
        let err = charter_to_sign("oc-me-v1", Some(served("oc-other-v1", TEXT))).unwrap_err();
        assert!(err.to_string().contains("`oc-other-v1`"), "{err}");
    }

    /// The vectors oc-me-web's tests hold its charter route to, byte for byte.
    fn vectors() -> serde_json::Value {
        serde_json::from_str(include_str!(
            "../../oc-guardian-core/test-fixtures/operator-signature-vectors.json"
        ))
        .unwrap()
    }

    fn text(v: &serde_json::Value) -> &str {
        v.as_str().unwrap()
    }

    #[test]
    fn charter_signatures_match_what_the_portal_takes() {
        let v = vectors();
        let signer = StaticSigner::from_hex(text(&v["private_key"])).unwrap();
        let cases = v["charter_signatures"].as_array().unwrap();
        assert!(!cases.is_empty());
        for case in cases {
            let c = &case["charter"];
            let meta = CharterMeta {
                federation_slug: text(&c["federation_slug"]).into(),
                charter_version: text(&c["charter_version"]).into(),
                charter_hash: text(&case["digest"]).into(),
                canonical_text: Some(text(&c["canonical_text"]).into()),
                ..oc_me_v1()
            };
            let meta = charter_to_sign(text(&c["federation_slug"]), Some(meta)).unwrap();
            let env = charter_envelope(&signer, &meta, case["now"].as_u64().unwrap()).unwrap();
            let bytes = serde_json::to_vec(&env.payload).unwrap();
            assert_eq!(String::from_utf8(bytes).unwrap(), text(&case["bytes"]));
            assert_eq!(serde_json::to_value(&env).unwrap(), case["envelope"]);
        }
    }

    /// A key store that names one key and signs with another.
    struct WrongKey(StaticSigner, StaticSigner);

    impl Signer for WrongKey {
        fn pubkey(&self) -> oc_guardian_core::identity::OperatorPubKey {
            self.0.pubkey()
        }
        fn sign(&self, message: &[u8]) -> Result<[u8; 64]> {
            self.1.sign(message)
        }
    }

    use oc_guardian_core::keychain::StaticSigner;

    #[test]
    fn sign_refuses_a_signature_its_key_does_not_verify() {
        let named = StaticSigner::from_hex(&"07".repeat(32)).unwrap();
        let other = StaticSigner::from_hex(&"08".repeat(32)).unwrap();
        let meta = served("oc-me-v1", TEXT);
        assert!(charter_envelope(&named, &meta, 1_795_000_000).is_ok());
        let err = charter_envelope(&WrongKey(named, other), &meta, 1_795_000_000).unwrap_err();
        assert!(err.to_string().contains("does not verify"), "{err}");
    }

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
