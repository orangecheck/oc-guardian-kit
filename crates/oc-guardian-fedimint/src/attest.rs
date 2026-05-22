//! Operator-signed runtime attestation — NOT TEE-based.
//!
//! §1A's load-bearing property is operator-key control + key diversity,
//! not hardware attestation. So the guardian's "attestation" is simply a
//! periodic runtime report (what version is running, which federation,
//! liveness) signed by the OPERATOR's Ed25519 key and POSTed to
//! `OC_ATTESTATION_POST_URL`.
//!
//! Crucially: OC cannot forge it. The signing key lives in the machine's
//! keychain under operator control; OC's Fly account runs the box but
//! holds no signing-capable key. If the operator key isn't present yet,
//! the guardian still runs — it just can't attest until the operator
//! provisions their key (honest: an un-attested box is visibly so).

use anyhow::{Context, Result};
use oc_guardian_core::identity::Signer;
use oc_guardian_core::keychain;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::config::FedimintdRuntime;

/// The signed body. Field order is the canonical signing order — the
/// verifier (me.ochk.io `/api/operator/attestation`) re-derives the same
/// `serde_json::to_vec` bytes, matching the kit's other envelopes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuntimeAttestation {
    /// Envelope discriminator.
    pub kind: String,
    pub operator_id: String,
    pub federation_slug: String,
    pub hosted_request_id: Option<String>,
    /// fedimintd version the guardian is running.
    pub fedimintd_version: String,
    pub p2p_url: String,
    pub api_url: String,
    /// Coarse liveness: "running" once the daemon answers its API,
    /// "starting" before then.
    pub status: String,
    /// Unix seconds. Receivers reject stale attestations.
    pub attested_at: u64,
}

/// The wire form: the attestation + the operator pubkey + hex signature.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedAttestation {
    pub attestation: RuntimeAttestation,
    /// Hex Ed25519 public key (32 bytes).
    pub pubkey_hex: String,
    /// Hex Ed25519 signature (64 bytes) over `serde_json::to_vec(&attestation)`.
    pub sig_hex: String,
}

/// Build the attestation body from the runtime + observed daemon state.
pub fn build(
    rt: &FedimintdRuntime,
    fedimintd_version: &str,
    status: &str,
    now_unix: u64,
) -> RuntimeAttestation {
    RuntimeAttestation {
        kind: "oc-guardian-attestation".to_string(),
        operator_id: rt.operator_id.clone(),
        federation_slug: rt.federation_slug.clone(),
        hosted_request_id: rt.hosted_request_id.clone(),
        fedimintd_version: fedimintd_version.to_string(),
        p2p_url: rt.p2p_url(),
        api_url: rt.api_url(),
        status: status.to_string(),
        attested_at: now_unix,
    }
}

/// Sign an attestation with the given signer. Returns the wire form.
pub fn sign(att: &RuntimeAttestation, signer: &dyn Signer) -> Result<SignedAttestation> {
    let bytes = serde_json::to_vec(att).context("serializing attestation")?;
    let sig = signer.sign(&bytes).context("signing attestation")?;
    Ok(SignedAttestation {
        attestation: att.clone(),
        pubkey_hex: hex::encode(signer.pubkey().0),
        sig_hex: hex::encode(sig),
    })
}

/// Build, sign (with the operator key from the keychain), and POST the
/// attestation. No-op with a warning when the operator key isn't present
/// (OC can't sign on the operator's behalf — by design) or when no
/// attestation URL is configured.
pub fn emit(
    rt: &FedimintdRuntime,
    fedimintd_version: &str,
    status: &str,
    now_unix: u64,
) -> Result<()> {
    let Some(url) = rt.attestation_post_url.as_deref() else {
        info!("no OC_ATTESTATION_POST_URL · skipping attestation");
        return Ok(());
    };
    let signer = match keychain::load(&rt.operator_id)? {
        Some(s) => s,
        None => {
            warn!(
                operator_id = %rt.operator_id,
                "operator key not in keychain · guardian runs but cannot attest until the \
                 operator provisions their key (OC cannot sign on their behalf)"
            );
            return Ok(());
        }
    };
    let att = build(rt, fedimintd_version, status, now_unix);
    let signed = sign(&att, &signer)?;
    post(url, &signed)?;
    info!(url, status, "posted operator-signed runtime attestation");
    Ok(())
}

fn post(url: &str, signed: &SignedAttestation) -> Result<()> {
    let resp = ureq::post(url)
        .set("content-type", "application/json")
        .send_json(serde_json::to_value(signed).context("encoding signed attestation")?);
    match resp {
        Ok(_) => Ok(()),
        // A non-2xx is surfaced but non-fatal to the daemon; the caller
        // logs + retries on the next interval.
        Err(ureq::Error::Status(code, _)) => {
            warn!(code, url, "attestation endpoint returned non-2xx");
            Ok(())
        }
        Err(e) => Err(e).context("posting attestation"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oc_guardian_core::identity::OperatorPubKey;

    struct FakeSigner {
        pk: [u8; 32],
    }
    impl Signer for FakeSigner {
        fn pubkey(&self) -> OperatorPubKey {
            OperatorPubKey(self.pk)
        }
        fn sign(&self, message: &[u8]) -> Result<[u8; 64]> {
            // Deterministic non-crypto stand-in: first byte = len, rest 0.
            let mut out = [0u8; 64];
            out[0] = (message.len() % 256) as u8;
            Ok(out)
        }
    }

    fn runtime() -> FedimintdRuntime {
        use std::collections::HashMap;
        let m = HashMap::from([
            ("OC_OPERATOR_ID".to_string(), "op-test".to_string()),
            ("OC_OPERATOR_PUBKEY_HEX".to_string(), "aa".to_string()),
            ("OC_FEDERATION_SLUG".to_string(), "oc-me-v1".to_string()),
            ("OC_PUBLIC_HOST".to_string(), "g.example.com".to_string()),
            (
                "OC_ESPLORA_URL".to_string(),
                "https://mempool.space/api".to_string(),
            ),
        ]);
        FedimintdRuntime::from_vars(|k| m.get(k).cloned()).unwrap()
    }

    #[test]
    fn build_carries_runtime_context() {
        let att = build(&runtime(), "0.7.2", "running", 1_700_000_000);
        assert_eq!(att.kind, "oc-guardian-attestation");
        assert_eq!(att.operator_id, "op-test");
        assert_eq!(att.federation_slug, "oc-me-v1");
        assert_eq!(att.p2p_url, "fedimint://g.example.com:9000");
        assert_eq!(att.status, "running");
        assert_eq!(att.fedimintd_version, "0.7.2");
    }

    // CROSS-LANGUAGE PARITY VECTOR. The me.ochk.io verifier
    // (oc-me-web src/lib/operator/attestation.ts → canonicalAttestationBytes)
    // re-derives the signed bytes in JS. Both sides assert against this
    // exact literal so a field-order/escaping drift on either side fails
    // CI immediately. If you change RuntimeAttestation, update BOTH.
    const PARITY_VECTOR: &str = r#"{"kind":"oc-guardian-attestation","operator_id":"op-abc123","federation_slug":"oc-me-v1","hosted_request_id":null,"fedimintd_version":"0.11.1","p2p_url":"fedimint://x.fly.dev:9000","api_url":"wss://x.fly.dev:9001","status":"running","attested_at":1779408000}"#;

    fn parity_attestation() -> RuntimeAttestation {
        RuntimeAttestation {
            kind: "oc-guardian-attestation".to_string(),
            operator_id: "op-abc123".to_string(),
            federation_slug: "oc-me-v1".to_string(),
            hosted_request_id: None,
            fedimintd_version: "0.11.1".to_string(),
            p2p_url: "fedimint://x.fly.dev:9000".to_string(),
            api_url: "wss://x.fly.dev:9001".to_string(),
            status: "running".to_string(),
            attested_at: 1_779_408_000,
        }
    }

    #[test]
    fn canonical_bytes_match_cross_language_vector() {
        let s = serde_json::to_string(&parity_attestation()).unwrap();
        assert_eq!(
            s, PARITY_VECTOR,
            "serde_json output drifted from the JS verifier vector"
        );
    }

    #[test]
    fn hosted_request_id_some_serializes_as_string_not_omitted() {
        let mut att = parity_attestation();
        att.hosted_request_id = Some("hr-7".to_string());
        let s = serde_json::to_string(&att).unwrap();
        assert!(
            s.contains(r#""hosted_request_id":"hr-7""#),
            "Some(_) must serialize as a string field, never be skipped: {s}"
        );
    }

    #[test]
    fn sign_is_deterministic_and_pubkey_matches() {
        let att = build(&runtime(), "0.7.2", "running", 1_700_000_000);
        let signer = FakeSigner { pk: [7u8; 32] };
        let a = sign(&att, &signer).unwrap();
        let b = sign(&att, &signer).unwrap();
        assert_eq!(a.sig_hex, b.sig_hex, "same body → same signature");
        assert_eq!(a.pubkey_hex, hex::encode([7u8; 32]));
        // The signed bytes are exactly serde_json::to_vec(&attestation).
        let expected_len = serde_json::to_vec(&att).unwrap().len();
        assert_eq!(
            a.sig_hex.chars().take(2).collect::<String>(),
            format!("{:02x}", expected_len % 256)
        );
    }
}
