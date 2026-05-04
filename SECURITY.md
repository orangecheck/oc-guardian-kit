# SECURITY.md — `oc-guardian-kit`

## Threat model

The kit's job is to let an operator stand up and run a Fedimint guardian without OC the company holding any material capable of compromising that guardian. Specifically:

| Threat | Mitigation |
|---|---|
| OC compromise → operator infrastructure compromise | Kit runs entirely under operator credentials on operator hardware. OC has zero credentials capable of accessing the operator's machines. |
| Portal compromise → guardian compromise | Every command the guardian acts on requires a signature produced by operator-held key material the portal cannot reach. Portal compromise produces signed-by-attacker requests, which the guardian rejects. |
| Supply-chain attack (kit binary tampered with) | Releases signed via cosign (Sigstore keyless signing) + SLSA Level 3 build provenance. Reproducible builds — operators can verify the binary matches audited source. |
| Operator key theft | Hardware-token-backed by default (YubiKey FIDO2, passkey, OS keychain with per-action user presence). Private key never extractable. |
| Replay of operator-signed commands | Each signed envelope carries a monotonic nonce + expiry timestamp. Guardian persists last-seen nonce per action type; rejects regress / repeats. |
| Confused-deputy attacks via portal | Action allowlist: guardian's local config declares which action types the operator key can authorize. New action types require explicit operator opt-in via `oc-guardian bridge allow <action>`. |
| Denial-of-service against guardian | Standard fedimintd DoS posture (rate limits, peer reputation). Kit adds nothing custodial; outages don't move funds. |
| OC sunset / portal goes dark | Kit works end-to-end without the portal. Operator's relationships, federation memberships, and payouts all survive in operator-controlled state. See [BYPASS.md](./BYPASS.md). |

## Key handling

- **Operator key generation** happens on the operator's hardware via `oc-guardian init --hsm <token>`. The private key never touches a network and never appears in any file system, env var, or log.
- **Application key** (used for the initial program application) is generated on the same hardware. Same lifecycle.
- **Federation key shares** (DKG output) are stored by `fedimintd` per its own security model. Kit does not handle these directly.
- **Charter signing** uses the operator key. Each signature is an Ed25519 signature over the SHA-256 of the canonicalized charter (RFC 8785).
- **Bridge subscriptions** (when the operator opts in to portal bridging) require the operator to acknowledge each authorized action type. The kit never auto-allows new types; the portal cannot escalate.

The kit's rule: **anything that produces authority is operator-hardware-mediated**. The kit's role is to format requests, verify other parties' signatures, and present challenges to the operator's hardware — not to hold or produce signatures itself.

## What OC sees vs. doesn't

OC sees:
- Your operator public key, when you register with the program.
- Application materials you submit (questionnaire answers, references).
- Federation memberships you opt into (because federations are public).
- Your guardian's published status payloads (if you publish them; signed by your key).
- Signed charters you publish (because charters are public).
- Audit log envelopes you choose to publish (signed by your key, optionally OTS-anchored).

OC does NOT see:
- Your operator private key. It's in your YubiKey / passkey / hardware token.
- Your `fedimintd` configuration files, key shares, or database.
- Your operator infrastructure credentials (cloud API keys, SSH keys, server access).
- The contents of any unpublished audit log entries.
- Anything about your guardian unless you publish it.

A hostile OC has no path to your funds, your federation's threshold-signing, or your operator hardware. The architectural posture survives that threat.

## Reporting vulnerabilities

Email `security@ochk.io` (or PGP to the key fingerprint published at `https://ochk.io/.well-known/security.txt`).

We aim to respond within 72 hours. Coordinated-disclosure policy:

- We commit to fixing high/critical vulnerabilities within 30 days and shipping a release.
- We commit to publishing a post-mortem with technical detail and crediting the reporter (unless they prefer anonymity).
- We commit to backporting fixes to the previous minor release line for 90 days after a major version bump.
- We do not currently offer a paid bounty program; we will credit responsibly-disclosed reports prominently in release notes and CHANGELOG.

## Cryptographic primitives

- **Operator identity**: Ed25519 (matches OC family auth), backed by hardware token via WebAuthn / FIDO2 / OS-passkey.
- **Action envelopes**: CBOR canonical encoding, hashed with SHA-256, signed with Ed25519.
- **Replay protection**: monotonic uint64 nonces per action type, persisted in guardian-local state.
- **Charter hashing**: RFC 8785 JSON canonicalization → SHA-256.
- **Audit log entries**: oc-stamp protocol envelope shape, OTS-anchored (optional, operator-chosen).
- **Release verification**: cosign keyless signing (Sigstore + Rekor transparency log) + SLSA Level 3 build provenance attestation.

## Reproducible builds

The kit's release CI builds with `cargo build --release --frozen --locked --offline` against a pinned Rust toolchain in a sandboxed Nix environment. The same source + same toolchain + same dependencies produce a byte-identical binary on any compatible host.

To reproduce a release locally:

```sh
git checkout v0.1.0
nix develop  # pulls the pinned toolchain
cargo build --release --frozen --locked --offline
sha256sum target/release/oc-guardian
# Compare against the published shasum at:
#   https://github.com/orangecheck/oc-guardian-kit/releases/download/v0.1.0/SHA256SUMS
```

The SHA256SUMS file is itself signed by the cosign release key + recorded in Rekor.

## What this kit is NOT

- **Not** a custody service. The kit doesn't hold funds. It coordinates an operator running their own `fedimintd`.
- **Not** a backup service. Operators are responsible for their `fedimintd` state backups; the kit can configure them but doesn't store them.
- **Not** a key escrow. There is no recovery path through OC. If an operator loses their hardware token + their `fedimintd` state, the federation continues with `N-1` guardians per its threshold; the operator exits via `oc-guardian exit-handoff`.
- **Not** a portal-replacement guarantee. Operators who actively choose to use the portal get a different UX; bypass parity guarantees the *capability* to operate without the portal, not that the kit's CLI matches the portal's UX surface-for-surface.
