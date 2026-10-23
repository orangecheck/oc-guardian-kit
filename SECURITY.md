# SECURITY.md — `oc-guardian-kit`

## Threat model

The kit's job is to let an operator stand up and run a Fedimint guardian without orangecheck holding anything that could take that guardian over. That holds for a seat the operator runs. While the system is in testing, orangecheck runs every test seat itself ([ochk.app/custody](https://ochk.app/custody)), and for those seats it holds everything.

| Threat | Mitigation |
|---|---|
| orangecheck compromise → operator infrastructure compromise | For a seat you run, the kit runs under your credentials on your hardware; orangecheck holds no credential for your machines. |
| Portal compromise → guardian compromise | Everything that carries an operator's authority is signed by the operator key on the operator's machine. The portal can ask for a signature; it cannot make one. |
| Someone else sets up your guardian first | Until DKG has run, fedimintd's setup API needs no password until local params are set, and fedimintd forgets them on every restart. `fedimintd run` will not start such a guardian with its setup reachable from other machines unless the setup gate is on (`OC_GUARDIAN_SETUP_PASSWORD`: fedimintd's API stays on loopback and only calls carrying that password pass; with `OC_GUARDIAN_NAME` the kit sets local params itself) or the operator passes `--allow-public-setup`. The setup UI binds loopback by default. |
| Supply-chain attack (kit binary tampered with) | Releases are signed with cosign (Sigstore keyless) and carry a SLSA build provenance attestation from GitHub Actions; each archive has a published SHA-256. Build from source with `--locked` to check a binary yourself. |
| Operator key theft | The key lives in the OS keychain, or with `init --key-file` in a file readable by you only. Both are software: anyone who controls your account can use it. Hardware-token backends are not built yet. |
| Replay of operator-signed envelopes | Each envelope carries a nonce (unix seconds) and an expiry; the portal rejects a nonce equal to or lower than one it has seen. |
| Confused-deputy attacks via portal | The portal bridge, which would carry portal requests to the kit, is not built; the kit acts on no portal request. |
| Denial-of-service against guardian | Standard fedimintd posture. The kit adds nothing custodial; an outage moves no funds. |
| orangecheck sunset / portal goes dark | The kit signs everything an operator signs without the portal. Federation membership is by operator key. See [BYPASS.md](./BYPASS.md). |

## Key handling

- **Operator key generation** happens on the operator's machine with `oc-guardian init`. The private key goes in the OS keychain, or in the file given with `--key-file` (mode 0600). It is never sent anywhere.
- **Federation key shares** (DKG output) are stored by `fedimintd` per its own security model. The kit does not handle them.
- **Charter signing** uses the operator key: an Ed25519 signature over the canonical charter (RFC 8785).
- **A hosted guardian** never holds the operator key. It signs liveness reports with a key of its own, which counts for the seat only under a delegation the operator signed (README §Hosted guardians).

## What orangecheck sees vs. doesn't

For a seat you run, orangecheck sees:
- Your operator public key, when you apply and are accepted.
- Application materials you submit (questionnaire answers, references).
- Federation memberships (federations are public).
- Liveness attestations your guardian sends, signed by your key.
- Signed envelopes you publish to the portal: charter ratifications, incidents, payout claims, exits.

It does not see:
- Your operator private key. It is in your OS keychain or your key file, on your machine.
- Your `fedimintd` configuration, key shares or database.
- Your infrastructure credentials (cloud API keys, SSH keys, server access).
- Anything about your guardian you do not send.

For a seat you run, a hostile orangecheck has no path to your keys or to your federation's threshold signing. For the seats orangecheck hosts today, it runs the machines and holds everything on them.

## Reporting vulnerabilities

Email `security@ochk.io`.

We aim to reply to every report within 30 days. We can't promise a time to a fix yet. Coordinated-disclosure policy:

- We commit to publishing a post-mortem with technical detail and crediting the reporter (unless they prefer anonymity).
- We do not currently offer a paid bounty program; we will credit responsibly-disclosed reports prominently in release notes and CHANGELOG.

## Cryptographic primitives

- **Operator identity**: Ed25519.
- **Action envelopes**: the payload's `serde_json` bytes, signed with Ed25519.
- **Replay protection**: a nonce and an expiry in every envelope, checked by the portal.
- **Charter hashing**: RFC 8785 JSON canonicalization → SHA-256.
- **Release verification**: cosign keyless signing (Sigstore + Rekor transparency log) and a SLSA build provenance attestation.

## Building it yourself

Release CI builds with `cargo build --release --locked` on a pinned Rust toolchain (1.85), so dependency versions come from `Cargo.lock`. The build is not yet checked for byte-identical reproducibility. To build and compare yourself:

```sh
git checkout v0.2.6
cargo build --release --locked -p oc-guardian-cli
sha256sum target/release/oc-guardian
```

## What this kit is NOT

- **Not** a custody service. The kit doesn't hold funds. It coordinates an operator running their own `fedimintd`.
- **Not** a backup service. Operators are responsible for their `fedimintd` state backups; the kit can configure them but doesn't store them.
- **Not** a key escrow. There is no recovery path through orangecheck. If an operator loses their operator key and their `fedimintd` state, the federation continues with `N-1` guardians per its threshold; the operator exits via `oc-guardian exit-handoff`.
- **Not** a portal-replacement guarantee. Operators who actively choose to use the portal get a different UX; bypass parity guarantees the *capability* to operate without the portal, not that the kit's CLI matches the portal's UX surface-for-surface.
