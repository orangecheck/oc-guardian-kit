# oc-guardian-kit

**The operator's actual control surface for running an OrangeCheck-affiliated Fedimint guardian.** Self-serve. Operator-controlled. Composes with `fedimintd` rather than replacing it. Optional companion to the [`ochk.app/me/operator`](https://ochk.app/me/operator) portal — the kit works end-to-end without ever touching the portal.

> **Architectural commitment:** OC the company never custodies funds, never operates guardians, never holds the surfaces that determine federation behavior. This kit is the tooling that makes that commitment scale.
>
> **Property the kit guarantees:** every action runs under operator-controlled credentials on operator-controlled infrastructure. OC has no access to your hardware, your keys, your `fedimintd`, or your operator identity at any point. The portal at `ochk.app/me/operator` is convenience, not control — it can request signatures from your hardware, but it cannot produce them.

## Install

Verified-release install (recommended). Archives exist for
`x86_64-unknown-linux-gnu`, `aarch64-apple-darwin` and `x86_64-apple-darwin`:

```sh
T=x86_64-unknown-linux-gnu
# 1. Pull the signed release.
gh release download v0.2.4 -R orangecheck/oc-guardian-kit -p "oc-guardian-$T.*"

# 2. Verify the cosign keyless signature.
cosign verify-blob \
  --certificate-identity-regexp 'https://github.com/orangecheck/oc-guardian-kit' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --bundle "oc-guardian-$T.bundle" \
  "oc-guardian-$T.tar.gz"

# 3. Verify the build provenance attestation (SLSA v1, GitHub artifact attestations).
gh attestation verify "oc-guardian-$T.tar.gz" -R orangecheck/oc-guardian-kit

# 4. Extract + place on PATH.
tar -xzf "oc-guardian-$T.tar.gz"
sudo install oc-guardian /usr/local/bin/
oc-guardian --version
```

Build-from-source install (for the trust-no-binaries among us):

```sh
git clone --depth 1 --branch v0.2.4 https://github.com/orangecheck/oc-guardian-kit
cd oc-guardian-kit
cargo build --release --locked -p oc-guardian-cli  # dependency versions pinned by Cargo.lock
sudo install target/release/oc-guardian /usr/local/bin/
```

## Quickstart

```sh
# Generate your operator identity (Ed25519). Stored in your OS keychain
# OR backed by a hardware token (--hsm yubikey | ledger | passkey).
oc-guardian init --hsm yubikey

# Apply to the program. Bypass: email apply@ochk.io with the same content.
oc-guardian apply

# Once accepted, you'll be matched with a federation seeking guardians.
oc-guardian federations list
oc-guardian federations join <federation-slug>

# Participate in the DKG ceremony with the other guardians.
oc-guardian ceremony start --peers '<peer1-url>,<peer2-url>,<peer3-url>'

# Sign the federation charter. Hardware key signs; OC sees only the
# signature.
oc-guardian charter sign --file charter.md

# Run the guardian.
oc-guardian fedimintd run --config /etc/oc-guardian/config.toml

# Day-to-day operations.
oc-guardian status                          # health + peer view
oc-guardian alerts list                     # subscribed federation alerts
oc-guardian audit log --since 24h           # local audit ledger
```

## Lifecycle commands

Every lifecycle stage of the program (recruitment → exit) has a kit command. The portal mirrors the same stages but routes through the same primitives. See [BYPASS.md](./BYPASS.md) for the canonical mapping.

| Stage | Command |
|---|---|
| Application | `oc-guardian apply` |
| Onboarding | `oc-guardian init` |
| Federation matching | `oc-guardian federations {list, join, leave}` |
| Ceremony | `oc-guardian ceremony {start, status, finalize}` |
| Charter signing | `oc-guardian charter {fetch, sign, publish}` |
| Status | `oc-guardian status` |
| Incident comms | `oc-guardian alerts {subscribe, post}` |
| Payouts | `oc-guardian payouts {list, claim}` |
| Exit | `oc-guardian exit-handoff <replacement-pubkey>` |

## Hosted guardians

A guardian on orangecheck-hosted hardware never holds your operator key. It signs its liveness attestations with a key of its own, which orangecheck generates and hands to the machine as a write-only Fly secret. Those attestations count for your seat only after you sign a delegation to that key on `ochk.app`, and only until it expires or you revoke it. A new machine gets a new key, and the delegation to the old one stops counting.

That key signs liveness and nothing else: not the charter, a payout claim, an exit, a ratification or a vote. Those still take your operator key.

**A hosted guardian's liveness is only as independent as orangecheck**, which runs the machine and made its key. Where that matters, run the guardian on hardware you control.

## Optional portal bridge

Operators who want the portal at `ochk.app/me/operator` to drive their guardian (push UI for ceremony, dashboards, signing requests) opt in via:

```sh
oc-guardian bridge enable                   # subscribe to portal action requests
oc-guardian bridge allow <action-type>      # explicit allowlist per action
```

When the bridge is enabled, the kit accepts portal-signed action *requests*. Each request becomes a notification in the kit; the kit then asks the operator's hardware key to sign the request. The signed action is what actually applies. **The portal never produces a signature on the operator's behalf.**

Disable any time:

```sh
oc-guardian bridge disable                  # operator's guardian keeps running
```

## Documentation

- [`BYPASS.md`](./BYPASS.md) — every portal feature ↔ kit-only equivalent. First-class, maintained at parity.
- [`SECURITY.md`](./SECURITY.md) — threat model, key handling, what OC sees vs. doesn't.
- [`CHARTER-FORMAT.md`](./CHARTER-FORMAT.md) — canonical charter document spec (RFC 8785 JSON).
- [Source](https://github.com/orangecheck/oc-guardian-kit) — open source, MIT.
- [Releases](https://github.com/orangecheck/oc-guardian-kit/releases) — signed; verified via cosign + SLSA.

## License

MIT. See [LICENSE](./LICENSE).

## Why "kit" not "client"?

A client implies a server it talks to. The kit implies a toolbox the operator runs against their own infrastructure. There is no central server you depend on; the portal at `ochk.app/me/operator` is one of many surfaces the kit can interoperate with, and operators can choose to use none of them.
