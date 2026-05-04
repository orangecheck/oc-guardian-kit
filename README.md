# oc-guardian-kit

**The operator's actual control surface for running an OrangeCheck-affiliated Fedimint guardian.** Self-serve. Operator-controlled. Composes with `fedimintd` rather than replacing it. Optional companion to the [`me.ochk.io/operator`](https://me.ochk.io/operator) portal — the kit works end-to-end without ever touching the portal.

> **Architectural commitment:** OC the company never custodies funds, never operates guardians, never holds the surfaces that determine federation behavior. This kit is the tooling that makes that commitment scale.
>
> **Property the kit guarantees:** every action runs under operator-controlled credentials on operator-controlled infrastructure. OC has no access to your hardware, your keys, your `fedimintd`, or your operator identity at any point. The portal at `me.ochk.io/operator` is convenience, not control — it can request signatures from your hardware, but it cannot produce them.

## Install

Verified-release install (recommended):

```sh
# 1. Pull the signed release.
gh release download v0.1.0 -R orangecheck/oc-guardian-kit -p '*x86_64-linux-gnu*'

# 2. Verify against the cosign attestation.
cosign verify-blob \
  --certificate-identity-regexp 'https://github.com/orangecheck/oc-guardian-kit' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --signature oc-guardian-x86_64-linux-gnu.sig \
  --bundle oc-guardian-x86_64-linux-gnu.bundle \
  oc-guardian-x86_64-linux-gnu.tar.gz

# 3. Verify against the SLSA Level 3 provenance attestation (for reproducible-build assurance).
slsa-verifier verify-artifact \
  --provenance-path oc-guardian-x86_64-linux-gnu.intoto.jsonl \
  --source-uri github.com/orangecheck/oc-guardian-kit \
  --source-tag v0.1.0 \
  oc-guardian-x86_64-linux-gnu.tar.gz

# 4. Extract + place on PATH.
tar -xzf oc-guardian-x86_64-linux-gnu.tar.gz
sudo install oc-guardian /usr/local/bin/
```

Build-from-source install (for the trust-no-binaries among us):

```sh
git clone --depth 1 --branch v0.1.0 https://github.com/orangecheck/oc-guardian-kit
cd oc-guardian-kit
cargo build --release --frozen --locked --offline  # reproducible: hash matches release
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

## Optional portal bridge

Operators who want the portal at `me.ochk.io/operator` to drive their guardian (push UI for ceremony, dashboards, signing requests) opt in via:

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

A client implies a server it talks to. The kit implies a toolbox the operator runs against their own infrastructure. There is no central server you depend on; the portal at `me.ochk.io/operator` is one of many surfaces the kit can interoperate with, and operators can choose to use none of them.
