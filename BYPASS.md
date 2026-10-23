# BYPASS.md — every portal feature has a kit-only equivalent

**Audience:** operators who want to participate in the OC guardian operator program *without ever touching the [`ochk.app/me/operator`](https://ochk.app/me/operator) portal*. This document is a first-class artifact maintained at parity with the portal — a portal feature is **not done** until its bypass is documented and verified working.

**Architectural commitment:** A guardian operating purely via the kit is **architecturally indistinguishable** at the federation layer from a guardian operating with the portal. Both produce the same envelopes, sign with the same operator key, and are accepted by federations and consumers identically.

---

## Table of equivalents

Every row here is a portal route the operator might land on, paired with the kit-only path that does the same thing. Both paths are supported. Both are documented at parity. The kit-only path never depends on `ochk.app/me/operator` being online.

| # | Lifecycle stage | Portal path | Kit-only equivalent |
|---|---|---|---|
| 01 | Apply to the program | `ochk.app/me/operator/apply`: paste your answers, signed with the key in your browser | Email `apply@ochk.io` with the application questionnaire — see [§01 below](#01-apply-to-the-program) |
| 02 | Get accepted + onboarded | Portal registers the key in your browser | `oc-guardian init` (OS keychain, or `--key-file` on a server) — see [§02](#02-get-accepted--onboarded) |
| 03 | Discover federations seeking guardians | Portal lists federations with seats open | `oc-guardian federations list` (the same directory, read directly) — see [§03](#03-discover-federations-seeking-guardians) |
| 04 | Join a federation | Portal mediates the seat and the charter | A seat assignment plus your charter ratification — see [§04](#04-join-a-federation) |
| 05 | Run the DKG ceremony | Portal drives the setup API of the seats it hosts | `oc-guardian ceremony {start, add-peer, dkg, status, finalize}` on your own guardian — see [§05](#05-run-the-dkg-ceremony) |
| 06 | Sign the federation charter | Portal renders the charter and asks your key to sign | `oc-guardian charter {fetch, sign, publish}` — see [§06](#06-sign-the-federation-charter) |
| 07 | Run the guardian | Portal shows install + run instructions | `oc-guardian fedimintd run` — see [§07](#07-run-the-guardian) |
| 08 | Operational status | Portal dashboard | `oc-guardian status`, `oc-guardian fedimintd status`, `oc-guardian verify-status` — see [§08](#08-operational-status) |
| 09 | Receive incident alerts | Portal alerts feed | The portal's published incidents; the kit has no feed yet — see [§09](#09-receive-incident-alerts) |
| 10 | Post an incident update | Portal "post update", signed by your key | `oc-guardian alerts post` writes a signed envelope — see [§10](#10-post-an-incident-update) |
| 11 | Track payouts | Portal shows accrued payouts + claim button | `oc-guardian payouts claim <slug> --to <lightning-address>` signs a claim — see [§11](#11-track-payouts) |
| 12 | Graceful exit | Portal coordinates handoff to replacement | `oc-guardian exit-handoff --federation <slug> --replacement <pubkey> --effective-date <date>` — see [§12](#12-graceful-exit) |
| 13 | Deauthenticate from portal | Portal "delete account" button | `oc-guardian portal forget` clears local state; your guardian is unaffected — see [§13](#13-deauthenticate-from-portal) |
| 14 | Let a hosted guardian attest | "Let this guardian attest" on the seat's hosted status | `oc-guardian attest-delegate --federation <slug> --seat <n> --attest-pubkey <hex> --block-height <h> --block-hash <hash>` — see [§14](#14-let-a-hosted-guardian-attest) |

---

## §01 — Apply to the program

**Portal path:** `ochk.app/me/operator/apply`. Paste your answers; the key in your browser signs them, with proof that your account holds that key, and a reviewer reads them.

**Bypass:**

1. Get the application questionnaire from this repo at [`docs/application-questionnaire.md`](./docs/application-questionnaire.md).
2. Fill it out, then sign it with your operator key:

   ```sh
   oc-guardian apply prepare --out application.json --questionnaire ./answers.md
   ```

   This produces a signed application envelope you can attach to email. The envelope contains a hash of the questionnaire content.

3. Email `apply@ochk.io` with the signed envelope as an attachment. Subject line: `OC Guardian Application — <your handle>`.

4. The OC reviewer team verifies your envelope's signature offline, runs the same vetting as the portal-mediated path, and replies via email with a reviewer-signed acceptance envelope (`acceptance-app_….json`). Verify it locally before trusting the email body:

   ```sh
   # one-time: pin the reviewer's public key from the JWKS endpoint
   curl -s https://me.ochk.io/.well-known/oc-operator-reviewer.json | jq

   oc-guardian apply verify-acceptance \
     --file acceptance-app_<your-id>.json \
     --reviewer-pubkey-hex <pinned-hex>
   ```

   A green check confirms the email genuinely came from OC; an unverified envelope means do not act on it.

The data flowing through this path is byte-for-byte identical to what the portal would have submitted. The portal is a UI; the email channel is the same protocol carried over a different transport.

---

## §02 — Get accepted + onboarded

**Portal path:** the portal registers the key in your browser.

**Bypass:**

```sh
# Generate your operator identity. The private key goes in your OS keychain.
oc-guardian init

# On a server with no OS keychain, keep the key in a file instead (mode 0600).
# The file is the key: anyone who can read it can sign as you.
oc-guardian init --key-file /var/lib/oc-guardian/operator.key

# Either way this writes:
#   ~/.config/oc-guardian/operator.pub  — your Ed25519 public key
#   ~/.config/oc-guardian/operator.id   — operator identifier (hash of pubkey)

# Check whether your key is in the public operator registry (it is once accepted).
oc-guardian register
```

`--hsm yubikey | ledger | passkey` is accepted, but no hardware-token backend is built yet: the key still goes in the OS keychain. The registry is the public list of accepted operator keys at `me.ochk.io/api/operator/registry`.

---

## §03 — Discover federations seeking guardians

**Portal path:** [ochk.app/me/operator/federations](https://ochk.app/me/operator/federations) lists federations with seats open.

**Bypass:**

```sh
oc-guardian federations list
```

This reads the public federation directory at `me.ochk.io/api/federations` (no auth), the same one the portal renders. Set `OC_PORTAL_BASE` to read another deployment.

---

## §04 — Join a federation

**Portal path:** the portal's seat and charter flow.

**Bypass:** joining is two things, not one envelope: an orangecheck admin assigns you a guardian seat once your application is accepted, and you ratify the federation's charter ([§06](#06-sign-the-federation-charter)), which is your join. `oc-guardian federations join <slug>` prints those steps.

---

## §05 — Run the DKG ceremony

**Portal path:** for seats orangecheck hosts, the portal calls each guardian's setup API in turn.

**Bypass:** on a guardian you run, the kit makes the same four calls to fedimintd 0.11's setup API on that machine. The password comes from `--password-file` or `FM_PASSWORD` and never crosses the network.

```sh
# Each guardian: name and password. The leader also names the federation and its size.
oc-guardian ceremony start --name g0 --leader --federation-name my-fed --federation-size 4
oc-guardian ceremony start --name g1
#   → prints this guardian's setup code; send it to every other guardian

oc-guardian ceremony add-peer --code <code> --code <code> --code <code>
oc-guardian ceremony dkg
oc-guardian ceremony status      # until RUNNING, as fedimintd itself reports it
oc-guardian ceremony finalize    # prints the invite code
```

DKG runs guardian to guardian over the P2P port. **Run `ceremony start` as soon as the guardian boots**: until local params are set, whoever reaches the setup API first sets the password and takes the seat. Progress is kept in `<FM_DATA_DIR>/oc-ceremony.json`.

---

## §06 — Sign the federation charter

**Portal path:** the portal renders the charter, computes its hash and asks your key to sign.

**Bypass:**

```sh
# Review what you would commit to: hash, version, canonical URL, ratifications.
oc-guardian charter fetch <federation-slug>

# Sign it with your operator key.
oc-guardian charter sign <federation-slug> --out charter-sig.json

# Publish your signature to the portal's /api/operator/charter (HTTPS only).
oc-guardian charter publish --file charter-sig.json
```

The charter signature is an Ed25519 signature over the canonical charter; it is the same bytes however it travels.

---

## §07 — Run the guardian

**Portal path:** the portal shows install + run instructions.

**Bypass:** install the kit (README §Install), then:

```sh
oc-guardian fedimintd install --version 0.11.4 --dir /usr/local/bin   # pinned, hash-checked
oc-guardian fedimintd run --config /usr/local/bin/fedimintd           # --config is the fedimintd binary
```

Settings come from the environment (README §Running fedimintd): who you are, the network (required, no default), the chain source, your public host, and any fedimintd binds of your own, which the kit passes through unchanged. Run it under your own service manager; the kit ships no unit file.

---

## §08 — Operational status

**Portal path:** the portal dashboard.

**Bypass:**

```sh
oc-guardian status              # your local identity, key store and bridge setting
oc-guardian fedimintd status    # whether fedimintd answers, and its setup phase
oc-guardian verify-status       # whether your key is in the public operator registry
```

---

## §09 — Receive incident alerts

**Portal path:** the portal alerts feed.

**Bypass:** published incidents are at `ochk.app/me/operator/incidents` and on the public federation timeline. The kit has no alert feed of its own yet; `oc-guardian alerts subscribe <slug>` says where to look.

---

## §10 — Post an incident update

**Portal path:** the portal's "post update", signed by your key.

**Bypass:**

```sh
oc-guardian alerts post \
    --federation <slug> \
    --severity warning \
    --body "guardian-3 unreachable since 09:14 UTC; investigating"
```

Writes `incident.json`, a signed envelope in the shape the portal takes at `/api/operator/incidents`.

---

## §11 — Track payouts

**Portal path:** the portal's accrued payouts and claim button.

**Bypass:**

```sh
oc-guardian payouts claim <federation-slug> --to you@wallet.example [--amount <sats>]
```

Writes a claim envelope signed with your operator key. Accrued figures are only shown signed in on the portal; `oc-guardian payouts list` says so.

---

## §12 — Graceful exit

**Portal path:** the portal's exit flow.

**Bypass:**

```sh
oc-guardian exit-handoff \
    --federation <slug> \
    --replacement <new-operator-pubkey> \
    --effective-date 2026-06-15
```

Produces a signed handoff envelope. The other guardians countersign it with `oc-guardian exit-ratify`.

---

## §13 — Deauthenticate from portal

**Portal path:** the portal's "delete account" button.

**Bypass:**

```sh
oc-guardian portal forget
```

This removes the kit's local operator state (the config dir and the keychain entry) on this machine. It sends nothing to the portal. Your guardian keeps running, and federations know you by your operator key, not a portal account. The portal bridge (`oc-guardian bridge …`) is not built yet, so there is nothing to disable.

---

## §14 — Let a hosted guardian attest

**Portal path:** "Let this guardian attest" on the seat's hosted status at `ochk.app/me/operator/federations/<slug>`.

A guardian on orangecheck-hosted hardware never holds your operator key, so it signs its liveness attestations with a key of its own. Its attestations count for your seat only once you sign a delegation to that key. The key signs liveness and nothing else, and a hosted guardian's liveness is only as independent as orangecheck, which runs the machine.

**Bypass:**

```sh
# The machine key is on the seat's hosted status. Take a bitcoin mainnet block
# within 6 of the tip, even for a signet or testnet federation: the portal
# dates what you sign against mainnet.
oc-guardian attest-delegate \
    --federation <slug> \
    --seat 0 \
    --attest-pubkey <64-hex machine key> \
    --days 180 \
    --block-height <recent mainnet height> \
    --block-hash <its hash>
```

Writes `attest-delegation.json`, signed with your operator key, in the shape the portal takes at `/api/operator/federations/<slug>/seats/<n>/attest-delegation`. `--seat` counts from 0: the portal's "Seat 1" is 0. A delegation runs at most 366 days. Revoking one is the portal's button; it needs no signature, because revoking only narrows what a key may do.

---

## How we test bypass parity

Some of what the kit signs is pinned by a cross-language test, where bytes or a signature made by one side's code are checked by the other's: runtime attestations, settlement receipts, the operator id derived from a key, and attest delegations. The other envelopes (application, charter signature, payout claim, exit and ratification) are checked against the portal's validators by hand, not yet by a shared test.

There is no end-to-end bypass suite against a live federation yet. It runs on the test federation once that is up.

---

## Maintenance

When a portal feature changes, this file changes with it, and a feature that touches what an operator signs gets a cross-language test on both sides.
