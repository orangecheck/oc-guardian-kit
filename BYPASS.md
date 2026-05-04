# BYPASS.md — every portal feature has a kit-only equivalent

**Audience:** operators who want to participate in the OC guardian operator program *without ever touching the [`me.ochk.io/operator`](https://me.ochk.io/operator) portal*. This document is a first-class artifact maintained at parity with the portal — a portal feature is **not done** until its bypass is documented and verified working.

**Architectural commitment:** A guardian operating purely via the kit is **architecturally indistinguishable** at the federation layer from a guardian operating with the portal. Both produce the same envelopes, sign with the same operator key, and are accepted by federations and consumers identically.

---

## Table of equivalents

Every row here is a portal route the operator might land on, paired with the kit-only path that does the same thing. Both paths are supported. Both are documented at parity. The kit-only path never depends on `me.ochk.io/operator` being online.

| # | Lifecycle stage | Portal path | Kit-only equivalent |
|---|---|---|---|
| 01 | Apply to the program | [me.ochk.io/operator/apply](https://me.ochk.io/operator/apply) | Email `apply@ochk.io` with the application questionnaire — see [§01 below](#01-apply-to-the-program) |
| 02 | Get accepted + onboarded | Portal walks WebAuthn key registration in your browser | `oc-guardian init --hsm <yubikey\|ledger\|passkey\|os-keychain>` — see [§02](#02-get-accepted--onboarded) |
| 03 | Discover federations seeking guardians | Portal lists federations with seats open | `oc-guardian federations list` (queries the same public registry directly) — see [§03](#03-discover-federations-seeking-guardians) |
| 04 | Join a federation | Portal mediates introduction + opt-in | `oc-guardian federations join <slug>` against the federation's public coordinator URL — see [§04](#04-join-a-federation) |
| 05 | Run the DKG ceremony | Portal coordinates message passing between guardians | `oc-guardian ceremony start --peers <urls>` — direct authenticated HTTPS between guardians, see [§05](#05-run-the-dkg-ceremony) |
| 06 | Sign the federation charter | Portal renders charter, requests WebAuthn signature | `oc-guardian charter sign --file charter.md --hsm yubikey` — see [§06](#06-sign-the-federation-charter) |
| 07 | Run the guardian | Portal shows install + run instructions | `oc-guardian fedimintd run --config /etc/oc-guardian/config.toml` — see [§07](#07-run-the-guardian) |
| 08 | Operational status | Portal dashboard mirrors guardian's status | Guardian's local `/status` endpoint + `oc-guardian status` CLI — see [§08](#08-operational-status) |
| 09 | Receive incident alerts | Portal hosts alerts feed | Subscribe to the federation's published Nostr alerts channel directly — see [§09](#09-receive-incident-alerts) |
| 10 | Post an incident update | Portal mediates the message + signs authorship | `oc-guardian alerts post --severity <level> --body <message>` signs locally — see [§10](#10-post-an-incident-update) |
| 11 | Track payouts | Portal shows accrued payouts + claim button | `oc-guardian payouts list` queries the federation's payout ledger directly — see [§11](#11-track-payouts) |
| 12 | Graceful exit | Portal coordinates handoff to replacement | `oc-guardian exit-handoff <replacement-pubkey>` + bilateral peer communication — see [§12](#12-graceful-exit) |
| 13 | Deauthenticate from portal | Portal "delete account" button | `oc-guardian bridge disable` + ignore the portal forever; your guardian is unaffected — see [§13](#13-deauthenticate-from-portal) |

---

## §01 — Apply to the program

**Portal path:** fill out [me.ochk.io/operator/apply](https://me.ochk.io/operator/apply); WebAuthn-sign the application; submit.

**Bypass:**

1. Download the application questionnaire from [me.ochk.io/operator/apply](https://me.ochk.io/operator/apply) (also tracked in this repo at [`docs/application-questionnaire.md`](./docs/application-questionnaire.md)).
2. Fill it out. Generate an Ed25519 application key locally:

   ```sh
   oc-guardian apply prepare --out application.json --hsm yubikey
   ```

   This produces a signed application envelope you can attach to email. The envelope contains a hash of the questionnaire content.

3. Email `apply@ochk.io` with the signed envelope as an attachment. Subject line: `OC Guardian Application — <your handle>`.

4. The OC reviewer team verifies your envelope's signature offline, runs the same vetting as the portal-mediated path, and replies via email with an acceptance envelope you can verify with `oc-guardian apply verify-acceptance --file acceptance.json`.

The data flowing through this path is byte-for-byte identical to what the portal would have submitted. The portal is a UI; the email channel is the same protocol carried over a different transport.

---

## §02 — Get accepted + onboarded

**Portal path:** Portal opens a WebAuthn registration prompt, generates a credential bound to your hardware token, registers the public key with the OC operator registry.

**Bypass:**

```sh
# Generate your operator identity locally. Backed by hardware token of
# your choice; private key never leaves the token.
oc-guardian init --hsm yubikey

# This produces:
#   ~/.config/oc-guardian/operator.pub  — your Ed25519 public key
#   ~/.config/oc-guardian/operator.id   — operator identifier (hash of pubkey)
# The private key stays inside the YubiKey.

# Register your public key with the OC operator registry. Default
# transport is HTTPS to the registry's public endpoint; can also be
# done via signed email to operators-registry@ochk.io.
oc-guardian register --transport https        # default
oc-guardian register --transport email        # for operators behind firewalls
```

The registry is just a list of operator public keys. It's published as an OC envelope at `https://ochk.io/.well-known/oc-guardian-operators.json`, signed by the OC release key. Federations consult this list when matching guardians to seats. Operators can register without ever loading any web UI.

---

## §03 — Discover federations seeking guardians

**Portal path:** [me.ochk.io/operator/federations](https://me.ochk.io/operator/federations) lists federations with seats open.

**Bypass:**

```sh
oc-guardian federations list
```

This queries `https://federations.ochk.io/api/v1/seats-open` (a public read-only endpoint, no auth required). The portal queries the same endpoint and renders it as cards.

Or query directly without the kit:

```sh
curl -s https://federations.ochk.io/api/v1/seats-open | jq
```

---

## §04 — Join a federation

**Portal path:** Portal "join" button → in-portal WebAuthn-signed opt-in → federation organizer notified.

**Bypass:**

```sh
oc-guardian federations join <federation-slug>
```

This produces a signed join-request envelope and POSTs it to the federation's published coordinator URL (e.g. `https://federation-foo.example/oc-coordinator/join`). The federation organizer accepts (or rejects) and replies with a signed acceptance envelope.

If the federation prefers email coordination:

```sh
oc-guardian federations join <federation-slug> --transport email
```

Generates the same signed envelope and exits with instructions on what to email and where.

---

## §05 — Run the DKG ceremony

**Portal path:** Portal hosts a real-time ceremony coordinator that pipes messages between participating guardians' kits.

**Bypass:**

```sh
# Each guardian runs:
oc-guardian ceremony start \
    --peers https://guard-1.example.com,https://guard-2.example.com,https://guard-3.example.com \
    --setup-code <code-from-federation-organizer>
```

The ceremony is direct authenticated HTTPS between guardian processes. Each `oc-guardian` exposes a temporary listener on `:8174` (configurable) during the ceremony. The cryptographic protocol is identical regardless of how messages arrive — portal-mediated WebSocket relay is a transport optimization, not a different ceremony.

Ceremony progress is logged locally in `~/.local/share/oc-guardian/ceremony-<id>.log`.

---

## §06 — Sign the federation charter

**Portal path:** Portal renders the charter, computes its SHA-256, requests WebAuthn signature, broadcasts the signed acceptance.

**Bypass:**

```sh
# Fetch the charter (or use a local copy).
oc-guardian charter fetch <federation-slug> > charter.md

# Sign it with your hardware key.
oc-guardian charter sign --file charter.md --hsm yubikey > charter-signature.json

# Publish your signature. Default transport is HTTPS POST to the
# federation's coordinator. Bypass: publish as a Nostr event signed
# by your operator key, OR email it to the federation organizer.
oc-guardian charter publish --file charter-signature.json
oc-guardian charter publish --file charter-signature.json --transport nostr
oc-guardian charter publish --file charter-signature.json --transport email
```

The charter signature is just an Ed25519 signature over the SHA-256 of the canonicalized charter document. The signature is the same byte sequence regardless of transport.

---

## §07 — Run the guardian

**Portal path:** Portal shows tutorial pages with one-click "copy install command."

**Bypass:** Read this README. The kit is the install command.

```sh
# Verify your release (see README §Install).
# Then:
oc-guardian fedimintd run --config /etc/oc-guardian/config.toml

# Or as a systemd service (Ansible playbook bundled):
sudo cp ansible/debian-systemd/oc-guardian.service /etc/systemd/system/
sudo systemctl enable --now oc-guardian
```

---

## §08 — Operational status

**Portal path:** Portal dashboard polls each operator's signed `/status` endpoint and renders.

**Bypass:**

```sh
# Read your own guardian's status locally:
oc-guardian status

# Or read another guardian's published status (their kit signs the
# response with their operator key, so you can verify it without
# trusting the portal as a middleman):
curl -s https://your-guardian.example/.well-known/oc-guardian-status.json | \
    oc-guardian verify-status
```

The `/status` JSON is signed by the operator's key with a freshness timestamp. The portal mirror is a UI; the signed JSON is the truth.

---

## §09 — Receive incident alerts

**Portal path:** Portal alerts feed.

**Bypass:** subscribe to the federation's Nostr alerts channel. Each federation publishes its alerts pubkey in its charter. Use any Nostr client; OC's kit also has:

```sh
oc-guardian alerts subscribe <federation-slug>
```

Which prints alerts to stderr as they arrive. Filter via `--severity ge warning`, `--since 24h`, etc.

---

## §10 — Post an incident update

**Portal path:** Portal "post update" UI, WebAuthn-signed, broadcast.

**Bypass:**

```sh
oc-guardian alerts post \
    --severity warning \
    --federation <slug> \
    --body "guardian-3 unreachable since 2026-05-04 09:14 UTC; investigating"
```

Signs locally, publishes as a Nostr event under the federation's alerts channel.

---

## §11 — Track payouts

**Portal path:** Portal "accrued payouts" view + claim button.

**Bypass:**

```sh
oc-guardian payouts list <federation-slug>
oc-guardian payouts claim <federation-slug> --to <bitcoin-address>
```

Queries the federation's payout ledger directly. Claim is a signed envelope POSTed to the federation's payout endpoint (or emailed, per the operator's preference).

---

## §12 — Graceful exit

**Portal path:** Portal "exit federation" coordination flow.

**Bypass:**

```sh
oc-guardian exit-handoff \
    --federation <slug> \
    --replacement <new-operator-pubkey> \
    --effective-date 2026-06-15
```

Produces a signed handoff envelope. Distribute to the federation organizer + remaining guardians via the federation's existing coordination channel (email, Signal, Nostr — whatever the federation uses). The replacement guardian's onboarding follows the standard ceremony flow with the existing guardians as peers.

---

## §13 — Deauthenticate from portal

**Portal path:** Portal "delete account" button.

**Bypass:**

```sh
# 1. If you'd been bridging the portal:
oc-guardian bridge disable

# 2. Optionally tell the portal to forget you (revokes its mirror of
#    your relationships; your guardian's federation memberships are
#    unaffected — federations track you by your operator pubkey, not
#    by your portal account):
oc-guardian portal forget
```

Or: never run those commands. Your guardian is unaffected by the portal's existence. There is no kill-switch the portal can pull on you — it never had push capability over your guardian to begin with.

---

## How we test bypass parity

Every release runs the bypass test suite (`tests/bypass/`) which exercises the kit-only path for each of §01-§13 against a live test federation. The test asserts that the resulting envelope, signature, and on-the-wire protocol output is byte-for-byte identical to what the portal-mediated path produces.

A release is blocked if any bypass test fails. The portal cannot ship a feature whose bypass path doesn't work.

---

## Maintenance

When a portal feature changes, this file changes in the same PR. The PR template enforces: "Did you update BYPASS.md?" — answer must be yes for any feature that touches the portal's `pages/`, `pages/api/`, or any operator-facing flow.

Bypass parity is a tested, enforced, first-class architectural property — not a documentation aspiration.
