# OC Guardian Operator · Application Questionnaire

The OC guardian operator program admits applicants who can credibly run an independent Fedimint guardian on infrastructure they control, in good faith, for the long term.

Submit it at [`ochk.app/me/operator/apply`](https://ochk.app/me/operator/apply), where you paste your answers and sign them with your operator key, or by emailing it to `apply@ochk.io` (the email path is documented in `BYPASS.md §01`).

Fill out every section. Sign the resulting JSON envelope with your operator key:

```sh
oc-guardian apply prepare --out application.json --questionnaire ./this-file.md
```

Then email `application.json` and this file, filled in, to `apply@ochk.io`. The envelope carries the SHA-256 and size of your answers, not the answers, so the reviewer needs both. On the portal you paste your answers instead, and the key in your browser signs them.

---

## §A — Identity

A1. **Operator handle** (public; how you'll be listed in charters):

A2. **Operator legal entity** (required; person OR org. if person, just your legal name; if org, the registered legal name + jurisdiction of incorporation):

A3. **Public contact channel** (Nostr npub OR HTTPS endpoint OR PGP-secured email — pick one; will be embedded in charters and used for incident comms):

A4. **PGP fingerprint** (optional; 40-hex-char fingerprint of a key you control. Nothing in the program uses it yet: there is no PGP path for charter signing or anything else):

A5. **Geographic jurisdiction** (country + region):

A6. **Conflicts of interest disclosure** (any affiliation with OrangeCheck, with another OC-affiliated guardian, with a Fedimint federation, or with a major Bitcoin custodian — disclose all; conflicts don't disqualify, but undisclosed conflicts do):

---

## §B — Operational readiness

B1. **Hosting environment** (description of where the guardian will run — your own bare metal, a specific cloud provider + region, a colocation facility — name it specifically):

B2. **Hosting environment disjointness** (which guardians, if any, you share infrastructure with — if you've never run anything before, just say so; we're checking for shared single points of failure):

B3. **Uptime commitment** (% target, recovery time objective, recovery point objective):

B4. **Operations team** (just you? a small team? — describe the bus factor):

B5. **Monitoring + alerting** (how you'll know when your guardian is degraded — be specific; "I'll check it sometimes" is not an answer; "Prometheus + PagerDuty + a runbook for these N alerts" is):

B6. **Incident response capacity** (how fast can you respond to a critical incident; what's your worst-case response time — vacation, sleep, etc.):

B7. **Bus factor / continuity** (if you're hit by a bus, who takes over your guardian; what's the documented handoff procedure):

---

## §C — Custody posture

C1. **Operator hardware token** (which token you would use: YubiKey FIDO2, Ledger, OS passkey, etc.; we recommend a hardware token with user-presence — a simple OS passkey is acceptable for v1. The kit does not use one yet: `--hsm` keeps the key in the OS keychain or a key file, see the README's "What is not built yet"):

C2. **Backup / recovery for the operator key** (how you'll recover if your primary token is lost — backup token? PGP-encrypted seed phrase printed and split across two safes? something else; "I haven't thought about it" is not an answer):

C3. **Federation `fedimintd` state backup strategy** (how often, where, encrypted with what):

C4. **Threat model self-assessment** (your honest assessment of what could go wrong on your watch — a guardian operator who can articulate their own threats is more valuable than one who can't):

---

## §D — Why you

D1. **Why are you doing this** (what's your motivation; what makes this a good fit for you long-term — payouts alone are insufficient):

D2. **What would make you exit** (what would cause you to wind down your guardian; we want operators who plan for graceful exit, not operators who'd just disappear):

D3. **References** (two people who can vouch for your operational competence; ideally one technical, one anything else — could be Fedimint community members, employers, GitHub project maintainers; we'll reach out):

---

## §E — Acknowledgements

E1. I understand that if accepted, I will be listed publicly in any charter I sign, with my legal entity, jurisdiction, and contact channel. ☐ yes

E2. I understand that I am responsible for my own infrastructure, my own operator key, and my own `fedimintd` lifecycle. orangecheck's servers never receive my operator key, and orangecheck cannot recover it on my behalf. A key I keep in ochk.app's browser storage can be read by the script ochk.app serves, which orangecheck deploys; the kit keeps the key in my OS keychain, outside any page. If I choose hosted hardware, orangecheck runs that machine. ☐ yes

E3. I understand what the portal can and cannot do. It cannot push updates to, modify, or shut down a guardian on my own hardware. Charter signatures, seat claims, amendment votes and exit ratifications need my operator key's signature; other operator actions, such as setting a federation's settlement key, take a signed-in ochk.app session rather than a signature, so I guard that session too. The kit signs without the portal, but I upload what it signs on ochk.app, signed in, and claiming a seat and voting on an amendment are signed only in the portal today. No operator key is hardware-backed yet. ☐ yes

E4. I have read [`SECURITY.md`](../SECURITY.md), [`BYPASS.md`](../BYPASS.md), and [`CHARTER-FORMAT.md`](../CHARTER-FORMAT.md). ☐ yes

E5. I have run `oc-guardian init` and have my operator pubkey ready to embed in this application. ☐ yes

---

**Signed envelope:** when you run `oc-guardian apply prepare`, the resulting `application.json` carries the SHA-256 and size of your filled-in answers and your operator pubkey, signed with your operator key. It does not carry the answers: send it with this file, filled in, so the reviewer can check the file against the hash. Acceptance returns a signed envelope you verify with `oc-guardian apply verify-acceptance`.

OC reviewers respond within 14 days. Applications with manual-review concerns may take longer. A reviewer can add a note to a decision saying what to address; a decision does not have to carry one.
