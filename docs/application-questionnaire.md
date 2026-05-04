# OC Guardian Operator · Application Questionnaire

The OC guardian operator program admits applicants who can credibly run an independent Fedimint guardian on infrastructure they control, in good faith, for the long term.

This questionnaire is the same whether you submit it via the [`guardian.ochk.io/apply`](https://guardian.ochk.io/apply) portal or by emailing it to `apply@ochk.io`. The portal renders the same fields; the email path is documented in `BYPASS.md §01`.

Fill out every section. Sign the resulting JSON envelope with your operator key:

```sh
oc-guardian apply prepare --out application.json --questionnaire ./this-file.md --hsm yubikey
```

Then either submit via the portal or attach the signed envelope to an email to `apply@ochk.io`.

---

## §A — Identity

A1. **Operator handle** (public; how you'll be listed in charters):

A2. **Operator legal entity** (required; person OR org. if person, just your legal name; if org, the registered legal name + jurisdiction of incorporation):

A3. **Public contact channel** (Nostr npub OR HTTPS endpoint OR PGP-secured email — pick one; will be embedded in charters and used for incident comms):

A4. **PGP fingerprint** (40-hex-char fingerprint of a key you control; for charter signing fallback if your hardware-token-backed operator key is unavailable):

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

C1. **Operator hardware token** (which token: YubiKey FIDO2, Ledger, OS passkey, etc.; we recommend a hardware token with user-presence — a simple OS passkey is acceptable for v1):

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

E2. I understand that I am responsible for my own infrastructure, my own operator key, and my own `fedimintd` lifecycle. OC the company has no access to any of these and cannot recover any of them on my behalf. ☐ yes

E3. I understand that the OC operator portal is convenience, not control. I can operate my guardian end-to-end without ever using the portal. The portal cannot push updates, modify, or shut down my guardian — every action requires my hardware-key signature. ☐ yes

E4. I have read [`SECURITY.md`](../SECURITY.md), [`BYPASS.md`](../BYPASS.md), and [`CHARTER-FORMAT.md`](../CHARTER-FORMAT.md). ☐ yes

E5. I have run `oc-guardian init` and have my operator pubkey ready to embed in this application. ☐ yes

---

**Signed envelope:** when you run `oc-guardian apply prepare`, the resulting `application.json` carries your filled-in answers + your operator pubkey, signed with your hardware key. Submit that file. Acceptance returns a signed envelope you verify with `oc-guardian apply verify-acceptance`.

OC reviewers respond within 14 days. Applications with manual-review concerns may take longer. Decisions include the reasoning so applicants who aren't admitted know what to address.
