# CHARTER-FORMAT.md — federation charter document spec

The charter is the human-readable + machine-checkable contract a federation publishes that operators sign to ratify their guardian seat. Consumers verify it before depositing into the federation.

This file specifies the **canonical form** of the charter — the exact bytes that get hashed when an operator signs.

> **What the kit does today.** `oc-guardian charter fetch <slug>` prints the charter's federation, version, hash, URL, publish time and signature count from the portal, not its text. `oc-guardian charter sign <slug>` signs the hash the portal serves without recomputing it from the canonical bytes (`crates/oc-guardian-charter`). To check that hash, rebuild the bytes and take their SHA-256 yourself. Every charter in the OC operator program so far is portal-published, in the plain-text form under [Portal-published charters](#portal-published-charters). The Markdown + YAML form below, with its RFC 8785 canonicalization, `charter validate` and test vectors, is specified here but not built.

## File layout

A charter is a single Markdown file with a YAML frontmatter header. The frontmatter contains the structured metadata; the body is the prose contract.

```markdown
---
charter_version: 1
federation_id: 7c9f3a2e...
federation_name: Example Riverside Federation
ratified_at: 2026-05-15T12:00:00Z
threshold:
  m: 3
  n: 4
guardians:
  - operator_id: op-3f7a8b2e
    legal_entity: Example Guardian One Ltd
    jurisdiction: KE
    api_endpoint: https://guard-1.example.org/api
    contact: security@example.org
    pgp_fingerprint: 2A4F 1B3D 5E7C 9A0F 1234 5678 ABCD EF01 23 45 6789
  - operator_id: op-9c2d1e4f
    legal_entity: Example Guardian Two Inc
    jurisdiction: US-NY
    api_endpoint: https://guard-2.example.com/api
    contact: ops@example.com
    pgp_fingerprint: 1C3E 5F7A 8B0D 2F4E 1234 5678 ABCD EF01 23 45 6789
  # ... 4 entries for a 3-of-4 federation
gateways:
  - operator: Example Gateway Co
    api_endpoint: https://ln-gateway.example.com
    fee_schedule_url: https://ln-gateway.example.com/.well-known/oc-fee-schedule
exit_clause:
  on_federation_sunset: "90 days' notice; users holding ecash in their own Fedimint client redeem it to Lightning or on-chain before shutdown"
  on_charter_amendment: "30-day notice + supermajority of guardians sign the new revision; old charter remains valid for in-flight deposits"
amendment_process:
  who_can_propose: "any guardian or affiliate"
  ratification: "supermajority of guardians sign the new revision"
  notice_period_days: 30
---

# Example Riverside Federation · Federation Charter

[prose body — guardian disclosures, custody promise, SLA commitments,
dispute resolution, etc.]
```

## Canonicalization

The charter hash is computed over **canonical bytes**, not the raw file:

1. Parse the YAML frontmatter into a structured object.
2. Apply RFC 8785 JSON canonicalization to the structured object → `meta_canon_bytes`.
3. UTF-8 NFC-normalize the prose body → `body_nfc_bytes`.
4. Concatenate: `meta_canon_bytes || 0x0a || body_nfc_bytes`.
5. SHA-256 the result.

The hex-encoded SHA-256 is the charter's hash. Operators sign this hash with their hardware key; consumers verify against it.

Not built: no kit command runs these steps yet, and there are no test vectors. `oc-guardian charter sign` signs the hash the portal serves, without recomputing it.

## Portal-published charters

The portal publishes the charter of `oc-me-v1` and of every self-serve federation as a plain-text block of `key: value` lines, the charter's "canonical bytes". Its hash is the SHA-256 of those exact UTF-8 bytes: newlines LF, one trailing newline, nothing parsed or normalized. `oc-me-v1`'s blocks are on its charter page, [docs.ochk.io/federation/oc-me-v1](https://docs.ochk.io/federation/oc-me-v1); a self-serve federation's block is built from its federation row, so anyone can rebuild it.

`GET /api/operator/charter?federation=<slug>` serves the current version (`meta.charter_version`, `meta.charter_hash`) and every signature recorded for the federation, each marked `matches_current_charter`. The portal refuses a signature over any hash but the current one, and only a seated guardian's signature over the current hash counts toward ratification.

A new version is a new hash. The versions it replaced stay listed under `meta.superseded`, each with its `charter_version`, `charter_hash`, `superseded_at` and `reason`. A signature over a superseded hash is kept as history and never counts, so every guardian signs the new version. `oc-me-v1` v1.0.0 (hash `58f5ac78…d4e8`) is superseded by v1.1.0: its exit clause, on-chain withdrawal by a threshold-signed transaction, describes a path that was never built.

## Required sections (per the program's §1 properties)

A charter must include these sections to be acceptable for the OC operator program:

| Section | Spec'd in frontmatter | Spec'd in body |
|---|---|---|
| Identity (federation_name, federation_id, ratified_at) | ✓ | — |
| Custody promise (threshold, m-of-n) | ✓ | + prose explanation |
| Guardian disclosures (entity, jurisdiction, contact, fingerprint) | ✓ per guardian | + per-guardian short bio |
| OC's role | — | "OC the company is a client of this federation, not a guardian" — verbatim or equivalent |
| Lightning gateway disclosure | ✓ per gateway | + fee schedule reference |
| Exit clause (sunset, amendment) | ✓ | + prose explanation; it states the exit that is built and working for this federation's users, not a planned one |
| Dispute resolution | — | how a user files a complaint, who responds, escalation path |
| Amendment process | ✓ | + ratification flow |

Operators should not sign a charter missing a required section.

## Required §1 property checks

These are the §1 property checks from `oc-me-web/FEDERATION-DEPLOYMENT.md` a charter must pass. Not built: no kit command runs them yet.

- §1.1 Guardian count ≥ 4.
- §1.2 Threshold strictly > N/2.
- §1.3 Operational independence (manual review surfaced via `--describe`).
- §1.5 ≥ 1 non-OC LN gateway.
- §1.6 No `*.ochk.io` in `guardians[].api_endpoint`.
- §1.7 Exit clause present.

Operators should not sign a charter that fails one.

## Test vectors

Not built. Planned for `crates/oc-guardian-charter/tests/charter-vectors/`:

- `valid-3of4.md` — fully compliant charter.
- `valid-4of7.md` — larger federation, multiple jurisdictions.
- `invalid-2of3.md` — rejected at §1.1 (guardian count too low).
- `invalid-2of4.md` — rejected at §1.2 (threshold not strictly > N/2).
- `invalid-oc-guardian.md` — rejected at §1.6 (`*.ochk.io` listed as guardian).

Each vector would ship with its expected canonical bytes + SHA-256 hash for cross-implementation verification.

## Versioning

`charter_version` is monotonic. v1 is described above. v2+ revisions document changes here and ship migration notes. For a portal-published charter, a new version is a new hash, and the old one moves to `meta.superseded` (see [Portal-published charters](#portal-published-charters)).
