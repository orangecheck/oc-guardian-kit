# CHARTER-FORMAT.md — federation charter document spec

The charter is the human-readable + machine-checkable contract a federation publishes that operators sign to ratify their guardian seat. Consumers verify it before depositing into the federation.

This file specifies the **canonical form** of the charter — the exact bytes that get hashed when an operator signs.

## File layout

A charter is a single Markdown file with a YAML frontmatter header. The frontmatter contains the structured metadata; the body is the prose contract.

```markdown
---
charter_version: 1
federation_id: 7c9f3a2e...
federation_name: BitSacco Sokoni
ratified_at: 2026-05-15T12:00:00Z
threshold:
  m: 3
  n: 4
guardians:
  - operator_id: op-3f7a8b2e
    legal_entity: BitSacco Cooperative Society Ltd
    jurisdiction: KE
    api_endpoint: https://guard-1.bitsacco.example/api
    contact: security@bitsacco.example
    pgp_fingerprint: 2A4F 1B3D 5E7C 9A0F 1234 5678 ABCD EF01 23 45 6789
  - operator_id: op-9c2d1e4f
    legal_entity: Foo Bar Corp
    jurisdiction: US-NY
    api_endpoint: https://guard-2.example.com/api
    contact: ops@example.com
    pgp_fingerprint: 1C3E 5F7A 8B0D 2F4E 1234 5678 ABCD EF01 23 45 6789
  # ... 4 entries for a 3-of-4 federation
gateways:
  - operator: Lightning Lab Inc
    api_endpoint: https://ln-gateway.example.com
    fee_schedule_url: https://ln-gateway.example.com/.well-known/oc-fee-schedule
exit_clause:
  on_federation_sunset: "every user can withdraw on-chain via threshold-signed transaction without OC services"
  on_charter_amendment: "30-day notice + supermajority of guardians sign the new revision; old charter remains valid for in-flight deposits"
amendment_process:
  who_can_propose: "any guardian or affiliate"
  ratification: "supermajority of guardians sign the new revision"
  notice_period_days: 30
---

# BitSacco Sokoni · Federation Charter

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

The kit's `oc-guardian charter sign` runs steps 1–5 internally; operators don't need to handle canonicalization manually. Other tools that produce charter signatures must produce byte-identical canonical bytes — see `crates/oc-guardian-charter/tests/canon-vectors.json` for test vectors.

## Required sections (per the program's §1 properties)

A charter must include these sections to be acceptable for the OC operator program:

| Section | Spec'd in frontmatter | Spec'd in body |
|---|---|---|
| Identity (federation_name, federation_id, ratified_at) | ✓ | — |
| Custody promise (threshold, m-of-n) | ✓ | + prose explanation |
| Guardian disclosures (entity, jurisdiction, contact, fingerprint) | ✓ per guardian | + per-guardian short bio |
| OC's role | — | "OC the company is a client of this federation, not a guardian" — verbatim or equivalent |
| Lightning gateway disclosure | ✓ per gateway | + fee schedule reference |
| Exit clause (sunset, amendment) | ✓ | + prose explanation |
| Dispute resolution | — | how a user files a complaint, who responds, escalation path |
| Amendment process | ✓ | + ratification flow |

Missing required sections cause the kit's `charter validate` to fail; operators should not sign such charters.

## Required §1 property checks

The kit also runs the §1 property checks from `oc-me-web/FEDERATION-DEPLOYMENT.md` against the charter:

- §1.1 Guardian count ≥ 4.
- §1.2 Threshold strictly > N/2.
- §1.3 Operational independence (manual review surfaced via `--describe`).
- §1.5 ≥ 1 non-OC LN gateway.
- §1.6 No `*.ochk.io` in `guardians[].api_endpoint`.
- §1.7 Exit clause present.

`oc-guardian charter validate <file>` reports each property's pass/fail/manual-review status. Operators should not sign charters with failing properties.

## Test vectors

`crates/oc-guardian-charter/tests/charter-vectors/` ships:

- `valid-3of4.md` — fully compliant charter.
- `valid-4of7.md` — larger federation, multiple jurisdictions.
- `invalid-2of3.md` — rejected at §1.1 (guardian count too low).
- `invalid-2of4.md` — rejected at §1.2 (threshold not strictly > N/2).
- `invalid-oc-guardian.md` — rejected at §1.6 (`*.ochk.io` listed as guardian).

Each vector ships with its expected canonical bytes + SHA-256 hash for cross-implementation verification.

## Versioning

`charter_version` is monotonic. v1 is described above. v2+ revisions document changes here and ship migration notes; v1 charters remain valid for in-flight deposits per the standard amendment process.
