# CHANGELOG

All notable changes to `oc-guardian-kit` are documented here. The
format is loosely based on [Keep a Changelog](https://keepachangelog.com/);
versioning follows [SemVer](https://semver.org/) for the public
surface (CLI flags, action-envelope schemas, file paths under
`~/.config/oc-guardian/`).

## 0.2.0

### Added

- **Real fedimintd lifecycle** (`oc-guardian fedimintd {install,run,status}`)
  — replaces the v0.1 stubs. The guardian's main process on a Fly machine:
  - `config` maps the OC-injected env (`OC_OPERATOR_ID`/`OC_OPERATOR_PUBKEY_HEX`/
    `OC_FEDERATION_SLUG`/`OC_ATTESTATION_POST_URL` + ports 9000 P2P / 9001 API,
    host from `FLY_APP_NAME`) → the `FM_*` env fedimintd reads.
  - `install` downloads + SHA-256-verifies a pinned fedimintd release; refuses
    unpinned versions (never installs an unverified consensus binary).
  - `run` resolves + spawns + supervises fedimintd (restart backoff) and runs
    the attestation ticker.
  - `status` probes the local consensus API.
- **Operator-signed runtime attestation** (NOT TEE) — periodic report
  (version/federation/urls/liveness) signed by the operator key and POSTed to
  `OC_ATTESTATION_POST_URL`. OC cannot forge it; no key present → runs but
  doesn't attest. TEE dropped: §1A's load-bearing property is operator-key
  control + diversity, not hardware attestation.
- **Docker image** (`Dockerfile`) — multi-stage build of `oc-guardian` + a
  pinned, build-time-verified fedimintd; entrypoint `oc-guardian fedimintd run`.
  The release workflow builds, cosign-signs, and pushes
  `ghcr.io/orangecheck/oc-guardian:<tag>` so the Fly deploy path
  (`provisionHosted`) runs a real guardian image.

## Unreleased

### Added

- **Charter fetch / sign / publish** · `oc-guardian charter {fetch,sign,publish}`.
  v0.1 stubs replaced with real implementations covering BYPASS.md §06
  end-to-end · the kit can now ratify an OC-Me federation charter
  without touching the portal UI. `charter fetch <slug>` hits the
  portal's `/api/operator/charter`, prints meta + ratification count.
  `charter sign <slug> --out <path>` produces a hardware-key-signed
  ActionEnvelope (action: `charter-sign`, replay-protected nonce +
  1-hour expiry); self-verifies before writing. `charter publish
  --file <path>` POSTs the envelope to the portal. **Refuses to sign**
  v0-pending fallback charters (unknown federation slugs) with a
  clean error pointing at `docs.ochk.io/federation/<slug>`.

- **Portal client** · `oc-guardian-core::portal_client`. Sync HTTP
  client (ureq, rustls-only TLS for reproducibility, 15s timeout,
  workspace user-agent) for kit-side portal interactions. Respects
  `OC_PORTAL_BASE` env override. Typed deserialization wrappers for
  `CharterFetchResponse`, `CharterMeta`, `CharterSignature`,
  `PublicFederation` mirroring me-web wire shapes field-for-field.
  8 unit tests on URL join + deserialization + env handling.

- **Best-practice infrastructure** · `rustfmt.toml` (stable-only
  formatting rules · workspace-wide 100-col, Unix newlines, import
  reordering), `clippy.toml` (msrv 1.85 pinned, too-many-arguments
  threshold tuned for the CLI's lifecycle dispatch, cognitive-
  complexity threshold 35), `deny.toml` (cargo-deny config ·
  permissive license allowlist, wildcard ban, crates.io-only
  registry, multiple-version detection). New `cargo-deny` job in
  CI alongside `cargo-audit`.

- **`oc-guardian apply verify-acceptance --file <path> --reviewer-pubkey-hex <hex>`**
  — replaces the v0.1 stub with a working Ed25519 verifier for
  reviewer-signed acceptance envelopes. The kit re-canonicalizes the
  payload, checks the signature against the pinned reviewer pubkey, and
  prints diagnostics (operator_id, operator_pubkey, accepted_at,
  reviewer_note, federation_slug, reviewer_kid). Exits 0 on verify, 1
  on any failure (bad sig, malformed envelope, wrong action, expired
  pubkey). Fully offline by design — the operator pulls the JWK once
  from
  [`me.ochk.io/.well-known/oc-operator-reviewer.json`](https://me.ochk.io/.well-known/oc-operator-reviewer.json)
  and pins the `pubkey_hex` field; rotates only when `kid` changes.

- **`AcceptanceEnvelope` + `AcceptancePayload` types** in
  `oc-guardian-core::actions`. Mirror the TypeScript signer at
  `oc-me-web/src/lib/operator/acceptance.ts` field-for-field; canonical
  encoding is byte-identical across both implementations and unit tests
  in both repos lock the field-declaration order in place.

- **Cross-language signed-envelope round-trip is now a tested
  invariant.** Two new core unit tests in `actions::tests` ·
  `acceptance_payload_serializes_in_field_declaration_order` and
  `acceptance_envelope_round_trips_under_ed25519`. Match the TS-side
  cases at `src/__tests__/lib/operator-acceptance.test.ts`.

### Hardened

- **`apply prepare`** now self-verifies the signature it just produced
  against the operator's own pubkey before writing the envelope to
  disk. Catches keychain-rotation races and any signing-pipeline bug
  before the operator emails an unverifiable `application.json`. The
  check uses the same Ed25519 verifier the OC reviewer team would
  run; if it fails locally, the kit refuses to write the file.

### Documentation

- `BYPASS.md` §01 now shows the real `apply verify-acceptance` recipe
  with the JWKS fetch URL (instead of pointing at the stub).
- `CHANGELOG.md` added (this file).

## v0.1.0 — 2026-05-04

Initial public release. Every kit subcommand has its CLI surface
settled; three lifecycle stages are real, the rest emit operator-
visible "v0.2 target" notices with pointers to BYPASS.md.

### Real

- `oc-guardian init [--hsm <backend>] [--config-dir <path>]` —
  generates the operator's Ed25519 identity, persists the private key
  to the OS keychain (Keychain on macOS, libsecret/gnome-keyring on
  Linux, Credential Vault on Windows), writes the public-key file +
  identifier + non-secret kit config to the config dir. Refuses to
  overwrite an existing identity.

- `oc-guardian status` — local-only state report. Operator id, pubkey,
  config dir contents, keychain reachability, hsm backend, bridge
  configuration. Useful before signing anything as a sanity check that
  the kit is reading the operator the operator expects.

- `oc-guardian apply prepare --out <path> --questionnaire <path>` —
  produces a signed `application.json` from a filled-out questionnaire.
  The envelope contains the questionnaire SHA-256 + a signed
  `program-apply` action that the OC reviewer team verifies offline
  against the matching pubkey. Bypass for portal §01 (apply).

### Architectural primitives

- `ActionEnvelope` / `ActionPayload` types · the canonical shape every
  state-changing operator action wraps in. Replay protection (monotonic
  per-action nonce + absolute expiration). Action allowlist (guardian
  rejects any action type the operator key isn't authorized to sign).

- Cosign keyless + SLSA Level 3 release pipeline in
  `.github/workflows/release.yml`. Reproducible builds via
  `cargo build --release --locked` against a pinned 1.85 toolchain.
  Linux + macOS x86_64 + macOS aarch64 targets.

- BYPASS.md — canonical mapping of every portal feature to the kit-only
  equivalent. Bypass parity is an architectural commitment: a guardian
  operating purely via the kit is indistinguishable at the federation
  layer from one using the portal.

### Stubs (v0.2 targets)

- `apply verify-acceptance` (lit up in Unreleased above)
- `register --transport https|email`
- `federations list / inspect / join / leave`
- `ceremony start / status / finalize`
- `charter fetch / sign / publish`
- `payouts claim / list`
- `alerts subscribe / publish`
- `bridge enable / disable / allow-action`

Each stub prints "not yet implemented in v0.1.0 — see BYPASS.md or run
`oc-guardian <cmd> --help`" with a pointer to the architecture brief
at `~/Projects/ochk/GUARDIAN-PROGRAM-DESIGN.md` (workspace root in
the OrangeCheck monorepo layout).
