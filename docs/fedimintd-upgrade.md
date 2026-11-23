# Moving the pinned fedimintd

The kit pins fedimintd 0.13.0, and keeps 0.11.4 installable. This is what
moves together when that pin changes, and what to check on the way.

## Rules that hold from 0.12

- `fedimintd run` sets `FM_PASSWORD_API` and `FM_PASSWORD_UI` from the guardian
  password. From 0.12, fedimintd answers admin calls (the setup API's
  `set_local_params`, `get_setup_code`, `add_peer_setup_code` and `start_dkg`
  included) only with that password, and never reads it from disk. The kit
  refuses to start fedimintd 0.12 or later without a guardian password.
- It refuses to start a guardian set up on 0.11 whose `password.private`
  holds a different password. 0.13 reads that file to open the guardian's
  encrypted private config, so it stays on an upgraded guardian. A guardian
  set up on 0.12 or later has no such file.
- It sets `FM_ENABLE_IROH=false`, all six module flags (`FEDERATION_DEFAULTS`
  in `crates/oc-guardian-fedimint/src/config.rs`) and `FM_IROH_NEXT_ENABLE=false`.
  From 0.12, a new federation otherwise gets iroh and the v2 modules only.
- DKG needs one fedimintd `major.minor` on every guardian (0.12: the same
  release). A new federation's guardians, hosted ones included, all run the
  same kit line. A running federation upgrades one guardian at a time.

## Pins to move, in this repository

- `Dockerfile`: `ARG FEDIMINTD_VERSION` and `ARG FEDIMINTD_SHA256`, the .deb's
  hash. The release workflow builds what the Dockerfile pins.
- `crates/oc-guardian-fedimint/src/install.rs`: version, URL and sha256 of
  the `fedimintd-v*` release asset.
- `README.md` and `BYPASS.md`: the version named, `install --version`, and
  the client's Esplora note.
- Doc comments that describe the setup API: `ceremony.rs`, `gate.rs`,
  `config.rs` and `run.rs`.
- `meta.rs`: the meta module's `federation_successor` keys and the invite
  code vector, read again from the new version's source.

## Check against the new version's source

- Every name in `FEDERATION_DEFAULTS` still exists (`fedimint-core`
  `envs.rs`, `fedimintd-envs`), parses `true`/`false`, and still means the
  same module. Each module's `is_enabled_by_default` with our flags gives
  ln, lnv2, mint, wallet and meta.
- `SetupStatus`, `SetLocalParamsRequest` and `ApiRequest { auth, params }`
  are unchanged, and so are the endpoint names the kit and the portal call.
- The core and module consensus versions, and the server database
  migrations.
- The release notes' upgrade section, and the security policy
  (`SECURITY.md`: fixes go to the latest stable line only).

## Prove it before release

- Run the onboarding examples' `guardian/local-federation.sh` with the new
  kit and the new fedimintd: four guardians, the ceremony, a client join, on
  the new client and on the oldest client still in use (the executor's).
- Upgrade a running local federation one guardian at a time and watch
  consensus continue.
- Read each fedimintd's environment from `/proc/<pid>/environ` and its
  log: the settings above and both passwords present, no "invalid" warning,
  no restart.

## Elsewhere

The me.ochk.io portal pins the same fedimintd for its executor's client, the
hosted guardian image and the shared gateway. Its own checklist moves with it
(oc-me-web `FEDERATION-DEPLOYMENT.md` §5.5).

The operator docs' test-stack page names the pinned version and its install
command (oc-docs `src/pages/me/operator/test-stack.mdx`, "What the kit pins"),
and the onboarding examples pin the kit release and fedimint's hashes
(`guardian/local-federation.sh`).
