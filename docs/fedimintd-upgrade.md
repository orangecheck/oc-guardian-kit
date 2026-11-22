# Moving the pinned fedimintd

The kit pins fedimintd 0.11.4. This is what moves together when that pin
changes, and what to check on the way. The next move is to the 0.13 line.

## Already in place on 0.11.4

- `fedimintd run` sets `FM_PASSWORD_API` and `FM_PASSWORD_UI` from the guardian
  password. From 0.12, fedimintd answers admin calls (the setup API's
  `set_local_params`, `get_setup_code`, `add_peer_setup_code` and `start_dkg`
  included) only with that password, and never reads it from disk.
- It refuses to start a set-up guardian whose `password.private` holds a
  different password.
- It sets `FM_ENABLE_IROH=false` and the v1 module set (`FEDERATION_DEFAULTS` in
  `crates/oc-guardian-fedimint/src/config.rs`). From 0.12, a new federation
  otherwise gets iroh and the v2 modules only.

## Pins to move, in this repository

- [ ] `Dockerfile`: `ARG FEDIMINTD_VERSION`, the `.deb` sha256 build arg and the
      comment that names both.
- [ ] `crates/oc-guardian-fedimint/src/install.rs`: version, URL and sha256 of
      the `fedimintd-v*` release asset.
- [ ] `.github/workflows/release.yml`: the `FEDIMINTD_VERSION` default, and the
      repository variable of the same name if it is set.
- [ ] `README.md` and `BYPASS.md`: "fedimintd 0.11", `install --version 0.11.4`,
      and the client's Esplora note.
- [ ] Doc comments that describe 0.11's setup API: `ceremony.rs`, `gate.rs`,
      `config.rs` (`is_set_up`, `PASSWORD_FILE`) and `run.rs`
      (`setup_exposure`). From 0.12 the setup password is fixed when fedimintd
      starts, not by the first `set_local_params` call. The setup gate still
      keeps the setup API off the network until DKG.
- [ ] `meta.rs`: the meta module's `federation_successor` keys and the invite
      code vector, read again from the new version's source.

## Check against the new version's source

- [ ] Every name in `FEDERATION_DEFAULTS` still exists (`fedimint-core`
      `envs.rs`), parses `true`/`false`, and still means the same module.
- [ ] `SetupStatus`, `SetLocalParamsRequest` and `ApiRequest { auth, params }`
      are unchanged (they are byte-identical from 0.11.4 to 0.13.0).
- [ ] The core and module consensus versions, and the server database
      migrations, against 0.11.4's.
- [ ] The DKG version rule: 0.12 needs the same release on every guardian of a
      new federation, 0.13 the same major.minor.
- [ ] The release notes' upgrade section, and the security policy
      (`SECURITY.md`: fixes go to the latest stable line only).

## Prove it before release

- [ ] Run the onboarding examples' `guardian/local-federation.sh` with the new
      kit and the new fedimintd: four guardians, the ceremony, a client join.
- [ ] Upgrade a running local federation one guardian at a time and watch
      consensus continue.
- [ ] Read each fedimintd's environment from `/proc/<pid>/environ` and its
      log, as the 0.11.4 check did: the six `FM_ENABLE_*` values and both
      passwords present, no "invalid" warning, no restart.

## Elsewhere

The me.ochk.io portal pins the same fedimintd for its executor's client, the
hosted guardian image and the shared gateway. Its own checklist moves with it.

The operator docs' test-stack page names the pinned version and its install
command (oc-docs `src/pages/me/operator/test-stack.mdx`, "What the kit pins").
