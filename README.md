# oc-guardian-kit

**The operator's own tooling for running a Fedimint guardian in an orangecheck federation.** Self-serve. Composes with `fedimintd` rather than replacing it. Optional companion to the [`ochk.app/me/operator`](https://ochk.app/me/operator) portal: everything an operator signs, the kit can sign without the portal.

> **Where things stand.** While the system is in testing, orangecheck holds every role, guardian seats included: it runs every test seat, on its own hardware, with its own keys ([ochk.app/custody](https://ochk.app/custody) shows the live picture). The kit is how independent operators take those seats over. orangecheck as the lasting operator is never the design.
>
> **What the kit guarantees for a seat you run yourself:** your operator key stays on your machine, and anything that carries your authority (a charter ratification, a payout claim, an exit) is signed there. The portal can ask; it cannot sign for you.

## Install

Verified-release install (recommended). Archives exist for
`x86_64-unknown-linux-gnu`, `aarch64-apple-darwin` and `x86_64-apple-darwin`:

```sh
T=x86_64-unknown-linux-gnu
# 1. Pull the latest signed release (name a tag after "download" to pin one).
gh release download -R orangecheck/oc-guardian-kit -p "oc-guardian-$T.*"

# 2. Verify the cosign keyless signature.
cosign verify-blob \
  --certificate-identity-regexp 'https://github.com/orangecheck/oc-guardian-kit' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --bundle "oc-guardian-$T.bundle" \
  "oc-guardian-$T.tar.gz"

# 3. Verify the build provenance attestation (SLSA v1, GitHub artifact attestations).
gh attestation verify "oc-guardian-$T.tar.gz" -R orangecheck/oc-guardian-kit

# 4. Extract + place on PATH.
tar -xzf "oc-guardian-$T.tar.gz"
sudo install oc-guardian /usr/local/bin/
oc-guardian --version
```

Build-from-source install:

```sh
git clone https://github.com/orangecheck/oc-guardian-kit
cd oc-guardian-kit
git checkout "$(git describe --tags --abbrev=0)"  # the latest release
cargo build --release --locked -p oc-guardian-cli  # dependency versions pinned by Cargo.lock
sudo install target/release/oc-guardian /usr/local/bin/
```

## Quickstart

```sh
# 1. Your operator identity (Ed25519). The private key goes in your OS keychain.
oc-guardian init
#    On a server with no OS keychain (init fails with a DBus error), keep it in
#    a file instead. The file is the key: anyone who can read it can sign as you.
oc-guardian init --key-file /var/lib/oc-guardian/operator.key
#    Bind it to your ochk.app account: ochk.app/me/operator shows this command
#    filled in, and takes the bind-claim.json it writes.
oc-guardian bind --did <your did:oc> --block-height <h> --block-hash <hash>

# 2. Apply. Email apply@ochk.io the signed envelope this writes.
oc-guardian apply prepare --out application.json --questionnaire ./answers.md

# 3. Once accepted and given a seat, review and ratify the federation's charter.
oc-guardian charter fetch <federation-slug>
oc-guardian charter sign <federation-slug> --out charter-sig.json
oc-guardian charter publish --file charter-sig.json

# 4. Run the guardian. Its settings come from the environment ("Running
#    fedimintd"). Until DKG is done its setup must not be reachable from other
#    machines, so give it a setup password (or bind its API and UI to 127.0.0.1).
OC_GUARDIAN_SETUP_PASSWORD=… oc-guardian fedimintd run

# 5. Set up the federation with the other guardians, with the same password
#    (see "The DKG ceremony").
FM_PASSWORD=… oc-guardian ceremony start --name <your-guardian-name>
```

## Running fedimintd

`oc-guardian fedimintd run` supervises a `fedimintd` 0.11 process: it starts it, restarts it with backoff, and sends signed liveness reports. `--config` is the path of the `fedimintd` binary to run; without it, `fedimintd` is taken from `PATH`. `oc-guardian fedimintd install --version 0.11.4 [--dir <dir>]` downloads a pinned, hash-checked release.

Settings come from the environment:

| Variable | Required | Meaning |
|---|---|---|
| `OC_OPERATOR_ID`, `OC_OPERATOR_PUBKEY_HEX`, `OC_FEDERATION_SLUG` | yes | who runs this seat, in which federation |
| `OC_BITCOIN_NETWORK` | yes | `bitcoin`, `testnet`, `testnet4`, `signet` or `regtest`. There is no default. |
| `OC_ESPLORA_URL`, or `OC_BITCOIND_URL` + `OC_BITCOIND_USERNAME` + `OC_BITCOIND_PASSWORD` | yes | the chain source fedimintd watches |
| `OC_PUBLIC_HOST` | yes, off Fly | the name peers and clients reach this guardian at (on Fly, `<app>.fly.dev`) |
| `OC_P2P_PORT`, `OC_API_PORT`, `OC_UI_PORT` | no | 9000, 9001, 8175 |
| `FM_BIND_P2P`, `FM_BIND_API`, `FM_BIND_UI`, `FM_P2P_URL`, `FM_API_URL`, `FM_DATA_DIR` | no | fedimintd's own settings. Set them and the kit passes them through unchanged. |
| `OC_GUARDIAN_SETUP_PASSWORD` | no | turns on the setup gate (below) until DKG is done |
| `OC_GUARDIAN_NAME`, and on the leader `OC_FEDERATION_NAME` + `OC_FEDERATION_SIZE` | no | with the setup password: the kit sets this guardian's local params itself |

Without your own binds, P2P and the API listen on all interfaces (peers and clients need them), and the **setup UI listens on 127.0.0.1 only**. The API URL is `ws://` for a loopback host and `wss://` otherwise (behind TLS); set `FM_API_URL` for anything else.

**Until DKG has run, whoever reaches the setup API first sets the guardian's password.** fedimintd serves its setup API on the API port and needs no password until local params are set, so the first caller claims the guardian. It also forgets local params, and comes back with a new setup code, every time it restarts. So `fedimintd run` will not start a guardian that has not finished DKG while its setup API or UI can be reached from other machines. Choose one of:

- **The setup gate: set `OC_GUARDIAN_SETUP_PASSWORD`.** Until DKG writes the consensus config, the kit keeps fedimintd's API on loopback and answers the public API port itself. It passes on `setup_status` and `invite_code` to anyone, and every other call only if it carries that password; it refuses JSON-RPC batches. Once DKG is done it hands the port back to fedimintd. Use the same password for the ceremony (`FM_PASSWORD` or `--password-file`).
  - **With `OC_GUARDIAN_NAME` as well** (and, on the leader, `OC_FEDERATION_NAME` and `OC_FEDERATION_SIZE`), the kit sets local params itself, at boot and again after every restart. Until it has, the public port answers every call with "this guardian is starting" (JSON-RPC error -32003), so it never offers unset params. Read the setup code with `oc-guardian ceremony status`, or `get_setup_code` with the password. After a restart the code is new, so send it to the other guardians again.
- **Bind the API and UI to loopback** (`FM_BIND_API=127.0.0.1:9001`) until DKG is done, then restart with the public bind. DKG runs over P2P; peers never call each other's API during it.
- **`--allow-public-setup`** starts it anyway, with a warning. Run `oc-guardian ceremony start` at once; a restart before DKG reopens the window.

**On Fly**, the setup UI isn't one of the app's public services. To reach it over the org's private network with `fly proxy 8175:8175 -a <app>`, bind it to the machine's private IPv6 address (the one `fly-local-6pn` names in `/etc/hosts`): `FM_BIND_UI=[<that address>]:8175`. Every machine in the org can reach that address, not just yours.

**More than one guardian on a host:** fedimintd's metrics listen on 127.0.0.1:8176 by default, so give each guardian its own `FM_BIND_METRICS`. Give each its own operator config dir too: `--config-dir <dir>` (or `OC_GUARDIAN_CONFIG_DIR`) works with every command.

**Ports:** choose ports below Linux's ephemeral range (32768–60999 by default). Any outgoing connection on the machine can take a port in that range, and a guardian that loses its P2P port during DKG restarts, forgets its setup, and leaves the ceremony to be run again.

**Where fedimintd runs:** the upstream `fedimintd` release the kit pins is a nix bundle. On hosts that restrict unprivileged user namespaces (Ubuntu 23.10 and later by default) it fails with "Cannot bind mount /dev … Permission denied". The guardian image installs upstream's `.deb` instead. On such a host, install that `.deb`, or unpack the bundle: `fedimintd --extract` unpacks into the current directory (`dat/nix/store`, plus `env` and `run`). The unpacked binary's loader and libraries point into `/nix/store`, so it does not run directly. Point `--config` at a wrapper that starts it through the loader it was built for:

```sh
#!/bin/sh
S=/path/to/dat/nix/store
BIN=$(ls "$S"/*-fedimintd-*/bin/fedimintd)
LD=$S/$(grep -aom1 '/nix/store/[a-z0-9]*-glibc-[^/]*/lib/ld-linux[a-z0-9_.-]*' "$BIN" | cut -d/ -f4-)
exec "$LD" --library-path "$(dirname "$LD"):$(ls -d "$S"/*/lib | tr '\n' ':')" "$BIN" "$@"
```

## The DKG ceremony

fedimintd 0.11 sets a federation up in four steps. The kit takes them through the setup API on the same machine, so the guardian password never crosses the network. The password comes from `--password-file` or `FM_PASSWORD`.

```sh
# Every guardian: name and password. The leader also names the federation and its size.
oc-guardian ceremony start --name g0 --leader --federation-name my-fed --federation-size 4
oc-guardian ceremony start --name g1
#   → prints this guardian's setup code. Send it to every other guardian.

# Every guardian: add every other guardian's code.
oc-guardian ceremony add-peer --code <code-of-g1> --code <code-of-g2> --code <code-of-g3>

# Every guardian, once all codes are in.
oc-guardian ceremony dkg

# Until it says RUNNING. It reports what fedimintd itself says, never just "the port answers".
oc-guardian ceremony status

# Once running: records it and prints the invite code.
oc-guardian ceremony finalize
```

The portal at `ochk.app/me/operator` drives the same four calls for the seats orangecheck hosts. Seats it hosts are set up from the portal; the kit is for seats you run.

## Lifecycle commands

Every lifecycle stage of the program (application → exit) has a kit command. See [BYPASS.md](./BYPASS.md) for the mapping to the portal.

| Stage | Command |
|---|---|
| Application | `oc-guardian apply {prepare, verify-acceptance}` |
| Onboarding | `oc-guardian init`, `oc-guardian register` (checks the registry), `oc-guardian bind` (binds the key to your ochk.app account) |
| Federations | `oc-guardian federations list` (`join` and `leave` print the steps) |
| Ceremony | `oc-guardian ceremony {start, add-peer, dkg, status, finalize}` |
| Charter | `oc-guardian charter {fetch, sign, publish}` |
| Run | `oc-guardian fedimintd {install, run, status}` |
| Local state | `oc-guardian status` |
| Incidents | `oc-guardian alerts post` |
| Payouts | `oc-guardian payouts claim <slug> --to <lightning-address>` |
| Exit | `oc-guardian exit-handoff`, `oc-guardian exit-ratify` |
| Hosted attestations | `oc-guardian attest-delegate` |

## What needs the portal

Only these commands call `me.ochk.io` (or `OC_PORTAL_BASE`): `register`, `verify-status`, `federations list` and `charter {fetch, sign, publish}`. `bind`, `alerts post`, `payouts claim`, `exit-handoff`, `exit-ratify` and `attest-delegate` sign locally and write a file you upload, signed in, on the ochk.app page the kit names (BYPASS.md, "Submitting what the kit signs"). `bind`, `exit-ratify` and `attest-delegate` need a recent bitcoin mainnet block (height and hash, within 6 of the tip). Everything else is local.

## Two fedimint behaviours to know

- After DKG, fedimintd publishes its API address to public pkarr relays unless `FM_PKARR_ENABLE=false`.
- The fedimint 0.11.4 client watches for deposits through Esplora only. Point it at one with `FM_DEFAULT_BITCOIN_RPC_KIND=esplora` and `FM_DEFAULT_BITCOIN_RPC_URL=<esplora url>`.

## What is not built yet

- **Hardware tokens.** `--hsm yubikey | ledger | passkey` is accepted and does nothing different: the key goes in the OS keychain (or the `--key-file` you gave). A hardware token that never releases the key is planned, not shipped.
- **The portal bridge.** `oc-guardian bridge {enable, allow, disable, status}` only logs that it is a stub. Nothing subscribes to portal requests, and no allowlist is kept.
- **Transports other than HTTPS.** `charter publish --transport` takes `https` only. `register` and `federations join` accept `--transport` and ignore it.
- **`alerts subscribe`, `payouts list`, `audit log --since`.** They point at the portal or list local files; there is no feed, ledger query or time filter.

## Hosted guardians

A guardian on orangecheck-hosted hardware never holds your operator key. It signs its liveness attestations with a key of its own, which orangecheck generates and hands to the machine as a write-only Fly secret. Those attestations count for your seat only after you sign a delegation to that key on `ochk.app`, and only until it expires or you revoke it. A new machine gets a new key, and the delegation to the old one stops counting.

That key signs liveness and nothing else: not the charter, a payout claim, an exit, a ratification or a vote. Those still take your operator key.

**A hosted guardian's liveness is only as independent as orangecheck**, which runs the machine and made its key. Where that matters, run the guardian on hardware you control.

## Documentation

- [`BYPASS.md`](./BYPASS.md) — every portal feature and its kit-only equivalent.
- [`SECURITY.md`](./SECURITY.md) — threat model, key handling, what orangecheck sees and doesn't.
- [`CHARTER-FORMAT.md`](./CHARTER-FORMAT.md) — canonical charter document spec (RFC 8785 JSON).
- [Source](https://github.com/orangecheck/oc-guardian-kit) — open source, MIT.
- [Releases](https://github.com/orangecheck/oc-guardian-kit/releases) — signed; verified via cosign + SLSA.

## License

MIT. See [LICENSE](./LICENSE).
