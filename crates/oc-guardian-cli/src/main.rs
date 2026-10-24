//! `oc-guardian` — operator CLI entry point.
//!
//! Every lifecycle stage of the OC guardian operator program has a
//! subcommand. Each subcommand is also documented in BYPASS.md as the
//! kit-only alternative to the corresponding portal feature.
//!
//! Architectural property: every action that produces or applies
//! authority is signed by operator-held key material via this CLI.
//! The CLI never holds, generates, or transmits a signing-capable key
//! — it asks the operator's hardware (WebAuthn / FIDO2 / passkey / OS
//! keychain) to sign, then routes the signed envelope.

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing::info;

#[derive(Parser)]
#[command(
    name = "oc-guardian",
    version,
    about = "OC guardian operator toolkit",
    long_about = "Self-serve provisioning + operations toolkit for running an \
                  OC-affiliated Fedimint guardian. Optional companion to the \
                  operator portal at ochk.app/me/operator — the kit works \
                  end-to-end without ever touching the portal. See BYPASS.md \
                  for the canonical mapping."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Increase log verbosity. Repeat for more detail.
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,

    /// The operator's config dir, for every command. Default: the platform's
    /// config dir + `oc-guardian` (`~/.config/oc-guardian/` on Linux).
    #[arg(long, global = true, env = "OC_GUARDIAN_CONFIG_DIR")]
    config_dir: Option<String>,
}

#[derive(Subcommand)]
enum Command {
    /// Generate operator identity + register hardware token.
    /// Bypass for portal §02 (onboarding).
    Init(InitArgs),

    /// Apply to the OC guardian operator program.
    /// Bypass for portal §01 (apply).
    #[command(subcommand)]
    Apply(ApplyCommand),

    /// Register your operator pubkey with the OC operator registry.
    /// Bypass for portal §02 (onboarding · publish).
    Register(RegisterArgs),

    /// Federation discovery + join + leave, and a creator's handover.
    /// Bypass for portal §03–§04.
    #[command(subcommand, visible_alias = "federation")]
    Federations(FederationsCommand),

    /// DKG ceremony coordination.
    /// Bypass for portal §05 (ceremony).
    #[command(subcommand)]
    Ceremony(CeremonyCommand),

    /// Charter fetch / sign / publish.
    /// Bypass for portal §06 (charter).
    #[command(subcommand)]
    Charter(CharterCommand),

    /// Manage the wrapped fedimintd binary lifecycle.
    /// Bypass for portal §07 (run).
    #[command(subcommand)]
    Fedimintd(FedimintdCommand),

    /// Show this guardian's operational status.
    /// Bypass for portal §08 (status).
    Status,

    /// Subscribe / post incident alerts.
    /// Bypass for portal §09–§10.
    #[command(subcommand)]
    Alerts(AlertsCommand),

    /// Manage payouts.
    /// Bypass for portal §11.
    #[command(subcommand)]
    Payouts(PayoutsCommand),

    /// Audit log inspection.
    #[command(subcommand)]
    Audit(AuditCommand),

    /// Coordinate graceful exit / handoff to a replacement guardian.
    /// Bypass for portal §12.
    ExitHandoff(ExitHandoffArgs),

    /// Countersign another guardian's exit.
    ExitRatify(ExitRatifyArgs),

    /// Let a hosted guardian's own key sign this seat's liveness attestations.
    AttestDelegate(AttestDelegateArgs),

    /// Bind your operator key to your ochk.app account, without the key
    /// entering a browser. Writes a file to upload at ochk.app/me/operator.
    Bind(BindArgs),

    /// Optional bridge: opt in to portal-mediated signed action requests.
    #[command(subcommand)]
    Bridge(BridgeCommand),

    /// Tell the portal to forget you. Your guardian is unaffected.
    /// Bypass for portal §13.
    #[command(subcommand)]
    Portal(PortalCommand),

    /// Verify a status payload signed by another operator.
    VerifyStatus,
}

#[derive(Parser)]
struct InitArgs {
    /// Hardware-token backend. Default: `os-keychain` (passkey API).
    /// Other options: `yubikey`, `ledger`, `passkey`.
    #[arg(long, default_value = "os-keychain")]
    hsm: String,

    /// Keep the operator key in this file instead of the OS keychain, for a
    /// machine without one (a headless server). The file is the key:
    /// anyone who can read it can sign as you.
    #[arg(long)]
    key_file: Option<String>,
}

#[derive(Subcommand)]
enum ApplyCommand {
    /// Prepare a signed application envelope from your filled-out
    /// questionnaire. Output is `application.json`, to email to
    /// apply@ochk.io.
    Prepare {
        #[arg(long, default_value = "application.json")]
        out: String,
        #[arg(long)]
        questionnaire: Option<String>,
        #[arg(long, default_value = "os-keychain")]
        hsm: String,
    },
    /// Verify a reviewer-signed acceptance envelope returned by OC.
    /// Confirms the email reply genuinely came from us — the kit
    /// reproduces the canonical encoding the reviewer signed over and
    /// checks the Ed25519 signature against the public key you pin
    /// with `--reviewer-pubkey-hex`. The hex form is published at
    /// `https://me.ochk.io/.well-known/oc-operator-reviewer.json`
    /// (the `keys[0].x` field, base64url-decoded then hex-encoded);
    /// re-pin and re-verify on every key rotation.
    VerifyAcceptance {
        /// Path to the acceptance envelope JSON (e.g. the
        /// `acceptance-app_….json` attached to the reviewer's email).
        #[arg(long)]
        file: String,
        /// Hex of the OC reviewer's Ed25519 public key (32 bytes =
        /// 64 hex chars). Pull from /.well-known/oc-operator-reviewer
        /// and pin locally; rotate when the published `kid` changes.
        #[arg(long, env = "OC_REVIEWER_PUBKEY_HEX")]
        reviewer_pubkey_hex: String,
    },
}

#[derive(Parser)]
struct RegisterArgs {
    /// Transport for registration. `https` (default) or `email`.
    #[arg(long, default_value = "https")]
    transport: String,
}

#[derive(Subcommand)]
enum FederationsCommand {
    /// List federations seeking guardians (queries the public registry).
    List,
    /// Sign + submit a join request to a federation.
    Join {
        slug: String,
        #[arg(long, default_value = "https")]
        transport: String,
    },
    /// Coordinate exit from a federation.
    Leave { slug: String },
    /// Hand a federation you created to another operator.
    #[command(subcommand)]
    Handover(HandoverCommand),
}

#[derive(Subcommand)]
enum HandoverCommand {
    /// Offer a federation you created to another operator's key. Upload the
    /// file at ochk.app/me/operator/federations/<slug>; that operator accepts.
    Offer {
        /// The federation's slug.
        #[arg(long)]
        federation: String,
        /// The operator id (op-…) of the key taking the federation on.
        #[arg(long)]
        to: String,
        /// How many days the offer stands, 1 to 30.
        #[arg(long, default_value_t = oc_guardian_core::commands::HANDOVER_OFFER_DEFAULT_DAYS)]
        valid_days: u64,
        #[arg(long, default_value = "creator-handover-offer.json")]
        out: String,
    },
    /// Accept an offer naming your operator key. Upload the file at
    /// ochk.app/me/operator/handovers; the federation is then yours.
    Accept {
        /// The federation's slug.
        #[arg(long)]
        federation: String,
        /// The offer's id (64 hex), as ochk.app/me/operator/handovers shows it.
        #[arg(long)]
        offer: String,
        #[arg(long, default_value = "creator-handover-accept.json")]
        out: String,
    },
}

#[derive(Subcommand)]
enum CeremonyCommand {
    /// Set this guardian's name and password (the leader also sets the
    /// federation's name and size), then print its setup code for the
    /// other guardians. Run it as soon as the guardian boots: until then the
    /// first caller of the setup API sets the password.
    Start {
        /// This guardian's name.
        #[arg(long)]
        name: String,
        /// This guardian leads the setup.
        #[arg(long)]
        leader: bool,
        /// The federation's name (leader only).
        #[arg(long)]
        federation_name: Option<String>,
        /// How many guardians the federation has (leader only).
        #[arg(long)]
        federation_size: Option<u32>,
        /// File holding the guardian password. Default: FM_PASSWORD.
        #[arg(long)]
        password_file: Option<String>,
    },
    /// Add the other guardians' setup codes, one --code for each.
    AddPeer {
        #[arg(long = "code", required = true)]
        codes: Vec<String>,
        #[arg(long)]
        password_file: Option<String>,
    },
    /// Start DKG, once every guardian has every other guardian's code.
    Dkg {
        #[arg(long)]
        password_file: Option<String>,
    },
    /// Show the phase fedimintd reports and the recorded progress.
    Status,
    /// Once consensus is running, record it and print the invite code.
    Finalize,
}

#[derive(Subcommand)]
enum CharterCommand {
    /// Fetch a federation's canonical charter meta · prints hash,
    /// version, canonical URL, ratification count. Read-only, no
    /// operator key involved. Run this first to review what `sign`
    /// would commit to.
    Fetch { slug: String },
    /// Produce a hardware-key-signed charter ratification envelope.
    /// Fetches the canonical charter meta from the portal, signs it
    /// with your operator key, writes the envelope JSON to disk.
    /// Idempotent · re-running produces a fresh envelope with a new
    /// nonce. Review the output, then `oc-guardian charter publish`
    /// to broadcast.
    Sign {
        /// Federation slug to ratify (e.g. `oc-me-v1`).
        slug: String,
        /// Path to write the signed envelope JSON.
        #[arg(long, default_value = "charter-sig.json")]
        out: String,
        /// Hardware-token backend. Default: `os-keychain`. v0.2 ships
        /// only os-keychain end-to-end; other backends route there.
        #[arg(long, default_value = "os-keychain")]
        hsm: String,
    },
    /// Publish a previously-signed charter ratification envelope.
    /// Reads the file produced by `charter sign` and POSTs it to the
    /// portal's `/api/operator/charter` endpoint. Idempotent · the
    /// portal returns the same signature row when called twice.
    Publish {
        #[arg(long)]
        file: String,
        #[arg(long, default_value = "https")]
        transport: String,
    },
}

#[derive(Subcommand)]
enum FedimintdCommand {
    /// Download + verify a fedimintd release.
    Install {
        #[arg(long)]
        version: String,
        /// Directory to install into. Default: <FM_DATA_DIR>/../bin, else
        /// /usr/local/bin.
        #[arg(long)]
        dir: Option<String>,
    },
    /// Run the wrapped fedimintd daemon. Reads the runtime config from
    /// the OC-injected env (OC_*/ports); `--config` is the path of the
    /// fedimintd binary to run (default: resolve from PATH).
    Run {
        #[arg(long, default_value = "auto")]
        config: String,
        /// Start an un-set-up guardian whose setup API or UI is reachable
        /// from other machines without the setup gate. Whoever first sets
        /// its local params sets its password: run `ceremony start` at once.
        #[arg(long)]
        allow_public_setup: bool,
    },
    /// Show wrapped fedimintd's status and setup phase.
    Status {
        /// The fedimintd binary path, as for `run`.
        #[arg(long, default_value = "auto")]
        config: String,
    },
}

#[derive(Subcommand)]
enum AlertsCommand {
    /// Subscribe to a federation's published alert channel.
    Subscribe { federation: String },
    /// Post a signed alert to a federation's channel.
    Post {
        #[arg(long)]
        federation: String,
        #[arg(long)]
        severity: String,
        #[arg(long)]
        body: String,
    },
}

#[derive(Subcommand)]
enum PayoutsCommand {
    /// List accrued payouts for a federation.
    List { federation: String },
    /// Claim accrued payouts to a Lightning address.
    Claim {
        federation: String,
        /// The Lightning address to be paid (you@wallet.example).
        #[arg(long)]
        to: String,
        /// Sats to claim; the whole distributed, unpaid balance when omitted.
        #[arg(long)]
        amount: Option<u64>,
    },
}

#[derive(Subcommand)]
enum AuditCommand {
    /// Tail the local audit log.
    Log {
        #[arg(long, default_value = "24h")]
        since: String,
    },
    /// Export the audit log as a signed envelope bundle.
    Export {
        #[arg(long, default_value = "audit-export.json")]
        out: String,
    },
}

#[derive(Parser)]
struct ExitHandoffArgs {
    #[arg(long)]
    federation: String,
    #[arg(long)]
    replacement: String,
    #[arg(long)]
    effective_date: String,
}

#[derive(Parser)]
struct ExitRatifyArgs {
    #[arg(long)]
    federation: String,
    #[arg(long)]
    exit_id: String,
    /// A recent bitcoin mainnet block's height and hash (within 6 of the tip), even for a
    /// federation on signet or testnet: the portal dates what you sign against mainnet.
    #[arg(long)]
    block_height: u64,
    #[arg(long)]
    block_hash: String,
    #[arg(long)]
    note: Option<String>,
}

#[derive(Parser)]
struct AttestDelegateArgs {
    #[arg(long)]
    federation: String,
    /// The seat's index from 0: ochk.app's "Seat 1" is 0.
    #[arg(long)]
    seat: u32,
    /// The machine's attestation pubkey, from the seat's hosted status.
    #[arg(long)]
    attest_pubkey: String,
    /// How long it counts for.
    #[arg(long, default_value_t = 180)]
    days: u64,
    /// A recent bitcoin mainnet block's height and hash (within 6 of the tip), even for a
    /// federation on signet or testnet: the portal dates what you sign against mainnet.
    #[arg(long)]
    block_height: u64,
    #[arg(long)]
    block_hash: String,
    #[arg(long, default_value = "attest-delegation.json")]
    out: String,
}

#[derive(Parser)]
struct BindArgs {
    /// Your ochk.app account's id (did:oc:…), as ochk.app/me/operator shows it.
    #[arg(long)]
    did: String,
    /// A recent bitcoin mainnet block's height and hash (within 6 of the tip).
    /// ochk.app/me/operator shows the command with the current tip filled in.
    #[arg(long)]
    block_height: u64,
    #[arg(long)]
    block_hash: String,
    #[arg(long, default_value = "bind-claim.json")]
    out: String,
}

#[derive(Subcommand)]
enum BridgeCommand {
    /// Opt in to portal-mediated signed action requests.
    Enable,
    /// Allowlist a specific portal action type.
    Allow { action: String },
    /// Disable the bridge. Guardian operation is unaffected.
    Disable,
    /// Show the current allowlist + bridge state.
    Status,
}

#[derive(Subcommand)]
enum PortalCommand {
    /// Tell the portal to forget the operator's relationship history.
    /// Federations track operators by pubkey, not by portal account,
    /// so this does not affect federation membership.
    Forget,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.verbose);
    if let Some(dir) = cli.config_dir {
        oc_guardian_core::config::set_dir_override(dir.into());
    }

    match cli.command {
        Command::Init(args) => oc_guardian_core::commands::init(args.hsm, args.key_file),
        Command::Apply(cmd) => match cmd {
            ApplyCommand::Prepare {
                out,
                questionnaire,
                hsm,
            } => oc_guardian_core::commands::apply_prepare(out, questionnaire, hsm),
            ApplyCommand::VerifyAcceptance {
                file,
                reviewer_pubkey_hex,
            } => oc_guardian_core::commands::apply_verify_acceptance(file, reviewer_pubkey_hex),
        },
        Command::Register(args) => oc_guardian_core::commands::register(args.transport),
        Command::Federations(cmd) => match cmd {
            FederationsCommand::List => oc_guardian_core::commands::federations_list(),
            FederationsCommand::Join { slug, transport } => {
                oc_guardian_core::commands::federations_join(slug, transport)
            }
            FederationsCommand::Leave { slug } => {
                oc_guardian_core::commands::federations_leave(slug)
            }
            FederationsCommand::Handover(cmd) => match cmd {
                HandoverCommand::Offer {
                    federation,
                    to,
                    valid_days,
                    out,
                } => oc_guardian_core::commands::federation_handover_offer(
                    federation, to, valid_days, out,
                ),
                HandoverCommand::Accept {
                    federation,
                    offer,
                    out,
                } => oc_guardian_core::commands::federation_handover_accept(federation, offer, out),
            },
        },
        Command::Ceremony(cmd) => match cmd {
            CeremonyCommand::Start {
                name,
                leader,
                federation_name,
                federation_size,
                password_file,
            } => oc_guardian_fedimint::ceremony::LocalParams::new(
                name,
                leader,
                federation_name,
                federation_size,
            )
            .and_then(|p| oc_guardian_fedimint::ceremony::start(p, password_file)),
            CeremonyCommand::AddPeer {
                codes,
                password_file,
            } => oc_guardian_fedimint::ceremony::add_peer(codes, password_file),
            CeremonyCommand::Dkg { password_file } => {
                oc_guardian_fedimint::ceremony::dkg(password_file)
            }
            CeremonyCommand::Status => oc_guardian_fedimint::ceremony::status(),
            CeremonyCommand::Finalize => oc_guardian_fedimint::ceremony::finalize(),
        },
        Command::Charter(cmd) => match cmd {
            CharterCommand::Fetch { slug } => oc_guardian_charter::fetch(slug),
            CharterCommand::Sign { slug, out, hsm } => oc_guardian_charter::sign(slug, out, hsm),
            CharterCommand::Publish { file, transport } => {
                oc_guardian_charter::publish(file, transport)
            }
        },
        Command::Fedimintd(cmd) => match cmd {
            FedimintdCommand::Install { version, dir } => {
                oc_guardian_fedimint::install(version, dir)
            }
            FedimintdCommand::Run {
                config,
                allow_public_setup,
            } => oc_guardian_fedimint::run(config, allow_public_setup),
            FedimintdCommand::Status { config } => oc_guardian_fedimint::status(config),
        },
        Command::Status => oc_guardian_core::commands::status(),
        Command::Alerts(cmd) => match cmd {
            AlertsCommand::Subscribe { federation } => {
                oc_guardian_core::commands::alerts_subscribe(federation)
            }
            AlertsCommand::Post {
                federation,
                severity,
                body,
            } => oc_guardian_core::commands::alerts_post(federation, severity, body),
        },
        Command::Payouts(cmd) => match cmd {
            PayoutsCommand::List { federation } => {
                oc_guardian_core::commands::payouts_list(federation)
            }
            PayoutsCommand::Claim {
                federation,
                to,
                amount,
            } => oc_guardian_core::commands::payouts_claim(federation, to, amount),
        },
        Command::Audit(cmd) => match cmd {
            AuditCommand::Log { since } => oc_guardian_core::commands::audit_log(since),
            AuditCommand::Export { out } => oc_guardian_core::commands::audit_export(out),
        },
        Command::ExitHandoff(args) => oc_guardian_core::commands::exit_handoff(
            args.federation,
            args.replacement,
            args.effective_date,
        ),
        Command::ExitRatify(args) => oc_guardian_core::commands::exit_ratify(
            args.federation,
            args.exit_id,
            args.block_height,
            args.block_hash,
            args.note,
        ),
        Command::AttestDelegate(args) => oc_guardian_core::commands::attest_delegate(
            args.federation,
            args.seat,
            args.attest_pubkey,
            args.days,
            args.block_height,
            args.block_hash,
            args.out,
        ),
        Command::Bind(args) => {
            oc_guardian_core::commands::bind(args.did, args.block_height, args.block_hash, args.out)
        }
        Command::Bridge(cmd) => match cmd {
            BridgeCommand::Enable => oc_guardian_portal_bridge::enable(),
            BridgeCommand::Allow { action } => oc_guardian_portal_bridge::allow(action),
            BridgeCommand::Disable => oc_guardian_portal_bridge::disable(),
            BridgeCommand::Status => oc_guardian_portal_bridge::status(),
        },
        Command::Portal(cmd) => match cmd {
            PortalCommand::Forget => oc_guardian_core::commands::portal_forget(),
        },
        Command::VerifyStatus => oc_guardian_core::commands::verify_status(),
    }?;

    info!("done");
    Ok(())
}

fn init_tracing(verbosity: u8) {
    let level = match verbosity {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level)),
        )
        .with_target(false)
        .with_writer(std::io::stderr)
        .try_init();
}
