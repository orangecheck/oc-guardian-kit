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
                  operator portal at me.ochk.io/operator — the kit works \
                  end-to-end without ever touching the portal. See BYPASS.md \
                  for the canonical mapping."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Increase log verbosity. Repeat for more detail.
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,
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

    /// Federation discovery + join + leave.
    /// Bypass for portal §03–§04.
    #[command(subcommand)]
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

    /// Path to write the operator's public key + identifier. Default
    /// is `~/.config/oc-guardian/`.
    #[arg(long)]
    config_dir: Option<String>,
}

#[derive(Subcommand)]
enum ApplyCommand {
    /// Prepare a signed application envelope from your filled-out
    /// questionnaire. Output is `application.json` ready for email
    /// or HTTP submission.
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
}

#[derive(Subcommand)]
enum CeremonyCommand {
    /// Start the DKG ceremony with peer guardians.
    Start {
        /// Comma-separated peer URLs.
        #[arg(long)]
        peers: String,
        /// Setup code from the federation organizer.
        #[arg(long)]
        setup_code: String,
    },
    /// Show in-progress ceremony state.
    Status,
    /// Finalize the ceremony after all rounds complete.
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
    },
    /// Run the wrapped fedimintd daemon.
    Run {
        #[arg(long)]
        config: String,
    },
    /// Show wrapped fedimintd's process status.
    Status,
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
    /// Claim accrued payouts to a Bitcoin address.
    Claim {
        federation: String,
        #[arg(long)]
        to: String,
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

    match cli.command {
        Command::Init(args) => oc_guardian_core::commands::init(args.hsm, args.config_dir),
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
        },
        Command::Ceremony(cmd) => match cmd {
            CeremonyCommand::Start { peers, setup_code } => {
                oc_guardian_core::commands::ceremony_start(peers, setup_code)
            }
            CeremonyCommand::Status => oc_guardian_core::commands::ceremony_status(),
            CeremonyCommand::Finalize => oc_guardian_core::commands::ceremony_finalize(),
        },
        Command::Charter(cmd) => match cmd {
            CharterCommand::Fetch { slug } => oc_guardian_charter::fetch(slug),
            CharterCommand::Sign { slug, out, hsm } => oc_guardian_charter::sign(slug, out, hsm),
            CharterCommand::Publish { file, transport } => {
                oc_guardian_charter::publish(file, transport)
            }
        },
        Command::Fedimintd(cmd) => match cmd {
            FedimintdCommand::Install { version } => oc_guardian_fedimint::install(version),
            FedimintdCommand::Run { config } => oc_guardian_fedimint::run(config),
            FedimintdCommand::Status => oc_guardian_fedimint::status(),
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
            PayoutsCommand::Claim { federation, to } => {
                oc_guardian_core::commands::payouts_claim(federation, to)
            }
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
        .try_init();
}
