//! `oc-guardian-core` — protocol types, operator-identity primitives,
//! signed action envelopes, and the lifecycle command implementations
//! the CLI dispatches into.
//!
//! This crate is the canonical home for the kit's runtime invariants:
//!
//!   - operator key handling (hardware-token-backed; the kit never
//!     holds a signing-capable key)
//!   - action envelopes (CBOR-canonicalized, Ed25519-signed, replay-
//!     protected via monotonic nonces)
//!   - federation membership state (locally stored; portal mirrors
//!     are advisory, not authoritative)
//!   - audit log appender (oc-stamp envelope shape, optional Bitcoin
//!     OTS anchoring at the operator's discretion)
//!
//! The public command surface lives in `commands::*` and is consumed
//! by `oc-guardian-cli` directly. Each command is a thin orchestrator
//! over the protocol primitives in this crate.

pub mod actions;
pub mod commands;
pub mod config;
pub mod identity;
pub mod keychain;
pub mod registry;

/// Library version, populated at build time from Cargo.toml.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
