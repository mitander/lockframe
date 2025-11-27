//! MLS (Messaging Layer Security) implementation.
//!
//! This module implements the MLS protocol (RFC 9420) for group messaging with
//! strong security guarantees including forward secrecy and post-compromise
//! security.
//!
//! # Architecture
//!
//! - **`group`**: Client-side MLS group state machine
//! - **`sequencer`**: Server-side ordering and conflict resolution
//! - **`authority`**: Server moderation via External Commits
//! - **`error`**: MLS-specific error types
//!
//! # Design Principles
//!
//! 1. **Sans-IO**: All MLS logic returns actions, no direct I/O
//! 2. **Epoch-based ordering**: Server enforces total order via epochs
//! 3. **Server authority**: Server can moderate via External Commits
//! 4. **Action pattern**: Methods return `Result<Vec<MlsAction>, MlsError>`

pub mod error;
pub mod group;

pub use error::MlsError;
pub use group::{MlsAction, MlsGroup};
