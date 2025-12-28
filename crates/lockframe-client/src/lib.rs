//! Client
//!
//! Action-based client state machine for the Lockframe protocol. Manages room
//! memberships, MLS group operations, and sender key encryption.
//!
//! # Architecture
//!
//! The client follows the same Sans-IO and Action-Based patterns as
//! [`lockframe_core`]. It receives events ([`ClientEvent`]), processes them
//! through pure state machine logic, and returns actions ([`ClientAction`]) for
//! the caller to execute.
//!
//! # Components
//!
//! - [`Client`]: Top-level state machine managing multiple rooms
//! - [`SenderKeyStore`]: Per-room sender key ratchet management
//! - [`ClientEvent`]: Events fed into the client
//! - [`ClientAction`]: Actions produced by the client
//!
//! # Transport (optional)
//!
//! With the `transport` feature enabled, this crate also provides:
//! - [`transport::ConnectedClient`]: Client with QUIC transport
//! - [`transport::connect`]: Connect to a server

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod client;
mod error;
mod event;
mod sender_key_store;

#[cfg(feature = "transport")]
pub mod transport;

pub use client::{Client, ClientIdentity};
pub use error::ClientError;
pub use event::{ClientAction, ClientEvent, RoomStateSnapshot};
pub use lockframe_core::{
    env::Environment,
    mls::{MemberId, RoomId},
};
pub use sender_key_store::SenderKeyStore;
