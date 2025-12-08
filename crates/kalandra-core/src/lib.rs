//! Kalandra protocol core logic
//!
//! This crate contains the pure state machine logic for the Kalandra protocol.
//! It is completely decoupled from I/O, enabling deterministic testing and
//! formal verification.
//!
//! # Architecture: "The Hollow Shell"
//!
//! Protocol logic is strictly separated from transport concerns:
//!
//! ```text
//!      ┌────────────────────────────┐
//!      │ kalandra-core              │
//!      │ - State machines           │
//!      │ - Protocol logic           │
//!      │ - Cryptographic operations │
//!      └────────────────────────────┘
//!         ↓                      ↓
//! ┌──────────────────┐  ┌─────────────────┐
//! │ kalandra-harness │  │ kalandra-server │
//! │ (Turmoil)        │  │ (Quinn/Tokio)   │
//! │ - Virtual time   │  │ - Real network  │
//! │ - Seeded RNG     │  │ - System clock  │
//! │ - Fault inject   │  │ - Production    │
//! └──────────────────┘  └─────────────────┘
//! ```
//!
//! # Key Principles
//!
//! - No I/O in Core: Never call `tokio::spawn`, `std::time::Instant::now()`, or
//!   `rand::thread_rng()` directly
//! - Environment Trait: All side effects go through the `Environment` trait
//! - Deterministic: Given the same inputs and environment state, produce the
//!   same outputs
//!
//! # Modules
//!
//! - [`connection`]: Connection state machine (handshake, heartbeat, timeout)
//! - [`mls`]: MLS group state machine (proposals, commits, messages)
//! - [`sequencer`]: Server-side frame sequencer with total ordering
//! - [`storage`]: Storage abstraction (frames, MLS state)
//! - [`env`]: Environment abstraction (time, RNG)
//! - [`transport`]: Transport abstraction (streams)
//! - [`error`]: Connection error types
//! - [`sender_keys`]: Data Plane encryption (sender keys, symmetric ratchet)

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod connection;
pub mod env;
pub mod error;
pub mod mls;
pub mod room_manager;
pub mod sender_keys;
pub mod sequencer;
pub mod storage;
pub mod transport;
