//! Deterministic simulation harness for Kalandra protocol testing.
//!
//! This crate provides Turmoil-based implementations of the `Environment`
//! and `Transport` traits, enabling deterministic, reproducible testing
//! of the Kalandra protocol under various network conditions.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod scenario;
pub mod sim_env;
pub mod sim_server;
pub mod sim_transport;

pub use sim_env::SimEnv;
pub use sim_server::{SharedSimServer, SimServer, create_shared_server};
pub use sim_transport::SimTransport;
