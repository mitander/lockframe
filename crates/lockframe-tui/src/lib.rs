//! Terminal UI for Lockframe
//!
//! mIRC-style terminal client for verifying the protocol logic. Designed
//! for developer testing and debugging with snapshot-testable UI components.
//!
//! # Architecture
//!
//! The TUI follows the same Sans-IO and Action-Based patterns as the rest of
//! Lockframe. Two layered state machines handle UI and protocol logic:
//!
//! - [`App`]: UI state machine (pure, testable)
//! - [`lockframe_client::Client`]: Protocol state machine
//!
//! The runtime glues these together, driving terminal I/O and network
//! operations based on the actions they produce.
//!
//! # Components
//!
//! - [`app`]: UI state machine with events and actions
//! - [`ui`]: Rendering functions for terminal output
//! - [`bridge`]: App↔Client translation layer
//! - [`server`]: In-process simulated server
//! - [`runtime`]: Async event loop (impure glue code)

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod app;
pub mod bridge;
pub mod runtime;
pub mod server;
pub mod ui;

pub use app::{App, AppAction, AppEvent};
pub use bridge::Bridge;
