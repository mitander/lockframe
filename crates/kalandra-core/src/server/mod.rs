//! Server driver module.
//!
//! This module provides the Sans-IO server orchestrator that ties together
//! connection management, room operations, and frame routing.
//!
//! ## Architecture
//!
//! ```text
//! ServerDriver (this module)
//!   ├─ connections: HashMap<u64, Connection>
//!   ├─ registry: ConnectionRegistry
//!   ├─ room_manager: RoomManager
//!   └─ storage: S (impl Storage)
//! ```
//!
//! ## Event/Action Pattern
//!
//! The server follows a Sans-IO pattern:
//! 1. External runtime produces `ServerEvent`s
//! 2. `ServerDriver::process_event()` returns `ServerAction`s
//! 3. `ActionExecutor` (runtime-specific) executes actions
//!
//! This enables deterministic simulation testing with turmoil.
//!
//! ## Module Structure
//!
//! - [`driver`]: Main `ServerDriver` orchestrator
//! - [`registry`]: Session/room subscription tracking
//! - [`executor`]: `ActionExecutor` trait for I/O execution
//! - [`error`]: Server error types

mod driver;
mod error;
mod executor;
mod registry;

pub use driver::{LogLevel, ServerAction, ServerConfig, ServerDriver, ServerEvent};
pub use error::{ExecutorError, ServerError};
pub use executor::{ActionExecutor, BroadcastPolicy};
pub use registry::{ConnectionRegistry, SessionInfo};
