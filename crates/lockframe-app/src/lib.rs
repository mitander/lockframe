//! Application layer for Lockframe
//!
//! Pure state machines and generic runtime for UI and protocol orchestration,
//! enabling deterministic simulation testing with the same code that runs in
//! production.
//!
//! # Components
//!
//! - [`App`]: UI state machine (input handling, room navigation, commands)
//! - [`Bridge`]: Protocol bridge (translates App actions to Client events)
//! - [`Driver`]: Trait for platform-specific I/O abstraction
//! - [`Runtime`]: Generic orchestration loop using Driver

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod action;
mod app;
mod bridge;
mod driver;
mod event;
mod input;
mod runtime;
mod state;

pub use action::AppAction;
pub use app::App;
pub use bridge::Bridge;
pub use driver::Driver;
pub use event::AppEvent;
pub use input::KeyInput;
pub use runtime::Runtime;
pub use state::{ConnectionState, Message, RoomState};
