//! Terminal UI for Lockframe
//!
//! A thin shell over [`lockframe_app::Driver`] that provides terminal-specific
//! I/O. All orchestration logic lives in the generic [`lockframe_app::Runtime`]
//!
//! This crate only handles terminal rendering.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod terminal;
pub mod ui;

pub use lockframe_app::{App, AppAction, AppEvent, Bridge, Driver, KeyInput, Runtime};
pub use terminal::{TerminalDriver, TerminalError};
