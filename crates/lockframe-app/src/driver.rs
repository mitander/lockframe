//! Driver trait for abstracting I/O operations.
//!
//! The [`Driver`] trait decouples the application runtime from specific I/O
//! implementations. Each frontend implements the trait to provide
//! platform-specific I/O, while the generic [`crate::Runtime`] handles all
//! orchestration.

use std::{future::Future, ops::Sub, time::Duration};

use lockframe_proto::Frame;

use crate::{App, AppEvent};

/// Abstracts I/O operations for the application runtime.
///
/// Implementations provide platform-specific I/O while the generic
/// [`Runtime`](crate::Runtime) handles orchestration logic. This ensures
/// the same orchestration code runs in production TUI and simulation.
///
/// # Implementations
///
/// - **TUI**: Uses crossterm for terminal events, quinn for QUIC transport
/// - **Simulation**: Uses turmoil for deterministic network simulation
/// - **Web**: Could use browser events and WebSocket/WebRTC
///
/// # Associated Types
///
/// - [`Error`](Driver::Error): Platform-specific error type
/// - [`Instant`](Driver::Instant): Time representation (real or virtual)
pub trait Driver: Send {
    /// Platform-specific error type.
    type Error: std::error::Error + Send + 'static;

    /// Time instant type. Enables virtual time in simulation.
    type Instant: Copy + Ord + Send + Sync + Sub<Output = Duration>;

    /// Poll for the next input event.
    ///
    /// Returns avaliable events or `None` if no events are ready.
    fn poll_event(&mut self) -> impl Future<Output = Result<Option<AppEvent>, Self::Error>> + Send;

    /// Send a frame to the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection is closed or send fails.
    fn send_frame(&mut self, frame: Frame) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Receive a frame from the server.
    ///
    /// Returns frame or `None` if the connection is closed.
    fn recv_frame(&mut self) -> impl Future<Output = Option<Frame>> + Send;

    /// Establish connection to the server.
    ///
    /// # Errors
    ///
    /// Returns an error if connection cannot be established.
    fn connect(&mut self, addr: &str) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Check if connected to server.
    fn is_connected(&self) -> bool;

    /// Current time instant.
    fn now(&self) -> Self::Instant;

    /// Render the application state.
    ///
    /// # Errors
    ///
    /// Returns an error if rendering fails.
    fn render(&mut self, app: &App) -> Result<(), Self::Error>;

    /// Stop the connection and clean up resources.
    fn stop(&mut self);
}
