//! Server error types.

use std::fmt;

use crate::server_error::ServerError as DriverError;

/// Errors that can occur in the server.
#[derive(Debug)]
pub enum ServerError {
    /// Configuration error (invalid bind address, missing TLS certs, etc.).
    ///
    /// These are fatal errors that prevent server startup. Fix configuration
    /// and restart.
    Config(String),

    /// Transport/network error (connection failure, I/O error, etc.).
    ///
    /// May be transient (network issues) or fatal (bind address in use).
    /// Check error message for details.
    Transport(String),

    /// Protocol error (invalid frame format, unsupported version, etc.).
    ///
    /// Indicates a client sent malformed data. Fatal for that connection,
    /// but server can continue serving other clients.
    Protocol(String),

    /// Internal error (unexpected state, logic bug, etc.).
    ///
    /// Should never happen in correct implementation. Indicates a bug.
    /// Fatal - report as issue.
    Internal(String),

    /// Driver error (from `ServerDriver` processing).
    ///
    /// Wraps errors from the core server logic. See `DriverError` for details.
    Driver(DriverError),
}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(msg) => write!(f, "configuration error: {msg}"),
            Self::Transport(msg) => write!(f, "transport error: {msg}"),
            Self::Protocol(msg) => write!(f, "protocol error: {msg}"),
            Self::Internal(msg) => write!(f, "internal error: {msg}"),
            Self::Driver(err) => write!(f, "driver error: {err}"),
        }
    }
}

impl std::error::Error for ServerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Driver(err) => Some(err),
            _ => None,
        }
    }
}

impl From<DriverError> for ServerError {
    fn from(err: DriverError) -> Self {
        Self::Driver(err)
    }
}

impl From<std::io::Error> for ServerError {
    fn from(err: std::io::Error) -> Self {
        Self::Transport(err.to_string())
    }
}
