//! MLS (Messaging Layer Security) implementation.
//!
//! Implements MLS (RFC 9420) for group messaging with forward secrecy and
//! post-compromise security. The server enforces total ordering by sequencing
//! frames within each epoch, and can moderate via External Commits.
//!
//! # Components
//!
//! - [`group`]: Client-side MLS group state machine
//! - [`state`]: MLS group state for storage and validation
//! - [`provider`]: `OpenMLS` provider integration
//! - [`validator`]: Frame validation for server sequencing
//! - [`error`]: MLS-specific error types
//! - [`constants`]: Protocol constants and limits

pub mod constants;
pub mod error;
pub mod group;
pub mod provider;
pub mod state;
pub mod validator;

pub use constants::MAX_EPOCH;
pub use error::MlsError;
pub use group::{MemberId, MlsAction, MlsGroup, PendingJoinState, RoomId};
pub use provider::MlsProvider;
pub use state::MlsGroupState;
pub use validator::{MlsValidator, ValidationResult};
