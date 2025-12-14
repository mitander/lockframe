//! Action executor trait for server I/O.
//!
//! The executor trait separates action generation (Sans-IO) from I/O execution.
//! Different implementations handle I/O differently:
//! - Simulation: Routes through SimTransport with virtual time
//! - Production: Uses Quinn/tokio for real network I/O
//!
//! # Broadcast Policy
//!
//! The executor can be configured with different policies for handling
//! broadcast failures:
//! - `BestEffort`: Log and continue (simulation)
//! - `Retry`: Retry with backoff (production)

use std::future::Future;

use super::error::ExecutorError;

/// Policy for handling broadcast send failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BroadcastPolicy {
    /// Log failure and continue to next recipient.
    /// Suitable for simulation where we want to test failure scenarios.
    #[default]
    BestEffort,

    /// Retry failed sends with exponential backoff.
    /// Suitable for production where delivery matters.
    Retry {
        /// Maximum number of retry attempts
        max_attempts: u32,
        /// Initial backoff duration in milliseconds
        initial_backoff_ms: u64,
    },
}

/// Trait for executing server actions.
///
/// Implementations perform the actual I/O (sending frames, persisting data).
/// The trait is async to support non-blocking I/O in production.
///
/// # Type Parameters
///
/// - `I`: The instant type (for timestamps in actions)
pub trait ActionExecutor<I>: Send + Sync {
    /// Execute a single server action.
    ///
    /// # Errors
    ///
    /// Returns `ExecutorError` if the action cannot be completed.
    /// The error type indicates whether retry is appropriate.
    fn execute(
        &self,
        action: super::ServerAction<I>,
    ) -> impl Future<Output = Result<(), ExecutorError>> + Send;

    /// Get the broadcast policy for this executor.
    fn broadcast_policy(&self) -> BroadcastPolicy {
        BroadcastPolicy::BestEffort
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broadcast_policy_default() {
        let policy = BroadcastPolicy::default();
        assert_eq!(policy, BroadcastPolicy::BestEffort);
    }

    #[test]
    fn broadcast_policy_retry() {
        let policy = BroadcastPolicy::Retry { max_attempts: 3, initial_backoff_ms: 100 };
        match policy {
            BroadcastPolicy::Retry { max_attempts, initial_backoff_ms } => {
                assert_eq!(max_attempts, 3);
                assert_eq!(initial_backoff_ms, 100);
            },
            _ => panic!("expected Retry policy"),
        }
    }
}
