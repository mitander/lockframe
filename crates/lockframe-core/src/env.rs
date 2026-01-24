//! Environment abstraction for deterministic testing.
//!
//! Decouples protocol logic from system resources (time, randomness). Enables
//! deterministic simulation with Turmoil (virtual clock, seeded RNG) and
//! production use with real system resources.

use std::time::Duration;

/// Abstract environment providing time, randomness, and async primitives.
///
/// # Safety
///
/// Implementations MUST guarantee:
///
/// - `now()` never goes backwards
/// - `random_bytes()` uses cryptographically secure entropy in production
/// - Methods are infallible except in exceptional circumstances (e.g., OS
///   entropy exhaustion, incorrect simulation setup)
pub trait Environment: Clone + Send + Sync + 'static {
    /// The specific instant type used by this environment.
    ///
    /// Production environments use `std::time::Instant`, while simulation
    /// environments use virtual time (e.g., `turmoil::Instant`).
    type Instant: Copy + Ord + Send + Sync + std::ops::Sub<Output = Duration>;

    /// Current time (monotonic).
    ///
    /// # Invariants
    ///
    /// - This method MUST return values that never decrease within a single
    ///   execution context. Subsequent calls must return times >= previous
    ///   calls.
    fn now(&self) -> Self::Instant;

    /// Sleeps for the specified duration.
    ///
    /// This is the ONLY async method in the trait, and it should only be used
    /// by driver code (not protocol logic).
    fn sleep(&self, duration: Duration) -> impl std::future::Future<Output = ()> + Send;

    /// Fills the provided buffer with random bytes.
    ///
    /// # Invariants
    ///
    /// - Given the same RNG seed, this produces the same sequence of bytes
    /// - Uses cryptographically secure RNG
    fn random_bytes(&self, buffer: &mut [u8]);

    /// Generates a random `u64`.
    ///
    /// This is a convenience method for common use cases like generating
    /// session IDs or request IDs.
    fn random_u64(&self) -> u64 {
        let mut bytes = [0u8; 8];
        self.random_bytes(&mut bytes);
        u64::from_be_bytes(bytes)
    }

    /// Generates a random `u128`.
    ///
    /// Useful for UUIDs or room IDs.
    fn random_u128(&self) -> u128 {
        let mut bytes = [0u8; 16];
        self.random_bytes(&mut bytes);
        u128::from_be_bytes(bytes)
    }
}
