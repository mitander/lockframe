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

    /// Wall-clock time as Unix timestamp (seconds since 1970-01-01 00:00:00
    /// UTC).
    ///
    /// Used for audit logging and persistent metadata (e.g., room creation
    /// time). Unlike `now()`, this returns absolute time suitable for
    /// storage.
    ///
    /// Use `now()` for timeouts and elapsed time. Use `wall_clock_secs()` for
    /// timestamps that need to be persisted or compared across restarts.
    fn wall_clock_secs(&self) -> u64;

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

/// Test utilities for deterministic testing.
///
/// This module provides mock implementations of the Environment trait
/// for use in unit and integration tests across all lockframe crates.
pub mod test_utils {
    use std::{
        sync::{
            Arc, Mutex,
            atomic::{AtomicU64, Ordering},
        },
        time::Duration,
    };

    use rand::{RngCore, SeedableRng, rngs::StdRng};

    use super::Environment;

    /// Mock environment with controllable time for deterministic testing.
    ///
    /// Time starts at a fixed virtual epoch (`Duration::ZERO`) and can be
    /// advanced manually via `advance_time()`. This ensures tests are fully
    /// reproducible regardless of when they run and eliminates any dependency
    /// on the system clock.
    ///
    /// Randomness is provided by a `StdRng` that is either:
    /// - Seeded with a fixed value (deterministic mode)
    /// - Seeded from OS entropy (crypto mode for MLS tests)
    #[derive(Clone)]
    pub struct MockEnv {
        /// Time offset from virtual epoch in nanoseconds (atomic for Send+Sync)
        offset_nanos: Arc<AtomicU64>,
        /// RNG for random number generation
        /// Mutex allows interior mutability while maintaining Send+Sync
        rng: Arc<Mutex<StdRng>>,
    }

    /// Virtual instant for deterministic testing.
    ///
    /// Represents time as a duration from a fixed epoch, ensuring complete
    /// determinism without any dependency on the system clock.
    #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct VirtualInstant(Duration);

    impl VirtualInstant {
        /// Creates a new virtual instant from the given duration since epoch.
        pub fn from_duration(duration: Duration) -> Self {
            Self(duration)
        }

        /// Returns the duration since the virtual epoch.
        pub fn since_epoch(&self) -> Duration {
            self.0
        }
    }

    impl std::ops::Sub for VirtualInstant {
        type Output = Duration;

        fn sub(self, rhs: Self) -> Self::Output {
            #[allow(clippy::expect_used)]
            self.0
                .checked_sub(rhs.0)
                .expect("invariant: time should not go backwards (later - earlier)")
        }
    }

    impl std::ops::Add<Duration> for VirtualInstant {
        type Output = Self;

        fn add(self, rhs: Duration) -> Self::Output {
            Self(self.0 + rhs)
        }
    }

    impl std::fmt::Debug for VirtualInstant {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "VirtualInstant({:?})", self.0)
        }
    }

    impl MockEnv {
        /// Create a new mock environment with deterministic randomness.
        ///
        /// Uses a fixed seed (0) for the RNG to ensure tests are reproducible.
        pub fn new() -> Self {
            let rng = StdRng::seed_from_u64(0);
            Self { offset_nanos: Arc::new(AtomicU64::new(0)), rng: Arc::new(Mutex::new(rng)) }
        }

        /// Create a mock environment with real cryptographic randomness.
        ///
        /// Uses OS entropy to seed the RNG. Use this for tests involving MLS
        /// or other crypto operations that need real randomness.
        pub fn with_crypto_rng() -> Self {
            let rng = StdRng::from_entropy();
            Self { offset_nanos: Arc::new(AtomicU64::new(0)), rng: Arc::new(Mutex::new(rng)) }
        }

        /// Advance the mock clock by the given duration.
        ///
        /// This allows tests to simulate time passing without actual delays.
        ///
        /// # Panics
        ///
        /// Panics if duration exceeds `u64::MAX` nanoseconds (~584 years).
        pub fn advance_time(&self, duration: Duration) {
            #[allow(clippy::expect_used)]
            let nanos = u64::try_from(duration.as_nanos())
                .expect("invariant: duration exceeds u64::MAX nanoseconds (~584 years)");
            self.offset_nanos.fetch_add(nanos, Ordering::SeqCst);
        }
    }

    impl Default for MockEnv {
        fn default() -> Self {
            Self::new()
        }
    }

    impl Environment for MockEnv {
        type Instant = VirtualInstant;

        fn now(&self) -> Self::Instant {
            let nanos = self.offset_nanos.load(Ordering::SeqCst);
            VirtualInstant(Duration::from_nanos(nanos))
        }

        async fn sleep(&self, _duration: Duration) {
            // Don't sleep, tests control time manually
        }

        fn random_bytes(&self, buffer: &mut [u8]) {
            #[allow(clippy::expect_used)]
            self.rng.lock().expect("MockEnv RNG mutex poisoned").fill_bytes(buffer);
        }

        fn wall_clock_secs(&self) -> u64 {
            // For testing, return a fixed timestamp (2024-01-01 00:00:00 UTC)
            // Tests that need specific timestamps can override this behavior
            1_704_067_200
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn mock_env_rng_advances() {
            let env = MockEnv::new();

            // Generate several random values - should all be different
            let val1 = env.random_u64();
            let val2 = env.random_u64();
            let val3 = env.random_u64();

            assert_ne!(val1, val2, "RNG should advance between calls");
            assert_ne!(val2, val3, "RNG should advance between calls");
            assert_ne!(val1, val3, "RNG should advance between calls");
        }

        #[test]
        fn mock_env_rng_deterministic() {
            // Create two environments with same seed
            let env1 = MockEnv::new();
            let env2 = MockEnv::new();

            // Should produce identical sequences
            let val1_env1 = env1.random_u64();
            let val2_env1 = env1.random_u64();
            let val3_env1 = env1.random_u64();

            let val1_env2 = env2.random_u64();
            let val2_env2 = env2.random_u64();
            let val3_env2 = env2.random_u64();

            assert_eq!(val1_env1, val1_env2, "Same seed should produce same sequence");
            assert_eq!(val2_env1, val2_env2, "Same seed should produce same sequence");
            assert_eq!(val3_env1, val3_env2, "Same seed should produce same sequence");
        }

        #[test]
        fn mock_env_time_advances() {
            let env = MockEnv::new();
            let t0 = env.now();

            env.advance_time(Duration::from_secs(5));
            let t1 = env.now();

            assert_eq!(t1 - t0, Duration::from_secs(5));
        }

        #[test]
        fn mock_env_crypto_rng_produces_random_bytes() {
            let env = MockEnv::with_crypto_rng();

            let val1 = env.random_u64();
            let val2 = env.random_u64();

            // Crypto RNG should produce different values
            assert_ne!(val1, val2);

            // Two separate crypto envs should produce different sequences
            let env_a = MockEnv::with_crypto_rng();
            let env_b = MockEnv::with_crypto_rng();

            let a1 = env_a.random_u64();
            let b1 = env_b.random_u64();

            // Very unlikely to be equal with real randomness
            assert_ne!(a1, b1);
        }

        #[test]
        fn mock_env_wall_clock_secs_returns_fixed_value() {
            let env = MockEnv::new();
            assert_eq!(
                env.wall_clock_secs(),
                1_704_067_200,
                "wall_clock_secs should return a fixed timestamp for testing"
            );
        }

        #[test]
        fn virtual_instant_from_duration_and_since_epoch() {
            let duration = Duration::from_secs(10);
            let instant = VirtualInstant::from_duration(duration);
            assert_eq!(instant.since_epoch(), duration);
        }

        #[test]
        fn virtual_instant_add_duration() {
            let initial_duration = Duration::from_secs(5);
            let add_duration = Duration::from_secs(3);
            let instant = VirtualInstant::from_duration(initial_duration);
            let new_instant = instant + add_duration;
            assert_eq!(new_instant.since_epoch(), initial_duration + add_duration);
        }

        #[test]
        fn mock_env_default_initializes_correctly() {
            let env_default = MockEnv::default();
            let env_new = MockEnv::new();

            // Both new and default should start with the same RNG seed and initial time
            assert_eq!(
                env_default.random_u64(),
                env_new.random_u64(),
                "Default and new MockEnv should have identical initial RNG state"
            );
        }
    }
}
