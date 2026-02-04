//! Production Environment implementation using system time and RNG.
//!
//! `SystemEnv` is the production implementation of the Environment trait using
//! real system time and cryptographic RNG.
//!
//! # Capabilities
//!
//! - Real system time (`std::time::Instant`) that advances naturally
//! - OS cryptographic RNG (getrandom). Truly random, not reproducible
//! - Tokio async sleep for actual wall-clock delays
//!
//! This means production behavior is non-deterministic, but provides real-world
//! timing and security-grade randomness.

use std::time::Duration;

use lockframe_core::env::Environment;

/// Production environment using system time and cryptographic RNG.
///
/// Uses `std::time::Instant::now()` for time, `tokio::time::sleep()` for async
/// sleeping, and getrandom for cryptographic randomness.
///
/// # Security
///
/// The RNG uses getrandom which provides OS-level cryptographic randomness
/// (e.g., /dev/urandom on Linux, `BCryptGenRandom` on Windows). Suitable for
/// generating session IDs, nonces, ephemeral keys, and other security-critical
/// values.
///
/// # Panics
///
/// Panics if the OS RNG fails. This is intentional - a server without
/// functioning cryptographic randomness cannot operate securely. RNG failure
/// is extremely rare (indicates OS-level issues) and continuing would
/// compromise session IDs, nonces, and all cryptographic operations.
#[derive(Clone, Default)]
pub struct SystemEnv;

impl SystemEnv {
    /// Create a new system environment.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Environment for SystemEnv {
    type Instant = std::time::Instant;

    #[allow(clippy::disallowed_methods)]
    fn now(&self) -> Self::Instant {
        std::time::Instant::now()
    }

    fn sleep(&self, duration: Duration) -> impl std::future::Future<Output = ()> + Send {
        tokio::time::sleep(duration)
    }

    #[allow(clippy::expect_used)]
    fn random_bytes(&self, buffer: &mut [u8]) {
        getrandom::fill(buffer)
            .expect("invariant: OS RNG failure is unrecoverable - server cannot operate securely");
    }

    #[allow(clippy::disallowed_methods)]
    #[allow(clippy::expect_used)]
    fn wall_clock_secs(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("invariant: system clock is after Unix epoch (1970-01-01)")
            .as_secs()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::disallowed_methods)]
    fn system_env_time_advances() {
        let env = SystemEnv::new();

        let t1 = env.now();
        std::thread::sleep(Duration::from_millis(10));
        let t2 = env.now();

        assert!(t2 > t1, "Time should advance");
    }

    #[test]
    fn system_env_random_bytes_are_random() {
        let env = SystemEnv::new();

        let mut bytes1 = [0u8; 32];
        let mut bytes2 = [0u8; 32];

        env.random_bytes(&mut bytes1);
        env.random_bytes(&mut bytes2);

        // Extremely unlikely to be equal if random
        assert_ne!(bytes1, bytes2, "Random bytes should differ");
    }

    #[test]
    fn system_env_random_bytes_fills_buffer() {
        let env = SystemEnv::new();

        let mut bytes = [0u8; 64];
        env.random_bytes(&mut bytes);

        // Check that at least some bytes are non-zero
        let non_zero_count = bytes.iter().filter(|&&b| b != 0).count();
        assert!(non_zero_count > 32, "Most bytes should be non-zero");
    }

    #[tokio::test]
    async fn system_env_sleep_works() {
        let env = SystemEnv::new();

        let start = env.now();
        env.sleep(Duration::from_millis(50)).await;
        let elapsed = env.now() - start;

        assert!(elapsed >= Duration::from_millis(50), "Sleep should wait at least 50ms");
    }
}
