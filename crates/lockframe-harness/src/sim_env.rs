//! Turmoil-based Environment implementation for deterministic testing.

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use lockframe_core::env::Environment;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

/// Simulation environment using Turmoil's virtual time and seeded RNG.
///
/// now() returns Turmoil's simulated time, which can be advanced instantly via
/// turmoil::sleep(). random_bytes() uses ChaCha20Rng seeded with a fixed value
/// (0 by default), ensuring reproducible test runs and easier debugging.
#[derive(Clone)]
pub struct SimEnv {
    /// Seeded RNG for deterministic random bytes
    ///
    /// Wrapped in Arc<Mutex<>> to allow Clone while maintaining shared state
    /// across clones (important for proper RNG sequence).
    /// Note: Turmoil is single-threaded, so this Mutex will never block.
    rng: Arc<Mutex<ChaCha20Rng>>,
}

impl SimEnv {
    /// Create a new SimEnv with default seed (0)
    ///
    /// Use this for most tests where determinism is important but the specific
    /// seed doesn't matter.
    pub fn new() -> Self {
        Self::with_seed(0)
    }

    /// Create a new SimEnv with a specific seed
    ///
    /// Use this when you want to test different random scenarios while
    /// maintaining reproducibility.
    pub fn with_seed(seed: u64) -> Self {
        Self { rng: Arc::new(Mutex::new(ChaCha20Rng::seed_from_u64(seed))) }
    }
}

impl Default for SimEnv {
    fn default() -> Self {
        Self::new()
    }
}

impl Environment for SimEnv {
    type Instant = tokio::time::Instant;

    fn now(&self) -> Self::Instant {
        tokio::time::Instant::now()
    }

    async fn sleep(&self, duration: Duration) {
        tokio::time::sleep(duration).await;
    }

    fn random_bytes(&self, dest: &mut [u8]) {
        self.rng
            .lock()
            .unwrap_or_else(|e| {
                // SAFETY: Turmoil is single threaded. Mutex can only be poisoned if another
                // thread panics while holding the lock.
                unreachable!("RNG mutex poisoned in single-threaded context: {}", e)
            })
            .fill_bytes(dest);
    }

    fn wall_clock_secs(&self) -> u64 {
        // For simulation, return a fixed timestamp (2024-01-01 00:00:00 UTC)
        // Virtual time in turmoil is relative, not absolute
        1704067200
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sim_env_time_advances() {
        let mut sim = turmoil::Builder::new().build();

        sim.client("test", async {
            let env = SimEnv::new();

            let start = env.now();
            env.sleep(Duration::from_secs(5)).await;
            let end = env.now();

            assert_eq!(end - start, Duration::from_secs(5));

            Ok(())
        });

        sim.run().expect("simulation failed");
    }

    #[test]
    fn sim_env_rng_is_deterministic() {
        // Run the same test twice with same seed, verify same output
        let run_test = |seed: u64| -> Vec<u8> {
            let env = SimEnv::with_seed(seed);
            let mut bytes = vec![0u8; 64];
            env.random_bytes(&mut bytes);
            bytes
        };

        let bytes1 = run_test(12345);
        let bytes2 = run_test(12345);

        // Same seed -> same bytes
        assert_eq!(bytes1, bytes2, "RNG with same seed should produce same output");

        let bytes3 = run_test(54321);
        // Different seed -> different bytes
        assert_ne!(bytes1, bytes3, "RNG with different seed should produce different output");
    }

    #[test]
    fn sim_env_rng_different_calls_different_output() {
        let env = SimEnv::new();

        let mut bytes1 = [0u8; 32];
        let mut bytes2 = [0u8; 32];

        env.random_bytes(&mut bytes1);
        env.random_bytes(&mut bytes2);

        // Sequential calls should produce different bytes
        assert_ne!(&bytes1[..], &bytes2[..]);
    }

    #[test]
    fn sim_env_clones_share_rng_state() {
        let env1 = SimEnv::with_seed(999);
        let env2 = env1.clone();

        let mut bytes1 = [0u8; 32];
        let mut bytes2 = [0u8; 32];

        env1.random_bytes(&mut bytes1);
        env2.random_bytes(&mut bytes2);

        // Clones share RNG state, so sequential calls produce different bytes
        assert_ne!(&bytes1[..], &bytes2[..]);
    }
}
