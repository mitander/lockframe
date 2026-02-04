//! Chaotic storage wrapper for fault injection testing
//!
//! Storage wrapper that randomly fails operations to test error handling and
//! recovery. Used for chaos testing to ensure the system handles storage
//! failures gracefully.

#![allow(clippy::disallowed_types, reason = "Locking simple RNG state")]

use std::sync::{Arc, Mutex};

use lockframe_core::mls::MlsGroupState;
use lockframe_proto::Frame;

use super::{Storage, StorageError, StoredRoomMetadata};

/// Chaotic storage wrapper that randomly injects failures
///
/// Delegates to an underlying storage implementation but randomly fails
/// operations based on a configured failure rate. Used for chaos testing to
/// verify error handling. Uses Arc<Mutex<>> for the RNG state, making it Clone
/// and thread-safe.
#[derive(Clone)]
pub struct ChaoticStorage<S: Storage> {
    inner: S,
    /// Failure rate (0.0 = never fail, 1.0 = always fail)
    failure_rate: f64,
    /// RNG state for deterministic chaos
    rng: Arc<Mutex<ChaoticRng>>,
    /// Operation counter for performance testing
    operation_count: Arc<Mutex<usize>>,
}

/// Simple deterministic RNG for chaos injection
///
/// Uses linear congruential generator (LCG) for fast, deterministic randomness.
/// This ensures chaos tests are reproducible with the same seed.
struct ChaoticRng {
    state: u64,
}

impl ChaoticRng {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Generate next random value [0.0, 1.0)
    fn next(&mut self) -> f64 {
        // LCG constants from Numerical Recipes
        const A: u64 = 1_664_525;
        const C: u64 = 1_013_904_223;
        const M: u64 = 1u64 << 32;

        self.state = (A.wrapping_mul(self.state).wrapping_add(C)) % M;
        (self.state as f64) / (M as f64)
    }

    /// Check if we should fail (returns true with probability = `failure_rate`)
    fn should_fail(&mut self, failure_rate: f64) -> bool {
        self.next() < failure_rate
    }
}

impl<S: Storage> ChaoticStorage<S> {
    /// Create a new chaotic storage wrapper
    ///
    /// # Panics
    ///
    /// Panics if `failure_rate` is not in [0.0, 1.0]
    pub fn new(inner: S, failure_rate: f64) -> Self {
        assert!(
            (0.0..=1.0).contains(&failure_rate),
            "failure_rate must be between 0.0 and 1.0, got {failure_rate}"
        );

        Self::with_seed(inner, failure_rate, 0x1234_5678_9ABC_DEF0)
    }

    /// Create with explicit seed for reproducible chaos
    pub fn with_seed(inner: S, failure_rate: f64, seed: u64) -> Self {
        assert!(
            (0.0..=1.0).contains(&failure_rate),
            "failure_rate must be between 0.0 and 1.0, got {failure_rate}"
        );

        Self {
            inner,
            failure_rate,
            rng: Arc::new(Mutex::new(ChaoticRng::new(seed))),
            operation_count: Arc::new(Mutex::new(0)),
        }
    }

    /// Underlying storage (for checking invariants after chaos).
    pub fn inner(&self) -> &S {
        &self.inner
    }

    /// Total number of storage operations attempted.
    ///
    /// Used for performance oracles to verify O(n) complexity.
    /// Each call to any storage method increments this counter.
    pub fn operation_count(&self) -> usize {
        #[allow(clippy::expect_used)]
        *self.operation_count.lock().expect("operation_count mutex poisoned")
    }

    /// Increment operation counter
    fn increment_operation_count(&self) {
        #[allow(clippy::expect_used)]
        let mut count = self.operation_count.lock().expect("operation_count mutex poisoned");
        *count += 1;
    }

    /// Check if this operation should fail
    fn should_fail(&self) -> bool {
        #[allow(clippy::expect_used)]
        self.rng.lock().expect("ChaoticRng mutex poisoned").should_fail(self.failure_rate)
    }
}

impl<S: Storage> Storage for ChaoticStorage<S> {
    fn store_frame(
        &self,
        room_id: u128,
        log_index: u64,
        frame: &Frame,
    ) -> Result<(), StorageError> {
        self.increment_operation_count();
        if self.should_fail() {
            return Err(StorageError::Io("chaotic failure injection".to_string()));
        }
        self.inner.store_frame(room_id, log_index, frame)
    }

    fn latest_log_index(&self, room_id: u128) -> Result<Option<u64>, StorageError> {
        self.increment_operation_count();
        if self.should_fail() {
            return Err(StorageError::Io("chaotic failure injection".to_string()));
        }
        self.inner.latest_log_index(room_id)
    }

    fn load_frames(
        &self,
        room_id: u128,
        from: u64,
        limit: usize,
    ) -> Result<Vec<Frame>, StorageError> {
        self.increment_operation_count();
        if self.should_fail() {
            return Err(StorageError::Io("chaotic failure injection".to_string()));
        }
        self.inner.load_frames(room_id, from, limit)
    }

    fn store_mls_state(&self, room_id: u128, state: &MlsGroupState) -> Result<(), StorageError> {
        self.increment_operation_count();
        if self.should_fail() {
            return Err(StorageError::Io("chaotic failure injection".to_string()));
        }
        self.inner.store_mls_state(room_id, state)
    }

    fn load_mls_state(&self, room_id: u128) -> Result<Option<MlsGroupState>, StorageError> {
        self.increment_operation_count();
        if self.should_fail() {
            return Err(StorageError::Io("chaotic failure injection".to_string()));
        }
        self.inner.load_mls_state(room_id)
    }

    fn store_group_info(
        &self,
        room_id: u128,
        epoch: u64,
        group_info: &[u8],
    ) -> Result<(), StorageError> {
        self.increment_operation_count();
        if self.should_fail() {
            return Err(StorageError::Io("chaotic failure injection".to_string()));
        }
        self.inner.store_group_info(room_id, epoch, group_info)
    }

    fn load_group_info(&self, room_id: u128) -> Result<Option<(u64, Vec<u8>)>, StorageError> {
        self.increment_operation_count();
        if self.should_fail() {
            return Err(StorageError::Io("chaotic failure injection".to_string()));
        }
        self.inner.load_group_info(room_id)
    }

    fn list_rooms(&self) -> Result<Vec<u128>, StorageError> {
        self.increment_operation_count();
        if self.should_fail() {
            return Err(StorageError::Io("chaotic failure injection".to_string()));
        }
        self.inner.list_rooms()
    }

    fn create_room(
        &self,
        room_id: u128,
        metadata: &StoredRoomMetadata,
    ) -> Result<(), StorageError> {
        self.increment_operation_count();
        if self.should_fail() {
            return Err(StorageError::Io("chaotic failure injection".to_string()));
        }
        self.inner.create_room(room_id, metadata)
    }

    fn load_room_metadata(
        &self,
        room_id: u128,
    ) -> Result<Option<StoredRoomMetadata>, StorageError> {
        self.increment_operation_count();
        if self.should_fail() {
            return Err(StorageError::Io("chaotic failure injection".to_string()));
        }
        self.inner.load_room_metadata(room_id)
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use lockframe_proto::{Frame, FrameHeader, Opcode};

    use super::*;
    use crate::storage::MemoryStorage;

    fn create_test_frame(room_id: u128, log_index: u64) -> Frame {
        let mut header = FrameHeader::new(Opcode::AppMessage);
        header.set_room_id(room_id);
        header.set_log_index(log_index);

        Frame::new(header, Bytes::new())
    }

    #[test]
    fn test_chaotic_with_zero_failure_rate() {
        let storage = MemoryStorage::new();
        let chaotic = ChaoticStorage::new(storage, 0.0);

        // With 0% failure rate, should always succeed
        for i in 0..100 {
            let frame = create_test_frame(100, i);
            chaotic.store_frame(100, i, &frame).expect("should not fail with 0% rate");
        }

        assert_eq!(chaotic.latest_log_index(100).expect("query failed"), Some(99));
    }

    #[test]
    fn test_chaotic_with_100_failure_rate() {
        let storage = MemoryStorage::new();
        let chaotic = ChaoticStorage::new(storage, 1.0);

        let frame = create_test_frame(100, 0);

        // With 100% failure rate, should always fail
        assert!(chaotic.store_frame(100, 0, &frame).is_err());
        assert!(chaotic.latest_log_index(100).is_err());
        assert!(chaotic.load_frames(100, 0, 10).is_err());
    }

    #[test]
    fn test_chaotic_deterministic_with_seed() {
        let storage1 = MemoryStorage::new();
        let chaotic1 = ChaoticStorage::with_seed(storage1, 0.5, 42);

        let storage2 = MemoryStorage::new();
        let chaotic2 = ChaoticStorage::with_seed(storage2, 0.5, 42);

        // Same seed should produce same failure pattern
        for i in 0..100 {
            let frame = create_test_frame(100, i);
            let result1 = chaotic1.store_frame(100, i, &frame);
            let result2 = chaotic2.store_frame(100, i, &frame);

            assert_eq!(result1.is_ok(), result2.is_ok(), "determinism violated at iteration {i}");
        }
    }

    #[test]
    fn test_chaotic_accesses_underlying_storage() {
        let storage = MemoryStorage::new();
        let chaotic = ChaoticStorage::new(storage, 0.0);

        let frame = create_test_frame(100, 0);
        chaotic.store_frame(100, 0, &frame).expect("store failed");

        // Check that inner storage actually has the frame
        assert_eq!(chaotic.inner().latest_log_index(100).expect("query failed"), Some(0));
    }

    #[test]
    #[should_panic(expected = "failure_rate must be between 0.0 and 1.0")]
    fn test_chaotic_rejects_invalid_failure_rate() {
        let storage = MemoryStorage::new();
        let _chaotic = ChaoticStorage::new(storage, 1.5); // Invalid!
    }
}
