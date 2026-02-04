//! `KeyPackage` registry for storing and retrieving MLS `KeyPackages`.
//!
//! Provides in-memory storage for `KeyPackages` indexed by `user_id`.
//! `KeyPackages` are consumed (deleted) after fetch to enforce one-time use.
//! Enforces capacity limits with LRU eviction to prevent unbounded growth.

#![allow(clippy::disallowed_types, reason = "Synchronous in-memory operations only")]
#![allow(clippy::expect_used, reason = "Mutex poisoning should cause a panic")]

use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
};

/// Default maximum number of `KeyPackages` to store.
pub const DEFAULT_MAX_CAPACITY: usize = 1000;

/// Result type for `KeyPackage` store operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreResult {
    /// `KeyPackage` was stored successfully.
    Success,
    /// `KeyPackage` was stored and another entry was evicted.
    Evicted,
    /// Registry is full and entry could not be stored.
    Full,
}

/// Stored `KeyPackage` entry with timestamp for LRU tracking.
#[derive(Debug, Clone)]
pub struct KeyPackageEntry {
    /// Serialized MLS `KeyPackage`.
    pub key_package_bytes: Vec<u8>,
    /// `KeyPackage` hash reference.
    pub hash_ref: Vec<u8>,
    /// Insertion timestamp for LRU tracking (simplified - using counter).
    timestamp: u64,
}

impl KeyPackageEntry {
    /// Create a new `KeyPackageEntry`.
    pub fn new(key_package_bytes: Vec<u8>, hash_ref: Vec<u8>) -> Self {
        Self {
            key_package_bytes,
            hash_ref,
            timestamp: 0, // Will be set by registry
        }
    }
}

/// In-memory registry for `KeyPackages` with LRU eviction.
///
/// Thread-safe via Arc<Mutex<_>>. Clone shares the same underlying storage.
#[derive(Clone)]
pub struct KeyPackageRegistry {
    inner: Arc<Mutex<KeyPackageRegistryInner>>,
}

/// Internal state for `KeyPackageRegistry`.
struct KeyPackageRegistryInner {
    /// `KeyPackage` entries indexed by `user_id`.
    entries: HashMap<u64, KeyPackageEntry>,
    /// LRU tracking - ordered list of `user_ids` (most recent at back).
    lru_order: VecDeque<u64>,
    /// Maximum capacity.
    max_capacity: usize,
    /// Monotonic counter for timestamps.
    timestamp_counter: u64,
}

impl Default for KeyPackageRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyPackageRegistry {
    /// Create a new empty registry with default capacity.
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_MAX_CAPACITY)
    }

    /// Create a new empty registry with specified capacity.
    pub fn with_capacity(max_capacity: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(KeyPackageRegistryInner {
                entries: HashMap::new(),
                lru_order: VecDeque::new(),
                max_capacity,
                timestamp_counter: 0,
            })),
        }
    }

    /// Store a `KeyPackage` for a user.
    ///
    /// Overwrites any existing `KeyPackage` for this `user_id` and updates LRU
    /// order. Evicts oldest entry if capacity is exceeded.
    ///
    /// Returns `StoreResult` indicating success, eviction, or if registry is
    /// full.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn store(&self, user_id: u64, mut entry: KeyPackageEntry) -> StoreResult {
        let mut inner = self.inner.lock().expect("KeyPackageRegistry mutex poisoned");

        entry.timestamp = inner.timestamp_counter;
        inner.timestamp_counter += 1;

        let is_new_entry = !inner.entries.contains_key(&user_id);
        if !is_new_entry {
            inner.lru_order.retain(|&id| id != user_id);
        }

        let result = if is_new_entry && inner.entries.len() >= inner.max_capacity {
            match inner.lru_order.pop_front() {
                Some(oldest_id) => {
                    inner.entries.remove(&oldest_id);
                    StoreResult::Evicted
                },
                None => return StoreResult::Full,
            }
        } else {
            StoreResult::Success
        };

        inner.entries.insert(user_id, entry);
        inner.lru_order.push_back(user_id);

        result
    }

    /// Fetch and remove a `KeyPackage` for a user.
    ///
    /// Returns `None` if no `KeyPackage` exists for this user.
    /// Removes the `KeyPackage` after fetching (one-time use).
    /// Also removes from LRU tracking.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn take(&self, user_id: u64) -> Option<KeyPackageEntry> {
        let mut inner = self.inner.lock().expect("KeyPackageRegistry mutex poisoned");

        let entry = inner.entries.remove(&user_id);
        // Remove from LRU order if entry existed
        if entry.is_some() {
            inner.lru_order.retain(|&id| id != user_id);
        }

        entry
    }

    /// Check if a `KeyPackage` exists for a user (without consuming it).
    ///
    /// # Concurrency
    ///
    /// The returned boolean may become stale immediately after this call
    /// returns. Another thread can call `take()` and remove the entry
    /// between your check and subsequent use. Callers must not assume the
    /// entry still exists after checking with `has()`.
    ///
    /// # Usage
    ///
    /// For atomic check-and-consume operations, prefer using `take()` directly
    /// and handling the `Option<KeyPackageEntry>` result, or use external
    /// synchronization to ensure atomicity.
    pub fn has(&self, user_id: u64) -> bool {
        let inner = self.inner.lock().expect("KeyPackageRegistry mutex poisoned");
        inner.entries.contains_key(&user_id)
    }

    /// Number of stored `KeyPackages`.
    pub fn count(&self) -> usize {
        let inner = self.inner.lock().expect("KeyPackageRegistry mutex poisoned");
        inner.entries.len()
    }

    /// Get the current capacity limit.
    pub fn capacity(&self) -> usize {
        let inner = self.inner.lock().expect("KeyPackageRegistry mutex poisoned");
        inner.max_capacity
    }

    /// Check if the registry is at capacity.
    pub fn is_full(&self) -> bool {
        let inner = self.inner.lock().expect("KeyPackageRegistry mutex poisoned");
        inner.entries.len() >= inner.max_capacity
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_and_take() {
        let registry = KeyPackageRegistry::new();

        let result = registry.store(42, KeyPackageEntry::new(vec![1, 2, 3], vec![4, 5, 6]));

        assert_eq!(result, StoreResult::Success);
        assert!(registry.has(42));
        assert_eq!(registry.count(), 1);

        let entry = registry.take(42).expect("should have entry");
        assert_eq!(entry.key_package_bytes, vec![1, 2, 3]);
        assert_eq!(entry.hash_ref, vec![4, 5, 6]);

        // Consumed after take
        assert!(!registry.has(42));
        assert_eq!(registry.count(), 0);
    }

    #[test]
    fn take_nonexistent_returns_none() {
        let registry = KeyPackageRegistry::new();
        assert!(registry.take(999).is_none());
    }

    #[test]
    fn store_overwrites_previous() {
        let registry = KeyPackageRegistry::new();

        registry.store(42, KeyPackageEntry::new(vec![1], vec![2]));
        registry.store(42, KeyPackageEntry::new(vec![3], vec![4]));

        let entry = registry.take(42).expect("should have entry");
        assert_eq!(entry.key_package_bytes, vec![3]);
    }

    #[test]
    fn clone_shares_state() {
        let registry1 = KeyPackageRegistry::new();
        let registry2 = registry1.clone();

        registry1.store(42, KeyPackageEntry::new(vec![1], vec![2]));

        assert!(registry2.has(42));
        let entry = registry2.take(42).expect("should have entry");
        assert_eq!(entry.key_package_bytes, vec![1]);

        assert!(!registry1.has(42));
    }

    #[test]
    fn with_capacity() {
        let registry = KeyPackageRegistry::with_capacity(5);
        assert_eq!(registry.capacity(), 5);
        assert!(!registry.is_full());
    }

    #[test]
    fn eviction_when_full() {
        let registry = KeyPackageRegistry::with_capacity(2);

        // Fill to capacity
        registry.store(1, KeyPackageEntry::new(vec![1], vec![1]));
        registry.store(2, KeyPackageEntry::new(vec![2], vec![2]));

        assert_eq!(registry.count(), 2);
        assert!(registry.is_full());

        // Add third entry - should evict oldest
        let result = registry.store(3, KeyPackageEntry::new(vec![3], vec![3]));
        assert_eq!(result, StoreResult::Evicted);

        assert_eq!(registry.count(), 2);
        assert!(!registry.has(1)); // Oldest evicted
        assert!(registry.has(2));
        assert!(registry.has(3));
    }

    #[test]
    fn overwrite_does_not_evict() {
        let registry = KeyPackageRegistry::with_capacity(2);

        // Fill to capacity
        registry.store(1, KeyPackageEntry::new(vec![1], vec![1]));
        registry.store(2, KeyPackageEntry::new(vec![2], vec![2]));

        assert_eq!(registry.count(), 2);

        // Overwrite existing entry - should not evict
        let result = registry.store(1, KeyPackageEntry::new(vec![10], vec![11]));
        assert_eq!(result, StoreResult::Success);

        assert_eq!(registry.count(), 2);
        assert!(registry.has(1));
        assert!(registry.has(2));

        let entry = registry.take(1).expect("should have entry");
        assert_eq!(entry.key_package_bytes, vec![10]); // Updated entry
    }

    #[test]
    fn lru_order_correct() {
        let registry = KeyPackageRegistry::with_capacity(3);

        // Add entries in order
        registry.store(1, KeyPackageEntry::new(vec![1], vec![1]));
        registry.store(2, KeyPackageEntry::new(vec![2], vec![2]));
        registry.store(3, KeyPackageEntry::new(vec![3], vec![3]));

        // Access entry 2 to make it most recent
        registry.store(2, KeyPackageEntry::new(vec![20], vec![22]));

        // Add entry 4 - should evict entry 1 (oldest)
        registry.store(4, KeyPackageEntry::new(vec![4], vec![4]));

        assert!(!registry.has(1)); // Evicted
        assert!(registry.has(2)); // Updated and kept
        assert!(registry.has(3));
        assert!(registry.has(4));
    }
}
