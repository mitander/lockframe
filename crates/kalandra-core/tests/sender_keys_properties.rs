//! Property-based tests for Sender Keys
//!
//! These tests verify the fundamental invariants of the sender keys system:
//!
//! 1. **Round-trip**: decrypt(encrypt(m)) == m for all messages
//! 2. **Key uniqueness**: Different ratchet generations produce different keys
//! 3. **Determinism**: Same inputs always produce same outputs
//! 4. **Isolation**: Different senders/epochs produce different keys

use std::time::Duration;

use kalandra_core::{
    env::Environment,
    sender_keys::{
        MessageKey, SymmetricRatchet, decrypt_message, derive_sender_key_seed, encrypt_message,
    },
};
use proptest::prelude::*;

// Test environment with configurable randomness
// Uses AtomicUsize for thread-safe index tracking
#[derive(Clone)]
struct TestEnv {
    random_byte: u8,
}

impl TestEnv {
    fn deterministic(value: u8) -> Self {
        Self { random_byte: value }
    }
}

impl Environment for TestEnv {
    type Instant = std::time::Instant;

    fn now(&self) -> Self::Instant {
        std::time::Instant::now()
    }

    fn sleep(&self, _duration: Duration) -> impl std::future::Future<Output = ()> + Send {
        async {}
    }

    fn random_bytes(&self, buffer: &mut [u8]) {
        buffer.fill(self.random_byte);
    }
}

// Helper to create a message key at a specific generation
fn create_message_key(seed: &[u8; 32], target_gen: u32) -> MessageKey {
    let mut ratchet = SymmetricRatchet::new(seed);
    let mut key = ratchet.advance().unwrap();
    for _ in 1..=target_gen {
        key = ratchet.advance().unwrap();
    }
    key
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn prop_encrypt_decrypt_roundtrip(
        plaintext in prop::collection::vec(any::<u8>(), 0..1000),
        epoch in any::<u64>(),
        sender_index in any::<u32>(),
        random_byte in any::<u8>(),
    ) {
        let env = TestEnv::deterministic(random_byte);
        let seed = derive_sender_key_seed(b"test_epoch_secret_______________", epoch, sender_index);
        let message_key = create_message_key(&seed, 0);

        let encrypted = encrypt_message(&plaintext, &message_key, epoch, sender_index, &env);
        let decrypted = decrypt_message(&encrypted, &message_key).unwrap();

        prop_assert_eq!(decrypted, plaintext);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    #[test]
    fn prop_ratchet_keys_unique(
        seed in prop::collection::vec(any::<u8>(), 32..=32).prop_map(|v| {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&v);
            arr
        }),
        num_keys in 2usize..20,
    ) {
        let mut ratchet = SymmetricRatchet::new(&seed);
        let mut keys = Vec::with_capacity(num_keys);

        for _ in 0..num_keys {
            keys.push(ratchet.advance().unwrap());
        }

        // All keys should be unique
        for i in 0..keys.len() {
            for j in (i + 1)..keys.len() {
                prop_assert_ne!(
                    keys[i].key(),
                    keys[j].key(),
                    "keys at generation {} and {} must be different",
                    keys[i].generation(),
                    keys[j].generation()
                );
            }
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    #[test]
    fn prop_derivation_deterministic(
        epoch_secret in prop::collection::vec(any::<u8>(), 1..100),
        epoch in any::<u64>(),
        sender_index in any::<u32>(),
    ) {
        let seed1 = derive_sender_key_seed(&epoch_secret, epoch, sender_index);
        let seed2 = derive_sender_key_seed(&epoch_secret, epoch, sender_index);

        prop_assert_eq!(seed1, seed2);
    }

    #[test]
    fn prop_ratchet_deterministic(
        seed in prop::collection::vec(any::<u8>(), 32..=32).prop_map(|v| {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&v);
            arr
        }),
        num_advances in 1usize..10,
    ) {
        let mut ratchet1 = SymmetricRatchet::new(&seed);
        let mut ratchet2 = SymmetricRatchet::new(&seed);

        for _ in 0..num_advances {
            let key1 = ratchet1.advance().unwrap();
            let key2 = ratchet2.advance().unwrap();

            prop_assert_eq!(key1.key(), key2.key());
            prop_assert_eq!(key1.generation(), key2.generation());
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    #[test]
    fn prop_different_senders_different_seeds(
        epoch_secret in prop::collection::vec(any::<u8>(), 32..=32),
        epoch in any::<u64>(),
        sender1 in any::<u32>(),
        sender2 in any::<u32>(),
    ) {
        prop_assume!(sender1 != sender2);

        let seed1 = derive_sender_key_seed(&epoch_secret, epoch, sender1);
        let seed2 = derive_sender_key_seed(&epoch_secret, epoch, sender2);

        prop_assert_ne!(seed1, seed2);
    }

    #[test]
    fn prop_different_epochs_different_seeds(
        epoch_secret in prop::collection::vec(any::<u8>(), 32..=32),
        epoch1 in any::<u64>(),
        epoch2 in any::<u64>(),
        sender_index in any::<u32>(),
    ) {
        prop_assume!(epoch1 != epoch2);

        let seed1 = derive_sender_key_seed(&epoch_secret, epoch1, sender_index);
        let seed2 = derive_sender_key_seed(&epoch_secret, epoch2, sender_index);

        prop_assert_ne!(seed1, seed2);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(30))]

    #[test]
    fn prop_advance_to_matches_sequential(
        seed in prop::collection::vec(any::<u8>(), 32..=32).prop_map(|v| {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&v);
            arr
        }),
        target_gen in 0u32..50,
    ) {
        // Sequential advance
        let mut ratchet_seq = SymmetricRatchet::new(&seed);
        let mut key_seq = ratchet_seq.advance().unwrap();
        for _ in 1..=target_gen {
            key_seq = ratchet_seq.advance().unwrap();
        }

        // Skip advance
        let mut ratchet_skip = SymmetricRatchet::new(&seed);
        let key_skip = ratchet_skip.advance_to(target_gen).unwrap();

        prop_assert_eq!(key_seq.key(), key_skip.key());
        prop_assert_eq!(key_seq.generation(), key_skip.generation());
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    #[test]
    fn prop_encrypted_message_structure(
        plaintext in prop::collection::vec(any::<u8>(), 0..500),
        epoch in any::<u64>(),
        sender_index in any::<u32>(),
    ) {
        let env = TestEnv::deterministic(0x42);
        let seed = derive_sender_key_seed(b"test_epoch_secret_______________", epoch, sender_index);
        let message_key = create_message_key(&seed, 0);

        let encrypted = encrypt_message(&plaintext, &message_key, epoch, sender_index, &env);

        // Verify metadata is preserved
        prop_assert_eq!(encrypted.epoch, epoch);
        prop_assert_eq!(encrypted.sender_index, sender_index);
        prop_assert_eq!(encrypted.generation, message_key.generation());

        // Verify ciphertext size (plaintext + 16-byte tag)
        prop_assert_eq!(encrypted.ciphertext.len(), plaintext.len() + 16);

        // Verify nonce structure
        prop_assert_eq!(&encrypted.nonce[0..8], &epoch.to_be_bytes());
        prop_assert_eq!(&encrypted.nonce[8..12], &sender_index.to_be_bytes());
    }
}
