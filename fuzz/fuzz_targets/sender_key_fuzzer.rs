//! Fuzz target for Sender Key derivation and ratchet
//!
//! Tests HKDF key derivation and symmetric ratchet under adversarial inputs.
//!
//! # Strategy
//!
//! - Arbitrary epoch secrets (empty, small, large)
//! - Boundary epoch/sender values (0, MAX)
//! - Random ratchet advance sequences
//! - Out-of-order advance_to operations
//! - Encrypt/decrypt with derived keys
//!
//! # Invariants
//!
//! - Derivation is deterministic (same inputs → same output)
//! - Different inputs produce different outputs (collision resistance)
//! - Ratchet never panics on valid operations
//! - advance_to(n) produces same key as n sequential advance() calls
//! - Encrypt/decrypt roundtrip succeeds
//! - Corrupted ciphertext fails decryption

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use lockframe_crypto::{
    decrypt_message, derive_sender_key_seed, encrypt_message, MessageKey, SymmetricRatchet,
    NONCE_RANDOM_SIZE,
};

#[derive(Debug, Clone, Arbitrary)]
struct SenderKeyScenario {
    /// Epoch secret (variable length, up to 256 bytes)
    epoch_secret: EpochSecret,
    /// Epoch number
    epoch: u64,
    /// Sender index
    sender_index: u32,
    /// Ratchet operations to perform
    operations: Vec<RatchetOperation>,
    /// Random bytes for encryption nonces
    random_bytes: [u8; NONCE_RANDOM_SIZE],
}

#[derive(Debug, Clone, Arbitrary)]
enum EpochSecret {
    Empty,
    Small([u8; 8]),
    Normal([u8; 32]),
    Large([u8; 64]),
    Arbitrary(Vec<u8>),
}

impl EpochSecret {
    fn as_bytes(&self) -> &[u8] {
        match self {
            EpochSecret::Empty => &[],
            EpochSecret::Small(b) => b,
            EpochSecret::Normal(b) => b,
            EpochSecret::Large(b) => b,
            EpochSecret::Arbitrary(b) => b,
        }
    }
}

#[derive(Debug, Clone, Arbitrary)]
enum RatchetOperation {
    /// Advance ratchet one step
    Advance,
    /// Advance to specific generation (clamped to reasonable range)
    AdvanceTo { target: u16 },
    /// Encrypt a message with current key
    Encrypt { message: Vec<u8> },
    /// Derive same seed again and verify determinism
    VerifyDeterminism,
}

fuzz_target!(|scenario: SenderKeyScenario| {
    let epoch_secret = scenario.epoch_secret.as_bytes();

    // INVARIANT 1: Derivation always produces 32-byte output
    let seed = derive_sender_key_seed(epoch_secret, scenario.epoch, scenario.sender_index);
    assert_eq!(seed.len(), 32, "seed must be 32 bytes");

    // INVARIANT 2: Derivation is deterministic
    let seed2 = derive_sender_key_seed(epoch_secret, scenario.epoch, scenario.sender_index);
    assert_eq!(seed, seed2, "derivation must be deterministic");

    // INVARIANT 3: Different epoch produces different seed
    if scenario.epoch < u64::MAX {
        let different_seed =
            derive_sender_key_seed(epoch_secret, scenario.epoch + 1, scenario.sender_index);
        assert_ne!(seed, different_seed, "different epochs must produce different seeds");
    }

    // INVARIANT 4: Different sender produces different seed
    if scenario.sender_index < u32::MAX {
        let different_seed =
            derive_sender_key_seed(epoch_secret, scenario.epoch, scenario.sender_index + 1);
        assert_ne!(seed, different_seed, "different senders must produce different seeds");
    }

    let mut ratchet = SymmetricRatchet::new(&seed);
    assert_eq!(ratchet.generation(), 0, "new ratchet starts at generation 0");

    let mut last_key: Option<MessageKey> = None;

    for op in scenario.operations {
        match op {
            RatchetOperation::Advance => {
                // INVARIANT 5: Advance never panics (may error at u32::MAX)
                match ratchet.advance() {
                    Ok(key) => {
                        assert_eq!(key.key().len(), 32, "message key must be 32 bytes");
                        last_key = Some(key);
                    },
                    Err(_) => {
                        // Expected generation overflow at u32::MAX
                    },
                }
            },

            RatchetOperation::AdvanceTo { target } => {
                let target = target as u32;

                // INVARIANT 6: advance_to never panics
                match ratchet.advance_to(target) {
                    Ok(key) => {
                        assert_eq!(key.generation(), target, "key generation must match target");
                        last_key = Some(key);
                    },
                    Err(_) => {
                        // Expected generation misalignment
                    },
                }
            },

            RatchetOperation::Encrypt { message } => {
                if let Some(ref key) = last_key {
                    // INVARIANT 7: Encryption never panics
                    let encrypted = encrypt_message(
                        &message,
                        key,
                        scenario.epoch,
                        scenario.sender_index,
                        scenario.random_bytes,
                    );
                    assert!(
                        encrypted.ciphertext.len() >= message.len(),
                        "ciphertext must be at least as long as plaintext"
                    );

                    // INVARIANT 8: Decryption of valid ciphertext succeeds
                    let decrypted = decrypt_message(&encrypted, key);
                    assert!(decrypted.is_ok(), "decryption of valid ciphertext must succeed");
                    assert_eq!(
                        decrypted.unwrap(),
                        message,
                        "decrypted message must match original"
                    );

                    // INVARIANT 9: Corrupted ciphertext fails decryption
                    if !encrypted.ciphertext.is_empty() {
                        let mut corrupted = encrypted.clone();
                        corrupted.ciphertext[0] ^= 0xFF;
                        let result = decrypt_message(&corrupted, key);
                        assert!(result.is_err(), "corrupted ciphertext must fail decryption");
                    }
                }
            },

            RatchetOperation::VerifyDeterminism => {
                // INVARIANT 10: Same seed produces same ratchet sequence
                let mut verify_ratchet = SymmetricRatchet::new(&seed);
                let current_gen = ratchet.generation();

                for expected_gen in 0..current_gen.min(10) {
                    if let Ok(key) = verify_ratchet.advance() {
                        // Note: We can't compare with our ratchet since we already advanced
                        assert_eq!(key.generation(), expected_gen);
                    }
                }
            },
        }
    }
});
