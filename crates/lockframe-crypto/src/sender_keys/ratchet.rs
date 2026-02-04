//! Symmetric Ratchet for forward-secure message key derivation
//!
//! # Security Properties
//!
//! - Forward Secrecy: Old chain keys are overwritten when advancing
//! - Key Uniqueness: Each generation produces a unique message key
//! - Determinism: Same seed always produces same key sequence

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

use super::error::SenderKeyError;

type HmacSha256 = Hmac<Sha256>;

/// Label for deriving the next chain key
const CHAIN_LABEL: &[u8] = b"chain";

/// Label for deriving a message key
const MESSAGE_LABEL: &[u8] = b"message";

/// Maximum number of generations to skip when catching up.
/// This limits the work done when receiving out-of-order messages.
const MAX_SKIP: u32 = 1000;

/// A message key derived from the ratchet.
///
/// This key is used for a single message encryption/decryption.
/// It should be used immediately and then discarded.
#[derive(Clone)]
pub struct MessageKey {
    /// The 32-byte symmetric key for XChaCha20-Poly1305
    key: [u8; 32],
    /// The generation (ratchet step) this key was derived from
    generation: u32,
}

impl MessageKey {
    /// 32-byte symmetric key for XChaCha20-Poly1305 AEAD.
    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }

    /// Ratchet generation this key was derived from.
    pub fn generation(&self) -> u32 {
        self.generation
    }
}

// Implement Drop to zeroize key material
impl Drop for MessageKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// Forward-secure symmetric ratchet.
///
/// Derives a sequence of message keys from an initial seed.
/// Each [`advance()`](Self::advance) call:
/// 1. Derives a message key from the current chain key
/// 2. Derives the next chain key
/// 3. Overwrites the old chain key (forward secrecy)
///
/// # Security
///
/// - Chain keys are overwritten immediately after use
/// - Compromise of current state doesn't reveal past keys
/// - Deterministic: same seed produces same sequence
pub struct SymmetricRatchet {
    /// Current chain key (32 bytes)
    chain_key: [u8; 32],
    /// Current generation (number of `advance()` calls)
    generation: u32,
}

impl SymmetricRatchet {
    /// Create a new ratchet from a sender key seed.
    ///
    /// The seed becomes the initial chain key (generation 0).
    pub fn new(seed: &[u8; 32]) -> Self {
        Self { chain_key: *seed, generation: 0 }
    }

    /// Current generation number.
    ///
    /// This is the number of times `advance()` has been called.
    pub fn generation(&self) -> u32 {
        self.generation
    }

    /// Advance the ratchet and derive the next message key.
    ///
    /// Returns message key for the current generation.
    ///
    /// This operation:
    /// 1. Derives a message key from the current chain key
    /// 2. Derives the next chain key
    /// 3. Overwrites the old chain key
    /// 4. Increments the generation counter
    pub fn advance(&mut self) -> Result<MessageKey, SenderKeyError> {
        if self.generation == u32::MAX {
            return Err(SenderKeyError::GenerationOverflow { current: self.generation });
        }

        let message_key = self.derive_message_key();
        let next_chain_key = self.derive_next_chain_key();

        // Zeroize and replace the old chain key for forward secrecy
        self.chain_key.zeroize();
        self.chain_key = next_chain_key;

        let current_gen = self.generation;
        self.generation = self.generation.wrapping_add(1);

        Ok(MessageKey { key: message_key, generation: current_gen })
    }

    /// Advance the ratchet to a specific generation.
    ///
    /// Used for decrypting out-of-order messages. If the target generation
    /// is ahead of our current position, we skip forward.
    pub fn advance_to(&mut self, target: u32) -> Result<MessageKey, SenderKeyError> {
        if target < self.generation {
            return Err(SenderKeyError::RatchetTooFarBehind {
                current: self.generation,
                requested: target,
            });
        }

        // We verified target >= self.generation above, so this won't underflow
        let skip_count = target.wrapping_sub(self.generation);
        if skip_count > MAX_SKIP {
            return Err(SenderKeyError::RatchetTooFarBehind {
                current: self.generation,
                requested: target,
            });
        }

        // Advance until we reach target
        // The last advance will return the message key we want
        let mut message_key = None;
        while self.generation <= target {
            message_key = Some(self.advance()?);
        }

        // We should always have a message key here since we loop at least once
        // (target >= self.generation at start, and we loop while generation <= target)
        message_key.ok_or(SenderKeyError::RatchetTooFarBehind {
            current: self.generation,
            requested: target,
        })
    }

    /// Derive the message key from the current chain key.
    fn derive_message_key(&self) -> [u8; 32] {
        let Ok(mut mac) = HmacSha256::new_from_slice(&self.chain_key) else {
            unreachable!("HMAC-SHA256 accepts any key size");
        };
        mac.update(MESSAGE_LABEL);
        let result = mac.finalize().into_bytes();

        let mut key = [0u8; 32];
        key.copy_from_slice(&result);
        key
    }

    /// Derive the next chain key from the current chain key.
    fn derive_next_chain_key(&self) -> [u8; 32] {
        let Ok(mut mac) = HmacSha256::new_from_slice(&self.chain_key) else {
            unreachable!("HMAC-SHA256 accepts any key size");
        };
        mac.update(CHAIN_LABEL);
        let result = mac.finalize().into_bytes();

        let mut key = [0u8; 32];
        key.copy_from_slice(&result);
        key
    }
}

impl Drop for SymmetricRatchet {
    fn drop(&mut self) {
        self.chain_key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_seed() -> [u8; 32] {
        let mut seed = [0u8; 32];
        for (i, byte) in seed.iter_mut().enumerate() {
            *byte = i as u8;
        }
        seed
    }

    #[test]
    fn new_ratchet_starts_at_generation_zero() {
        let ratchet = SymmetricRatchet::new(&test_seed());
        assert_eq!(ratchet.generation(), 0);
    }

    #[test]
    fn advance_increments_generation() {
        let mut ratchet = SymmetricRatchet::new(&test_seed());

        let key0 = ratchet.advance().unwrap();
        assert_eq!(key0.generation(), 0);
        assert_eq!(ratchet.generation(), 1);

        let key1 = ratchet.advance().unwrap();
        assert_eq!(key1.generation(), 1);
        assert_eq!(ratchet.generation(), 2);
    }

    #[test]
    fn advance_produces_unique_keys() {
        let mut ratchet = SymmetricRatchet::new(&test_seed());

        let key0 = ratchet.advance().unwrap();
        let key1 = ratchet.advance().unwrap();
        let key2 = ratchet.advance().unwrap();

        assert_ne!(key0.key(), key1.key(), "keys must be unique");
        assert_ne!(key1.key(), key2.key(), "keys must be unique");
        assert_ne!(key0.key(), key2.key(), "keys must be unique");
    }

    #[test]
    fn ratchet_is_deterministic() {
        let seed = test_seed();

        let mut ratchet1 = SymmetricRatchet::new(&seed);
        let mut ratchet2 = SymmetricRatchet::new(&seed);

        for _ in 0..10 {
            let key1 = ratchet1.advance().unwrap();
            let key2 = ratchet2.advance().unwrap();
            assert_eq!(key1.key(), key2.key(), "same seed must produce same keys");
            assert_eq!(key1.generation(), key2.generation());
        }
    }

    #[test]
    fn different_seeds_produce_different_keys() {
        let mut seed1 = [0u8; 32];
        let mut seed2 = [0u8; 32];
        seed1[0] = 1;
        seed2[0] = 2;

        let mut ratchet1 = SymmetricRatchet::new(&seed1);
        let mut ratchet2 = SymmetricRatchet::new(&seed2);

        let key1 = ratchet1.advance().unwrap();
        let key2 = ratchet2.advance().unwrap();

        assert_ne!(key1.key(), key2.key(), "different seeds must produce different keys");
    }

    #[test]
    fn advance_to_current_generation() {
        let mut ratchet = SymmetricRatchet::new(&test_seed());

        // Advance to generation 0 (current)
        let key = ratchet.advance_to(0).unwrap();
        assert_eq!(key.generation(), 0);
        assert_eq!(ratchet.generation(), 1);
    }

    #[test]
    fn advance_to_skips_forward() {
        let mut ratchet = SymmetricRatchet::new(&test_seed());

        // Skip to generation 5
        let key = ratchet.advance_to(5).unwrap();
        assert_eq!(key.generation(), 5);
        assert_eq!(ratchet.generation(), 6);
    }

    #[test]
    fn advance_to_matches_sequential_advance() {
        let seed = test_seed();

        // Sequential advance
        let mut ratchet1 = SymmetricRatchet::new(&seed);
        for _ in 0..5 {
            ratchet1.advance().unwrap();
        }
        let key_sequential = ratchet1.advance().unwrap();

        // Skip advance
        let mut ratchet2 = SymmetricRatchet::new(&seed);
        let key_skip = ratchet2.advance_to(5).unwrap();

        assert_eq!(
            key_sequential.key(),
            key_skip.key(),
            "skip and sequential must produce same key"
        );
    }

    #[test]
    fn advance_to_rejects_past_generation() {
        let mut ratchet = SymmetricRatchet::new(&test_seed());

        // Advance to generation 5
        ratchet.advance_to(5).unwrap();

        // Try to go back to generation 3
        let result = ratchet.advance_to(3);
        assert!(result.is_err());

        match result {
            Err(SenderKeyError::RatchetTooFarBehind { current, requested }) => {
                assert_eq!(current, 6); // We're at 6 after advance_to(5)
                assert_eq!(requested, 3);
            },
            _ => unreachable!("expected RatchetTooFarBehind error"),
        }
    }

    #[test]
    fn advance_to_rejects_too_far_ahead() {
        let mut ratchet = SymmetricRatchet::new(&test_seed());

        // Try to skip more than MAX_SKIP
        let result = ratchet.advance_to(MAX_SKIP + 100);
        assert!(result.is_err());

        match result {
            Err(SenderKeyError::RatchetTooFarBehind { .. }) => {},
            _ => unreachable!("expected RatchetTooFarBehind error"),
        }
    }

    #[test]
    fn message_key_has_32_byte_key() {
        let mut ratchet = SymmetricRatchet::new(&test_seed());
        let key = ratchet.advance().unwrap();
        assert_eq!(key.key().len(), 32);
    }
}
