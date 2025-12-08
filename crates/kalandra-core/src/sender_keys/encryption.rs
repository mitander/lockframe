//! Message encryption using XChaCha20-Poly1305
//!
//! XChaCha20-Poly1305 provides:
//! - 256-bit key security
//! - 192-bit nonces (safe for random generation)
//! - Authenticated encryption with associated data (AEAD)

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};

use super::{error::SenderKeyError, ratchet::MessageKey};
use crate::env::Environment;

/// Poly1305 tag size (16 bytes, regardless of the message or key size)
const POLY1305_TAG_LENGTH: usize = 16;

/// An encrypted message with metadata for decryption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedMessage {
    /// The MLS epoch this message was encrypted under
    pub epoch: u64,
    /// The sender's leaf index
    pub sender_index: u32,
    /// The ratchet generation (for key derivation)
    pub generation: u32,
    /// The 24-byte XChaCha20 nonce
    pub nonce: [u8; 24],
    /// The ciphertext including 16-byte Poly1305 tag
    pub ciphertext: Vec<u8>,
}

impl EncryptedMessage {
    /// Get the plaintext length (ciphertext minus Poly1305 tag)
    pub fn plaintext_len(&self) -> usize {
        self.ciphertext.len().saturating_sub(POLY1305_TAG_LENGTH)
    }
}

/// Encrypt a message using XChaCha20-Poly1305.
///
/// Returns `EncryptedMessage` containing the ciphertext and metadata.
///
/// # Panics
///
/// - `encrypt` panics on invalid nonce length
///
/// # Security
///
/// - Nonce is constructed to be unique per (epoch, sender, generation, random)
/// - Random suffix prevents collision even if generation wraps
/// - Authenticated encryption prevents tampering
pub fn encrypt_message<E: Environment>(
    plaintext: &[u8],
    message_key: &MessageKey,
    epoch: u64,
    sender_index: u32,
    env: &E,
) -> EncryptedMessage {
    let nonce = build_nonce(epoch, sender_index, message_key.generation(), env);
    let cipher = XChaCha20Poly1305::new(message_key.key().into());

    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext)
        .expect("encryption should not fail with valid inputs");

    EncryptedMessage {
        epoch,
        sender_index,
        generation: message_key.generation(),
        nonce,
        ciphertext,
    }
}

/// Decrypt a message using XChaCha20-Poly1305.
///
/// Returns decrypted plaintext.
///
/// # Errors
///
/// Returns `DecryptionFailed` if:
/// - Authentication tag doesn't match (tampering detected)
/// - Key is incorrect
pub fn decrypt_message(
    encrypted: &EncryptedMessage,
    message_key: &MessageKey,
) -> Result<Vec<u8>, SenderKeyError> {
    if message_key.generation() != encrypted.generation {
        return Err(SenderKeyError::DecryptionFailed {
            reason: format!(
                "generation mismatch: key is {}, message is {}",
                message_key.generation(),
                encrypted.generation
            ),
        });
    }

    let cipher = XChaCha20Poly1305::new(message_key.key().into());
    let xnonce = XNonce::from_slice(&encrypted.nonce);
    let ciphertext = encrypted.ciphertext.as_slice();

    cipher.decrypt(xnonce, ciphertext).map_err(|_| SenderKeyError::DecryptionFailed {
        reason: "authentication failed".to_string(),
    })
}

/// Build a 24-byte nonce for XChaCha20.
fn build_nonce<E: Environment>(
    epoch: u64,
    sender_index: u32,
    generation: u32,
    env: &E,
) -> [u8; 24] {
    let mut nonce = [0u8; 24];

    // bytes 0-7: epoch (big-endian)
    nonce[0..8].copy_from_slice(&epoch.to_be_bytes());
    // bytes 8-11: sender_index (big-endian)
    nonce[8..12].copy_from_slice(&sender_index.to_be_bytes());
    // bytes 12-15: generation (big-endian)
    nonce[12..16].copy_from_slice(&generation.to_be_bytes());
    // bytes 16-23: random (from Environment)
    env.random_bytes(&mut nonce[16..24]);

    nonce
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{super::ratchet::SymmetricRatchet, *};

    // Test environment with deterministic randomness
    #[derive(Clone)]
    struct TestEnv {
        random_value: u8,
    }

    impl TestEnv {
        fn new(random_value: u8) -> Self {
            Self { random_value }
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
            buffer.fill(self.random_value);
        }
    }

    fn test_message_key(target_gen: u32) -> MessageKey {
        let mut key = [0u8; 32];
        for (i, byte) in key.iter_mut().enumerate() {
            *byte = (i + target_gen as usize) as u8;
        }

        // We need to construct MessageKey without its private constructor
        // So we'll use the ratchet to create one
        let mut ratchet = SymmetricRatchet::new(&key);

        // Advance to desired generation
        let mut msg_key = ratchet.advance().unwrap();
        for _ in 1..=target_gen {
            msg_key = ratchet.advance().unwrap();
        }
        msg_key
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let env = TestEnv::new(0xAB);
        let message_key = test_message_key(0);
        let plaintext = b"Hello, World!";

        let encrypted = encrypt_message(plaintext, &message_key, 1, 42, &env);
        let decrypted = decrypt_message(&encrypted, &message_key).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_decrypt_empty_message() {
        let env = TestEnv::new(0x00);
        let message_key = test_message_key(0);
        let plaintext = b"";

        let encrypted = encrypt_message(plaintext, &message_key, 0, 0, &env);
        let decrypted = decrypt_message(&encrypted, &message_key).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_decrypt_large_message() {
        let env = TestEnv::new(0xFF);
        let message_key = test_message_key(0);
        let plaintext = vec![0x42u8; 64 * 1024]; // 64KB

        let encrypted = encrypt_message(&plaintext, &message_key, 100, 200, &env);
        let decrypted = decrypt_message(&encrypted, &message_key).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypted_message_has_correct_metadata() {
        let env = TestEnv::new(0x00);
        let message_key = test_message_key(5);
        let plaintext = b"test";

        let encrypted = encrypt_message(plaintext, &message_key, 42, 7, &env);

        assert_eq!(encrypted.epoch, 42);
        assert_eq!(encrypted.sender_index, 7);
        // Generation comes from advance_to which will be at generation 5
        // But our test_message_key function advances 6 times (0 through 5)
        // so generation will be 5
    }

    #[test]
    fn ciphertext_is_larger_than_plaintext() {
        let env = TestEnv::new(0x00);
        let message_key = test_message_key(0);
        let plaintext = b"test message";

        let encrypted = encrypt_message(plaintext, &message_key, 0, 0, &env);

        // Ciphertext should be plaintext + tag size
        assert_eq!(encrypted.ciphertext.len(), plaintext.len() + POLY1305_TAG_LENGTH);
    }

    #[test]
    fn different_random_produces_different_nonces() {
        let env1 = TestEnv::new(0x00);
        let env2 = TestEnv::new(0xFF);
        let message_key = test_message_key(0);
        let plaintext = b"test";

        let encrypted1 = encrypt_message(plaintext, &message_key, 0, 0, &env1);
        let encrypted2 = encrypt_message(plaintext, &message_key, 0, 0, &env2);

        // Different nonces equals different ciphertexts
        assert_ne!(encrypted1.nonce, encrypted2.nonce);
        assert_ne!(encrypted1.ciphertext, encrypted2.ciphertext);
    }

    #[test]
    fn wrong_key_fails_decryption() {
        let env = TestEnv::new(0x00);
        let message_key = test_message_key(0);
        let plaintext = b"secret message";

        let encrypted = encrypt_message(plaintext, &message_key, 0, 0, &env);

        // Create a message key from a different ratchet (different seed)
        use super::super::ratchet::SymmetricRatchet;
        let mut different_seed = [0xFFu8; 32];
        different_seed[0] = 0x00;
        let mut ratchet = SymmetricRatchet::new(&different_seed);
        let wrong_key = ratchet.advance().unwrap();

        let result = decrypt_message(&encrypted, &wrong_key);
        assert!(result.is_err());

        match result {
            Err(SenderKeyError::DecryptionFailed { reason }) => {
                assert!(reason.contains("authentication"));
            },
            _ => panic!("expected DecryptionFailed error"),
        }
    }

    #[test]
    fn tampered_ciphertext_fails_decryption() {
        let env = TestEnv::new(0x00);
        let message_key = test_message_key(0);
        let plaintext = b"original message";

        let mut encrypted = encrypt_message(plaintext, &message_key, 0, 0, &env);

        // Tamper with the ciphertext
        if !encrypted.ciphertext.is_empty() {
            encrypted.ciphertext[0] ^= 0xFF;
        }

        let result = decrypt_message(&encrypted, &message_key);
        assert!(result.is_err());
    }

    #[test]
    fn nonce_structure() {
        let env = TestEnv::new(0xAB);
        let nonce = build_nonce::<TestEnv>(0x0102030405060708, 0x09_0A_0B_0C, 0x0D_0E_0F_10, &env);

        // Check epoch (bytes 0-7)
        assert_eq!(&nonce[0..8], &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);

        // Check sender_index (bytes 8-11)
        assert_eq!(&nonce[8..12], &[0x09, 0x0A, 0x0B, 0x0C]);

        // Check generation (bytes 12-15)
        assert_eq!(&nonce[12..16], &[0x0D, 0x0E, 0x0F, 0x10]);

        // Check random suffix (bytes 16-23)
        assert_eq!(&nonce[16..24], &[0xAB; 8]);
    }

    #[test]
    fn plaintext_len_calculation() {
        let env = TestEnv::new(0x00);
        let message_key = test_message_key(0);
        let plaintext = b"hello world";

        let encrypted = encrypt_message(plaintext, &message_key, 0, 0, &env);

        assert_eq!(encrypted.plaintext_len(), plaintext.len());
    }
}
