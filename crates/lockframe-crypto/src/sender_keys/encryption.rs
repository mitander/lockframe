//! Message encryption using `XChaCha20-Poly1305`
//!
//! All functions are pure - random bytes must be provided by the caller.
//! This enables deterministic testing and maintains action-based compatibility.

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};

use super::{error::SenderKeyError, ratchet::MessageKey};

/// Size of the random suffix in the nonce (8 bytes)
pub const NONCE_RANDOM_SIZE: usize = 8;

/// Poly1305 tag size (16 bytes)
const POLY1305_TAG_SIZE: usize = 16;

/// An encrypted message with metadata for decryption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedMessage {
    /// The MLS epoch this message was encrypted under
    pub epoch: u64,
    /// The sender's leaf index
    pub sender_index: u32,
    /// The ratchet generation (for key derivation)
    pub generation: u32,
    /// The 24-byte `XChaCha20` nonce
    pub nonce: [u8; 24],
    /// The ciphertext including 16-byte Poly1305 tag
    pub ciphertext: Vec<u8>,
}

impl EncryptedMessage {
    /// Plaintext length (ciphertext length minus authentication tag).
    pub fn plaintext_len(&self) -> usize {
        self.ciphertext.len().saturating_sub(POLY1305_TAG_SIZE)
    }
}

/// Encrypt a message using `XChaCha20-Poly1305`.
///
/// Returns `EncryptedMessage` containing the ciphertext and metadata.
///
/// # Security
///
/// - Nonce is constructed to be unique per (epoch, sender, generation, random)
/// - Random suffix prevents collision even if generation wraps
/// - Authenticated encryption prevents tampering
/// - Caller MUST provide cryptographically secure random bytes in production
pub fn encrypt_message(
    plaintext: &[u8],
    message_key: &MessageKey,
    epoch: u64,
    sender_index: u32,
    random_suffix: [u8; NONCE_RANDOM_SIZE],
) -> EncryptedMessage {
    let nonce = build_nonce(epoch, sender_index, message_key.generation(), random_suffix);
    let cipher = XChaCha20Poly1305::new(message_key.key().into());

    let Ok(ciphertext) = cipher.encrypt(XNonce::from_slice(&nonce), plaintext) else {
        unreachable!("XChaCha20-Poly1305 encryption cannot fail with valid inputs");
    };

    EncryptedMessage {
        epoch,
        sender_index,
        generation: message_key.generation(),
        nonce,
        ciphertext,
    }
}

/// Decrypt a message using `XChaCha20-Poly1305`.
///
/// Returns the decrypted plaintext.
///
/// # Errors
///
/// - `DecryptionFailed`: If authentication tag or key is incorrect (tamper)
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
    let nonce = XNonce::from_slice(&encrypted.nonce);
    let plaintext = encrypted.ciphertext.as_slice();

    cipher.decrypt(nonce, plaintext).map_err(|_| SenderKeyError::DecryptionFailed {
        reason: "authentication failed".to_string(),
    })
}

/// Build a 24-byte nonce for `XChaCha20`.
///
/// Structure:
/// - bytes 0-7: epoch (big-endian)
/// - bytes 8-11: `sender_index` (big-endian)
/// - bytes 12-15: generation (big-endian)
/// - bytes 16-23: random suffix (caller-provided)
fn build_nonce(
    epoch: u64,
    sender_index: u32,
    generation: u32,
    random_suffix: [u8; NONCE_RANDOM_SIZE],
) -> [u8; 24] {
    let mut nonce = [0u8; 24];

    // Epoch (8 bytes)
    nonce[0..8].copy_from_slice(&epoch.to_be_bytes());

    // Sender index (4 bytes)
    nonce[8..12].copy_from_slice(&sender_index.to_be_bytes());

    // Generation (4 bytes)
    nonce[12..16].copy_from_slice(&generation.to_be_bytes());

    // Random suffix (8 bytes)
    nonce[16..24].copy_from_slice(&random_suffix);

    nonce
}

#[cfg(test)]
mod tests {
    use super::{super::ratchet::SymmetricRatchet, *};

    fn test_message_key(target_gen: u32) -> MessageKey {
        let mut key = [0u8; 32];
        for (i, byte) in key.iter_mut().enumerate() {
            *byte = (i + target_gen as usize) as u8;
        }

        let mut ratchet = SymmetricRatchet::new(&key);

        let mut msg_key = ratchet.advance().unwrap();
        for _ in 1..=target_gen {
            msg_key = ratchet.advance().unwrap();
        }
        msg_key
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let message_key = test_message_key(0);
        let plaintext = b"Hello, World!";
        let random_suffix = [0xAB; NONCE_RANDOM_SIZE];

        let encrypted = encrypt_message(plaintext, &message_key, 1, 42, random_suffix);
        let decrypted = decrypt_message(&encrypted, &message_key).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_decrypt_empty_message() {
        let message_key = test_message_key(0);
        let plaintext = b"";
        let random_suffix = [0x00; NONCE_RANDOM_SIZE];

        let encrypted = encrypt_message(plaintext, &message_key, 0, 0, random_suffix);
        let decrypted = decrypt_message(&encrypted, &message_key).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_decrypt_large_message() {
        let message_key = test_message_key(0);
        let plaintext = vec![0x42u8; 64 * 1024]; // 64KB
        let random_suffix = [0xFF; NONCE_RANDOM_SIZE];

        let encrypted = encrypt_message(&plaintext, &message_key, 100, 200, random_suffix);
        let decrypted = decrypt_message(&encrypted, &message_key).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypted_message_has_correct_metadata() {
        let message_key = test_message_key(5);
        let plaintext = b"test";
        let random_suffix = [0x00; NONCE_RANDOM_SIZE];

        let encrypted = encrypt_message(plaintext, &message_key, 42, 7, random_suffix);

        assert_eq!(encrypted.epoch, 42);
        assert_eq!(encrypted.sender_index, 7);
        assert_eq!(encrypted.generation, 5);
    }

    #[test]
    fn ciphertext_is_larger_than_plaintext() {
        let message_key = test_message_key(0);
        let plaintext = b"test message";
        let random_suffix = [0x00; NONCE_RANDOM_SIZE];

        let encrypted = encrypt_message(plaintext, &message_key, 0, 0, random_suffix);

        // Ciphertext should be plaintext + 16-byte tag
        assert_eq!(encrypted.ciphertext.len(), plaintext.len() + POLY1305_TAG_SIZE);
    }

    #[test]
    fn different_random_produces_different_nonces() {
        let message_key = test_message_key(0);
        let plaintext = b"test";

        let encrypted1 = encrypt_message(plaintext, &message_key, 0, 0, [0x00; NONCE_RANDOM_SIZE]);
        let encrypted2 = encrypt_message(plaintext, &message_key, 0, 0, [0xFF; NONCE_RANDOM_SIZE]);

        assert_ne!(encrypted1.nonce, encrypted2.nonce);
        // Ciphertexts should also differ due to different nonces
        assert_ne!(encrypted1.ciphertext, encrypted2.ciphertext);
    }

    #[test]
    fn wrong_key_fails_decryption() {
        let message_key = test_message_key(0);
        let plaintext = b"secret message";
        let random_suffix = [0x00; NONCE_RANDOM_SIZE];

        let encrypted = encrypt_message(plaintext, &message_key, 0, 0, random_suffix);

        // Create a message key from a different ratchet (different seed)
        let mut different_seed = [0xFFu8; 32];
        different_seed[0] = 0x00;
        let mut ratchet = SymmetricRatchet::new(&different_seed);
        let wrong_key = ratchet.advance().unwrap();

        let result = decrypt_message(&encrypted, &wrong_key);
        assert!(result.is_err());

        assert!(matches!(
            result,
            Err(SenderKeyError::DecryptionFailed { reason })
                if reason.contains("authentication")
        ));
    }

    #[test]
    fn tampered_ciphertext_fails_decryption() {
        let message_key = test_message_key(0);
        let plaintext = b"original message";
        let random_suffix = [0x00; NONCE_RANDOM_SIZE];

        let mut encrypted = encrypt_message(plaintext, &message_key, 0, 0, random_suffix);

        // Tamper with the ciphertext
        if !encrypted.ciphertext.is_empty() {
            encrypted.ciphertext[0] ^= 0xFF;
        }

        let result = decrypt_message(&encrypted, &message_key);
        assert!(result.is_err());
    }

    #[test]
    fn nonce_structure() {
        let random_suffix = [0xAB; NONCE_RANDOM_SIZE];
        let nonce = build_nonce(0x0102_0304_0506_0708, 0x09_0A_0B_0C, 0x0D_0E_0F_10, random_suffix);

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
        let message_key = test_message_key(0);
        let plaintext = b"hello world";
        let random_suffix = [0x00; NONCE_RANDOM_SIZE];

        let encrypted = encrypt_message(plaintext, &message_key, 0, 0, random_suffix);

        assert_eq!(encrypted.plaintext_len(), plaintext.len());
    }
}
