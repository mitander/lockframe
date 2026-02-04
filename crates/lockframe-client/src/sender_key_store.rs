//! Sender key store for managing per-member ratchets.
//!
//! Each room member has their own symmetric ratchet for message encryption.
//! Keys are derived from the MLS epoch secret and re-initialized on each
//! epoch transition.

use std::collections::HashMap;

use lockframe_crypto::{
    EncryptedMessage, NONCE_RANDOM_SIZE, SenderKeyError, SymmetricRatchet, decrypt_message,
    derive_sender_key_seed, encrypt_message,
};

/// Manages sender key ratchets for all members in a room.
///
/// Each member has their own symmetric ratchet, initialized from the
/// MLS epoch secret. Keys are re-derived on every epoch transition.
///
/// # Invariants
///
/// - All ratchets are for the same epoch
/// - Ratchet generations only increase (forward secrecy)
/// - Store is immutable after creation (new epoch = new store)
pub struct SenderKeyStore {
    /// Current epoch these keys are valid for.
    epoch: u64,

    /// Ratchet state per member (`sender_index` -> ratchet).
    ratchets: HashMap<u32, SymmetricRatchet>,
}

impl SenderKeyStore {
    /// Initialize sender keys for a new epoch.
    ///
    /// Called after MLS commit advances the epoch. Derives fresh
    /// ratchets for all members from the epoch secret.
    pub fn initialize_epoch(epoch_secret: &[u8], epoch: u64, member_indices: &[u32]) -> Self {
        let mut ratchets = HashMap::with_capacity(member_indices.len());

        for &sender_index in member_indices {
            let seed = derive_sender_key_seed(epoch_secret, epoch, sender_index);
            ratchets.insert(sender_index, SymmetricRatchet::new(&seed));
        }

        Self { epoch, ratchets }
    }

    /// Current MLS epoch for this room.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Number of senders with initialized ratchets.
    pub fn member_count(&self) -> usize {
        self.ratchets.len()
    }

    /// Check if a sender index is in this store.
    pub fn has_member(&self, sender_index: u32) -> bool {
        self.ratchets.contains_key(&sender_index)
    }

    /// Encrypt a message as a specific sender.
    ///
    /// Advances the sender's ratchet and returns the encrypted message.
    pub fn encrypt(
        &mut self,
        sender_index: u32,
        plaintext: &[u8],
        random_bytes: [u8; NONCE_RANDOM_SIZE],
    ) -> Result<EncryptedMessage, SenderKeyError> {
        let ratchet = self
            .ratchets
            .get_mut(&sender_index)
            .ok_or(SenderKeyError::UnknownSender { sender_index })?;

        let message_key = ratchet.advance()?;
        Ok(encrypt_message(plaintext, &message_key, self.epoch, sender_index, random_bytes))
    }

    /// Decrypt a message from any member.
    ///
    /// Advances the sender's ratchet to match the message generation.
    ///
    /// # Errors
    ///
    /// - `SenderKeyError::EpochMismatch` if message is for a different epoch
    /// - `SenderKeyError::UnknownSender` if sender not in this store
    /// - `SenderKeyError::RatchetTooFarBehind` if message generation too far
    ///   ahead
    /// - `SenderKeyError::DecryptionFailed` if authentication failed (tampering
    ///   or wrong key)
    pub fn decrypt(&mut self, encrypted: &EncryptedMessage) -> Result<Vec<u8>, SenderKeyError> {
        if encrypted.epoch != self.epoch {
            return Err(SenderKeyError::EpochMismatch {
                expected: self.epoch,
                actual: encrypted.epoch,
            });
        }

        let ratchet = self
            .ratchets
            .get_mut(&encrypted.sender_index)
            .ok_or(SenderKeyError::UnknownSender { sender_index: encrypted.sender_index })?;

        let message_key = ratchet.advance_to(encrypted.generation)?;
        decrypt_message(encrypted, &message_key)
    }

    /// Current generation for a sender's ratchet. `None` if sender not
    /// initialized.
    ///
    /// Returns `None` if the sender is not in this store.
    pub fn generation(&self, sender_index: u32) -> Option<u32> {
        self.ratchets.get(&sender_index).map(SymmetricRatchet::generation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_epoch_secret() -> [u8; 32] {
        let mut secret = [0u8; 32];
        for (i, byte) in secret.iter_mut().enumerate() {
            *byte = i as u8;
        }
        secret
    }

    #[test]
    fn initialize_epoch_creates_ratchets_for_all_members() {
        let members = vec![0, 1, 5, 10];
        let store = SenderKeyStore::initialize_epoch(&test_epoch_secret(), 1, &members);

        assert_eq!(store.epoch(), 1);
        assert_eq!(store.member_count(), 4);
        assert!(store.has_member(0));
        assert!(store.has_member(1));
        assert!(store.has_member(5));
        assert!(store.has_member(10));
        assert!(!store.has_member(2));
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let members = vec![0, 1];
        let mut store = SenderKeyStore::initialize_epoch(&test_epoch_secret(), 1, &members);

        let plaintext = b"Hello, World!";
        let random = [0xAB; NONCE_RANDOM_SIZE];

        // Encrypt as member 0
        let encrypted = store.encrypt(0, plaintext, random).unwrap();

        assert_eq!(encrypted.epoch, 1);
        assert_eq!(encrypted.sender_index, 0);
        assert_eq!(encrypted.generation, 0);

        // Decrypt (different store instance to simulate receiver)
        let mut receiver_store =
            SenderKeyStore::initialize_epoch(&test_epoch_secret(), 1, &members);
        let decrypted = receiver_store.decrypt(&encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_advances_ratchet() {
        let members = vec![0];
        let mut store = SenderKeyStore::initialize_epoch(&test_epoch_secret(), 1, &members);

        assert_eq!(store.generation(0), Some(0));

        let _ = store.encrypt(0, b"msg1", [0; NONCE_RANDOM_SIZE]).unwrap();
        assert_eq!(store.generation(0), Some(1));

        let _ = store.encrypt(0, b"msg2", [0; NONCE_RANDOM_SIZE]).unwrap();
        assert_eq!(store.generation(0), Some(2));
    }

    #[test]
    fn decrypt_unknown_sender_fails() {
        let members = vec![0];
        let mut store = SenderKeyStore::initialize_epoch(&test_epoch_secret(), 1, &members);

        let encrypted = EncryptedMessage {
            epoch: 1,
            sender_index: 5, // not in store
            generation: 0,
            nonce: [0; 24],
            ciphertext: vec![0; 32],
        };

        let result = store.decrypt(&encrypted);
        assert!(matches!(result, Err(SenderKeyError::UnknownSender { sender_index: 5 })));
    }

    #[test]
    fn decrypt_wrong_epoch_fails() {
        let members = vec![0];
        let mut store = SenderKeyStore::initialize_epoch(&test_epoch_secret(), 1, &members);

        let encrypted = EncryptedMessage {
            epoch: 2, // wrong!
            sender_index: 0,
            generation: 0,
            nonce: [0; 24],
            ciphertext: vec![0; 32],
        };

        let result = store.decrypt(&encrypted);
        assert!(matches!(result, Err(SenderKeyError::EpochMismatch { expected: 1, actual: 2 })));
    }

    #[test]
    fn out_of_order_messages_decrypt() {
        let members = vec![0, 1];
        let epoch_secret = test_epoch_secret();

        // Sender encrypts messages 0, 1, 2
        let mut sender_store = SenderKeyStore::initialize_epoch(&epoch_secret, 1, &members);
        let msg0 = sender_store.encrypt(0, b"msg0", [0; NONCE_RANDOM_SIZE]).unwrap();
        let _msg1 = sender_store.encrypt(0, b"msg1", [1; NONCE_RANDOM_SIZE]).unwrap();
        let msg2 = sender_store.encrypt(0, b"msg2", [2; NONCE_RANDOM_SIZE]).unwrap();

        // Receiver gets them out of order: 2, 0, 1
        let mut receiver_store = SenderKeyStore::initialize_epoch(&epoch_secret, 1, &members);

        // Receive msg2 first (skips to generation 2)
        let decrypted = receiver_store.decrypt(&msg2).unwrap();
        assert_eq!(decrypted, b"msg2");

        // msg0 and msg1 are now behind the ratchet - should fail
        let result = receiver_store.decrypt(&msg0);
        assert!(matches!(result, Err(SenderKeyError::RatchetTooFarBehind { .. })));
    }

    #[test]
    fn different_epochs_produce_different_keys() {
        let members = vec![0];
        let epoch_secret = test_epoch_secret();

        let mut store1 = SenderKeyStore::initialize_epoch(&epoch_secret, 1, &members);
        let mut store2 = SenderKeyStore::initialize_epoch(&epoch_secret, 2, &members);

        let msg1 = store1.encrypt(0, b"test", [0; NONCE_RANDOM_SIZE]).unwrap();
        let msg2 = store2.encrypt(0, b"test", [0; NONCE_RANDOM_SIZE]).unwrap();

        // Same plaintext, different epochs = different ciphertext
        assert_ne!(msg1.ciphertext, msg2.ciphertext);
    }
}
