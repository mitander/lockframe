//! Key derivation for Sender Keys using HKDF

use hkdf::Hkdf;
use sha2::Sha256;

/// Label used for sender key derivation
const SENDER_KEY_LABEL: &[u8] = b"lockframeSenderV1";

/// Derive a sender key seed from the MLS epoch secret.
///
/// This produces a 32-byte seed that is unique per (epoch, `sender_index`)
/// pair. The seed is used to initialize a [`crate::SymmetricRatchet`] for that
/// sender.
///
/// # Security
///
/// - Different epochs produce different seeds (forward secrecy at epoch
///   boundary)
/// - Different senders produce different seeds (sender isolation)
/// - Deterministic: same inputs always produce same output
pub fn derive_sender_key_seed(epoch_secret: &[u8], epoch: u64, sender_index: u32) -> [u8; 32] {
    // Use HKDF with the epoch secret as the PRK
    // We extract first to ensure the key material is properly distributed
    let hkdf = Hkdf::<Sha256>::new(None, epoch_secret);

    // Build the info parameter: label || epoch || sender_index
    // Capacity: 16 (label) + 8 (epoch) + 4 (sender_index) = 28
    let mut info = Vec::with_capacity(28);
    info.extend_from_slice(SENDER_KEY_LABEL);
    info.extend_from_slice(&epoch.to_be_bytes());
    info.extend_from_slice(&sender_index.to_be_bytes());

    let mut seed = [0u8; 32];
    let Ok(()) = hkdf.expand(&info, &mut seed) else {
        unreachable!("32 bytes is a valid HKDF-SHA256 output length");
    };

    seed
}

/// Derive multiple sender key seeds for all members in a room.
///
/// Convenience function for initializing sender keys for all room members
/// at once (e.g., after joining a room or epoch transition).
///
/// Returns vector of (`sender_index`, seed) pairs.
pub fn derive_all_sender_seeds(
    epoch_secret: &[u8],
    epoch: u64,
    member_indices: &[u32],
) -> Vec<(u32, [u8; 32])> {
    member_indices
        .iter()
        .map(|&index| (index, derive_sender_key_seed(epoch_secret, epoch, index)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_produces_32_byte_seed() {
        let epoch_secret = [0u8; 32];
        let seed = derive_sender_key_seed(&epoch_secret, 0, 0);
        assert_eq!(seed.len(), 32);
    }

    #[test]
    fn derive_is_deterministic() {
        let epoch_secret = b"test_epoch_secret_material_here!";
        let epoch = 42u64;
        let sender_index = 7u32;

        let seed1 = derive_sender_key_seed(epoch_secret, epoch, sender_index);
        let seed2 = derive_sender_key_seed(epoch_secret, epoch, sender_index);

        assert_eq!(seed1, seed2, "same inputs must produce same output");
    }

    #[test]
    fn different_epochs_produce_different_seeds() {
        let epoch_secret = b"test_epoch_secret_material_here!";
        let sender_index = 0u32;

        let seed_epoch_0 = derive_sender_key_seed(epoch_secret, 0, sender_index);
        let seed_epoch_1 = derive_sender_key_seed(epoch_secret, 1, sender_index);

        assert_ne!(seed_epoch_0, seed_epoch_1, "different epochs must produce different seeds");
    }

    #[test]
    fn different_senders_produce_different_seeds() {
        let epoch_secret = b"test_epoch_secret_material_here!";
        let epoch = 5u64;

        let seed_sender_0 = derive_sender_key_seed(epoch_secret, epoch, 0);
        let seed_sender_1 = derive_sender_key_seed(epoch_secret, epoch, 1);

        assert_ne!(seed_sender_0, seed_sender_1, "different senders must produce different seeds");
    }

    #[test]
    fn different_epoch_secrets_produce_different_seeds() {
        let epoch = 0u64;
        let sender_index = 0u32;

        let seed_a =
            derive_sender_key_seed(b"epoch_secret_a__________________", epoch, sender_index);
        let seed_b =
            derive_sender_key_seed(b"epoch_secret_b__________________", epoch, sender_index);

        assert_ne!(seed_a, seed_b, "different epoch secrets must produce different seeds");
    }

    #[test]
    fn derive_all_produces_correct_count() {
        let epoch_secret = b"test_epoch_secret_material_here!";
        let members = vec![0, 1, 5, 10];

        let seeds = derive_all_sender_seeds(epoch_secret, 0, &members);

        assert_eq!(seeds.len(), 4);
        assert_eq!(seeds[0].0, 0);
        assert_eq!(seeds[1].0, 1);
        assert_eq!(seeds[2].0, 5);
        assert_eq!(seeds[3].0, 10);
    }

    #[test]
    fn derive_all_matches_individual_derivation() {
        let epoch_secret = b"test_epoch_secret_material_here!";
        let epoch = 3u64;
        let members = vec![2, 7];

        let batch_seeds = derive_all_sender_seeds(epoch_secret, epoch, &members);

        for (index, batch_seed) in batch_seeds {
            let individual_seed = derive_sender_key_seed(epoch_secret, epoch, index);
            assert_eq!(
                batch_seed, individual_seed,
                "batch and individual must match for sender {index}"
            );
        }
    }

    #[test]
    fn works_with_empty_epoch_secret() {
        // Edge case: empty input should still produce valid output
        let seed = derive_sender_key_seed(&[], 0, 0);
        assert_eq!(seed.len(), 32);
    }

    #[test]
    fn works_with_large_epoch_secret() {
        // Edge case: large input should still work
        let large_secret = vec![0xABu8; 1024];
        let seed = derive_sender_key_seed(&large_secret, 0, 0);
        assert_eq!(seed.len(), 32);
    }

    #[test]
    fn epoch_boundary_values() {
        let epoch_secret = b"test_epoch_secret_material_here!";

        // Test boundary values for epoch
        let _ = derive_sender_key_seed(epoch_secret, 0, 0);
        let _ = derive_sender_key_seed(epoch_secret, u64::MAX, 0);

        // Test boundary values for sender_index
        let _ = derive_sender_key_seed(epoch_secret, 0, u32::MAX);
    }
}
