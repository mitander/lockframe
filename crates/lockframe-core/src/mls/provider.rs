//! `OpenMLS` provider integration with Lockframe's Environment abstraction.
//!
//! Bridges `OpenMLS`'s provider pattern with our deterministic Environment trait,
//! enabling deterministic testing with Turmoil.

use openmls_memory_storage::MemoryStorage;
use openmls_rust_crypto::RustCrypto;
use openmls_traits::{OpenMlsProvider, random::OpenMlsRand};

use crate::env::Environment;

/// Lockframe's `OpenMLS` provider that uses our Environment trait for RNG.
pub struct MlsProvider<E: Environment> {
    /// `OpenMLS` crypto provider (sync crypto operations)
    crypto: RustCrypto,

    /// RNG adapter wrapping our environment
    rand: EnvironmentRng<E>,

    /// In-memory storage (TODO: make configurable)
    storage: MemoryStorage,
}

impl<E: Environment> MlsProvider<E> {
    /// Initialize a provider with in-memory storage and RNG seeded by the
    /// environment. In simulation, the environment provides deterministic RNG.
    /// In production, it provides crypto-secure randomness.
    pub fn new(env: E) -> Self {
        Self {
            crypto: RustCrypto::default(),
            rand: EnvironmentRng { env },
            storage: MemoryStorage::default(),
        }
    }

    /// Current time from the environment.
    ///
    /// Used for tracking when commits are sent for timeout detection.
    pub fn now(&self) -> E::Instant {
        self.rand.env.now()
    }
}

/// RNG adapter that delegates to our Environment trait.
///
/// This allows `OpenMLS` to use our deterministic RNG in simulation or
/// crypto-secure RNG in production.
pub struct EnvironmentRng<E: Environment> {
    env: E,
}

impl<E: Environment> rand::RngCore for EnvironmentRng<E> {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.env.random_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        self.env.random_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.env.random_bytes(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.env.random_bytes(dest);
        Ok(())
    }
}

impl<E: Environment> rand::CryptoRng for EnvironmentRng<E> {}

/// Implement `OpenMLS`'s RNG trait using our Environment abstraction.
impl<E: Environment> OpenMlsRand for EnvironmentRng<E> {
    type Error = std::convert::Infallible;

    fn random_array<const N: usize>(&self) -> Result<[u8; N], Self::Error> {
        let mut bytes = [0u8; N];
        self.env.random_bytes(&mut bytes);
        Ok(bytes)
    }

    fn random_vec(&self, len: usize) -> Result<Vec<u8>, Self::Error> {
        let mut bytes = vec![0u8; len];
        self.env.random_bytes(&mut bytes);
        Ok(bytes)
    }
}

impl<E: Environment> OpenMlsProvider for MlsProvider<E> {
    type CryptoProvider = RustCrypto;
    type RandProvider = EnvironmentRng<E>;
    type StorageProvider = MemoryStorage;

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.rand
    }

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }
}
