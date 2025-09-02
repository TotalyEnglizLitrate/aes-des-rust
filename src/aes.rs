use crate::cryptographic_algorithm::CryptographicAlgorithm;

/// Advanced Encryption Standard (AES) implementation.
/// Implements the [CryptographicAlgorithm] trait.
pub struct Aes;

impl CryptographicAlgorithm for Aes {
    const BLOCK_SIZE: usize = 16; // AES block size in bytes
    const KEY_SIZE: usize = 16; // AES key size in bytes (128 bits)
    fn encrypt(&self, plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
        unimplemented!()
    }

    fn decrypt(&self, ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
        unimplemented!()
    }
}
