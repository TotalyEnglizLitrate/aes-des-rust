use crate::block_cipher::BlockCipher;

/// Advanced Encryption Standard (AES) implementation.
/// Implements the [BlockCipher] trait.
pub struct Aes;

impl BlockCipher for Aes {
    const BLOCK_SIZE: usize = 16; // AES block size in bytes
    const KEY_SIZE: usize = 16; // AES key size in bytes (128 bits)
    fn encrypt(&self, plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
        unimplemented!()
    }

    fn decrypt(&self, ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
        unimplemented!()
    }
}
