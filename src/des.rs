use crate::cryptographic_algorithm::CryptographicAlgorithm;

/// Data Encryption Standard (DES) implementation.
/// implements the [CryptographicAlgorithm] trait.
pub struct Des;

/// Triple Data Encryption Standard (3DES) implementation.
/// Internally uses [Des] for encryption and decryption.
/// Implements the [CryptographicAlgorithm] trait.
pub struct TripleDes {
    des: Des,
}

impl CryptographicAlgorithm for Des {
    const BLOCK_SIZE: usize = 8; // DES block size in bytes
    const KEY_SIZE: usize = 8; // DES key size in bytes (64 bits)
    fn encrypt(&self, plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
        unimplemented!()
    }

    fn decrypt(&self, ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
        unimplemented!()
    }
}

impl CryptographicAlgorithm for TripleDes {
    const BLOCK_SIZE: usize = 8; // 3DES block size in bytes
    const KEY_SIZE: usize = 24; // 3DES key size in bytes (192 bits)
    fn encrypt(&self, plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
        unimplemented!();
    }

    fn decrypt(&self, ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
        unimplemented!();
    }
}
