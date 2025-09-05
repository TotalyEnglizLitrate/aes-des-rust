use crate::block_cipher::BlockCipher;

/// Advanced Encryption Standard (AES) implementation.
/// Implements the [BlockCipher] trait.
#[allow(unused)]
pub struct Aes128;

#[allow(unused)]
impl BlockCipher<16, 16> for Aes128 {
    const BLOCK_SIZE: usize = 16; // AES block size in bytes
    const KEY_SIZE: usize = 16; // AES key size in bytes (128 bits)
    fn encrypt(plaintext: &[u8], key: &[u8], pad: bool) -> Result<Vec<u8>, String> {
        unimplemented!()
    }

    fn decrypt(ciphertext: &[u8], key: &[u8], pad: bool) -> Result<Vec<u8>, String> {
        unimplemented!()
    }
}

#[cfg(test)]
#[allow(unused)]
mod tests {
    use super::Aes128;

    fn test_encryption_decryption_aes() {
        unimplemented!()
    }
}
