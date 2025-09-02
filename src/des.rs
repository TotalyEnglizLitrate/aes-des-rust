use crate::block_cipher::BlockCipher;

/// Data Encryption Standard (DES) implementation.
/// implements the [BlockCipher] trait.
pub struct Des;

/// Triple Data Encryption Standard (3DES) implementation.
/// Internally uses [Des] for encryption and decryption.
/// Implements the [BlockCipher] trait.
pub struct TripleDes {
    des: Des,
}

impl BlockCipher for Des {
    const BLOCK_SIZE: usize = 8; // DES block size in bytes
    const KEY_SIZE: usize = 7; // DES key size in bytes (56 bits)
    fn encrypt(&self, plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
        unimplemented!()
    }

    fn decrypt(&self, ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
        unimplemented!()
    }
}

impl BlockCipher for TripleDes {
    const BLOCK_SIZE: usize = 8; // 3DES block size in bytes
    const KEY_SIZE: usize = 21; // 3DES key size in bytes (168 bits i.e 3 * 56 bits)
    fn encrypt(&self, plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
        let (k1, k2, k3) = Self::split_keys(key)?;

        // 3DES: Encrypt with K1, Decrypt with K2, Encrypt with K3
        let first_encryption = self.des.encrypt(plaintext, k1)?;
        let decryption = self.des.decrypt(&first_encryption, k2)?;
        self.des.encrypt(&decryption, k3)
    }

    fn decrypt(&self, ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
        let (k1, k2, k3) = Self::split_keys(key)?;

        // 3DES: Decrypt with K3, Encrypt with K2, Decrypt with K1
        let first_decryption = self.des.decrypt(ciphertext, k3)?;
        let encryption = self.des.encrypt(&first_decryption, k2)?;
        self.des.decrypt(&encryption, k1)
    }
}

impl TripleDes {
    /// Creates a new instance of TripleDes. Takes no arguments.
    pub fn new() -> Self {
        Self { des: Des }
    }

    /// Splits a TripleDes key into 3 induvidual DES keys
    /// # Arguments
    /// * `key` - A byte slice representing the TripleDes key.
    /// # Returns
    /// - `Ok((k1, k2, k3))` - A tuple containing three induvidual DES keys.
    /// - `Err(String)` - An error message if the key length is not the same as the expected number
    /// of bytes.
    fn split_keys(key: &[u8]) -> Result<(&[u8], &[u8], &[u8]), String> {
        if key.len() != Self::KEY_SIZE {
            return Err("Key must be 24 bytes long for 3DES".to_string());
        }
        Ok((&key[0..8], &key[8..16], &key[16..24]))
    }
}

#[cfg(test)]
mod tests {
    use super::{Des, TripleDes};
    use des::{Des as DesImpl, TdesEde3 as TripleDesImpl};

    #[test]
    fn test_encrytion_des() {
        unimplemented!()
    }

    #[test]
    fn test_decryption_des() {
        unimplemented!()
    }

    #[test]
    fn test_encryption_3des() {
        unimplemented!()
    }

    #[test]
    fn test_decryption_3des() {
        unimplemented!()
    }
}
