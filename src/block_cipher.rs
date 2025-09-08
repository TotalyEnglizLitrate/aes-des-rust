use rand::random;

/// A trait representing a generic cryptographic algorithm.
/// This trait defines the essential methods and constants required for encryption and decryption
/// operations.
/// # Generic parameters
/// * `BLOCK_SIZE` - The block size used by the algorithm in bytes. For example, AES-128 has a block size size of 16 bytes (128 bits).
/// * `KEY_SIZE` - The key size used by the algorithm in bytes. For example, AES-128 has a key size
/// of 16 bytes (128 bits)
#[allow(unused)]
pub trait BlockCipher<const BLOCK_SIZE: usize, const KEY_SIZE: usize> {
    const BLOCK_SIZE: usize = BLOCK_SIZE;
    const KEY_SIZE: usize = KEY_SIZE;

    /// The key size of the algorithm in bytes.
    /// For example, AES-128 has a key size of 16 bytes (128 bits).

    /// Encrypts the given plaintext using the specified key.
    ///
    /// # Arguments
    /// * `plaintext` - The data to be encrypted.
    /// * `key` - The key used for encryption.
    /// * `pad` - Whether to pad the plaintext before encryption - set to false to omit ONLY IF
    /// DATA IS PADDED ELSEWHERE
    ///
    /// # Returns
    /// - `Ok(Vec<u8>)`: A vector containing the encrypted data.
    /// - `Err(String)`: An error message if encryption fails.
    ///
    /// # Examples
    /// ```
    /// let algorithm: <T: impl BlockCipher> = YourAlgorithmImplementation;
    /// let plaintext = b"Hello, World!";
    /// let key = b"your-encryption-key";
    /// let ciphertext = algorithm.encrypt(plaintext, key).unwrap();
    /// ```
    fn encrypt(plaintext: &[u8], key: &[u8], pad: bool) -> Result<Vec<u8>, String>;

    /// Decrypts the given ciphertext using the specified key.
    ///
    /// # Arguments
    /// * `ciphertext` - The data to be decrypted.
    /// * `key` - The key used for decryption.
    /// * `unpad` - Wheter to unpad the decrypted plaintext data - set to false to omit
    ///
    /// # Returns
    /// - `Ok(Vec<u8>)`: A vector containing the decrypted data.
    /// - `Err(String)`: An error message if decryption fails.
    ///
    /// # Examples
    /// ```
    /// let algorithm: <T: impl BlockCipher> = YourAlgorithmImplementation;
    /// let ciphertext = b"EncryptedData";
    /// let key = b"your-encryption-key";
    /// let plaintext = algorithm.decrypt(ciphertext, key).unwrap();
    /// ```
    fn decrypt(ciphertext: &[u8], key: &[u8], pad: bool) -> Result<Vec<u8>, String>;

    /// Pads the input data to ensure its length is a multiple of the block size.
    /// This method uses PKCS#7 padding scheme.
    /// # Arguments
    /// * `data` - The input data to be padded.
    /// # Returns
    /// - A vector containing the padded data.
    /// # Examples
    /// ```
    /// let algorithm: <T: impl BlockCipher> = YourAlgorithmImplementation;
    /// let data = b"YELLOW SUBMARINE";
    /// let padded_data = algorithm.pad(data);
    /// assert!(algorithm.is_padded(&padded_data));
    /// ```
    fn pad(data: &[u8]) -> Vec<u8> {
        let padding_needed = BLOCK_SIZE - (data.len() % BLOCK_SIZE);
        let mut padded_data = Vec::with_capacity(data.len() + padding_needed);
        padded_data.extend_from_slice(data);
        padded_data.extend(std::iter::repeat(padding_needed as u8).take(padding_needed));
        padded_data
    }

    /// Removes PKCS#7 padding from data.
    /// # Arguments
    /// * `data` - The input data from which padding is to be removed.
    /// # Returns
    /// - `Ok(Vec<u8>)`: A vector containing the unpadded data.
    /// - `Err(String)`: An error message if unpadding fails.
    /// # Examples
    /// ```
    /// // Assumes block is 4 bytes for this example
    /// let algorithm: <T: impl BlockCipher> = YourAlgorithmImplementation;
    /// let padded_data = b"YELLOW SUBMARINE\x04\x04\x04\x04";
    /// let unpadded_data = algorithm.unpad(padded_data);
    /// assert_eq!(unpadded_data.unwrap(), b"YELLOW SUBMARINE");
    /// ```
    fn unpad(data: &[u8]) -> Result<Vec<u8>, String> {
        let padding_length = *data.last().ok_or("Data is empty, cannot unpad")? as usize;

        if !(1..=BLOCK_SIZE).contains(&padding_length) {
            return Err("Invalid padding length".into());
        }

        if data[data.len() - padding_length..]
            .iter()
            .any(|&byte| byte as usize != padding_length)
        {
            return Err("Invalid padding bytes".into());
        }

        Ok(data[..data.len() - padding_length].to_vec())
    }

    /// Checks if the data is correctly padded according to PKCS#7.
    /// # Arguments
    /// * `data` - The input data to be checked.
    /// # Returns
    /// - true if the data is correctly padded, false otherwise.
    /// # Examples
    /// ```
    /// // Assumes block is 4 bytes for this example
    /// let algorithm: <T: impl BlockCipher> = YourAlgorithmImplementation;
    /// let padded_data = b"YELLOW SUBMARINE\x04\x04\x04\x04";
    /// let is_padded = algorithm.is_padded(padded_data);
    /// assert!(is_padded);
    /// let unpadded_data = b"YELLOW SUBMARINE";
    /// let is_padded = algorithm.is_padded(unpadded_data);
    /// assert!(!is_padded);
    /// ```
    fn is_padded(data: &[u8]) -> bool {
        if data.is_empty() {
            return false;
        }

        let padding_length = *data.last().unwrap() as usize;

        if !(1..=BLOCK_SIZE).contains(&padding_length) {
            return false;
        }

        !data[data.len() - padding_length..]
            .iter()
            .any(|&byte| byte as usize != padding_length)
    }

    /// Generate a key for the block cipher. Takes no arguments
    /// # Returns
    /// A valid key byte-array
    /// # Examples
    /// ```
    /// let algorithm: <T: impl BlockCipher> = YourAlgorithmImplementation;
    /// let key = algorithm.gen_key();
    /// ```
    fn gen_key() -> [u8; KEY_SIZE] {
        random()
    }

    /// Validates the length of the provided key.
    /// # Arguments
    /// * `key` - The key to be validated.
    /// # Returns
    /// - `Ok(())`: If the key length is valid.
    /// - `Err(String)`: An error message if the key length is invalid.
    fn validate_key(key: &[u8]) -> Result<(), String> {
        if key.len() != KEY_SIZE {
            return Err(format!(
                "Invalid key length: expected {} bytes, got {} bytes",
                KEY_SIZE,
                key.len()
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::BlockCipher;

    struct DummyCipher;

    impl BlockCipher<8, 8> for DummyCipher {
        fn encrypt(plaintext: &[u8], _key: &[u8], _pad: bool) -> Result<Vec<u8>, String> {
            Ok(plaintext.to_vec())
        }

        fn decrypt(ciphertext: &[u8], _key: &[u8], _pad: bool) -> Result<Vec<u8>, String> {
            Ok(ciphertext.to_vec())
        }

        fn gen_key() -> [u8; 8] {
            unimplemented!()
        }
    }

    #[test]
    fn test_pad() {
        let data = b"YELLOW SUBMARINE";
        let padded = DummyCipher::pad(data);
        assert_eq!(padded.len() % 8, 0);
        assert_eq!(&padded[data.len()..], &[0x08; 8][..]);
    }

    #[test]
    fn test_unpad() {
        let padded_data = b"YELLOW SUBMARINE\x08\x08\x08\x08\x08\x08\x08\x08";
        let unpadded = DummyCipher::unpad(padded_data).unwrap();
        assert_eq!(&unpadded, b"YELLOW SUBMARINE");
    }

    #[test]
    fn test_is_padded() {
        let padded_data = b"YELLOW SUBMARINE\x08\x08\x08\x08\x08\x08\x08\x08";
        assert!(DummyCipher::is_padded(padded_data));

        let unpadded_data = b"YELLOW SUBMARINE";
        assert!(!DummyCipher::is_padded(unpadded_data));
    }

    #[test]
    fn test_encrypt_decrypt() {
        let plaintext = b"Hello, World!";
        let key = b"12345678";

        let ciphertext = DummyCipher::encrypt(plaintext, key, true).unwrap();
        let decrypted = DummyCipher::decrypt(&ciphertext, key, true).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_validate_key() {
        let valid_key = b"12345678";
        assert!(DummyCipher::validate_key(valid_key).is_ok());
        let invalid_key = b"12345";
        assert!(DummyCipher::validate_key(invalid_key).is_err());
    }
}
