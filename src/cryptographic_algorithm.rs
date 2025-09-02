/// A trait representing a generic cryptographic algorithm.
/// This trait defines the essential methods and constants required for encryption and decryption
/// operations.
pub trait CryptographicAlgorithm {
    /// The block size of the algorithm in bytes.
    /// For example, AES has a block size of 16 bytes (128 bits).
    const BLOCK_SIZE: usize;

    /// The key size of the algorithm in bytes.
    /// For example, AES-128 has a key size of 16 bytes (128 bits
    const KEY_SIZE: usize;

    /// Encrypts the given plaintext using the specified key.
    ///
    /// # Arguments
    /// * `plaintext` - The data to be encrypted.
    /// * `key` - The key used for encryption.
    ///
    /// # Returns
    /// - Ok(Vec<u8>): A vector containing the encrypted data.
    /// - Err(String): An error message if encryption fails.
    ///
    /// # Examples
    /// ```
    /// let algorithm: <T: impl CryptographicAlgorithm> = YourAlgorithmImplementation;
    /// let plaintext = b"Hello, World!";
    /// let key = b"your-encryption-key";
    /// let ciphertext = algorithm.encrypt(plaintext, key).unwrap();
    /// ```
    fn encrypt(&self, plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>, String>;

    /// Decrypts the given ciphertext using the specified key.
    ///
    /// # Arguments
    /// * `ciphertext` - The data to be decrypted.
    /// * `key` - The key used for decryption.
    ///
    /// # Returns
    /// - Ok(Vec<u8>): A vector containing the decrypted data.
    /// - Err(String): An error message if decryption fails.
    ///
    /// # Examples
    /// ```
    /// let algorithm: <T: impl CryptographicAlgorithm> = YourAlgorithmImplementation;
    /// let ciphertext = b"EncryptedData";
    /// let key = b"your-encryption-key";
    /// let plaintext = algorithm.decrypt(ciphertext, key).unwrap();
    /// ```
    fn decrypt(&self, ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>, String>;

    /// Pads the input data to ensure its length is a multiple of the block size.
    /// This method uses PKCS#7 padding scheme.
    /// # Arguments
    /// * `data` - The input data to be padded.
    /// # Returns
    /// - A vector containing the padded data.
    /// # Examples
    /// ```
    /// let algorithm: <T: impl CryptographicAlgorithm> = YourAlgorithmImplementation;
    /// let data = b"YELLOW SUBMARINE";
    /// let padded_data = algorithm.pad(data);
    /// ```
    fn pad(data: &[u8]) -> Vec<u8> {
        let padding_needed = Self::BLOCK_SIZE - (data.len() % Self::BLOCK_SIZE);
        let mut padded_data = Vec::with_capacity(data.len() + padding_needed);
        padded_data.extend_from_slice(data);
        padded_data.extend(std::iter::repeat(padding_needed as u8).take(padding_needed));
        padded_data
    }

    /// Removes PKCS#7 padding from data.
    /// # Arguments
    /// * `data` - The input data from which padding is to be removed.
    /// # Returns
    /// - Ok(Vec<u8>): A vector containing the unpadded data.
    /// - Err(String): An error message if unpadding fails.
    /// # Examples
    /// ```
    /// let algorithm: <T: impl CryptographicAlgorithm> = YourAlgorithmImplementation;
    /// let padded_data = b"YELLOW SUBMARINE\x04\x04\x04\x04";
    /// let unpadded_data = algorithm.unpad(padded_data);
    /// ```
    fn unpad(data: &[u8]) -> Result<Vec<u8>, String> {
        if data.is_empty() {
            return Err("Data is empty, cannot unpad".into());
        }

        let padding_length = *data.last().ok_or("Data is empty, cannot unpad")? as usize;

        if !(1..=Self::BLOCK_SIZE).contains(&padding_length) {
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
    /// let algorithm: <T: impl CryptographicAlgorithm> = YourAlgorithmImplementation;
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

        if !(1..=Self::BLOCK_SIZE).contains(&padding_length) {
            return false;
        }

        !data[data.len() - padding_length..]
            .iter()
            .any(|&byte| byte as usize != padding_length)
    }
}
