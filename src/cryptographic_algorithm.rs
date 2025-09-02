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
}
