use crate::block_cipher::BlockCipher;

/// Permuted Choice 1 (PC-1) table
const PC_1: [usize; 56] = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60,
    52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
];

/// Permuted Choice 2 (PC-2) table
const PC_2: [usize; 48] = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52,
    31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
];

const SHIFTS: [usize; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

/// Data Encryption Standard (DES) implementation.
/// implements the [BlockCipher] trait.
#[allow(unused)]
pub struct Des;

/// Triple Data Encryption Standard (3DES) implementation.
/// Internally uses [Des] for encryption and decryption.
/// Implements the [BlockCipher] trait.
#[allow(unused)]
pub struct TripleDes {
    des: Des,
}

#[allow(unused)]
impl BlockCipher for Des {
    const BLOCK_SIZE: usize = 8; // DES block size in bytes
    const KEY_SIZE: usize = 8; // DES key size in bytes (64 bits, including parity)
    fn encrypt(&self, plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
        Self::validate_key(key)?;

        let mut padded: Vec<u8>;

        if Self::is_padded(plaintext) {
            padded = plaintext.to_vec();
        } else {
            padded = Self::pad(plaintext);
        }

        unimplemented!()
    }

    fn decrypt(&self, ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
        unimplemented!()
    }
}

#[allow(unused)]
impl Des {
    fn round_keys(key: &[u8; 8]) -> [[u8; 6]; 16] {
        // Apply PC-1 permutation to get 56-bit key
        let mut permuted_key = [0u8; 7];
        for (i, &pos) in PC_1.iter().enumerate() {
            let byte_index = (pos - 1) / 8;
            let bit_index = (pos - 1) % 8;
            let bit = (key[byte_index] >> (7 - bit_index)) & 1;
            permuted_key[i / 8] |= bit << (7 - (i % 8));
        }

        // Split the 56-bit key into two 28-bit halves
        // C = bits 0-27, D = bits 28-55
        let mut c = Self::extract_28_bits(&permuted_key, 0);
        let mut d = Self::extract_28_bits(&permuted_key, 28);

        let mut round_keys = [[0u8; 6]; 16];

        for (round, &shift) in SHIFTS.iter().enumerate() {
            // Perform left circular shifts on 28-bit halves
            c = Self::left_circular_shift_28(c, shift);
            d = Self::left_circular_shift_28(d, shift);

            // Combine C and D into 56-bit value
            let combined = Self::combine_28_bit_halves(c, d);

            // Apply PC-2 to get the 48-bit round key
            for (i, &pos) in PC_2.iter().enumerate() {
                let bit_pos = pos - 1; // PC-2 positions are 1-indexed
                let bit = (combined >> (55 - bit_pos)) & 1;
                if bit != 0 {
                    round_keys[round][i / 8] |= 1 << (7 - (i % 8));
                }
            }
        }

        round_keys
    }

    /// Helper function to extract 28 bits starting at the given bit position.
    ///
    /// # Arguments
    /// * `key` - A reference to a 7-byte array representing the 56-bit key.
    /// * `start_bit` - The starting bit position (0-based) from which to extract 28 bits.
    ///
    /// # Returns
    /// * A `u32` value containing the lower 28 bits filled with the extracted bits.
    ///
    /// # Example
    /// ```
    /// let key: [u8; 7] = [0b11110000, 0b11001100, 0b10101010, 0b11110000, 0b11001100, 0b10101010, 0b11110000];
    /// let extracted = extract_28_bits(&key, 0);
    /// assert_eq!(extracted, 0b1111000011001100101010101111);
    /// ```
    fn extract_28_bits(key: &[u8; 7], start_bit: usize) -> u32 {
        let mut result = 0u32;
        for i in 0..28 {
            let bit_pos = start_bit + i;
            let byte_index = bit_pos / 8;
            let bit_index = bit_pos % 8;
            let bit = (key[byte_index] >> (7 - bit_index)) & 1;
            result |= (bit as u32) << (27 - i);
        }
        result
    }

    /// Helper function to perform a left circular shift on a 28-bit value.
    ///
    /// # Arguments
    /// * `value` - A 28-bit `u32` value to be shifted.
    /// * `positions` - The number of positions to shift left.
    ///
    /// # Returns
    /// * A `u32` value representing the left-circular-shifted 28-bit value.
    ///
    /// # Example
    /// ```
    /// let value: u32 = 0b1111000011001100101010101111;
    /// let shifted = left_circular_shift_28(value, 2);
    /// assert_eq!(shifted, 0b1100001100110010101010111111);
    /// ``
    fn left_circular_shift_28(value: u32, positions: usize) -> u32 {
        let mask = 0x0FFFFFFF;
        let shifted = ((value << positions) | (value >> (28 - positions))) & mask;
        shifted
    }

    /// Helper function to combine two 28-bit halves into a 56-bit value.
    ///
    /// # Arguments
    /// * `c` - The left 28-bit half as a `u32`.
    /// * `d` - The right 28-bit half as a `u32`.
    ///
    /// # Returns
    /// * A `u64` value representing the combined 56-bit value.
    ///
    /// # Example
    /// ```
    /// let c: u32 = 0b1111000011001100101010101111;
    /// let d: u32 = 0b0000111100001111000011110000;
    /// let combined = combine_28_bit_halves(c, d);
    /// assert_eq!(combined, 0b1111000011001100101010101111000011110000111100001111);
    /// ```
    fn combine_28_bit_halves(c: u32, d: u32) -> u64 {
        ((c as u64) << 28) | (d as u64)
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

#[allow(unused)]
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
            return Err(format!(
                "Invalid key length: expected {} bytes, got {} bytes",
                Self::KEY_SIZE,
                key.len()
            ));
        }
        Ok((&key[0..8], &key[8..16], &key[16..24]))
    }
}

#[cfg(test)]
#[allow(unused)]
mod tests {
    use super::{Des, TripleDes};
    use crate::block_cipher::BlockCipher;

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
