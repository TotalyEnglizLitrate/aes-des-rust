use crate::block_cipher::BlockCipher;

// Permuted Choice 1 (PC-1) table
const PC_1: [usize; 56] = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60,
    52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
];

// Permuted Choice 2 (PC-2) table
const PC_2: [usize; 48] = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52,
    31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
];

// Shifts to be applied for each round
const SHIFTS: [usize; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

// Expansion table (E)
const E: [u8; 48] = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18,
    19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
];

// S-boxes (S1..S8)
const S: [[[u8; 16]; 4]; 8] = [
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    ],
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    ],
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    ],
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    ],
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    ],
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    ],
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    ],
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
    ],
];

// Permutation P
const P: [u8; 32] = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19,
    13, 30, 6, 22, 11, 4, 25,
];

// FP table
const FP: [u8; 64] = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
];

// IP table
const IP: [u8; 64] = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61,
    53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
];

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

impl BlockCipher for Des {
    const BLOCK_SIZE: usize = 8; // DES block size in bytes
    const KEY_SIZE: usize = 8; // DES key size in bytes (64 bits, including parity)
    fn encrypt(&self, plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
        Self::validate_key(key)?;

        // Pad plaintext if needed
        let padded = if Self::is_padded(plaintext) {
            plaintext.to_vec()
        } else {
            Self::pad(plaintext)
        };

        // We can call unwrap() without worrying about panicking because we validate the key length
        // at the start of the function
        let key_arr: [u8; 8] = key.try_into().unwrap();
        let round_keys = Self::round_keys(&key_arr);

        let mut ciphertext = Vec::with_capacity(padded.len());

        for block in padded.chunks(Self::BLOCK_SIZE) {
            let mut block_arr = [0u8; 8];
            block_arr.copy_from_slice(block);

            let block_u64 = Self::initial_permutation(&block_arr);

            let mut l = (block_u64 >> 32) as u32;
            let mut r = (block_u64 & 0xFFFF_FFFF) as u32;

            // 16 rounds
            for i in 0..16 {
                let temp = r;
                r = l ^ Self::feistel(r, &round_keys[i]);
                l = temp;
            }

            let preoutput = ((r as u64) << 32) | (l as u64);
            let encrypted_block = Self::final_permutation(preoutput);
            ciphertext.extend_from_slice(&encrypted_block);
        }

        Ok(ciphertext)
    }

    fn decrypt(&self, ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
        Self::validate_key(key)?;

        let key_arr: [u8; 8] = key.try_into().map_err(|_| "Key must be 8 bytes")?;
        let round_keys = Self::round_keys(&key_arr);

        let mut plaintext = Vec::with_capacity(ciphertext.len());

        for block in ciphertext.chunks(Self::BLOCK_SIZE) {
            let mut block_arr = [0u8; 8];
            block_arr.copy_from_slice(block);

            let block_u64 = Self::initial_permutation(&block_arr);

            let mut l = (block_u64 >> 32) as u32;
            let mut r = (block_u64 & 0xFFFF_FFFF) as u32;

            // 16 rounds in reverse order
            for i in (0..16).rev() {
                let temp = r;
                r = l ^ Self::feistel(r, &round_keys[i]);
                l = temp;
            }

            let preoutput = ((r as u64) << 32) | (l as u64);
            let decrypted_block = Self::final_permutation(preoutput);
            plaintext.extend_from_slice(&decrypted_block);
        }

        // Unpad the plaintext
        Self::unpad(&plaintext)
    }
}

#[allow(dead_code)]
impl Des {
    /// Performs the Feistel function for a single DES round.
    ///
    /// # Arguments
    /// * `r` - A `u32` value representing the 32-bit right half of the block.
    /// * `round_key` - A reference to a 6-byte array representing the 48-bit round key.
    ///
    /// # Returns
    /// * A `u32` value representing the 32-bit output of the Feistel function.
    ///
    /// # Example
    /// ```
    /// let r: u32 = 0x12345678;
    /// let round_key: [u8; 6] = [0x1B, 0x02, 0xEF, 0xCD, 0xAB, 0x89];
    /// let result = Des::feistel(r, &round_key);
    /// ```
    fn feistel(r: u32, round_key: &[u8; 6]) -> u32 {
        // Expansion (E): expand 32 bits to 48 bits
        let mut expanded = 0u64;
        for (i, &e) in E.iter().enumerate() {
            let bit = (r >> (32 - e)) & 1;
            expanded |= (bit as u64) << (47 - i);
        }

        // Key mixing: XOR with round key
        let mut expanded_bytes = [0u8; 6];
        for i in 0..6 {
            expanded_bytes[i] = ((expanded >> (8 * (5 - i))) & 0xFF) as u8;
        }
        for i in 0..6 {
            expanded_bytes[i] ^= round_key[i];
        }

        // S-box substitution
        let mut sbox_out = 0u32;
        for i in 0..8 {
            let chunk = ((expanded >> (42 - 6 * i)) & 0x3F) as u8;
            let row = ((chunk & 0b100000) >> 4) | (chunk & 0b000001);
            let col = (chunk & 0b011110) >> 1;

            let s_val = S[i][row as usize][col as usize];
            sbox_out |= (s_val as u32) << (28 - 4 * i);
        }

        // Permutation
        let mut p_out = 0u32;
        for (i, &p) in P.iter().enumerate() {
            let bit = (sbox_out >> (32 - p)) & 1;
            p_out |= (bit as u32) << (31 - i);
        }
        p_out
    }

    /// Performs the initial permutation (IP) on the input block.
    ///
    /// # Arguments
    /// * `block` - A reference to an 8-byte array representing the 64-bit input block.
    ///
    /// # Returns
    /// * A `u64` value representing the permuted 64-bit block.
    ///
    /// # Example
    /// ```
    /// let block: [u8; 8] = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
    /// let permuted = Des::initial_permutation(&block);
    /// ```
    fn initial_permutation(block: &[u8; 8]) -> u64 {
        let mut out = 0u64;
        for (i, &ip) in IP.iter().enumerate() {
            let bit = (block[((ip - 1) / 8) as usize] >> (7 - ((ip - 1) % 8))) & 1;
            out |= (bit as u64) << (63 - i);
        }
        out
    }

    /// Performs the final permutation (IP^-1) on the input block.
    ///
    /// # Arguments
    /// * `block` - A `u64` value representing the 64-bit input block after all rounds.
    ///
    /// # Returns
    /// * An 8-byte array `[u8; 8]` representing the permuted 64-bit block.
    ///
    /// # Example
    /// ```
    /// let block: u64 = 0x123456789ABCDEF0;
    /// let permuted = Des::final_permutation(block);
    /// ```
    fn final_permutation(block: u64) -> [u8; 8] {
        let mut out = [0u8; 8];
        for (i, &fp) in FP.iter().enumerate() {
            let bit_pos = 63 - (fp - 1);
            let bit = (block >> bit_pos) & 1;
            out[i / 8] |= (bit as u8) << (7 - (i % 8));
        }
        out
    }

    /// Generates the 16 round keys for the DES encryption/decryption process.
    ///
    /// # Arguments
    /// * `key` - A reference to an 8-byte array representing the 64-bit key.
    ///
    /// # Returns
    /// * A 2D array `[[u8; 6]; 16]` where each inner array represents a 48-bit round key.
    ///
    /// # Panics
    /// This function will panic if the provided key is not exactly 8 bytes long.
    ///
    /// # Example
    /// ```
    /// let key: [u8; 8] = [0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1];
    /// let round_keys = Des::round_keys(&key);
    /// assert_eq!(round_keys.len(), 16);
    /// ```
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
    /// ```
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
    const KEY_SIZE: usize = 24; // 3DES key size in bytes (192 bits i.e 3 * 64 bits)
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

    /// Splits a TripleDes key into 3 individual DES keys
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
mod tests {
    use super::{BlockCipher, Des, TripleDes};

    #[test]
    fn test_encrytion_decryption_des() {
        let plaintext = "Hello World!";
        let key = [0u8; 8];
        let des = Des;
        let ciphertext = des.encrypt(plaintext.as_bytes(), &key).unwrap();
        let decrypted = des.decrypt(&ciphertext, &key).unwrap();

        assert_eq!(plaintext, String::from_utf8(decrypted).unwrap());
    }

    #[test]
    fn test_encrytion_decryption_3des() {
        let plaintext = "Hello World!";
        let key = [0u8; 24];
        let tripledes = TripleDes::new();
        let ciphertext = tripledes.encrypt(plaintext.as_bytes(), &key).unwrap();
        let decrypted = tripledes.decrypt(&ciphertext, &key).unwrap();

        assert_eq!(plaintext, String::from_utf8(decrypted).unwrap());
    }
}
