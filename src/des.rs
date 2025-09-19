use crate::{block_cipher::BlockCipher, helper::des::*};
use rand::random;

/// Data Encryption Standard (DES) implementation.
/// implements the [BlockCipher] trait.
#[allow(unused)]
pub struct Des;

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

        let mut expanded_bytes = [0u8; 6];
        for i in 0..6 {
            expanded_bytes[i] = ((expanded >> (8 * (5 - i))) & 0xFF) as u8 ^ round_key[i];
        }

        let xor_val: u64 = expanded_bytes
            .iter()
            .fold(0u64, |acc, &b| (acc << 8) | b as u64);

        // S-box substitution
        let mut sbox_out = 0u32;
        for i in 0..8 {
            let chunk = ((xor_val >> (42 - 6 * i)) & 0x3F) as u8;
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

    /// Validates the DES key to ensure it meets the required criteria.
    /// # Arguments
    /// * `key` - A byte slice representing the DES key.
    /// # Returns
    /// - `Ok(())` - If the key is valid.
    /// - `Err(String)` - An error message if the key is invalid.
    /// # Criteria
    /// - The key must be exactly 8 bytes long.
    /// - Each byte in the key must have odd parity (i.e., an odd number of '1' bits).
    /// # Example
    /// ```
    /// let key: [u8; 8] = [0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1];
    /// assert!(Des::validate_key(&key).is_ok());
    /// ```
    fn validate_key(key: &[u8]) -> Result<(), String> {
        // Defer to the BlockCipher trait for length validation
        <Self as BlockCipher<8, 8>>::validate_key(key)?;
        if key.iter().all(|&b| b.count_ones() & 1 == 1) {
            Ok(())
        } else {
            Err("Invalid DES key parity".to_string())
        }
    }
}

impl BlockCipher<8, 8> for Des {
    fn encrypt(plaintext: &[u8], key: &[u8], pad: bool) -> Result<Vec<u8>, String> {
        Self::validate_key(key)?;

        // Pad plaintext if needed
        let padded = match (pad, Self::is_padded(plaintext)) {
            (true, true) => plaintext.to_vec(),
            (true, false) => Self::pad(plaintext),
            (false, _) => plaintext.to_vec(),
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
            let mut temp;

            // 16 rounds
            for i in 0..16 {
                temp = r;
                r = l ^ Self::feistel(r, &round_keys[i]);
                l = temp;
            }

            let preoutput = ((r as u64) << 32) | (l as u64);
            let encrypted_block = Self::final_permutation(preoutput);
            ciphertext.extend_from_slice(&encrypted_block);
        }

        Ok(ciphertext)
    }

    fn decrypt(ciphertext: &[u8], key: &[u8], unpad: bool) -> Result<Vec<u8>, String> {
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
            let mut temp;

            // 16 rounds in reverse order
            for i in (0..16).rev() {
                temp = r;
                r = l ^ Self::feistel(r, &round_keys[i]);
                l = temp;
            }

            let preoutput = ((r as u64) << 32) | (l as u64);
            let decrypted_block = Self::final_permutation(preoutput);
            plaintext.extend_from_slice(&decrypted_block);
        }

        if unpad {
            Self::unpad(&plaintext)
        } else {
            Ok(plaintext.to_vec())
        }
    }

    fn gen_key() -> [u8; Self::KEY_SIZE] {
        let mut key: [u8; Self::KEY_SIZE] = random();
        set_key_parity(&mut key);
        key
    }
}

/// Triple Data Encryption Standard (3DES) implementation.
/// Internally uses [Des] for encryption and decryption.
/// Implements the [BlockCipher] trait.
#[allow(unused)]
pub struct TripleDes;

#[allow(unused)]
impl TripleDes {
    /// Splits a TripleDes key into 3 individual DES keys
    /// # Arguments
    /// * `key` - A byte slice representing the TripleDes key.
    /// # Returns
    /// - `Ok((k1, k2, k3))` - A tuple containing three individual DES keys.
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

impl BlockCipher<8, 24> for TripleDes {
    fn encrypt(plaintext: &[u8], key: &[u8], pad: bool) -> Result<Vec<u8>, String> {
        let (k1, k2, k3) = Self::split_keys(key)?;

        Des::validate_key(k1)?;
        Des::validate_key(k2)?;
        Des::validate_key(k3)?;

        // Pad plaintext if needed
        let padded = match (pad, Self::is_padded(plaintext)) {
            (true, true) => plaintext.to_vec(),
            (true, false) => Self::pad(plaintext),
            (false, _) => plaintext.to_vec(),
        };

        // 3DES: Encrypt with K1, Decrypt with K2, Encrypt with K3
        let first_encryption = Des::encrypt(&padded, k1, false)?;
        let decryption = Des::decrypt(&first_encryption, k2, false)?;
        Des::encrypt(&decryption, k3, false)
    }

    fn decrypt(ciphertext: &[u8], key: &[u8], unpad: bool) -> Result<Vec<u8>, String> {
        let (k1, k2, k3) = Self::split_keys(key)?;

        Des::validate_key(k1)?;
        Des::validate_key(k2)?;
        Des::validate_key(k3)?;

        // 3DES: Decrypt with K3, Encrypt with K2, Decrypt with K1
        let first_decryption = Des::decrypt(ciphertext, k3, false)?;
        let encryption = Des::encrypt(&first_decryption, k2, false)?;
        let plaintext = Des::decrypt(&encryption, k1, false)?;

        if unpad {
            Self::unpad(&plaintext)
        } else {
            Ok(plaintext)
        }
    }

    fn gen_key() -> [u8; Self::KEY_SIZE] {
        let mut key: [u8; Self::KEY_SIZE] = random();
        set_key_parity(&mut key);
        key
    }
}

#[allow(dead_code)]
fn set_key_parity(key: &mut [u8]) {
    for byte in key.iter_mut() {
        if byte.count_ones() & 1 == 0 {
            *byte = *byte ^ 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{BlockCipher, Des, TripleDes};

    #[test]
    fn test_encrytion_decryption_des() {
        let plaintext = "Food for thought";
        let key = Des::gen_key();
        let ciphertext = Des::encrypt(plaintext.as_bytes(), &key, true).unwrap();
        let decrypted = Des::decrypt(&ciphertext, &key, true).unwrap();

        println!("key: {:?}\nciphertext: {:?}", key, ciphertext);

        assert_eq!(plaintext.as_bytes(), decrypted.as_slice());
    }

    #[test]
    fn test_encrytion_decryption_3des() {
        let plaintext = "Food for thought";
        let key = TripleDes::gen_key();
        let ciphertext = TripleDes::encrypt(plaintext.as_bytes(), &key, true).unwrap();
        let decrypted = TripleDes::decrypt(&ciphertext, &key, true).unwrap();

        println!("key: {:?}\nciphertext: {:?}", key, ciphertext);

        assert_eq!(plaintext.as_bytes(), decrypted.as_slice());
    }
}
