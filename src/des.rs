use crate::{block_cipher::BlockCipher, utils::*};

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
        let mut c = extract_28_bits(&permuted_key, 0);
        let mut d = extract_28_bits(&permuted_key, 28);

        let mut round_keys = [[0u8; 6]; 16];

        for (round, &shift) in SHIFTS.iter().enumerate() {
            // Perform left circular shifts on 28-bit halves
            c = left_circular_shift_28(c, shift);
            d = left_circular_shift_28(d, shift);

            // Combine C and D into 56-bit value
            let combined = combine_28_bit_halves(c, d);

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
