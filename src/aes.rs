use crate::{block_cipher::BlockCipher, helper::aes::*};
use rand::random;

/// Advanced Encryption Standard (AES) implementation.
/// Implements the [BlockCipher] trait.
#[allow(unused)]
pub struct Aes128;

#[allow(unused)]
impl BlockCipher<16, 16> for Aes128 {
    const BLOCK_SIZE: usize = 16; // AES block size in bytes
    const KEY_SIZE: usize = 16; // AES key size in bytes (128 bits)

    fn encrypt(plaintext: &[u8], key: &[u8], pad: bool) -> Result<Vec<u8>, String> {
        if key.len() != Self::KEY_SIZE {
            return Err(format!(
                "Invalid key length: expected {} bytes, got {}",
                Self::KEY_SIZE,
                key.len()
            ));
        }

        if plaintext.is_empty() {
            return Err("Plaintext cannot be empty".to_string());
        }

        let padded = match (pad, Self::is_padded(plaintext)) {
            (true, true) => plaintext.to_vec(),
            (true, false) => Self::pad(plaintext),
            (false, _) => {
                if plaintext.len() % Self::BLOCK_SIZE != 0 {
                    return Err(
                        "Plaintext length must be multiple of block size when padding is disabled"
                            .to_string(),
                    );
                }
                plaintext.to_vec()
            }
        };

        let key_schedule = Self::key_expansion(key);
        let mut ciphertext = Vec::with_capacity(padded.len());

        for block in padded.chunks_exact(Self::BLOCK_SIZE) {
            let mut state = Self::block_to_state(block);
            state = Self::add_round_key(state, &key_schedule[0]);

            for round in 1..10 {
                state = Self::sub_bytes(state);
                state = Self::shift_rows(state);
                state = Self::mix_columns(state);
                state = Self::add_round_key(state, &key_schedule[round]);
            }

            // Final round (no MixColumns)
            state = Self::sub_bytes(state);
            state = Self::shift_rows(state);
            state = Self::add_round_key(state, &key_schedule[10]);

            ciphertext.extend_from_slice(&Self::state_to_block(state));
        }

        Ok(ciphertext)
    }

    fn decrypt(ciphertext: &[u8], key: &[u8], unpad: bool) -> Result<Vec<u8>, String> {
        if key.len() != Self::KEY_SIZE {
            return Err(format!(
                "Invalid key length: expected {} bytes, got {}",
                Self::KEY_SIZE,
                key.len()
            ));
        }

        if ciphertext.is_empty() {
            return Err("Ciphertext cannot be empty".to_string());
        }

        if ciphertext.len() % Self::BLOCK_SIZE != 0 {
            return Err("Ciphertext length must be multiple of block size".to_string());
        }

        let key_schedule = Self::key_expansion(key);
        let mut plaintext = Vec::with_capacity(ciphertext.len());

        for block in ciphertext.chunks_exact(Self::BLOCK_SIZE) {
            let mut state = Self::block_to_state(block);
            state = Self::add_round_key(state, &key_schedule[10]);

            for round in (1..10).rev() {
                state = Self::inv_shift_rows(state);
                state = Self::inv_sub_bytes(state);
                state = Self::add_round_key(state, &key_schedule[round]);
                state = Self::inv_mix_columns(state);
            }

            // Final round (no InvMixColumns)
            state = Self::inv_shift_rows(state);
            state = Self::inv_sub_bytes(state);
            state = Self::add_round_key(state, &key_schedule[0]);

            plaintext.extend_from_slice(&Self::state_to_block(state));
        }

        if unpad {
            Self::unpad(&plaintext)
        } else {
            Ok(plaintext)
        }
    }

    fn gen_key() -> [u8; Self::KEY_SIZE] {
        random()
    }
}

impl Aes128 {
    /// Expands the key into 11 round keys for AES-128
    ///
    /// Arguments:
    /// * `key` - A 16-byte array representing the original key
    /// Returns:
    /// * A vector of 11 round keys, each being a 16-byte array
    /// Example:
    /// ```
    /// let key: [u8; 16] = rand::random();
    /// let round_keys = Aes128::key_expansion(&key);
    /// ```
    fn key_expansion(key: &[u8]) -> Vec<[u8; 16]> {
        let mut key_schedule = vec![[0u8; 16]; 11];
        key_schedule[0].copy_from_slice(key);

        for i in 1..11 {
            let mut temp = [0u8; 4];
            temp.copy_from_slice(&key_schedule[i - 1][12..16]);
            temp = Self::key_schedule_core(temp, i);

            for j in 0..4 {
                key_schedule[i][j] = temp[j] ^ key_schedule[i - 1][j];
            }

            for j in 4..16 {
                key_schedule[i][j] = key_schedule[i][j - 4] ^ key_schedule[i - 1][j];
            }
        }

        key_schedule
    }

    /// Key schedule core function for key expansion
    /// Arguments:
    /// * `word` - A 4-byte array (last 4 bytes of previous round key)
    /// * `round` - The current round number (1 to 10)
    /// Returns:
    /// * A transformed 4-byte array
    /// Example:
    /// ```
    /// let word: [u8; 4] = [0x01, 0x02, 0x03, 0x04];
    /// let round = 1;
    /// let transformed = Aes128::key_schedule_core(word, round);
    /// ```
    fn key_schedule_core(mut word: [u8; 4], round: usize) -> [u8; 4] {
        word.rotate_left(1);

        for i in 0..4 {
            word[i] = S_BOX[(word[i] >> 4) as usize][(word[i] & 0xF) as usize];
        }

        word[0] ^= RCON[round];
        word
    }

    /// Convert a 16-byte block to a 4x4 state matrix (column-major)
    /// Arguments:
    /// * `block` - A 16-byte array representing the block
    /// Returns:
    /// * A 4x4 matrix (array of arrays) representing the state
    /// Example:
    /// ```
    /// let block: [u8; 16] = [0; 16];
    /// let state = Aes128::block_to_state(&block);
    /// ```
    fn block_to_state(block: &[u8]) -> [[u8; 4]; 4] {
        let mut state = [[0u8; 4]; 4];
        for i in 0..16 {
            state[i % 4][i / 4] = block[i];
        }
        state
    }

    /// Convert a 4x4 state matrix to a 16-byte block (column-major)
    /// Arguments:
    /// * `state` - A 4x4 matrix (array of arrays) representing the state
    /// Returns:
    /// * A 16-byte array representing the block
    /// Example:
    /// ```
    /// let state: [[u8; 4]; 4] = [[0; 4]; 4];
    /// let block = Aes128::state_to_block(state);
    /// ```
    fn state_to_block(state: [[u8; 4]; 4]) -> [u8; 16] {
        let mut block = [0u8; 16];
        for i in 0..16 {
            block[i] = state[i % 4][i / 4];
        }
        block
    }

    /// XOR state with round key
    /// Arguments:
    /// * `state` - A 4x4 matrix (array of arrays) representing the state
    /// * `round_key` - A 16-byte array representing the round key
    /// Returns:
    /// * A 4x4 matrix (array of arrays) after XOR with the round
    /// key
    /// Example:
    /// ```
    /// let state: [[u8; 4]; 4] = [[0; 4]; 4];
    /// let round_key: [u8; 16] = [0; 16];
    fn add_round_key(mut state: [[u8; 4]; 4], round_key: &[u8; 16]) -> [[u8; 4]; 4] {
        for i in 0..16 {
            state[i % 4][i / 4] ^= round_key[i];
        }
        state
    }

    /// Apply S-box substitution to each byte in the state
    /// Arguments:
    /// * `state` - A 4x4 matrix (array of arrays) representing the state
    /// Returns:
    /// * A 4x4 matrix (array of arrays) after S-box substitution
    /// Example:
    /// ```
    /// let state: [[u8; 4]; 4] = [[0; 4]; 4];
    /// let substituted = Aes128::sub_bytes(state);
    /// ```
    fn sub_bytes(mut state: [[u8; 4]; 4]) -> [[u8; 4]; 4] {
        for i in 0..4 {
            for j in 0..4 {
                let byte = state[i][j];
                state[i][j] = S_BOX[(byte >> 4) as usize][(byte & 0xF) as usize];
            }
        }
        state
    }

    /// Apply inverse S-box substitution to each byte in the state
    /// Arguments:
    /// * `state` - A 4x4 matrix (array of arrays) representing the state
    /// Returns:
    /// * A 4x4 matrix (array of arrays) after inverse S-box substitution
    /// Example:
    /// ```
    /// let state: [[u8; 4]; 4] = [[0; 4]; 4];
    /// let inv_substituted = Aes128::inv_sub_bytes(state);
    /// ```
    fn inv_sub_bytes(mut state: [[u8; 4]; 4]) -> [[u8; 4]; 4] {
        for i in 0..4 {
            for j in 0..4 {
                let byte = state[i][j];
                state[i][j] = INVERSE_S_BOX[(byte >> 4) as usize][(byte & 0xF) as usize];
            }
        }
        state
    }

    /// Shift rows of the state matrix
    /// Arguments:
    /// * `state` - A 4x4 matrix (array of arrays) representing the state
    /// Returns:
    /// * A 4x4 matrix (array of arrays) after shifting rows
    /// Example:
    /// ```
    /// let state: [[u8; 4]; 4] = [[0; 4]; 4];
    /// let shifted = Aes128::shift_rows(state);
    /// ```
    fn shift_rows(mut state: [[u8; 4]; 4]) -> [[u8; 4]; 4] {
        for i in 1..4 {
            state[i].rotate_left(i);
        }
        state
    }

    /// Inverse shift rows of the state matrix
    /// Arguments:
    /// * `state` - A 4x4 matrix (array of arrays) representing the state
    /// Returns:
    /// * A 4x4 matrix (array of arrays) after inverse shifting rows
    /// Example:
    /// ```
    /// let state: [[u8; 4]; 4] = [[0; 4]; 4];
    /// let inv_shifted = Aes128::inv_shift_rows(state);
    /// ```
    fn inv_shift_rows(mut state: [[u8; 4]; 4]) -> [[u8; 4]; 4] {
        for i in 1..4 {
            state[i].rotate_right(i);
        }
        state
    }

    /// Mix columns transformation
    /// Arguments:
    /// * `state` - A 4x4 matrix (array of arrays) representing the state
    /// Returns:
    /// * A 4x4 matrix (array of arrays) after mixing columns
    /// Example:
    /// ```
    /// let state: [[u8; 4]; 4] = [[0; 4]; 4];
    /// let mixed = Aes128::mix_columns(state);
    /// ```
    fn mix_columns(state: [[u8; 4]; 4]) -> [[u8; 4]; 4] {
        mix_state(state)
    }

    /// Inverse mix columns transformation
    /// Arguments:
    /// * `state` - A 4x4 matrix (array of arrays) representing the state
    /// Returns:
    /// * A 4x4 matrix (array of arrays) after inverse mixing columns
    /// Example:
    /// ```
    /// let state: [[u8; 4]; 4] = [[0; 4]; 4];
    /// let inv_mixed = Aes128::inv_mix_columns(state);
    /// ```
    fn inv_mix_columns(state: [[u8; 4]; 4]) -> [[u8; 4]; 4] {
        inv_mix_state(state)
    }
}

#[cfg(test)]
mod tests {
    use super::{Aes128, BlockCipher};

    #[test]
    fn test_encryption_decryption_aes() {
        let plaintext = "Food for thought";
        let key = Aes128::gen_key();
        let ciphertext = Aes128::encrypt(plaintext.as_bytes(), &key, true).unwrap();
        let decrypted = Aes128::decrypt(&ciphertext, &key, true).unwrap();

        println!("key: {:?}\nciphertext: {:?}", key, ciphertext);

        assert_eq!(plaintext.as_bytes(), decrypted.as_slice());
    }
}
