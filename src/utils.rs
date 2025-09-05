/// DES Helper function to extract 28 bits starting at the given bit position.
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
pub fn extract_28_bits(key: &[u8; 7], start_bit: usize) -> u32 {
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

/// DES Helper function to perform a left circular shift on a 28-bit value.
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
pub fn left_circular_shift_28(value: u32, positions: usize) -> u32 {
    let mask = 0x0FFFFFFF;
    let shifted = ((value << positions) | (value >> (28 - positions))) & mask;
    shifted
}

/// DES Helper function to combine two 28-bit halves into a 56-bit value.
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
pub fn combine_28_bit_halves(c: u32, d: u32) -> u64 {
    ((c as u64) << 28) | (d as u64)
}
