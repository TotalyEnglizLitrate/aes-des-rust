/// DES Heloper function to extract 28 bits starting at the given bit position
pub fn extract_28_bits(data: &[u8; 7], start_bit: usize) -> u32 {
    let mut result = 0u32;
    for i in 0..28 {
        let bit_pos = start_bit + i;
        let byte_index = bit_pos / 8;
        let bit_index = bit_pos % 8;
        let bit = (data[byte_index] >> (7 - bit_index)) & 1;
        result |= (bit as u32) << (27 - i);
    }
    result
}

/// DES helper fucntion to perform left circular shift on a 28-bit value
pub fn left_circular_shift_28(value: u32, positions: usize) -> u32 {
    let mask = 0x0FFFFFFF;
    let shifted = ((value << positions) | (value >> (28 - positions))) & mask;
    shifted
}

/// DES helper function combine two 28-bit halves into a 56-bit value
pub fn combine_28_bit_halves(c: u32, d: u32) -> u64 {
    ((c as u64) << 28) | (d as u64)
}
