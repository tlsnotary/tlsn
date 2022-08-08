const BIT_MASKS: [u8; 8] = [
    0b10000000, 0b01000000, 0b00100000, 0b00010000, 0b00001000, 0b00000100, 0b00000010, 0b00000001,
];

/// Unsafe matrix transpose
///
/// This function transposes a matrix of generic elements. This function is an implementation of
/// the byte-level transpose in
/// https://docs.rs/oblivious-transfer/latest/oblivious_transfer/extension/fn.transpose128.html
/// Caller has to ensure that
///   - number of rows is a power of 2
///   - slice is rectangular (matrix)
///   - rounds == ld(rows)
#[inline]
pub unsafe fn transpose_unchecked<T>(matrix: &mut [T], rounds: usize)
where
    T: Default + Copy,
{
    let half = matrix.len() >> 1;
    let mut matrix_copy_half = vec![T::default(); half];
    let mut matrix_pointer: *mut T;
    for _ in 0..rounds {
        matrix_copy_half.copy_from_slice(&matrix[..half]);
        matrix_pointer = matrix.as_mut_ptr();
        for k in 0..half {
            std::ptr::copy_nonoverlapping(&matrix_copy_half[k], matrix_pointer, 1);
            std::ptr::copy_nonoverlapping(&matrix[half + k], matrix_pointer, 1);
            matrix_pointer = matrix_pointer.add(2);
        }
    }
}

/// Unsafe single-row bit-mask shift
///
/// This function is an implementation of the bit-level transpose in
/// https://docs.rs/oblivious-transfer/latest/oblivious_transfer/extension/fn.transpose128.html
#[inline]
pub fn bitmask_shift(matrix: &mut [u8], columns: usize) {
    let mut shifted_row = Vec::with_capacity(columns);
    let mut high_bits: [u8; 8] = [0; 8];
    for row in matrix.chunks_mut(columns) {
        for _ in 0..8 {
            for bytes in row.chunks_mut(8) {
                bytes.iter_mut().enumerate().for_each(|(k, b)| {
                    high_bits[k] = *b & BIT_MASKS[k] | !BIT_MASKS[k];
                    *b <<= 1;
                });
            }
            shifted_row.push(high_bits.iter().fold(0b11111111, |acc, b| acc & *b));
        }
        row.copy_from_slice(&shifted_row)
    }
}
