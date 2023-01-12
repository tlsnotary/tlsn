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
    let mut matrix_cache = matrix.to_vec();
    let mut write_reference = (*matrix).as_mut_ptr();
    let mut read_reference = matrix_cache.as_mut_ptr();
    if rounds & 1 == 0 {
        std::mem::swap(&mut write_reference, &mut read_reference);
    }
    for _ in 0..rounds {
        for k in 0..half {
            write_reference
                .add(2 * k)
                .copy_from_nonoverlapping(read_reference.add(k), 1);
            write_reference
                .add(2 * k + 1)
                .copy_from_nonoverlapping(read_reference.add(half + k), 1);
        }
        std::mem::swap(&mut write_reference, &mut read_reference);
    }
}

/// Single-row bit-mask shift
///
/// This function is an implementation of the bit-level transpose in
/// https://docs.rs/oblivious-transfer/latest/oblivious_transfer/extension/fn.transpose128.html
/// Caller has to make sure that columns is a multiple of 8
#[inline]
pub fn bitmask_shift(matrix: &mut [u8], columns: usize) {
    for row in matrix.chunks_mut(columns) {
        let mut shifted_row = Vec::with_capacity(columns);
        for _ in 0..8 {
            for bytes in row.chunks_mut(8) {
                let mut high_bits: u8 = 0b00000000;
                bytes.iter_mut().enumerate().for_each(|(k, b)| {
                    high_bits |= (0b10000000 & *b) >> k;
                    *b <<= 1;
                });
                shifted_row.push(high_bits);
            }
        }
        row.copy_from_slice(&shifted_row)
    }
}
