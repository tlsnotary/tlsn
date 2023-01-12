#![cfg_attr(
    feature = "simd-transpose",
    feature(slice_split_at_unchecked),
    feature(portable_simd),
    feature(stmt_expr_attributes),
    feature(slice_as_chunks)
)]

#[cfg(feature = "simd-transpose")]
#[cfg(target_arch = "x86_64")]
pub const LANE_COUNT: usize = 32;

#[cfg(feature = "simd-transpose")]
#[cfg(target_arch = "wasm32")]
pub const LANE_COUNT: usize = 16;

#[cfg(not(feature = "simd-transpose"))]
pub const LANE_COUNT: usize = 8;

#[cfg(not(feature = "simd-transpose"))]
mod scalar;
#[cfg(feature = "simd-transpose")]
mod simd;

#[cfg(feature = "simd-transpose")]
pub use simd::transpose_unchecked;

#[cfg(not(feature = "simd-transpose"))]
pub use scalar::transpose_unchecked;

use thiserror::Error;

/// This function transposes a matrix on the bit-level.
///
/// This implementation requires that the number of rows is a power of 2
/// and that the number of columns is a multiple of 8
pub fn transpose_bits(matrix: &mut [u8], rows: usize) -> Result<(), TransposeError> {
    // Check that number of rows is a power of 2
    if rows & (rows - 1) != 0 {
        return Err(TransposeError::InvalidNumberOfRows);
    }

    // Check that slice is rectangular i.e. the number of cells is a multiple of the number of rows
    if matrix.len() & (rows - 1) != 0 {
        return Err(TransposeError::MalformedSlice);
    }

    // Check that columns is a multiple of 8
    let columns = matrix.len() / rows;
    if columns & 7 != 0 || columns < 8 {
        return Err(TransposeError::InvalidNumberOfColumns);
    }

    #[cfg(feature = "simd-transpose")]
    simd::transpose_bits(matrix, rows)?;
    #[cfg(not(feature = "simd-transpose"))]
    unsafe {
        scalar::transpose_unchecked(matrix, rows.trailing_zeros() as usize);
        scalar::bitmask_shift(matrix, rows);
    }
    Ok(())
}

#[derive(Error, Debug, PartialEq)]
pub enum TransposeError {
    #[error("Number of rows is not a power of 2")]
    InvalidNumberOfRows,
    #[error("Provided slice is not of rectangular shape")]
    MalformedSlice,
    #[error("Number of columns must be a multiple of lane count")]
    InvalidNumberOfColumns,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{
        distributions::{Distribution, Standard},
        prelude::*,
    };

    fn random_vec<T>(elements: usize) -> Vec<T>
    where
        Standard: Distribution<T>,
    {
        let mut rng = thread_rng();
        (0..elements).map(|_| rng.gen::<T>()).collect()
    }

    #[test]
    fn test_transpose_bits() {
        let mut rows = 512;
        let columns = 256;

        let mut matrix: Vec<u8> = random_vec::<u8>(columns * rows);
        let original = matrix.clone();
        transpose_bits(&mut matrix, rows).unwrap();
        rows = columns;
        transpose_bits(&mut matrix, 8 * rows).unwrap();
        assert_eq!(original, matrix);
    }

    #[test]
    fn test_transpose() {
        let rounds = 7_u32;
        let mut rows = 2_usize.pow(rounds);
        let mut columns = 64;

        let mut matrix: Vec<u8> = random_vec::<u8>(columns * rows);
        let original = matrix.clone();
        unsafe {
            #[cfg(feature = "simd-transpose")]
            simd::transpose_unchecked::<32, u8>(&mut matrix, rounds as usize);
            #[cfg(not(feature = "simd-transpose"))]
            scalar::transpose_unchecked::<u8>(&mut matrix, rounds as usize);
        }

        (rows, columns) = (columns, rows);
        for (k, element) in matrix.iter().enumerate() {
            let row_number = k / columns;
            let column_number = k % columns;
            assert_eq!(*element, original[column_number * rows + row_number])
        }
    }

    #[test]
    fn test_bitmask_shift() {
        let columns = 64;
        let rows = 128;

        let mut matrix: Vec<u8> = random_vec::<u8>(columns * rows);
        let mut original = matrix.clone();
        #[cfg(feature = "simd-transpose")]
        unsafe {
            simd::bitmask_shift_unchecked(&mut matrix, columns);
        }
        #[cfg(not(feature = "simd-transpose"))]
        scalar::bitmask_shift(&mut matrix, columns);

        for (row_index, row) in original.chunks_mut(columns).enumerate() {
            for k in 0..8 {
                for (l, chunk) in row.chunks(8).enumerate() {
                    let expected: u8 = chunk.iter().enumerate().fold(0, |acc, (m, element)| {
                        acc + (element >> 7) * 2_u8.pow(7_u32 - m as u32)
                    });
                    let actual = matrix[row_index * columns + columns / 8 * k + l];
                    assert_eq!(expected, actual);
                }
                let shifted_row = row.iter_mut().map(|el| *el << 1).collect::<Vec<u8>>();
                row.copy_from_slice(&shifted_row);
            }
        }
    }
}
