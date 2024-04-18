use crate::{
    backend::halo2::{
        circuit::{BIT_COLUMNS, USABLE_ROWS},
        CHUNK_SIZE,
    },
    utils::boolvec_to_u8vec,
};
use cfg_if::cfg_if;
use ff::{Field, FromUniformBytes, PrimeField};
use halo2_proofs::halo2curves::bn256::Fr as F;
use itybity::{FromBitIterator, IntoBits, StrToBits, ToBits};
use num::{bigint::Sign, BigInt, BigUint, Signed};

#[cfg(test)]
use crate::backend::halo2::prover::TEST_BINARY_CHECK_FAIL_IS_RUNNING;

/// Converts big-endian bytes into a field element by reducing by the modulus.
///
/// # Panics
///
/// Panics if the count of bytes is > 64.
pub fn bytes_be_to_f(mut bytes: Vec<u8>) -> F {
    bytes.reverse();
    let mut wide = [0u8; 64];
    wide[0..bytes.len()].copy_from_slice(&bytes);
    F::from_uniform_bytes(&wide)
}

/// Converts bits in MSB-first order into a field element by reducing by the modulus.
///
/// # Panics
///
/// Panics if the count of bits is > 512.
pub fn bits_to_f(bits: &[bool]) -> F {
    bytes_be_to_f(boolvec_to_u8vec(bits))
}

/// Decomposes a field element into 256 bits in MSB-first bit order.
pub fn f_to_bits(f: &F) -> [bool; 256] {
    let mut bytes = f.to_bytes();
    // Reverse to get bytes in big-endian.
    bytes.reverse();
    // It is safe to `unwrap` since 32 bytes will always convert to 256 bits.
    bytes.to_msb0_vec().try_into().unwrap()
}

/// Converts a slice of `items` into a matrix in column-major order performing the necessary padding.
///
/// Each chunk of `chunk_size` items will be padded with the default value on the left in order to
/// bring the size of the chunk to `pad_chunk_to_size`. Then a matrix of `row_count` rows and
/// `column_count` columns will be filled with items in row-major order, filling any empty cells with
/// the default value. Finally, the matrix will be transposed.
///
/// # Panics
///
/// Panics if the matrix cannot be created.
pub fn slice_to_columns<V>(
    items: &[V],
    chunk_size: usize,
    pad_chunk_to_size: usize,
    row_count: usize,
    column_count: usize,
) -> Vec<Vec<V>>
where
    V: Default + Clone,
{
    let total = row_count * column_count;
    assert!(pad_chunk_to_size >= chunk_size);

    // Left-pad each individual chunk.
    let mut items = items
        .chunks(chunk_size)
        .flat_map(|chunk| {
            let mut v = vec![V::default(); pad_chunk_to_size - chunk.len()];
            v.extend(chunk.to_vec());
            v
        })
        .collect::<Vec<_>>();

    assert!(items.len() <= total);

    // Fill empty cells of the matrix.
    items.extend(vec![V::default(); total - items.len()]);

    // Create a row-major matrix.
    let items = items
        .chunks(column_count)
        .map(|c| c.to_vec())
        .collect::<Vec<_>>();

    debug_assert!(items.len() == row_count);

    // Transpose to column-major.
    transpose_matrix(items)
}

/// Composes the 64 `bits` of a limb with the given `index` into a field element, left shifting if
/// needed. `bits` are in MSB-first order. The limb with `index` 0 is the highest limb.
///
/// # Panics
///
/// Panics if limb index > 3 or if any of the `bits` is not a boolean value.
#[allow(clippy::collapsible_else_if)]
pub fn compose_bits(bits: &[F; 64], index: usize) -> F {
    assert!(index < 4);
    let bits = bits
        .iter()
        .map(|bit| {
            if *bit == F::zero() {
                false
            } else if *bit == F::one() {
                true
            } else {
                cfg_if! {
                if #[cfg(test)] {
                    if unsafe{TEST_BINARY_CHECK_FAIL_IS_RUNNING} {
                        // Don't panic, use an arbitrary valid bit value.
                        true
                    } else {
                        // For all other tests, panic as usual.
                        panic!("field element is not a boolean value");
                    }
                }
                else {
                    panic!("field element is not a boolean value");
                }
                }
            }
        })
        .collect::<Vec<_>>();

    let two = F::one() + F::one();

    // Left-shift.
    bits_to_f(&bits) * two.pow([((3 - index as u64) * 64).to_le()])
}

/// Transposes a matrix.
///
/// # Panics
///
/// Panics if `matrix` is not a rectangular matrix.
fn transpose_matrix<V>(matrix: Vec<Vec<V>>) -> Vec<Vec<V>>
where
    V: Clone,
{
    let len = matrix[0].len();
    matrix[1..].iter().for_each(|row| assert!(row.len() == len));

    (0..len)
        .map(|i| {
            matrix
                .iter()
                .map(|inner| inner[i].clone())
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes_be_to_f() {
        assert_eq!(bytes_be_to_f(vec![1u8, 2u8]), F::from(258u64));
    }

    #[test]
    fn test_bits_to_f() {
        // 01 0000 0011 == 259
        let bits = [
            false, true, false, false, false, false, false, false, true, true,
        ];
        assert_eq!(bits_to_f(&bits), F::from(259u64));
    }

    #[test]
    fn test_f_to_bits() {
        let mut bits = vec![false; 246];
        bits.extend([
            // 01 0000 0100 == 260
            false, true, false, false, false, false, false, true, false, false,
        ]);
        let expected: [bool; 256] = bits.try_into().unwrap();
        assert_eq!(f_to_bits(&F::from(260u64)), expected);
    }

    #[test]
    fn test_slice_to_columns() {
        let slice = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

        // First the matrix will be padded and chunked.
        // It will look like this in row-major order:
        // 0 0 1 2
        // 3 0 0 4
        // 5 6 0 0
        // 7 8 9 0
        // 0 0 0 10
        // 0 0 0 0
        // Then it will be transposed to column-major order:
        let expected1 = vec![
            vec![0, 3, 5, 7, 0, 0],
            vec![0, 0, 6, 8, 0, 0],
            vec![1, 0, 0, 9, 0, 0],
            vec![2, 4, 0, 0, 10, 0],
        ];
        let expected2 = vec![
            vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            vec![0, 1, 0, 4, 0, 7, 0, 0, 0, 0],
            vec![0, 2, 0, 5, 0, 8, 0, 0, 0, 0],
            vec![0, 3, 0, 6, 0, 9, 0, 10, 0, 0],
        ];
        assert_eq!(slice_to_columns(&slice, 3, 5, 6, 4), expected1);
        assert_eq!(slice_to_columns(&slice, 3, 8, 10, 4), expected2);
    }

    #[test]
    fn test_transpose_matrix() {
        let matrix = vec![
            vec![1, 2, 3],
            vec![4, 5, 6],
            vec![7, 8, 9],
            vec![10, 11, 12],
        ];

        let expected = vec![vec![1, 4, 7, 10], vec![2, 5, 8, 11], vec![3, 6, 9, 12]];
        assert_eq!(transpose_matrix(matrix), expected);
    }
}
