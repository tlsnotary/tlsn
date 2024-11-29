use cfg_if::cfg_if;
use ff::{Field, FromUniformBytes};
use halo2_proofs::halo2curves::bn256::Fr as F;
use itybity::{FromBitIterator, ToBits};

#[cfg(test)]
use crate::backend::halo2::prover::TEST_BINARY_CHECK_FAIL_IS_RUNNING;

/// Converts byte representation of a scalar into a field element.
///
/// # Arguments
///
/// * `bytes` - The little-endian bytes to be converted.
///
/// # Panics
///
/// Panics if the count of bytes is > 64.
pub fn bytes_to_f(bytes: &[u8]) -> F {
    let mut wide = [0u8; 64];
    wide[0..bytes.len()].copy_from_slice(bytes);
    F::from_uniform_bytes(&wide)
}

/// Converts a field element into LSB0 bits.
///
/// # Arguments
///
/// * `f` - The field element to decompose.
pub fn f_to_bits(f: &F) -> [bool; 256] {
    // It is safe to `unwrap` since 32 bytes will always convert to 256 bits.
    f.to_bytes().to_lsb0_vec().try_into().unwrap()
}

/// Converts a slice of `items` into a matrix in column-major order performing the necessary padding.
///
/// Each chunk of `chunk_size` items will be padded with the default value on the right in order to
/// bring the size of the chunk to `pad_chunk_to_size`. Then a matrix of `row_count` rows and
/// `column_count` columns will be filled with items in row-major order, filling any empty trailing
/// cells with the default value. Finally, the matrix will be transposed.
///
/// # Arguments
///
/// * `items` -        The items to be arranged into a matrix.
/// * `chunk_size` -   The size of a chunk of items that has to be padded to the `pad_chunk_to_size` size.
/// * `pad_chunk_to_size` - The size to which a chunk of items will be padded.
/// * `row_count` -    The amount of rows in the resulting matrix.
/// * `column_count` - The amount of columns in the resulting matrix.
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

    // Right-pad each individual chunk.
    let mut items = items
        .chunks(chunk_size)
        .flat_map(|chunk| {
            let mut chunk = chunk.to_vec();
            let padding = vec![V::default(); pad_chunk_to_size - chunk.len()];
            chunk.extend(padding);
            chunk
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
/// needed.
///
/// # Arguments
///
/// * `bits` - The bits to be composed in LSB0 bit order.
/// * `index` - The index of a limb to be composed (the low limb has index 0).
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
    bits_to_f(&bits) * two.pow([(index as u64 * 64).to_le()])
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

/// Converts bits in LSB0 order into a field element by reducing by the modulus.
///
/// # Panics
///
/// Panics if the count of bits is > 512.
fn bits_to_f(bits: &[bool]) -> F {
    bytes_to_f(&Vec::<u8>::from_lsb0_iter(bits.iter().copied()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes_to_f() {
        assert_eq!(bytes_to_f(&[2u8, 1u8]), F::from(258u64));
    }

    #[test]
    fn test_f_to_bits() {
        let mut bits = vec![
            // 01 0000 0100 == 260
            false, true, false, false, false, false, false, true, false, false,
        ];
        // Reverse to little endian.
        bits.reverse();
        bits.extend(std::iter::repeat(false).take(256 - bits.len()));

        let expected: [bool; 256] = bits.try_into().unwrap();
        assert_eq!(f_to_bits(&F::from(260u64)), expected);
    }

    #[test]
    fn test_slice_to_columns() {
        let slice = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

        // First the matrix will be padded and chunked.
        // It will look like this in row-major order:
        // 1 2 3 0
        // 0 4 5 6
        // 0 0 7 8
        // 9 0 0 10
        // 0 0 0 0
        // 0 0 0 0
        // Then it will be transposed to column-major order:
        let expected1 = vec![
            vec![1, 0, 0, 9, 0, 0],
            vec![2, 4, 0, 0, 0, 0],
            vec![3, 5, 7, 0, 0, 0],
            vec![0, 6, 8, 10, 0, 0],
        ];
        let expected2 = vec![
            vec![1, 0, 4, 0, 7, 0, 10, 0, 0, 0],
            vec![2, 0, 5, 0, 8, 0, 0, 0, 0, 0],
            vec![3, 0, 6, 0, 9, 0, 0, 0, 0, 0],
            vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        ];
        assert_eq!(slice_to_columns(&slice, 3, 5, 6, 4), expected1);
        assert_eq!(slice_to_columns(&slice, 3, 8, 10, 4), expected2);
    }

    #[test]
    fn test_compose_bits() {
        let two = F::from(2);
        let mut bits: [F; 64] = (0..64)
            .map(|_| F::zero())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        for (i, limb) in (0..4).zip([1, 3, 7, 15]) {
            // On each iteration, set one more LSB.
            bits[i] = F::one();
            assert_eq!(
                compose_bits(&bits, i),
                F::from(limb) * two.pow_vartime([64 * i as u64])
            );
        }
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

    #[test]
    fn test_bits_to_f() {
        // 01 0000 0011 == 259
        let mut bits = [
            false, true, false, false, false, false, false, false, true, true,
        ];
        // Reverse to little-endian.
        bits.reverse();
        assert_eq!(bits_to_f(&bits), F::from(259u64));
    }
}
