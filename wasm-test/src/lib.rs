#![feature(portable_simd)]
#![feature(slice_as_chunks)]
#![feature(slice_split_at_unchecked)]
use std::simd::{LaneCount, Simd, SupportedLaneCount};
use thiserror::Error;

/// This function transposes a matrix, which is encoded as a slice of bytes. The transposition is
/// applied on the bit level, meaning that each matrix element is a single bit. The number of rows
/// has to be a power of 2. The whole transposition consists of byte-level transposition, followed
/// by a bit-level transposition.
///
/// We use the following algorithm:
/// https://docs.rs/oblivious-transfer/latest/oblivious_transfer/extension/fn.transpose128.html
pub fn transpose(matrix: &mut [u8], rows: u32) -> Result<(), TransposeError> {
    // Check that number of rows is a power of 2
    if rows & (rows - 1) != 0 {
        return Err(TransposeError::InvalidNumberOfRows);
    }

    // Calculate number of rounds for transpose_bytes
    let rounds = rows.trailing_zeros();

    // Check that slice is rectangular
    if matrix.len() & ((1 << rounds) - 1) != 0 {
        return Err(TransposeError::MalformedSlice);
    }

    unsafe {
        transpose_bytes::<32>(matrix, rounds);
    }
    Ok(())
}

unsafe fn transpose_bytes<const N: usize>(matrix: &mut [u8], rounds: u32)
where
    LaneCount<N>: SupportedLaneCount,
{
    let half = matrix.len() >> 1;
    let mut matrix_copy: Vec<u8> = Vec::with_capacity(matrix.len());
    for i in 0_..rounds as usize {
        matrix_copy.copy_from_slice(matrix);
        let mut lanes: Vec<Simd<u8, N>> = matrix_copy
            .as_chunks_unchecked_mut::<N>()
            .iter_mut()
            .map(|lane| Simd::from_array(*lane))
            .collect();
        let (chunk1, chunk2) = lanes.split_at_mut_unchecked(half / N);
        for (v1, v2) in chunk1.iter_mut().zip(chunk2) {
            (*v1, *v2) = v1.interleave(*v2);
            matrix[2 * i * N..(2 * i + 1) * N].copy_from_slice(&v1.to_array());
            matrix[(2 * i + 1) * N..(2 + 1) * i * N].copy_from_slice(&v2.to_array());
        }
    }
}

#[derive(Error, Debug)]
pub enum TransposeError {
    #[error("Number of rows is not a power of 2")]
    InvalidNumberOfRows,
    #[error("Provided slice is not of rectangular shape")]
    MalformedSlice,
}
