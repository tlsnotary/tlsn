use std::slice::{Chunks, ChunksMut};

use matrix_transpose::transpose_bits;
use thiserror::Error;

/// Minimal matrix implementation
///
/// This provides some convenience when dealing with matrices in the KOS15 protocol
#[derive(Debug, PartialEq, Clone)]
pub struct KosMatrix {
    // The receiver of extended OT will have a matrix R and the sender of extended
    // OT will have a matrix S, such that for each row j: if receiver's choice bit
    // was 0 then S[j] = R[j], or if receiver's choice bit was 1 then S[j] =
    // R[j] ⊕ B, where B is derived from base OT choices and is known only to the
    // sender.
    inner: Vec<u8>,
    rows: usize,
    columns: usize,
}

impl KosMatrix {
    /// Create a new matrix from a vector of bytes
    ///
    /// Use columns to indicate the row length of the matrix
    pub fn new(bytes: Vec<u8>, columns: usize) -> Result<Self, Error> {
        let length = bytes.len();
        if bytes.is_empty() || length % columns != 0 {
            return Err(Error::Initialize);
        }

        let matrix = Self {
            inner: bytes,
            rows: length / columns,
            columns,
        };
        Ok(matrix)
    }

    /// Returns the number of rows or the length of a column
    pub fn rows(&self) -> usize {
        self.rows
    }

    /// Returns the number of columns or the length of a row
    pub fn columns(&self) -> usize {
        self.columns
    }

    /// Returns a reference to the inner Vec
    pub fn inner(&self) -> &Vec<u8> {
        &self.inner
    }

    /// Returns the inner Vec
    pub fn into_inner(self) -> Vec<u8> {
        self.inner
    }

    /// Transpose bitwise
    ///
    /// The matrix is treated as a matrix of bits, then transposed and again encoded as a byte
    /// matrix
    pub fn transpose_bits(&mut self) -> Result<(), Error> {
        let rows = self.rows;
        transpose_bits(&mut self.inner, rows).map_err(Error::Transpose)?;
        (self.rows, self.columns) = (self.columns * 8, self.rows / 8);
        Ok(())
    }

    /// Splits the byte matrix at the given row index. Mutates `self` to become
    /// the first part of the split and returns the second part of the split.
    pub fn split_off_rows(&mut self, n: usize) -> Result<Self, Error> {
        if n > self.rows() {
            return Err(Error::InvalidNumberOfRows);
        }

        let split_off = n * self.columns();

        let split_vec = self.inner.drain(split_off..).collect();
        let split_matrix = Self {
            inner: split_vec,
            rows: self.rows() - n,
            columns: self.columns(),
        };
        self.rows = n;
        Ok(split_matrix)
    }

    /// Like `split_off_rows` but returns the first part and the second part
    /// will be `self`
    pub fn split_off_rows_reverse(&mut self, n: usize) -> Result<Self, Error> {
        if n > self.rows() {
            return Err(Error::InvalidNumberOfRows);
        }

        let split_off = n * self.columns();

        let split_vec = self.inner.drain(..split_off).collect();
        let split_matrix = Self {
            inner: split_vec,
            rows: n,
            columns: self.columns(),
        };
        self.rows = self.rows() - n;
        Ok(split_matrix)
    }

    /// Iterate row by row over matrix
    pub fn iter_rows(&self) -> Chunks<u8> {
        self.inner.chunks(self.columns())
    }

    /// Iterate in a mutable way row by row over matrix
    pub fn iter_rows_mut(&mut self) -> ChunksMut<u8> {
        let columns = self.columns();
        self.inner.chunks_mut(columns)
    }
}

#[cfg(test)]
impl KosMatrix {
    /// Returns the number of elements
    pub fn len(&self) -> usize {
        self.inner.len()
    }
}

impl<T> std::ops::Index<T> for KosMatrix
where
    T: std::slice::SliceIndex<[u8]>,
{
    type Output = T::Output;

    fn index(&self, index: T) -> &Self::Output {
        &self.inner[index]
    }
}

impl<T> std::ops::IndexMut<T> for KosMatrix
where
    T: std::slice::SliceIndex<[u8]>,
{
    fn index_mut(&mut self, index: T) -> &mut Self::Output {
        &mut self.inner[index]
    }
}

#[derive(Debug, Error, PartialEq)]
pub enum Error {
    #[error("Can not initialize as matrix with given parameters")]
    Initialize,
    #[error("Error during transpose: {0}")]
    Transpose(#[source] matrix_transpose::TransposeError),
    #[error("Invalid number of rows")]
    InvalidNumberOfRows,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gen_vec(n: u8) -> Vec<u8> {
        (0..n).collect()
    }

    #[test]
    fn test_byte_matrix_new() {
        let inner = gen_vec(12);
        let _matrix = KosMatrix::new(inner, 3).unwrap();
        assert!(true);
    }

    #[test]
    fn test_byte_matrix_new_panic() {
        let inner = gen_vec(12);
        let matrix_empty = KosMatrix::new(vec![], 7).unwrap_err();
        let matrix_remainder = KosMatrix::new(inner, 7).unwrap_err();
        assert_eq!(matrix_empty, Error::Initialize);
        assert_eq!(matrix_remainder, Error::Initialize);
    }

    #[test]
    fn test_byte_matrix_getters() {
        let inner = gen_vec(12);
        let matrix = KosMatrix::new(inner, 3).unwrap();
        assert_eq!(matrix.columns(), 3);
        assert_eq!(matrix.rows(), 4);
        assert_eq!(matrix.len(), 12);
    }

    #[test]
    fn test_byte_matrix_transpose() {
        let inner = gen_vec(128);
        let mut matrix = KosMatrix::new(inner, 8).unwrap();
        matrix.transpose_bits().unwrap();
        assert_eq!(matrix.columns(), 2);
        assert_eq!(matrix.rows(), 64);
    }

    #[test]
    fn test_byte_matrix_split() {
        let inner = gen_vec(12);
        let mut matrix = KosMatrix::new(inner, 4).unwrap();
        let split_matrix = matrix.split_off_rows(1).unwrap();
        assert_eq!(matrix.len(), 4);
        assert_eq!(split_matrix.len(), 8);

        assert_eq!(matrix.rows(), 1);
        assert_eq!(split_matrix.rows(), 2);

        assert_eq!(matrix.columns(), 4);
        assert_eq!(split_matrix.columns(), 4);

        assert_eq!(matrix.inner(), &(0..4).collect::<Vec<u8>>());
        assert_eq!(split_matrix.inner(), &(4..12).collect::<Vec<u8>>());
    }

    #[test]
    fn test_byte_matrix_split_reverse() {
        let inner = gen_vec(12);
        let mut matrix = KosMatrix::new(inner, 4).unwrap();
        let split_matrix = matrix.split_off_rows_reverse(1).unwrap();
        assert_eq!(matrix.len(), 8);
        assert_eq!(split_matrix.len(), 4);

        assert_eq!(matrix.rows(), 2);
        assert_eq!(split_matrix.rows(), 1);

        assert_eq!(matrix.columns(), 4);
        assert_eq!(split_matrix.columns(), 4);

        assert_eq!(matrix.inner(), &(4..12).collect::<Vec<u8>>());
        assert_eq!(split_matrix.inner(), &(0..4).collect::<Vec<u8>>());
    }
}
