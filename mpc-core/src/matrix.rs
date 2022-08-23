use std::slice::{Chunks, ChunksMut};

use matrix_transpose::transpose_bits;
use thiserror::Error;

/// Minimal matrix implementation
///
/// This provides some comfort when dealing with matrices in the KOS15 protocol
#[derive(Debug, Clone)]
pub struct ByteMatrix {
    inner: Vec<u8>,
    rows: usize,
    columns: usize,
}

impl ByteMatrix {
    /// Create a new matrix from a vector of bytes
    ///
    /// Use columns to indicate the row length of the matrix
    pub fn new(bytes: Vec<u8>, columns: usize) -> Result<Self, Error> {
        let length = bytes.len();
        if length % columns != 0 {
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

    /// Returns the number of elements
    pub fn len(&self) -> usize {
        self.inner.len()
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
        let _ = transpose_bits(&mut self.inner, rows).map_err(|err| Error::Transpose(err))?;
        (self.rows, self.columns) = (self.columns * 8, self.rows / 8);
        Ok(())
    }

    /// Splits the byte matrix at the given row index
    pub fn split_off_rows(&mut self, n: usize) -> Result<Self, Error> {
        if n > self.rows() {
            return Err(Error::InvalidNumberOfRows);
        }

        let split_off = n * self.columns();

        let split_vec = self.inner.drain(split_off..).collect();
        let split_matrix = Self {
            inner: split_vec,
            rows: self.rows() - split_off,
            columns: self.columns(),
        };
        self.rows = split_off;
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
            rows: split_off,
            columns: self.columns(),
        };
        self.rows = self.rows() - split_off;
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

impl<T> std::ops::Index<T> for ByteMatrix
where
    T: std::slice::SliceIndex<[u8]>,
{
    type Output = T::Output;

    fn index(&self, index: T) -> &Self::Output {
        &self.inner[index]
    }
}

impl<T> std::ops::IndexMut<T> for ByteMatrix
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
