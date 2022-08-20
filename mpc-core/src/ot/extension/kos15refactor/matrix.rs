use matrix_transpose::transpose_bits;
use thiserror::Error;

/// Minimal matrix implementation
///
/// This provides some comfort when dealing with matrices in the KOS15 protocol
pub struct ByteMatrix {
    inner: Vec<u8>,
    rows: usize,
    columns: usize,
}

impl ByteMatrix {
    /// Create a new matrix from a vector of bytes
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

    /// Transpose bitwise
    ///
    /// The matrix is treated as a matrix of bits, then transposed and again encoded as a byte
    /// matrix
    pub fn transpose_bits(&mut self) -> Result<(), Error> {
        let _ =
            transpose_bits(&mut self.inner, self.rows()).map_err(|err| Error::Transpose(err))?;
        (self.rows, self.columns) = (self.columns * 8, self.rows / 8);
        Ok(())
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

#[derive(Debug, Error)]
pub enum Error {
    #[error("Can not initialize as matrix with given parameters")]
    Initialize,
    #[error("Error during transpose: {0}")]
    Transpose(#[source] matrix_transpose::TransposeError),
}
