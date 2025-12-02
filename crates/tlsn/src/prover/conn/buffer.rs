//! Simple buffer implementation.

use crate::prover::conn::BUF_CAP;
use bytes::{Buf, BufMut, BytesMut};

pub(crate) struct SimpleBuffer {
    buf: BytesMut,
}

impl Default for SimpleBuffer {
    fn default() -> Self {
        Self {
            buf: BytesMut::with_capacity(BUF_CAP),
        }
    }
}

impl SimpleBuffer {
    /// Returns the underlying parts of the buffer which has not yet been
    /// consumed.
    pub(crate) fn inner(&self) -> &[u8] {
        &self.buf
    }

    /// Marks bytes as consumed.
    ///
    /// # Arguments
    ///
    /// * `n` - How many bytes to mark consumed.
    pub(crate) fn consume(&mut self, n: usize) {
        self.buf.advance(n);
    }

    /// Appends bytes to the end of the buffer.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The byte slice to append.
    pub(crate) fn extend(&mut self, bytes: &[u8]) {
        self.buf.put_slice(bytes);
    }

    /// Returns the number of consumable bytes.
    pub(crate) fn len(&self) -> usize {
        self.buf.len()
    }
}
