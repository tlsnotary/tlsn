//! Provides [`DuplexStream`].

use bytes::{Buf, BufMut, BytesMut};
use std::{
    io::{Read, Write},
    sync::{Arc, Mutex},
};

/// A sync duplex byte stream.
///
/// Use [`duplex`] function to create two handles of [`DuplexStream`], which
/// behave like a sync pipe for reading and writing bytes. Implements
/// [`std::io::Read`] and [`std::io::Write`].
#[derive(Debug)]
pub(crate) struct DuplexStream {
    read: ReadHalf<SimplexStream>,
    write: WriteHalf<SimplexStream>,
    is_closed: Arc<Mutex<bool>>,
}

impl DuplexStream {
    /// Returns if the stream has been closed.
    pub(crate) fn is_closed(&self) -> bool {
        *self
            .is_closed
            .lock()
            .expect("should be able to acquire lock")
    }

    /// Closes the stream.
    pub(crate) fn close(&mut self) {
        let mut is_closed = self
            .is_closed
            .lock()
            .expect("should be able to acquire lock");
        *is_closed = true;
    }

    /// Returns if the stream has new data available.
    pub(crate) fn wants_write(&self) -> bool {
        self.read.can_read_from()
    }

    /// Returns if new data can be written to the stream.
    pub(crate) fn can_read(&self) -> bool {
        self.write.can_write_to()
    }
}

impl Drop for DuplexStream {
    fn drop(&mut self) {
        let mut is_closed = self
            .is_closed
            .lock()
            .expect("should be able to acquire lock");
        *is_closed = true;
    }
}

/// Create a new pair of `DuplexStream`s that act like a pair of connected
/// sockets.
///
/// The `max_buf_size` argument is the maximum amount of bytes that can be
/// written to a side.
pub(crate) fn duplex(max_buf_size: usize) -> (DuplexStream, DuplexStream) {
    let (read_0, write_0) = simplex(max_buf_size);
    let (read_1, write_1) = simplex(max_buf_size);
    let is_closed = Arc::new(Mutex::new(false));

    (
        DuplexStream {
            read: read_0,
            write: write_1,
            is_closed: Arc::clone(&is_closed),
        },
        DuplexStream {
            read: read_1,
            write: write_0,
            is_closed,
        },
    )
}

impl Read for DuplexStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.read.read(buf)
    }
}

impl Write for DuplexStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.write.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.write.flush()
    }
}

#[derive(Debug)]
pub(crate) struct ReadHalf<T>(Arc<Mutex<T>>);

impl ReadHalf<SimplexStream> {
    fn can_read_from(&self) -> bool {
        let inner = self.0.lock().expect("should be able to acquire lock");
        inner.has_remaining()
    }
}

impl<T: Read> Read for ReadHalf<T> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut inner = self
            .0
            .lock()
            .map_err(|err| std::io::Error::other(err.to_string()))?;
        inner.read(buf)
    }
}

#[derive(Debug)]
pub(crate) struct WriteHalf<T>(Arc<Mutex<T>>);

impl WriteHalf<SimplexStream> {
    fn can_write_to(&self) -> bool {
        let inner = self.0.lock().expect("should be able to acquire lock");
        inner.has_remaining_mut()
    }
}

impl<T: Write> Write for WriteHalf<T> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut inner = self
            .0
            .lock()
            .map_err(|err| std::io::Error::other(err.to_string()))?;
        inner.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let mut inner = self
            .0
            .lock()
            .map_err(|err| std::io::Error::other(err.to_string()))?;
        inner.flush()
    }
}

#[derive(Debug)]
struct SimplexStream {
    max_buf_size: usize,
    /// The buffer storing the bytes written, also read from.
    buffer: BytesMut,
}

fn simplex(max_buf_size: usize) -> (ReadHalf<SimplexStream>, WriteHalf<SimplexStream>) {
    let stream = SimplexStream::new_unsplit(max_buf_size);
    let stream = Arc::new(Mutex::new(stream));

    let read = ReadHalf(stream.clone());
    let write = WriteHalf(stream);

    (read, write)
}

impl SimplexStream {
    /// Creates unidirectional buffer that acts like in memory pipe. To create
    /// split version with separate reader and writer you can use
    /// [`simplex`] function.
    ///
    /// The `max_buf_size` argument is the maximum amount of bytes that can be
    /// written to a buffer.
    fn new_unsplit(max_buf_size: usize) -> SimplexStream {
        SimplexStream {
            max_buf_size,
            buffer: BytesMut::new(),
        }
    }

    fn has_remaining(&self) -> bool {
        self.buffer.has_remaining()
    }

    fn has_remaining_mut(&self) -> bool {
        self.buffer.has_remaining_mut()
    }
}

impl Read for SimplexStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let len = self.buffer.remaining().min(buf.len());
        buf[..len].copy_from_slice(&self.buffer[..len]);
        self.buffer.advance(len);

        Ok(len)
    }
}

impl Write for SimplexStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let avail = self.max_buf_size - self.buffer.len();
        let len = buf.len().min(avail);
        self.buffer.extend_from_slice(&buf[..len]);

        Ok(len)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
