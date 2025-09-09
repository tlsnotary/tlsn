use std::{
    pin::pin,
    task::{Context as StdContext, Poll},
};

use futures::{AsyncRead, AsyncWrite};
use tlsn::prover::TlsConnection;

use crate::{Error, instance::Context};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct IoId(pub usize);

pub struct IoInstance {
    conn: TlsConnection,
    write_buf: Buf,
    wants_write_close: bool,
    write_closed: bool,
    read_buf: Buf,
    read_closed: bool,
    wants_write: bool,
    wants_read: bool,
}

impl IoInstance {
    pub(crate) fn new(conn: TlsConnection) -> Self {
        const BUF_SIZE: usize = 8192;
        Self {
            conn,
            write_buf: Buf::new(BUF_SIZE),
            wants_write_close: false,
            write_closed: false,
            read_buf: Buf::new(BUF_SIZE),
            read_closed: false,
            wants_write: false,
            wants_read: false,
        }
    }

    pub fn check_write(&mut self, cx: &mut Context) -> Poll<Result<usize, std::io::Error>> {
        if self.write_closed {
            return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
        }

        match self.write_buf.remaining_mut() {
            0 => {
                self.wants_write = true;
                cx.waker.set_wake();
                Poll::Pending
            }
            n => Poll::Ready(Ok(n)),
        }
    }

    pub fn write(&mut self, buf: &[u8]) -> Result<(), std::io::Error> {
        if self.write_closed {
            return Err(std::io::ErrorKind::BrokenPipe.into());
        }

        let remaining_capacity = self.write_buf.remaining_mut();
        if buf.len() > remaining_capacity {
            todo!()
        }

        let n = buf.len().min(remaining_capacity);

        self.write_buf.chunk_mut()[..n].copy_from_slice(&buf[..n]);
        self.write_buf.advance_mut(n);

        self.wants_write = false;

        Ok(())
    }

    pub fn flush(&mut self) -> Result<(), std::io::Error> {
        Ok(())
    }

    pub fn available(&self) -> usize {
        self.read_buf.remaining()
    }

    pub fn read_closed(&self) -> bool {
        self.read_closed
    }

    pub fn read(&mut self, len: usize, cx: &mut Context) -> Poll<Result<Vec<u8>, std::io::Error>> {
        let chunk = self.read_buf.chunk();
        let available = chunk.len();

        if available == 0 && !self.read_closed {
            self.wants_read = true;
            cx.waker.set_wake();
            return Poll::Pending;
        }

        let len = available.min(len);
        let out = chunk[..len].to_vec();
        self.read_buf.advance(len);

        self.wants_read = false;

        Poll::Ready(Ok(out))
    }

    pub fn close(&mut self, cx: &mut Context) -> Poll<Result<(), std::io::Error>> {
        if self.write_closed {
            Poll::Ready(Ok(()))
        } else {
            self.wants_write_close = true;
            cx.waker.set_wake();
            Poll::Pending
        }
    }

    pub fn poll(
        &mut self,
        cx_std: &mut StdContext<'_>,
        cx: &mut Context,
    ) -> Poll<Result<(), Error>> {
        while self.read_buf.remaining_mut() > 0 && !self.read_closed {
            if let Poll::Ready(res) =
                pin!(&mut self.conn).poll_read(cx_std, self.read_buf.chunk_mut())
            {
                let n = res.unwrap();
                self.read_buf.advance_mut(n);

                if n == 0 {
                    println!("server closed conn");
                    self.read_closed = true;
                }

                if self.wants_read {
                    cx.waker.set_call();
                }
            } else {
                break;
            }
        }

        while self.write_buf.remaining() > 0 {
            if let Poll::Ready(res) =
                pin!(&mut self.conn).poll_write(cx_std, self.write_buf.chunk())
            {
                let n = res.unwrap();
                println!("prover wrote {n} bytes to server");
                self.write_buf.advance(n);

                if self.wants_write {
                    cx.waker.set_call();
                }
            } else {
                break;
            }
        }

        if self.write_buf.remaining() == 0 && self.wants_write_close && !self.write_closed {
            if let Poll::Ready(res) = pin!(&mut self.conn).poll_close(cx_std) {
                res.unwrap();
                self.write_closed = true;
                if self.wants_write_close {
                    cx.waker.set_call();
                }
                println!("prover closed conn");
            }
        }

        Poll::Pending
    }
}

/// A fixed-size buffer that is guaranteed to be initialized.
pub(crate) struct Buf {
    data: Box<[u8]>,
    len: usize,
    pos: usize,
    cap: usize,
}

impl Buf {
    pub(crate) fn new(size: usize) -> Self {
        // SAFETY: It is critical that memory of the buffer is initialized.
        #[allow(unused_unsafe)]
        let buf = unsafe { vec![0; size].into_boxed_slice() };

        Self {
            data: buf,
            len: 0,
            pos: 0,
            cap: size,
        }
    }

    /// Remaining bytes in the buffer.
    pub(crate) fn remaining(&self) -> usize {
        self.len - self.pos
    }

    /// Returns a reference to the bytes in the buffer.
    pub(crate) fn chunk(&self) -> &[u8] {
        &self.data[self.pos..self.len]
    }

    /// Advance the position of the buffer.
    pub(crate) fn advance(&mut self, cnt: usize) {
        assert!(cnt <= self.remaining(), "advance past end of buffer");
        self.pos += cnt;
        if self.pos == self.len {
            self.pos = 0;
            self.len = 0;
        }
    }

    /// Remaining room in the buffer.
    pub(crate) fn remaining_mut(&self) -> usize {
        self.cap - self.len
    }

    /// Advance the length of the buffer.
    pub(crate) fn advance_mut(&mut self, cnt: usize) {
        assert!(self.len + cnt <= self.cap, "advance past end of buffer");
        self.len += cnt;
    }

    /// Returns a mutable reference to the remaining room in the buffer.
    pub(crate) fn chunk_mut(&mut self) -> &mut [u8] {
        &mut self.data[self.len..]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fixed_buf() {
        let mut buf = Buf::new(10);

        assert_eq!(buf.remaining(), 0);
        assert_eq!(buf.remaining_mut(), 10);
        assert_eq!(buf.chunk(), &[] as &[u8]);
        assert_eq!(buf.chunk_mut(), &[0; 10]);
    }

    #[test]
    fn test_fixed_buf_advance() {
        let mut buf = Buf::new(10);

        buf.advance_mut(5);
        assert_eq!(buf.remaining_mut(), 5);
        assert_eq!(buf.remaining(), 5);

        buf.advance(3);
        assert_eq!(buf.remaining_mut(), 5);
        assert_eq!(buf.remaining(), 2);

        buf.advance(buf.remaining());
        assert_eq!(buf.remaining(), 0);
        // Buffer should reset.
        assert_eq!(buf.remaining_mut(), 10);
    }
}
