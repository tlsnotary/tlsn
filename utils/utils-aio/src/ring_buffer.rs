use futures::{
    task::{AtomicWaker, Context, Poll},
    AsyncRead, AsyncWrite,
};
use std::{
    io::{Error, Read, Write},
    pin::Pin,
    sync::atomic::AtomicUsize,
};

#[derive(Debug)]
pub struct RingBuffer {
    buffer: Vec<u8>,
    read_mark: AtomicUsize,
    write_mark: AtomicUsize,
    read_waker: AtomicWaker,
    write_waker: AtomicWaker,
}

impl RingBuffer {
    pub fn new(size: usize) -> Self {
        let optimized_size = size.next_power_of_two();
        Self {
            buffer: vec![0; optimized_size],
            read_mark: AtomicUsize::new(0),
            write_mark: AtomicUsize::new(0),
            read_waker: AtomicWaker::new(),
            write_waker: AtomicWaker::new(),
        }
    }

    unsafe fn raw_mut(&self) -> &mut [u8] {
        unsafe {
            let slice_start = self.buffer.as_ptr() as *mut u8;
            std::slice::from_raw_parts_mut(slice_start, self.buffer.len())
        }
    }

    fn compute_new_read_mark(&self, max: usize) -> Result<(usize, usize, usize), BufferError> {
        let read_mark = self.read_mark.load(std::sync::atomic::Ordering::Relaxed);
        let write_mark = self.write_mark.load(std::sync::atomic::Ordering::Relaxed);

        if read_mark == write_mark {
            return Err(BufferError::NoProgress);
        }

        let distance = self.compute_distance(read_mark, write_mark, max);
        let new_mark = (read_mark + distance) & (self.buffer.len() - 1);

        Ok((read_mark, new_mark, distance))
    }

    fn compute_new_write_mark(&self, max: usize) -> Result<(usize, usize, usize), BufferError> {
        let write_mark = self.write_mark.load(std::sync::atomic::Ordering::Relaxed);
        let read_mark = self.read_mark.load(std::sync::atomic::Ordering::Relaxed);

        if (write_mark + 1) & (self.buffer.len() - 1) == read_mark {
            return Err(BufferError::NoProgress);
        }

        let mut distance = self.compute_distance(write_mark, read_mark, max);
        let mut new_mark = (write_mark + distance) & (self.buffer.len() - 1);

        if new_mark == read_mark {
            distance -= 1;
            new_mark = (write_mark + distance) & (self.buffer.len() - 1);
        }

        Ok((write_mark, new_mark, distance))
    }

    fn compute_distance(&self, mark_to_increment: usize, until_mark: usize, max: usize) -> usize {
        let mut distance = mark_to_increment.abs_diff(until_mark);
        if until_mark <= mark_to_increment {
            distance = self.buffer.len() - distance;
        }
        std::cmp::min(distance, max)
    }
}

impl AsyncWrite for &RingBuffer {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        let byte_buffer = Pin::into_inner(self);
        byte_buffer.write_waker.register(cx.waker());

        match Write::write(byte_buffer, buf) {
            Ok(len) => {
                byte_buffer.read_waker.wake();
                Poll::Ready(Ok(len))
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => Poll::Pending,
            _ => unreachable!(),
        }
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for RingBuffer {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        Pin::new(&mut (&*self)).poll_write(cx, buf)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(&mut (&*self)).poll_close(cx)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(&mut (&*self)).poll_flush(cx)
    }
}

impl Write for &RingBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self.compute_new_write_mark(buf.len()) {
            Ok((old_mark, new_mark, len)) => {
                let buffer = unsafe { self.raw_mut() };
                let buffer_len = buffer.len();
                if old_mark + len <= buffer_len {
                    _ = (&mut buffer[old_mark..old_mark + len]).write(buf);
                } else {
                    _ = (&mut buffer[old_mark..]).write(buf);
                    _ = (&mut buffer[..len - (buffer_len - old_mark)])
                        .write(&buf[buffer_len - old_mark..]);
                }
                self.write_mark
                    .store(new_mark, std::sync::atomic::Ordering::Relaxed);
                Ok(len)
            }
            Err(BufferError::NoProgress) => Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "No progress was made",
            )),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Write for RingBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        (&*self).write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl AsyncRead for &RingBuffer {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, Error>> {
        let byte_buffer = Pin::into_inner(self);
        byte_buffer.read_waker.register(cx.waker());

        match Read::read(byte_buffer, buf) {
            Ok(len) => {
                byte_buffer.write_waker.wake();
                Poll::Ready(Ok(len))
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => Poll::Pending,
            _ => unreachable!(),
        }
    }
}

impl AsyncRead for RingBuffer {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, Error>> {
        Pin::new(&mut (&*self)).poll_read(cx, buf)
    }
}

impl Read for &RingBuffer {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let buffer = &self.buffer;
        match self.compute_new_read_mark(buf.len()) {
            Ok((old_mark, new_mark, len)) => {
                if old_mark + len <= buffer.len() {
                    _ = (&buffer[old_mark..old_mark + len]).read(buf);
                } else {
                    _ = (&buffer[old_mark..]).read(buf);
                    _ = (&buffer[..len - (buffer.len() - old_mark)])
                        .read(&mut buf[buffer.len() - old_mark..]);
                }
                self.read_mark
                    .store(new_mark, std::sync::atomic::Ordering::Relaxed);
                Ok(len)
            }
            Err(BufferError::NoProgress) => Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "No progress was made",
            )),
        }
    }
}

impl Read for RingBuffer {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        (&*self).read(buf)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BufferError {
    #[error("No progress was made")]
    NoProgress,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    #[test]
    fn test_ring_buffer_write_longer_input() {
        let mut buffer = RingBuffer::new(256);
        let input = vec![1; 512];
        let result = buffer.write(&input);

        assert_eq!(buffer.read_mark.load(Ordering::SeqCst), 0);
        assert_eq!(buffer.write_mark.load(Ordering::SeqCst), 255);
        assert_eq!(buffer.buffer, [vec![1; 255], vec![0]].concat());
        assert!(matches!(result, Ok(255)));
    }

    #[test]
    fn test_ring_buffer_write_shorter_input() {
        let mut buffer = RingBuffer::new(256);
        let input = vec![1; 30];
        let result = buffer.write(&input);

        assert_eq!(buffer.read_mark.load(Ordering::SeqCst), 0);
        assert_eq!(buffer.write_mark.load(Ordering::SeqCst), 30);
        assert_eq!(buffer.buffer, [vec![1; 30], vec![0; 226]].concat().to_vec());
        assert!(matches!(result, Ok(30)));
    }

    #[test]
    fn test_ring_buffer_read_longer_output() {
        let mut buffer = RingBuffer::new(256);
        buffer.buffer = vec![1; 256];
        buffer.write_mark.store(255, Ordering::SeqCst);

        let mut output = vec![0; 512];

        let result = buffer.read(&mut output);

        assert_eq!(buffer.read_mark.load(Ordering::SeqCst), 255);
        assert_eq!(buffer.write_mark.load(Ordering::SeqCst), 255);
        assert_eq!(output, [vec![1; 255], vec![0; 257]].concat().to_vec());
        assert!(matches!(result, Ok(255)));
    }

    #[test]
    fn test_ring_buffer_read_shorter_output() {
        let mut buffer = RingBuffer::new(256);
        buffer.buffer = vec![1; 256];
        buffer.write_mark.store(255, Ordering::SeqCst);

        let mut output = vec![0; 30];
        let result = buffer.read(&mut output);

        assert_eq!(buffer.read_mark.load(Ordering::SeqCst), 30);
        assert_eq!(buffer.write_mark.load(Ordering::SeqCst), 255);
        assert_eq!(output, vec![1; 30]);
        assert!(matches!(result, Ok(30)));
    }

    #[test]
    fn test_ring_buffer_read_write_long_repeatd() {
        let input = (0..=255).collect::<Vec<u8>>();
        let mut output = vec![0; 256];

        let buffer = RingBuffer::new(128);

        let mut read_mark = 0;
        let mut write_mark = 0;
        loop {
            write_mark += (&buffer).write(&input[write_mark..]).unwrap();
            read_mark += (&buffer).read(&mut output[read_mark..]).unwrap();
            if write_mark == input.len() {
                break;
            }
        }
        assert_eq!(input, output);
    }

    #[test]
    fn test_ring_buffer_read_write_short_repeated() {
        let input = (0..64).collect::<Vec<u8>>();
        let mut output = vec![0; 64];

        let buffer = RingBuffer::new(128);

        let mut read_mark = 0;
        let mut write_mark = 0;
        loop {
            write_mark += (&buffer).write(&input[write_mark..]).unwrap();
            read_mark += (&buffer).read(&mut output[read_mark..]).unwrap();
            if write_mark == input.len() {
                break;
            }
        }
        assert_eq!(input, output);
    }

    #[test]
    fn test_ring_buffer_multi_thread_long() {
        let input = (0..=255).collect::<Vec<u8>>();
        let mut output = vec![0; 256];
        let buffer = RingBuffer::new(128);

        std::thread::scope(|s| {
            s.spawn(|| {
                let mut write_counter = 0;
                loop {
                    match (&buffer).write(&input[write_counter..]) {
                        Ok(len) => write_counter += len,
                        Err(_) => continue,
                    }
                    if write_counter == input.len() {
                        break;
                    }
                }
            });
            s.spawn(|| {
                let mut read_counter = 0;
                loop {
                    match (&buffer).read(&mut output[read_counter..]) {
                        Ok(len) => read_counter += len,
                        Err(_) => continue,
                    }
                    if read_counter == output.len() {
                        break;
                    }
                }
            });
        });
        assert_eq!(input, output);
    }

    #[test]
    fn test_ring_buffer_multi_thread_short() {
        let input = (0..64).collect::<Vec<u8>>();
        let mut output = vec![0; 64];
        let buffer = RingBuffer::new(128);

        std::thread::scope(|s| {
            s.spawn(|| {
                let mut write_counter = 0;
                loop {
                    match (&buffer).write(&input[write_counter..]) {
                        Ok(len) => write_counter += len,
                        Err(_) => continue,
                    }
                    if write_counter == input.len() {
                        break;
                    }
                }
            });
            s.spawn(|| {
                let mut read_counter = 0;
                loop {
                    match (&buffer).read(&mut output[read_counter..]) {
                        Ok(len) => read_counter += len,
                        Err(_) => continue,
                    }
                    if read_counter == output.len() {
                        break;
                    }
                }
            });
        });
        assert_eq!(input, output);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_ring_buffer_async_long() {
        let input = (0..=255).collect::<Vec<u8>>();
        let mut output = vec![0; 256];
        let mut buffer: &'static RingBuffer = Box::leak(Box::new(RingBuffer::new(128)));

        let fut_write = tokio::spawn(async move {
            let mut write_mark = 0;
            loop {
                match futures::AsyncWriteExt::write(&mut buffer, &input[write_mark..]).await {
                    Ok(len) => write_mark += len,
                    Err(_) => continue,
                }
                if write_mark == input.len() {
                    break input;
                }
            }
        });

        let fut_read = tokio::spawn(async move {
            let mut read_mark = 0;
            loop {
                match futures::AsyncReadExt::read(&mut buffer, &mut output[read_mark..]).await {
                    Ok(len) => read_mark += len,
                    Err(_) => continue,
                }
                if read_mark == output.len() {
                    break output;
                }
            }
        });
        let (input, output) = tokio::try_join!(fut_write, fut_read).unwrap();
        assert_eq!(input, output);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_ring_buffer_async_short() {
        let input = (0..64).collect::<Vec<u8>>();
        let mut output = vec![0; 64];
        let mut buffer: &'static RingBuffer = Box::leak(Box::new(RingBuffer::new(128)));

        let fut_write = tokio::spawn(async move {
            let mut write_mark = 0;
            loop {
                match futures::AsyncWriteExt::write(&mut buffer, &input[write_mark..]).await {
                    Ok(len) => write_mark += len,
                    Err(_) => continue,
                }
                if write_mark == input.len() {
                    break input;
                }
            }
        });

        let fut_read = tokio::spawn(async move {
            let mut read_mark = 0;
            loop {
                match futures::AsyncReadExt::read(&mut buffer, &mut output[read_mark..]).await {
                    Ok(len) => read_mark += len,
                    Err(_) => continue,
                }
                if read_mark == output.len() {
                    break output;
                }
            }
        });
        let (input, output) = tokio::try_join!(fut_write, fut_read).unwrap();
        assert_eq!(input, output);
    }
}
