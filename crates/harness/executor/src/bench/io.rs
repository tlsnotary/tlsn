use std::{
    io::{IoSlice, Result},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
};

use futures::{AsyncRead, AsyncWrite};
use pin_project_lite::pin_project;
use web_time::Instant;

#[derive(Clone, Debug)]
pub(crate) struct MeterStats {
    sent: Arc<AtomicU64>,
    recv: Arc<AtomicU64>,
    read_wait_ns: Arc<AtomicU64>,
    write_wait_ns: Arc<AtomicU64>,
}

impl MeterStats {
    fn new() -> Self {
        Self {
            sent: Arc::new(AtomicU64::new(0)),
            recv: Arc::new(AtomicU64::new(0)),
            read_wait_ns: Arc::new(AtomicU64::new(0)),
            write_wait_ns: Arc::new(AtomicU64::new(0)),
        }
    }

    pub(crate) fn snapshot(&self) -> MeterSnapshot {
        MeterSnapshot {
            sent: self.sent.load(Ordering::Relaxed),
            recv: self.recv.load(Ordering::Relaxed),
            read_wait_ns: self.read_wait_ns.load(Ordering::Relaxed),
            write_wait_ns: self.write_wait_ns.load(Ordering::Relaxed),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct MeterSnapshot {
    pub(crate) sent: u64,
    pub(crate) recv: u64,
    pub(crate) read_wait_ns: u64,
    pub(crate) write_wait_ns: u64,
}

pin_project! {
    pub(crate) struct Meter<Io> {
        stats: MeterStats,
        pending_read: Option<Instant>,
        pending_write: Option<Instant>,
        pending_write_vectored: Option<Instant>,
        pending_flush: Option<Instant>,
        #[pin] io: Io,
    }
}

impl<Io> Meter<Io> {
    pub(crate) fn new(io: Io) -> Self {
        Self {
            stats: MeterStats::new(),
            pending_read: None,
            pending_write: None,
            pending_write_vectored: None,
            pending_flush: None,
            io,
        }
    }

    pub(crate) fn stats(&self) -> MeterStats {
        self.stats.clone()
    }
}

fn wait_started_at(slot: &mut Option<Instant>) {
    if slot.is_none() {
        *slot = Some(Instant::now());
    }
}

fn finish_wait(slot: &mut Option<Instant>, counter: &AtomicU64) {
    if let Some(started_at) = slot.take() {
        counter.fetch_add(duration_to_ns(started_at.elapsed()), Ordering::Relaxed);
    }
}

fn duration_to_ns(duration: std::time::Duration) -> u64 {
    duration.as_nanos().min(u64::MAX as u128) as u64
}

impl<Io> AsyncWrite for Meter<Io>
where
    Io: AsyncWrite,
{
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize>> {
        let mut this = self.project();
        match this.io.as_mut().poll_write(cx, buf) {
            Poll::Pending => {
                wait_started_at(this.pending_write);
                Poll::Pending
            }
            Poll::Ready(result) => {
                finish_wait(this.pending_write, &this.stats.write_wait_ns);

                Poll::Ready(result.map(|n| {
                    this.stats.sent.fetch_add(n as u64, Ordering::Relaxed);
                    n
                }))
            }
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<Result<usize>> {
        let mut this = self.project();
        match this.io.as_mut().poll_write_vectored(cx, bufs) {
            Poll::Pending => {
                wait_started_at(this.pending_write_vectored);
                Poll::Pending
            }
            Poll::Ready(result) => {
                finish_wait(this.pending_write_vectored, &this.stats.write_wait_ns);

                Poll::Ready(result.map(|n| {
                    this.stats.sent.fetch_add(n as u64, Ordering::Relaxed);
                    n
                }))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        let mut this = self.project();
        match this.io.as_mut().poll_flush(cx) {
            Poll::Pending => {
                wait_started_at(this.pending_flush);
                Poll::Pending
            }
            Poll::Ready(result) => {
                finish_wait(this.pending_flush, &this.stats.write_wait_ns);
                Poll::Ready(result)
            }
        }
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        self.project().io.poll_close(cx)
    }
}

impl<Io> AsyncRead for Meter<Io>
where
    Io: AsyncRead,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize>> {
        let mut this = self.project();
        match this.io.as_mut().poll_read(cx, buf) {
            Poll::Pending => {
                wait_started_at(this.pending_read);
                Poll::Pending
            }
            Poll::Ready(result) => {
                finish_wait(this.pending_read, &this.stats.read_wait_ns);

                Poll::Ready(result.map(|n| {
                    this.stats.recv.fetch_add(n as u64, Ordering::Relaxed);
                    n
                }))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, io, thread, time::Duration};

    use futures::task::noop_waker;

    use super::*;

    fn ready<T>(poll: Poll<io::Result<T>>) -> T {
        match poll {
            Poll::Ready(Ok(value)) => value,
            Poll::Ready(Err(err)) => panic!("unexpected io error: {err}"),
            Poll::Pending => panic!("operation should be ready"),
        }
    }

    #[derive(Default)]
    struct ScriptedIo {
        reads: VecDeque<ReadStep>,
        writes: VecDeque<Step<usize>>,
        vectored_writes: VecDeque<Step<usize>>,
        flushes: VecDeque<Step<()>>,
    }

    enum ReadStep {
        Pending,
        Ready(Vec<u8>),
    }

    enum Step<T> {
        Pending,
        Ready(T),
    }

    impl AsyncWrite for ScriptedIo {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            match self.writes.pop_front().expect("write step should exist") {
                Step::Pending => Poll::Pending,
                Step::Ready(n) => Poll::Ready(Ok(n)),
            }
        }

        fn poll_write_vectored(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _bufs: &[IoSlice<'_>],
        ) -> Poll<io::Result<usize>> {
            match self
                .vectored_writes
                .pop_front()
                .expect("vectored write step should exist")
            {
                Step::Pending => Poll::Pending,
                Step::Ready(n) => Poll::Ready(Ok(n)),
            }
        }

        fn poll_flush(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            match self.flushes.pop_front().expect("flush step should exist") {
                Step::Pending => Poll::Pending,
                Step::Ready(()) => Poll::Ready(Ok(())),
            }
        }

        fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncRead for ScriptedIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            match self.reads.pop_front().expect("read step should exist") {
                ReadStep::Pending => Poll::Pending,
                ReadStep::Ready(bytes) => {
                    buf[..bytes.len()].copy_from_slice(&bytes);
                    Poll::Ready(Ok(bytes.len()))
                }
            }
        }
    }

    #[test]
    fn meter_preserves_byte_counters() {
        let io = ScriptedIo {
            reads: VecDeque::from([ReadStep::Ready(vec![1, 2, 3, 4])]),
            writes: VecDeque::from([Step::Ready(3)]),
            vectored_writes: VecDeque::from([Step::Ready(5)]),
            flushes: VecDeque::from([Step::Ready(())]),
        };
        let mut meter = Meter::new(io);
        let stats = meter.stats();
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let _ = ready(Pin::new(&mut meter).poll_write(&mut cx, b"abcdef"));

        let bufs = [IoSlice::new(b"ab"), IoSlice::new(b"cdefg")];
        let _ = ready(Pin::new(&mut meter).poll_write_vectored(&mut cx, &bufs));

        let mut buf = [0u8; 8];
        let _ = ready(Pin::new(&mut meter).poll_read(&mut cx, &mut buf));

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.sent, 8);
        assert_eq!(snapshot.recv, 4);
    }

    #[test]
    fn meter_accumulates_pending_ready_wait_time() {
        let io = ScriptedIo {
            reads: VecDeque::from([ReadStep::Pending, ReadStep::Ready(vec![1])]),
            writes: VecDeque::from([Step::Pending, Step::Ready(1)]),
            vectored_writes: VecDeque::from([Step::Pending, Step::Ready(2)]),
            flushes: VecDeque::from([Step::Pending, Step::Ready(())]),
        };
        let mut meter = Meter::new(io);
        let stats = meter.stats();
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(Pin::new(&mut meter).poll_write(&mut cx, b"x").is_pending());
        thread::sleep(Duration::from_millis(2));
        let _ = ready(Pin::new(&mut meter).poll_write(&mut cx, b"x"));

        let bufs = [IoSlice::new(b"x"), IoSlice::new(b"y")];
        assert!(Pin::new(&mut meter)
            .poll_write_vectored(&mut cx, &bufs)
            .is_pending());
        thread::sleep(Duration::from_millis(2));
        let _ = ready(Pin::new(&mut meter).poll_write_vectored(&mut cx, &bufs));

        assert!(Pin::new(&mut meter).poll_flush(&mut cx).is_pending());
        thread::sleep(Duration::from_millis(2));
        ready(Pin::new(&mut meter).poll_flush(&mut cx));

        let mut buf = [0u8; 1];
        assert!(Pin::new(&mut meter)
            .poll_read(&mut cx, &mut buf)
            .is_pending());
        thread::sleep(Duration::from_millis(2));
        let _ = ready(Pin::new(&mut meter).poll_read(&mut cx, &mut buf));

        let snapshot = stats.snapshot();
        assert!(snapshot.write_wait_ns > 0);
        assert!(snapshot.read_wait_ns > 0);
        assert_eq!(snapshot.sent, 3);
        assert_eq!(snapshot.recv, 1);
    }
}
