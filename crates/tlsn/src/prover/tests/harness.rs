use std::{
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
};

use futures::{io::AsyncWrite, task::ArcWake};

/// Counts wake-ups without scheduling any work.
pub(super) struct WakeCounter(AtomicUsize);

impl WakeCounter {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self(AtomicUsize::new(0)))
    }

    /// Returns and resets the number of wake-ups observed.
    pub(super) fn take(&self) -> usize {
        self.0.swap(0, Ordering::Relaxed)
    }
}

impl ArcWake for WakeCounter {
    fn wake_by_ref(arc_self: &Arc<Self>) {
        arc_self.0.fetch_add(1, Ordering::Relaxed);
    }
}

/// Accepts at most `max_write` bytes per poll.
pub(super) struct PartialWriter {
    pub(super) max_write: usize,
    pub(super) written: usize,
}

impl AsyncWrite for PartialWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let written = self.max_write.min(buf.len());
        self.written += written;
        Poll::Ready(Ok(written))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
