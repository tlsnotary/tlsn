//! Regression test for the mpz `Context::map` concurrency bound
//! (privacy-ethereum/mpz#403): mapping over N items must open at most
//! `DEFAULT_CONCURRENCY_LIMIT` mux streams at once, not one per item. Before
//! #403 this grew unbounded with the transcript size and aborted preprocessing
//! with `TooManyStreams`. tlsn's executor relies on this bound.

use std::{
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context as TaskContext, Poll},
};

use futures::{AsyncRead, AsyncWrite};
use mpz_common::{Session, context::DEFAULT_CONCURRENCY_LIMIT, io::Io, mux::Mux};

#[derive(Clone, Default)]
struct Counter {
    live: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
}

/// A mux whose streams track the number of concurrently open streams.
struct CountingMux(Counter);

impl Mux for CountingMux {
    fn open(&self, _id: &[u8]) -> Result<Io, std::io::Error> {
        let live = self.0.live.fetch_add(1, Ordering::Relaxed) + 1;
        self.0.peak.fetch_max(live, Ordering::Relaxed);
        Ok(Io::from_io(CountingStream(self.0.live.clone())))
    }
}

/// A no-op stream that decrements the live count when dropped. The map closure
/// performs no IO, so the read/write impls are never exercised.
struct CountingStream(Arc<AtomicUsize>);

impl Drop for CountingStream {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

impl AsyncRead for CountingStream {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut TaskContext<'_>,
        _: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        Poll::Ready(Ok(0))
    }
}

impl AsyncWrite for CountingStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn test_streams_bounded() {
    // Far more items than the limit: an unbounded map would open N streams.
    const N: usize = 1000;

    let counter = Counter::default();
    // Built like tlsn's executor (default concurrency limit); `cooperative`
    // avoids a thread pool while exercising the same `buffered` bound.
    let session = Session::builder()
        .cooperative()
        .build(CountingMux(counter.clone()))
        .unwrap();
    let mut ctx = session.new_context().unwrap();

    // The context's own channel is one open stream; map's children stack on it.
    let baseline = counter.live.load(Ordering::Relaxed);

    let items: Vec<usize> = (0..N).collect();
    let results = ctx
        .map(items, |_ctx, i| {
            // Yield so the `buffered` window fills before any item completes.
            Box::pin(async move {
                tokio::task::yield_now().await;
                i
            })
        })
        .await
        .unwrap();

    let peak = counter.peak.load(Ordering::Relaxed);
    assert_eq!(results.len(), N);
    assert!(peak > baseline, "map should run items concurrently (peak {peak})");
    assert!(
        peak <= baseline + DEFAULT_CONCURRENCY_LIMIT,
        "peak {peak} exceeds the bound; map concurrency regressed \
         (unbounded would peak at ~{})",
        baseline + N
    );

    drop(ctx);
    assert_eq!(counter.live.load(Ordering::Relaxed), 0, "all streams closed");
}
