//! IO adapters for WASM.
//!
//! This module provides adapters to bridge JavaScript IO streams to Rust's
//! async IO traits.

use std::{
    collections::VecDeque,
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    task::{Context, Poll, Waker},
};

use futures::{AsyncRead, AsyncWrite, Future};
use js_sys::{Promise, Uint8Array};
use wasm_bindgen::{JsCast, prelude::*};
use wasm_bindgen_futures::JsFuture;

/// JavaScript interface for IO channels.
///
/// This is the interface that JavaScript objects must implement to be used
/// as IO streams with the SDK.
#[wasm_bindgen]
extern "C" {
    /// An IO channel from JavaScript.
    #[wasm_bindgen(typescript_type = "IoChannel")]
    pub type JsIo;

    /// Reads bytes from the stream.
    ///
    /// Returns a Promise that resolves to a Uint8Array, or null if EOF.
    #[wasm_bindgen(method, catch)]
    pub fn read(this: &JsIo) -> Result<Promise, JsValue>;

    /// Writes bytes to the stream.
    ///
    /// Returns a Promise that resolves when the write is complete.
    #[wasm_bindgen(method, catch)]
    pub fn write(this: &JsIo, data: &Uint8Array) -> Result<Promise, JsValue>;

    /// Closes the stream.
    ///
    /// Returns a Promise that resolves when the stream is closed.
    #[wasm_bindgen(method, catch)]
    pub fn close(this: &JsIo) -> Result<Promise, JsValue>;

    /// Pushes bytes back to the front of the stream's read queue.
    ///
    /// This method must be synchronous.
    #[wasm_bindgen(method, catch)]
    pub fn unread(this: &JsIo, data: &Uint8Array) -> Result<(), JsValue>;
}

/// TypeScript declaration for the [`JsIo`] interface.
///
/// `typescript_type` only names the type; wasm-bindgen does not derive the
/// shape of an imported JS object, so the interface must be supplied here.
#[wasm_bindgen(typescript_custom_section)]
const IO_CHANNEL: &'static str = r#"
export interface IoChannel {
    read(): Promise<Uint8Array | null>;
    write(data: Uint8Array): Promise<void>;
    close(): Promise<void>;
    unread(data: Uint8Array): void;
}
"#;

/// Internal state for the adapter.
struct AdapterState {
    /// Buffered data from reads.
    read_buffer: VecDeque<u8>,
    /// Whether we've seen EOF.
    eof: bool,
    /// Pending read future.
    pending_read: Option<JsFuture>,
    /// Waker for when data becomes available.
    read_waker: Option<Waker>,
    /// Whether the stream is closed.
    closed: bool,
    /// Any error that occurred.
    error: Option<String>,
}

/// Handle to an adapter's shared read state.
///
/// The wasm prover/verifier retain this so that bytes the adapter buffered
/// beyond what TLSNotary consumed can be returned to the caller's channel
/// once the session finishes.
#[derive(Clone)]
pub(crate) struct AdapterStateHandle(Arc<Mutex<AdapterState>>);

impl AdapterStateHandle {
    /// Drains and returns any bytes that were buffered but never consumed.
    pub(crate) fn take_remainder(&self) -> Vec<u8> {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        // The session driver only completes after its final read has resolved,
        // so a read must never still be in flight when the IO is reclaimed.
        // Were that to change, bytes delivered to `pending_read` would be
        // dropped instead of returned below.
        debug_assert!(
            state.pending_read.is_none(),
            "session IO reclaimed with a read still in flight; bytes would be lost"
        );
        state.read_buffer.drain(..).collect()
    }
}

/// Returns any bytes the adapter over-read back to the original channel.
///
/// TLSNotary may read more from the channel than it consumes while decoding
/// frames; the surplus sits in the adapter. Once the session has released the
/// channel, push those bytes back via `IoChannel.unread` so the caller's next
/// `read()` observes them. Both args are `take()`n, so a second call is a
/// no-op.
///
/// Returns an error if the channel does not implement `unread`, so a channel
/// that would otherwise silently drop over-read bytes is surfaced rather than
/// corrupting the caller's view of the stream.
pub(crate) fn return_over_read_bytes(
    channel: &mut Option<JsValue>,
    remainder: &mut Option<AdapterStateHandle>,
) -> Result<(), JsError> {
    let (Some(channel), Some(remainder)) = (channel.take(), remainder.take()) else {
        return Ok(());
    };

    let bytes = remainder.take_remainder();
    if bytes.is_empty() {
        return Ok(());
    }

    channel
        .unchecked_ref::<JsIo>()
        .unread(&Uint8Array::from(bytes.as_slice()))
        .map_err(|e| {
            JsError::new(&format!(
                "IoChannel must implement unread() to return over-read bytes: {e:?}"
            ))
        })
}

/// Adapter that wraps a JavaScript IoChannel object.
///
/// This adapter implements `AsyncRead` and `AsyncWrite` by calling the
/// JavaScript methods on the underlying object.
pub(crate) struct JsIoAdapter {
    inner: JsIo,
    state: Arc<Mutex<AdapterState>>,
}

impl JsIoAdapter {
    fn lock_state(&self) -> std::io::Result<MutexGuard<'_, AdapterState>> {
        self.state.lock().map_err(|e: PoisonError<_>| {
            std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
        })
    }

    /// Creates a new adapter wrapping the given JavaScript IO object.
    pub(crate) fn new(js_io: JsIo) -> Self {
        Self {
            inner: js_io,
            state: Arc::new(Mutex::new(AdapterState {
                read_buffer: VecDeque::new(),
                eof: false,
                pending_read: None,
                read_waker: None,
                closed: false,
                error: None,
            })),
        }
    }

    /// Returns a handle that can drain any buffered (over-read) bytes.
    pub(crate) fn state_handle(&self) -> AdapterStateHandle {
        AdapterStateHandle(self.state.clone())
    }
}

impl AsyncRead for JsIoAdapter {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let mut state = match this.lock_state() {
            Ok(guard) => guard,
            Err(e) => return Poll::Ready(Err(e)),
        };

        // Check for errors.
        if let Some(ref err) = state.error {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                err.clone(),
            )));
        }

        // If we have buffered data, return it.
        if !state.read_buffer.is_empty() {
            let to_read = std::cmp::min(buf.len(), state.read_buffer.len());
            for (i, byte) in state.read_buffer.drain(..to_read).enumerate() {
                buf[i] = byte;
            }
            return Poll::Ready(Ok(to_read));
        }

        // If we've seen EOF, return 0.
        if state.eof {
            return Poll::Ready(Ok(0));
        }

        // Store waker for later.
        state.read_waker = Some(cx.waker().clone());

        // If there's no pending read, start one.
        if state.pending_read.is_none() {
            match this.inner.read() {
                Ok(promise) => {
                    state.pending_read = Some(JsFuture::from(promise));
                }
                Err(e) => {
                    let err_msg = format!("read error: {:?}", e);
                    state.error = Some(err_msg.clone());
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        err_msg,
                    )));
                }
            }
        }

        // Poll the pending read.
        if let Some(ref mut future) = state.pending_read {
            // SAFETY: We're inside a WASM context where this is safe.
            let future = unsafe { Pin::new_unchecked(future) };
            match future.poll(cx) {
                Poll::Ready(Ok(value)) => {
                    state.pending_read = None;

                    // Check if it's null (EOF).
                    if value.is_null() || value.is_undefined() {
                        tracing::warn!("JsIo read returned null/undefined (EOF)");
                        state.eof = true;
                        return Poll::Ready(Ok(0));
                    }

                    // Convert to bytes.
                    let array = Uint8Array::new(&value);
                    let bytes = array.to_vec();

                    if bytes.is_empty() {
                        tracing::warn!("JsIo read returned empty array (EOF)");
                        state.eof = true;
                        return Poll::Ready(Ok(0));
                    }

                    // Copy to buffer and return.
                    let to_read = std::cmp::min(buf.len(), bytes.len());
                    buf[..to_read].copy_from_slice(&bytes[..to_read]);

                    // Buffer any remaining bytes.
                    if bytes.len() > to_read {
                        state.read_buffer.extend(&bytes[to_read..]);
                    }

                    Poll::Ready(Ok(to_read))
                }
                Poll::Ready(Err(e)) => {
                    state.pending_read = None;
                    let err_msg = format!("read error: {:?}", e);
                    state.error = Some(err_msg.clone());
                    Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, err_msg)))
                }
                Poll::Pending => Poll::Pending,
            }
        } else {
            Poll::Pending
        }
    }
}

impl AsyncWrite for JsIoAdapter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let state = match this.lock_state() {
            Ok(guard) => guard,
            Err(e) => return Poll::Ready(Err(e)),
        };

        // Check for errors.
        if let Some(ref err) = state.error {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                err.clone(),
            )));
        }

        if state.closed {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "stream closed",
            )));
        }

        // Create Uint8Array from buffer.
        let array = Uint8Array::from(buf);

        // Fire-and-forget write: common pattern for WASM IO.
        // We don't wait for the Promise to resolve to avoid backpressure.
        match this.inner.write(&array) {
            Ok(_promise) => {
                // Return success immediately without waiting for Promise.
                Poll::Ready(Ok(buf.len()))
            }
            Err(e) => {
                let err_msg = format!("write error: {:?}", e);
                tracing::error!("JsIo write failed: {}", err_msg);
                Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, err_msg)))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // JS streams typically auto-flush.
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let mut state = match this.lock_state() {
            Ok(guard) => guard,
            Err(e) => return Poll::Ready(Err(e)),
        };

        if state.closed {
            return Poll::Ready(Ok(()));
        }

        // Fire-and-forget close to avoid blocking.
        match this.inner.close() {
            Ok(_promise) => {
                state.closed = true;
                Poll::Ready(Ok(()))
            }
            Err(e) => {
                let err_msg = format!("close error: {:?}", e);
                Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, err_msg)))
            }
        }
    }
}

// SAFETY: `JsIo` (a JS handle via wasm_bindgen) is `!Send`. This is safe
// because `JsIoAdapter` is only used from the main WASM async executor thread.
// While the extension does use multi-threaded WASM (SharedArrayBuffer + rayon
// via web-spawn), the rayon worker threads only perform parallel computation
// (mpz/garble) on shared memory and never access JS handles or this adapter.
unsafe impl Send for JsIoAdapter {}

#[cfg(test)]
mod tests {
    use super::{AdapterStateHandle, JsIo, JsIoAdapter, return_over_read_bytes};
    use crate::test_utils::MockIoChannel;
    use futures::{AsyncReadExt, AsyncWriteExt};
    use js_sys::Uint8Array;
    use wasm_bindgen::{JsCast, JsValue};
    use wasm_bindgen_test::wasm_bindgen_test;

    /// Builds an adapter backed by `mock`, also returning the channel as a
    /// [`JsValue`] (for handoff tests) and a handle to its read state.
    fn adapter_for(mock: &MockIoChannel) -> (JsValue, JsIoAdapter, AdapterStateHandle) {
        let channel = mock.as_js_value();
        let adapter = JsIoAdapter::new(channel.clone().unchecked_into::<JsIo>());
        let handle = adapter.state_handle();
        (channel, adapter, handle)
    }

    /// Sanity check for the test double itself: a chunk pushed into the mock
    /// channel comes back out of the adapter.
    #[wasm_bindgen_test]
    async fn mock_channel_feeds_the_adapter() {
        let mock = MockIoChannel::new();
        mock.push(&Uint8Array::from(&b"hello"[..]));

        let mut adapter = JsIoAdapter::new(mock.as_js_value().unchecked_into::<JsIo>());

        let mut buf = [0u8; 5];
        adapter.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
    }

    /// A read smaller than the delivered chunk leaves the surplus buffered,
    /// and it stays recoverable until drained.
    #[wasm_bindgen_test]
    async fn over_read_bytes_are_buffered_then_drained() {
        let mock = MockIoChannel::new();
        mock.push(&Uint8Array::from(&b"abcde"[..]));
        let (_channel, mut adapter, handle) = adapter_for(&mock);

        let mut one = [0u8; 1];
        assert_eq!(adapter.read(&mut one).await.unwrap(), 1);
        assert_eq!(&one, b"a");

        assert_eq!(handle.take_remainder(), b"bcde");
        // Draining is idempotent.
        assert!(handle.take_remainder().is_empty());
    }

    /// Channel reads are short: a chunk smaller than the caller's buffer is
    /// returned as-is, and bytes buffered from a previous over-read are served
    /// before the adapter reads the next chunk.
    #[wasm_bindgen_test]
    async fn buffered_bytes_are_served_before_the_next_channel_read() {
        let mock = MockIoChannel::new();
        mock.push(&Uint8Array::from(&b"abc"[..]));
        mock.push(&Uint8Array::from(&b"de"[..]));
        let (_channel, mut adapter, handle) = adapter_for(&mock);

        // The whole "abc" chunk is pulled, but only two bytes are consumed...
        let mut two = [0u8; 2];
        assert_eq!(adapter.read(&mut two).await.unwrap(), 2);
        assert_eq!(&two, b"ab");

        // ...so the buffered "c" is served next, without touching "de".
        assert_eq!(adapter.read(&mut two).await.unwrap(), 1);
        assert_eq!(&two[..1], b"c");

        // Only once the buffer is empty does the adapter read "de".
        assert_eq!(adapter.read(&mut two).await.unwrap(), 2);
        assert_eq!(&two, b"de");

        assert!(handle.take_remainder().is_empty());
    }

    /// The core handoff: over-read bytes are pushed back onto the original
    /// channel and become visible to its next `read()`.
    #[wasm_bindgen_test]
    async fn handoff_returns_over_read_bytes_to_the_channel() {
        let mock = MockIoChannel::new();
        mock.push(&Uint8Array::from(&b"abcde"[..]));
        let (channel, mut adapter, handle) = adapter_for(&mock);
        let mut one = [0u8; 1];
        assert_eq!(adapter.read(&mut one).await.unwrap(), 1);

        let mut channel = Some(channel);
        let mut remainder = Some(handle);
        return_over_read_bytes(&mut channel, &mut remainder).unwrap();

        assert_eq!(mock.unread_count(), 1);
        assert_eq!(mock.unread_bytes(0), b"bcde");

        // The mock pushes the bytes back onto its read queue, so the next read
        // sees them again.
        let mut again = [0u8; 4];
        adapter.read_exact(&mut again).await.unwrap();
        assert_eq!(&again, b"bcde");
    }

    /// Nothing buffered means no `unread()` call.
    #[wasm_bindgen_test]
    async fn handoff_without_remainder_is_a_noop() {
        let mock = MockIoChannel::new();
        let (channel, _adapter, handle) = adapter_for(&mock);

        let mut channel = Some(channel);
        let mut remainder = Some(handle);
        return_over_read_bytes(&mut channel, &mut remainder).unwrap();

        assert_eq!(mock.unread_count(), 0);
    }

    /// The args are `take()`n, so a repeated handoff cannot double-push.
    #[wasm_bindgen_test]
    async fn handoff_is_idempotent() {
        let mock = MockIoChannel::new();
        mock.push(&Uint8Array::from(&b"abcde"[..]));
        let (channel, mut adapter, handle) = adapter_for(&mock);
        let mut one = [0u8; 1];
        assert_eq!(adapter.read(&mut one).await.unwrap(), 1);

        let mut channel = Some(channel);
        let mut remainder = Some(handle);
        return_over_read_bytes(&mut channel, &mut remainder).unwrap();
        return_over_read_bytes(&mut channel, &mut remainder).unwrap();

        assert_eq!(mock.unread_count(), 1);
    }

    /// A channel that cannot `unread` surfaces an error rather than dropping
    /// the over-read bytes silently.
    #[wasm_bindgen_test]
    async fn handoff_errors_when_channel_cannot_unread() {
        let mock = MockIoChannel::new();
        mock.push(&Uint8Array::from(&b"abcde"[..]));
        mock.fail_unread(true);
        let (channel, mut adapter, handle) = adapter_for(&mock);
        let mut one = [0u8; 1];
        assert_eq!(adapter.read(&mut one).await.unwrap(), 1);

        let mut channel = Some(channel);
        let mut remainder = Some(handle);
        assert!(return_over_read_bytes(&mut channel, &mut remainder).is_err());
    }

    /// Writes and close are wired straight through to the channel.
    #[wasm_bindgen_test]
    async fn writes_and_close_reach_the_channel() {
        let mock = MockIoChannel::new();
        let (_channel, mut adapter, _handle) = adapter_for(&mock);

        adapter.write_all(b"ping").await.unwrap();
        assert_eq!(mock.write_count(), 1);

        adapter.close().await.unwrap();
        assert!(mock.is_closed());
    }
}
