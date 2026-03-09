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
use wasm_bindgen::prelude::*;
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
}

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
