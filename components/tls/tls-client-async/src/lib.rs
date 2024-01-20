//! Provides a TLS client which exposes an async socket.
//!
//! This library provides the [bind_client] function which attaches a TLS client to a socket
//! connection and then exposes a [TlsConnection] object, which provides an async socket API for
//! reading and writing cleartext. The TLS client will then automatically encrypt and decrypt
//! traffic and forward that to the provided socket.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

mod conn;

use bytes::{Buf, Bytes};
use futures::{
    channel::mpsc, future::Fuse, select_biased, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt,
    Future, FutureExt, SinkExt, StreamExt,
};

use std::{
    pin::Pin,
    task::{Context, Poll},
};

#[cfg(feature = "tracing")]
use tracing::{debug, debug_span, error, trace, Instrument};

use tls_client::ClientConnection;

pub use conn::TlsConnection;

const RX_TLS_BUF_SIZE: usize = 1 << 13; // 8 KiB
const RX_BUF_SIZE: usize = 1 << 13; // 8 KiB

/// An error that can occur during a TLS connection.
#[allow(missing_docs)]
#[derive(Debug, thiserror::Error)]
pub enum ConnectionError {
    #[error(transparent)]
    TlsError(#[from] tls_client::Error),
    #[error(transparent)]
    IOError(#[from] std::io::Error),
}

/// Closed connection data.
#[derive(Debug)]
pub struct ClosedConnection {
    /// The connection for the client
    pub client: ClientConnection,
    /// Sent plaintext bytes
    pub sent: Vec<u8>,
    /// Received plaintext bytes
    pub recv: Vec<u8>,
}

/// A future which runs the TLS connection to completion.
///
/// This future must be polled in order for the connection to make progress.
#[must_use = "futures do nothing unless polled"]
pub struct ConnectionFuture {
    fut: Pin<Box<dyn Future<Output = Result<ClosedConnection, ConnectionError>> + Send>>,
}

impl Future for ConnectionFuture {
    type Output = Result<ClosedConnection, ConnectionError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.fut.poll_unpin(cx)
    }
}

/// Binds a client connection to the provided socket.
///
/// Returns a connection handle and a future which runs the connection to completion.
///
/// # Errors
///
/// Any connection errors that occur will be returned from the future, not [`TlsConnection`].
pub fn bind_client<T: AsyncRead + AsyncWrite + Send + Unpin + 'static>(
    socket: T,
    mut client: ClientConnection,
) -> (TlsConnection, ConnectionFuture) {
    let (tx_sender, mut tx_receiver) = mpsc::channel(1 << 14);
    let (mut rx_sender, rx_receiver) = mpsc::channel(1 << 14);

    let conn = TlsConnection::new(tx_sender, rx_receiver);

    let fut = async move {
        client.start().await?;
        let mut notify = client.get_notify().await?;

        let (mut server_rx, mut server_tx) = socket.split();

        let mut rx_tls_buf = [0u8; RX_TLS_BUF_SIZE];
        let mut rx_buf = [0u8; RX_BUF_SIZE];

        let mut client_closed = false;
        let mut server_closed = false;

        let mut sent = Vec::with_capacity(1024);
        let mut recv = Vec::with_capacity(1024);

        let mut rx_tls_fut = server_rx.read(&mut rx_tls_buf).fuse();
        let mut tx_recv_fut = tx_receiver.next().fuse();

        // Runs both the tx and rx halves of the connection to completion.
        // This loop does not terminate until the *SERVER* closes the connection and
        // we've processed all received data. If an error occurs, the `TlsConnection`
        // channels will be closed and the error will be returned from this future.
        'conn: loop {
            select_biased! {
                // Reads TLS data from the server and writes it into the client.
                received = &mut rx_tls_fut => {
                    let received = received?;
                    #[cfg(feature = "tracing")]
                    trace!("received {} tls bytes from server", received);

                    // Loop until we've processed all the data we received in this read.
                    // Note that we must make one iteration even if `received == 0`.
                    let mut processed = 0;
                    let mut reader = rx_tls_buf[..received].reader();
                    loop {
                        processed += client.read_tls(&mut reader)?;
                        client.process_new_packets().await?;

                        debug_assert!(processed <= received);
                        if processed >= received {
                            break;
                        }
                    }

                    if received == 0 {
                        #[cfg(feature = "tracing")]
                        debug!("server closed connection");
                        server_closed = true;
                        client.server_closed().await?;
                        // Do not read from the socket again.
                        rx_tls_fut = Fuse::terminated();
                    } else {
                        // Reset the read future so next iteration we can read again.
                        rx_tls_fut = server_rx.read(&mut rx_tls_buf).fuse();
                    }
                }
                // If we receive None from `TlsConnection`, it has closed, so we
                // send a close_notify to the server, flush and close.
                data = &mut tx_recv_fut => {
                    if let Some(data) = data {
                        sent.extend(&data);
                        client
                            .write_all_plaintext(&data)
                            .await?;

                        tx_recv_fut = tx_receiver.next().fuse();
                    } else {
                        #[cfg(feature = "tracing")]
                        debug!("client closed connection");

                        #[cfg(feature = "tracing")]
                        trace!("sending close_notify to server");
                        client.send_close_notify().await?;

                        // Flush all remaining plaintext
                        while client.wants_write() {
                            let _sent = client.write_tls_async(&mut server_tx).await?;
                            #[cfg(feature = "tracing")]
                            trace!("sent {} tls bytes to server", _sent);
                        }
                        server_tx.flush().await?;
                        server_tx.close().await?;
                        client_closed = true;

                        tx_recv_fut = Fuse::terminated();
                    }
                }
                // Waits for a notification from the backend that it is ready to decrypt data.
                _ = &mut notify => {
                    #[cfg(feature = "tracing")]
                    trace!("backend is ready to decrypt");

                    client.process_new_packets().await?;
                }
            }

            // Write all pending TLS data to the server.
            if client.wants_write() {
                while client.wants_write() && !client_closed {
                    let _sent = client.write_tls_async(&mut server_tx).await?;
                    #[cfg(feature = "tracing")]
                    trace!("sent {} tls bytes to server", _sent);
                }
                server_tx.flush().await?;
            }

            // Forward received plaintext to `TlsConnection`.
            while !client.plaintext_is_empty() {
                let read = client.read_plaintext(&mut rx_buf)?;
                recv.extend(&rx_buf[..read]);
                // Ignore if the receiver has hung up.
                _ = rx_sender
                    .send(Ok(Bytes::copy_from_slice(&rx_buf[..read])))
                    .await;
            }

            let buffer_len = client.buffer_len().await?;
            if server_closed && buffer_len == 0 {
                break 'conn;
            }
        }

        #[cfg(feature = "tracing")]
        debug!("client shutdown");

        tx_receiver.close();
        rx_sender.close_channel();

        #[cfg(feature = "tracing")]
        trace!(
            "server close notify: {}, sent: {}, recv: {}",
            client.received_close_notify(),
            sent.len(),
            recv.len()
        );

        Ok(ClosedConnection { client, sent, recv })
    };

    #[cfg(feature = "tracing")]
    let fut = fut.instrument(debug_span!("tls_connection"));

    let fut = ConnectionFuture { fut: Box::pin(fut) };

    (conn, fut)
}
