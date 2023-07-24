//! Provides a TLS client which exposes an async socket.
//!
//! This library provides the [bind_client] function which enables to attach a TLS client to a
//! socket connection and then exposes a [TlsConnection] object, which provides an async socket API
//! for reading and writing cleartext. The TLS client will then automatically encrypt and decrypt
//! traffic and forward that to the provided socket.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

mod conn;

use bytes::Bytes;
use futures::{
    channel::{mpsc, oneshot},
    future::Fuse,
    select_biased, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, Future, FutureExt, SinkExt,
    StreamExt,
};

use std::{
    io::Read,
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
pub fn bind_client<T: AsyncRead + AsyncWrite + Send + Unpin + 'static>(
    socket: T,
    mut client: ClientConnection,
) -> (TlsConnection, ConnectionFuture) {
    let (tx_sender, mut tx_receiver) = mpsc::channel(1 << 14);
    let (mut rx_sender, rx_receiver) = mpsc::channel(1 << 14);
    let (close_send, mut close_recv) = oneshot::channel();

    let conn = TlsConnection::new(tx_sender, rx_receiver, close_send);

    let fut = async move {
        client.start().await?;

        let (mut server_rx, mut server_tx) = socket.split();

        let mut rx_tls_buf = [0u8; RX_TLS_BUF_SIZE];
        let mut rx_buf = [0u8; RX_BUF_SIZE];

        let mut client_closed = false;
        let mut server_closed = false;

        let mut sent = Vec::with_capacity(1024);
        let mut recv = Vec::with_capacity(1024);

        let mut rx_tls_fut = server_rx.read(&mut rx_tls_buf).fuse();

        'outer: loop {
            select_biased! {
                read_res = &mut rx_tls_fut => {
                    let received = read_res?;

                    #[cfg(feature = "tracing")]
                    trace!("received {} tls bytes from server", received);

                    // Loop until we've processed all the data we received in this read.
                    let mut processed = 0;
                    while processed < received {
                        processed += client.read_tls(&mut &rx_tls_buf[processed..received])?;
                        match client.process_new_packets().await {
                            Ok(_) => {}
                            Err(e) => {
                                // In case we have an alert to send describing this error,
                                // try a last-gasp write -- but don't predate the primary
                                // error.
                                let _ignored = client.write_tls_async(&mut server_tx).await;

                                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                            }
                        }
                    }

                    if received == 0 {
                        #[cfg(feature = "tracing")]
                        debug!("server closed connection");
                        server_closed = true;

                        // Do not read from the socket again.
                        rx_tls_fut = Fuse::terminated();
                    } else {
                        // Reset the read future so next iteration we can read again.
                        rx_tls_fut = server_rx.read(&mut rx_tls_buf).fuse();
                    }
                }
                data = tx_receiver.select_next_some() => {
                    sent.extend(&data);
                    client
                        .write_all_plaintext(&data)
                        .await?;

                    #[cfg(feature = "tracing")]
                    trace!("processed {} bytes to the server", data.len());
                },
                close_send = &mut close_recv => {
                    client_closed = true;

                    #[cfg(feature = "tracing")]
                    trace!("sending close_notify to server");

                    client.send_close_notify().await?;

                    // Flush all remaining plaintext
                    while client.wants_write() {
                        client.write_tls_async(&mut server_tx).await?;
                    }
                    server_tx.flush().await?;
                    server_tx.close().await?;

                    // Send the close signal to the TlsConnection
                    if let Ok(close_send) = close_send {
                        _ = close_send.send(());
                    }

                    #[cfg(feature = "tracing")]
                    debug!("client closed connection");
                }
            }

            while client.wants_write() && !client_closed {
                let _sent = client.write_tls_async(&mut server_tx).await?;
                #[cfg(feature = "tracing")]
                trace!("sent {} tls bytes to server", _sent);
            }

            // Flush all remaining plaintext to the server
            // otherwise this loop could hang forever as the server
            // waits for more data before responding.
            server_tx.flush().await?;

            // Forward all plaintext to the TLSConnection
            loop {
                let n = match client.reader().read(&mut rx_buf) {
                    Ok(n) => n,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        if server_closed {
                            #[cfg(feature = "tracing")]
                            debug!("server closed, no more data to read");
                            break 'outer;
                        } else {
                            break;
                        }
                    }
                    // Some servers will not send a close_notify, in which case we need to
                    // error because we can't reveal the MAC key to the Notary.
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                        #[cfg(feature = "tracing")]
                        error!("server did not send close_notify");
                        return Err(e)?;
                    }
                    Err(e) => return Err(e)?,
                };

                if n > 0 {
                    #[cfg(feature = "tracing")]
                    trace!("received {} bytes from server", n);
                    recv.extend(&rx_buf[..n]);
                    // Ignore if the receiver has hung up.
                    _ = rx_sender
                        .send(Ok(Bytes::copy_from_slice(&rx_buf[..n])))
                        .await;
                } else {
                    #[cfg(feature = "tracing")]
                    debug!("server closed, no more data to read");
                    break 'outer;
                }
            }

            if client_closed && server_closed {
                break;
            }
        }

        #[cfg(feature = "tracing")]
        debug!("client shutdown");

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
