//! Provides a TLS client which exposes an async socket.
//!
//! The [bind_client] function attaches a TLS client to a socket connection and
//! then exposes a [TlsConnection] object, which provides an async socket API
//! for reading and writing cleartext. The TLS client will then automatically
//! encrypt and decrypt traffic and forward that to the provided socket.

use futures::{Future, FutureExt, select_biased};
use std::{
    io::{Read, Write},
    pin::Pin,
    task::{Context, Poll},
};
use tls_client::ClientConnection;
use tracing::{Instrument, debug, debug_span, error, trace, warn};

use crate::byte_stream::{DuplexStream, duplex};

const BUF_SIZE: usize = 1 << 13; // 8 KiB

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
/// Returns a connection handle and a future which runs the connection to
/// completion.
///
/// # Errors
///
/// Any connection errors that occur will be returned from the future, not
/// [`TlsConnection`].
pub fn bind_client(mut client: ClientConnection) -> (DuplexStream, DuplexStream, ConnectionFuture) {
    let (client_socket, mut client_handle) = duplex(BUF_SIZE);
    let (server_socket, mut server_handle) = duplex(BUF_SIZE);

    let poll_loop = async move {
        client.start().await?;
        let mut notify = client.get_notify().await?;

        let mut rx_tls_buf = [0u8; BUF_SIZE];
        let mut rx_buf = [0u8; BUF_SIZE];

        let mut tx_tls_buf = [0u8; BUF_SIZE];
        let mut tx_buf = [0u8; BUF_SIZE];

        let mut handshake_done = false;
        let mut client_closed = false;

        loop {
            // Write all pending TLS data to `server_handle`.
            if client.wants_write() && !client_closed {
                trace!("client wants to write");
                while client.wants_write() {
                    let sent_tls = client.write_tls(&mut tx_tls_buf.as_mut_slice())?;
                    server_handle.write_all(&tx_tls_buf[..sent_tls])?;
                    trace!("sent {} tls bytes to server_handle", sent_tls);
                }
                server_handle.flush()?;
            }

            // Forward received plaintext to `client_handle`.
            while !client.plaintext_is_empty() {
                let read = client.read_plaintext(&mut rx_buf)?;
                client_handle.write_all(&rx_buf[..read])?;
                trace!("sent {} clear bytes to client_handle", read);
            }

            // Read application data, which should be sent to the server, only if handshake is done
            if !client.is_handshaking() && !handshake_done {
                debug!("handshake complete");
                handshake_done = true;
            }

            if handshake_done {
                while let read = client_handle.read(&mut tx_buf)?
                    && read > 0
                {
                    client.write_all_plaintext(&tx_buf[..read]).await?;
                }
            }

            if client_handle.is_closed() {
                if !server_handle.is_closed() {
                    if let Err(e) = send_close_notify(&mut client, &mut server_handle).await {
                        warn!("failed to send close_notify to server: {}", e);
                    }
                }
                client_closed = true;
            }

            if server_handle.is_closed() && client.plaintext_is_empty() && client.is_empty().await?
            {
                client.server_closed().await?;
                break;
            }

            // Reads TLS data from the server and writes it into the client.
            let read_tls = server_handle.read(&mut rx_tls_buf)?;
            trace!("received {} tls bytes from server_handle", read_tls);
            while let processed = client.read_tls(&mut &rx_tls_buf[..read_tls])?
                && processed < read_tls
            {
                client.process_new_packets().await?;
                trace!("processed {} tls bytes from server", processed);
            }

            select_biased! {
                // Waits for a notification from the backend that it is ready to decrypt data.
                _ = &mut notify => {
                    trace!("backend is ready to decrypt");

                    client.process_new_packets().await?;
                },
                _ = futures::future::ready(()) => {}
            }
        }
        debug!("client shutdown");

        server_handle.close();
        client_handle.close();

        trace!("server close notify: {}", client.received_close_notify());

        Ok(ClosedConnection { client })
    };

    let fut = poll_loop.instrument(debug_span!("tls_connection"));
    let fut = ConnectionFuture { fut: Box::pin(fut) };

    (client_socket, server_socket, fut)
}

async fn send_close_notify(
    client: &mut ClientConnection,
    server_handle: &mut (impl std::io::Write + Unpin),
) -> Result<(), ConnectionError> {
    trace!("sending close_notify to server");
    client.send_close_notify().await?;
    client.process_new_packets().await?;

    // Flush all remaining plaintext
    while client.wants_write() {
        client.write_tls(server_handle)?;
    }
    server_handle.flush()?;

    Ok(())
}
