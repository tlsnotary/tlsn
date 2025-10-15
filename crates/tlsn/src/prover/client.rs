//! Provides a TLS client that sits in between client and server and
//! encrypts/decrypts between cleartext and TLS traffic.
//!
//! The [`build_tls_client`] function is a helper to create the TLS
//! [`ClientConnection`]. [`ConnectionFuture`] comes in 2 variants:
//!   - [`ConnectionFuture::new`] comes with sync duplex streams and provides a
//!     sans-io api.
//!   - [`ConnectionFuture::new_with_socket`] connects the client to an async
//!     socket and exposes an async client.
use futures::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, Future, FutureExt, TryFutureExt,
    future::FusedFuture, select_biased,
};
use mpc_tls::LeaderCtrl;
use rustls_pki_types::CertificateDer;
use std::{
    io::{Read, Write},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Waker},
};
use tls_backend::BackendNotify;
use tls_client::{ClientConnection, ServerName as TlsServerName};
use tlsn_core::connection::ServerName;
use tracing::{Instrument, debug, debug_span, error, trace, warn};
use webpki::anchor_from_trusted_cert;

use crate::{
    byte_stream::{DuplexStream, duplex},
    prover::{ProverConfig, ProverError},
};

const BUF_SIZE: usize = 8 * 1024; // 8 KiB

/// An error that can occur during a TLS connection.
#[allow(missing_docs)]
#[derive(Debug, thiserror::Error)]
pub enum ConnectionError {
    #[error(transparent)]
    TlsError(#[from] tls_client::Error),
    #[error(transparent)]
    IOError(#[from] std::io::Error),
}

/// A future which runs the TLS connection to completion.
///
/// This future must be polled in order for the connection to make progress.
#[must_use = "futures do nothing unless polled"]
pub(crate) struct ConnectionFuture {
    fut: Pin<Box<dyn Future<Output = Result<ClientConnection, ConnectionError>> + Send>>,
}

impl ConnectionFuture {
    /// Attaches duplex byte streams to the provided TLS client.
    ///
    /// # Returns
    ///   - a duplex stream for reading/writing cleartext between client and TLS
    ///     client
    ///   - a duplex stream for reading/writing TLS traffic between TLS client
    ///     and server
    ///   - a future which must be polled and runs the connection to completion.
    ///
    /// # Errors
    ///
    /// Any connection errors that occur will be returned from the future.
    pub(crate) fn new(client: ClientConnection) -> (DuplexStream, DuplexStream, Self) {
        let (client, server, mut inner_fut) = InnerFuture::new(client);

        let future = ConnectionFuture {
            fut: Box::pin(
                async move {
                    let mut waker: Option<Waker> = None;
                    loop {
                        futures::select! {
                            conn = &mut inner_fut => break conn,
                            default => {
                                if let Some(waker) = waker {
                                    waker.wake();
                                }
                            }
                        }
                        waker = inner_fut.waker();
                    }
                }
                .instrument(debug_span!("tls_connection")),
            ),
        };

        (client, server, future)
    }

    /// Attaches an async socket to the provided TLS client.
    ///
    /// # Returns
    ///   - an async duplex stream for reading and writing cleartext from/to the
    ///     server, i.e. the client handle.
    ///   - a future which must be polled and runs the connection to completion.
    ///
    /// # Errors
    ///
    /// Any connection errors that occur will be returned from the future.
    pub(crate) fn new_with_socket<S: AsyncRead + AsyncWrite + Send + Unpin + 'static>(
        socket: S,
        client_conn: ClientConnection,
    ) -> (futures_plex::DuplexStream, Self) {
        let (client_async_socket, client_async_handle) = futures_plex::duplex(BUF_SIZE);
        let (mut client_handle, mut server_handle, mut inner_fut) = InnerFuture::new(client_conn);

        let mut client_buffer1 = [0_u8; BUF_SIZE];
        let mut client_buffer2 = [0_u8; BUF_SIZE];
        let mut server_buffer1 = [0_u8; BUF_SIZE];
        let mut server_buffer2 = [0_u8; BUF_SIZE];

        let (mut client_async_read, mut client_async_write) = client_async_handle.split();
        let (mut server_async_read, mut server_async_write) = socket.split();

        let future = ConnectionFuture {
            fut: Box::pin(
                async move {
                    let mut waker: Option<Waker> = None;
                    loop {
                        let mut client_future = std::pin::pin!(
                            async {
                                let mut read_op =
                                    client_async_read.read(&mut client_buffer1).fuse();
                                let mut write_op =
                                    futures::future::ready(client_handle.read(&mut client_buffer2))
                                        .and_then(|read_count| {
                                            client_async_write.write(&client_buffer2[..read_count])
                                        });

                                futures::select! {
                                    read_count = read_op => {
                                        client_handle.write_all(&client_buffer1[..read_count?])?;
                                    },
                                    _ = write_op => {}

                                }
                                Ok::<_, std::io::Error>(())
                            }
                            .fuse()
                        );

                        let mut server_future = std::pin::pin!(
                            async {
                                let mut read_op =
                                    server_async_read.read(&mut server_buffer1).fuse();
                                let mut write_op =
                                    futures::future::ready(server_handle.read(&mut server_buffer2))
                                        .and_then(|read_count| {
                                            server_async_write.write(&server_buffer2[..read_count])
                                        });

                                futures::select! {
                                    read_count = read_op => {
                                        let read_count = read_count?;
                                        if read_count > 0 {
                                            server_handle.write_all(&server_buffer1[..read_count])?;
                                        } else {
                                            server_handle.close();
                                        }
                                    },
                                    _ = write_op => {}

                                }
                                Ok::<_, std::io::Error>(())
                            }
                            .fuse()
                        );

                        futures::select! {
                            conn = &mut inner_fut => break conn,
                            _ = client_future => (),
                            _ = server_future => (),
                            default => {
                                if let Some(waker) = waker {
                                    waker.wake_by_ref();
                                }
                            }
                        }
                        waker = inner_fut.waker();
                    }
                }
                .instrument(debug_span!("tls_connection")),
            ),
        };

        (client_async_socket, future)
    }
}

impl Future for ConnectionFuture {
    type Output = Result<ClientConnection, ConnectionError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.fut.poll_unpin(cx)
    }
}

pin_project_lite::pin_project! {
    struct InnerFuture {
        inner: InnerState,
    }
}
impl InnerFuture {
    fn waker(&self) -> Option<Waker> {
        if let InnerState::Run { waker, .. } = &self.inner {
            waker.clone()
        } else {
            None
        }
    }
}

enum InnerState {
    Init {
        client: Box<ClientConnection>,
        client_handle: DuplexStream,
        server_handle: DuplexStream,
    },
    Start {
        fut: StartFuture,
        client_handle: DuplexStream,
        server_handle: DuplexStream,
    },
    Run {
        fut: PollFuture,
        waker: Option<Waker>,
    },
    Finished,
    Error,
}

type StartFuture = Pin<
    Box<
        dyn Future<Output = Result<(ClientConnection, BackendNotify), ConnectionError>>
            + Send
            + 'static,
    >,
>;
type PollFuture =
    Pin<Box<dyn Future<Output = Result<PollingLoop, ConnectionError>> + Send + 'static>>;

impl InnerFuture {
    fn new(client: ClientConnection) -> (DuplexStream, DuplexStream, Self) {
        let (client_socket, client_handle) = duplex(BUF_SIZE);
        let (server_socket, server_handle) = duplex(BUF_SIZE);

        (
            client_socket,
            server_socket,
            InnerFuture {
                inner: InnerState::Init {
                    client: Box::new(client),
                    client_handle,
                    server_handle,
                },
            },
        )
    }
}

impl Future for InnerFuture {
    type Output = Result<ClientConnection, ConnectionError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let inner = self.as_mut().project().inner;
        let current = std::mem::replace(inner, InnerState::Error);

        match current {
            InnerState::Init {
                client,
                client_handle,
                server_handle,
            } => {
                *inner = InnerState::Start {
                    fut: Box::pin(async {
                        let mut client = *client;
                        client.start().await?;
                        let notify = client.get_notify().await.map_err(ConnectionError::from)?;

                        Ok((client, notify))
                    }),
                    client_handle,
                    server_handle,
                };
                self.poll(cx)
            }
            InnerState::Start {
                mut fut,
                client_handle,
                server_handle,
            } => match fut.as_mut().poll(cx) {
                Poll::Ready(client) => {
                    let (client, notify) = client?;
                    let rx_tls_buf = [0u8; BUF_SIZE];
                    let rx_buf = [0u8; BUF_SIZE];

                    let tx_tls_buf = [0u8; BUF_SIZE];
                    let tx_buf = [0u8; BUF_SIZE];

                    let handshake_done = false;
                    let client_closed = false;
                    let finished = false;

                    let fut = PollingLoop {
                        client,
                        client_handle,
                        server_handle,
                        notify,
                        rx_tls_buf,
                        rx_buf,
                        tx_tls_buf,
                        tx_buf,
                        handshake_done,
                        client_closed,
                        finished,
                    };
                    *inner = InnerState::Run {
                        fut: Box::pin(fut.run()),
                        waker: None,
                    };
                    self.poll(cx)
                }
                Poll::Pending => {
                    *inner = InnerState::Start {
                        fut,
                        client_handle,
                        server_handle,
                    };
                    Poll::Pending
                }
            },
            InnerState::Run { mut fut, waker } => match fut.as_mut().poll(cx) {
                Poll::Ready(res) => {
                    let polling_loop = res?;
                    if polling_loop.finished {
                        *inner = InnerState::Finished;
                        Poll::Ready(Ok(polling_loop.client))
                    } else {
                        let waker = cx.waker().clone();
                        *inner = InnerState::Run {
                            fut: Box::pin(polling_loop.run()),
                            waker: Some(waker),
                        };
                        Poll::Pending
                    }
                }
                Poll::Pending => {
                    *inner = InnerState::Run { fut, waker };
                    Poll::Pending
                }
            },
            InnerState::Finished => {
                *inner = InnerState::Finished;
                Poll::Pending
            }
            InnerState::Error => panic!("reached error state for `InnerFuture`"),
        }
    }
}

impl FusedFuture for InnerFuture {
    fn is_terminated(&self) -> bool {
        matches!(self.inner, InnerState::Finished)
    }
}

struct PollingLoop {
    client: ClientConnection,
    client_handle: DuplexStream,
    server_handle: DuplexStream,
    notify: BackendNotify,
    rx_tls_buf: [u8; BUF_SIZE],
    rx_buf: [u8; BUF_SIZE],
    tx_tls_buf: [u8; BUF_SIZE],
    tx_buf: [u8; BUF_SIZE],
    handshake_done: bool,
    client_closed: bool,
    finished: bool,
}

impl PollingLoop {
    async fn run(mut self) -> Result<Self, ConnectionError> {
        // Write all pending TLS data to `server_handle`.
        if self.client.wants_write() && !self.client_closed {
            trace!("client wants to write");
            while self.client.wants_write() {
                let sent_tls = self.client.write_tls(&mut self.tx_tls_buf.as_mut_slice())?;
                self.server_handle.write_all(&self.tx_tls_buf[..sent_tls])?;
                trace!("sent {} tls bytes to server_handle", sent_tls);
            }
            self.server_handle.flush()?;
        }

        // Forward received plaintext to `client_handle`.
        while !self.client.plaintext_is_empty() {
            let read = self.client.read_plaintext(&mut self.rx_buf)?;
            self.client_handle.write_all(&self.rx_buf[..read])?;
            trace!("sent {} clear bytes to client_handle", read);
        }

        // Read application data, which should be sent to the server, only if handshake
        // is done
        if !self.client.is_handshaking() && !self.handshake_done {
            debug!("handshake complete");
            self.handshake_done = true;
        }

        if self.handshake_done {
            while let read = self.client_handle.read(&mut self.tx_buf)?
                && read > 0
            {
                self.client
                    .write_all_plaintext(&self.tx_buf[..read])
                    .await?;
            }
        }

        if self.client_handle.is_closed() {
            if !self.server_handle.is_closed()
                && let Err(e) = send_close_notify(&mut self.client, &mut self.server_handle).await
            {
                warn!("failed to send close_notify to server: {}", e);
            }
            self.client_closed = true;
        }

        // Reads TLS data from the server and writes it into the client.
        let read_tls = self.server_handle.read(&mut self.rx_tls_buf)?;
        trace!("received {} tls bytes from server_handle", read_tls);
        while let processed = self.client.read_tls(&mut &self.rx_tls_buf[..read_tls])?
            && processed < read_tls
        {
            self.client.process_new_packets().await?;
            trace!("processed {} tls bytes from server", processed);
        }

        select_biased! {
            // Waits for a notification from the backend that it is ready to decrypt data.
            _ = &mut self.notify => {
                trace!("backend is ready to decrypt");

                self.client.process_new_packets().await?;
            },
            _ = futures::future::ready(()) => {}
        }

        if self.server_handle.is_closed()
            && self.client.plaintext_is_empty()
            && self.client.is_empty().await?
        {
            self.client.server_closed().await?;
            debug!("client shutdown");

            self.server_handle.close();
            self.client_handle.close();

            trace!(
                "server close notify: {}",
                self.client.received_close_notify()
            );
            self.finished = true;
        }
        Ok(self)
    }
}

pub(crate) fn build_tls_client(
    config: &ProverConfig,
    mpc_ctrl: &LeaderCtrl,
) -> Result<ClientConnection, ProverError> {
    let ServerName::Dns(server_name) = config.server_name();
    let server_name = TlsServerName::try_from(server_name.as_ref()).expect("name was validated");

    let root_store = if let Some(root_store) = config.tls_config().root_store() {
        let roots = root_store
            .roots
            .iter()
            .map(|cert| {
                let der = CertificateDer::from_slice(&cert.0);
                anchor_from_trusted_cert(&der)
                    .map(|anchor| anchor.to_owned())
                    .map_err(ProverError::config)
            })
            .collect::<Result<Vec<_>, _>>()?;
        tls_client::RootCertStore { roots }
    } else {
        tls_client::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        }
    };

    let client_config_builder = tls_client::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store);

    let client_config = if let Some((cert, key)) = config.tls_config().client_auth() {
        client_config_builder
            .with_single_cert(
                cert.iter()
                    .map(|cert| tls_client::Certificate(cert.0.clone()))
                    .collect(),
                tls_client::PrivateKey(key.0.clone()),
            )
            .map_err(ProverError::config)?
    } else {
        client_config_builder.with_no_client_auth()
    };

    let client = ClientConnection::new(
        Arc::new(client_config),
        Box::new(mpc_ctrl.clone()),
        server_name,
    )
    .map_err(ProverError::config)?;

    Ok(client)
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

#[cfg(test)]
mod client_test;
#[cfg(test)]
mod mpc_tls_test;
