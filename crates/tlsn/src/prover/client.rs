//! Provides a TLS client.

use crate::{TlsOutput, deps::ProverZk};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::Poll,
};

mod mpc;
pub(crate) use mpc::MpcTlsClient;

mod proxy;
use mpz_common::Context;
pub(crate) use proxy::ProxyTlsClient;

/// TLS client for MPC and proxy-based TLS implementations.
pub(crate) trait TlsClient {
    type Error: std::error::Error + Send + Sync + Unpin + 'static;

    /// Returns `true` if the client wants to read TLS data from the server.
    fn wants_read_tls(&self) -> bool;

    /// Returns `true` if the client wants to write TLS data to the server.
    fn wants_write_tls(&self) -> bool;

    /// Reads TLS data from the server.
    fn read_tls(&mut self, buf: &[u8]) -> Result<usize, Self::Error>;

    /// Writes TLS data for the server into the provided buffer.
    fn write_tls(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error>;

    /// Returns `true` if the client wants to read plaintext data.
    fn wants_read(&self) -> bool;

    /// Returns `true` if the client wants to write plaintext data.
    fn wants_write(&self) -> bool;

    /// Reads plaintext data from the server into the provided buffer.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error>;

    /// Writes plaintext data to be sent to the server.
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error>;

    /// Client closes the connection.
    fn client_close(&mut self);

    /// Server closes the connection.
    fn server_close(&mut self);

    /// Returns whether the peer has sent a TLS `close_notify`.
    fn received_close_notify(&self) -> bool {
        false
    }

    /// Returns whether the TLS handshake is still in progress.
    fn is_handshaking(&self) -> bool {
        false
    }

    /// Returns whether the peer's TLS write side is finished.
    ///
    /// For proxy mode this becomes true when rustls has processed the server's
    /// `close_notify`, or when the transport has reached EOF and everything
    /// buffered before it has been fed to rustls.
    fn incoming_finished(&self) -> bool {
        false
    }

    /// Returns whether decrypted application data is still waiting to be read.
    fn plaintext_pending(&self) -> bool {
        false
    }

    /// Returns whether any decrypted application data is buffered.
    ///
    /// Unlike [`TlsClient::wants_read`], this must reflect the actual
    /// plaintext buffer, not merely that the client is in a readable state.
    fn has_pending_plaintext(&self) -> bool {
        self.wants_read()
    }

    /// Returns true when the write half of the transport can be closed.
    fn wants_write_shutdown(&self) -> bool {
        false
    }

    /// Notifies the client that the write half of the transport has been
    /// closed.
    fn write_shutdown_complete(&mut self) {}
    /// Returns the decryption state.
    fn decrypt(&self) -> Arc<DecryptState>;

    /// Polls the client to make progress.
    fn poll(
        &mut self,
        cx: &mut std::task::Context,
    ) -> Poll<Result<(Context, ProverZk, TlsOutput), Self::Error>>;
}

/// Decryption state.
#[derive(Debug)]
pub(crate) struct DecryptState {
    decrypt: AtomicBool,
}

impl DecryptState {
    #[cfg(test)]
    pub(crate) fn new() -> Self {
        Self {
            decrypt: AtomicBool::new(false),
        }
    }

    pub(crate) fn enable_decryption(&self, enable: bool) {
        self.decrypt.store(enable, Ordering::Release);
    }

    pub(crate) fn is_decrypting(&self) -> bool {
        self.decrypt.load(Ordering::Acquire)
    }
}
