//! Provides a TLS client.

use crate::prover::ProverError;
use std::task::{Context, Poll};
use tlsn_core::transcript::TlsTranscript;

mod mpc;

pub(crate) use mpc::{MpcControl, MpcTlsClient};

pub(crate) trait TlsClient {
    /// Returns `true` if the client can read TLS data from the server.
    fn can_read_tls(&self) -> bool;

    /// Returns `true` if the client wants to write TLS data to the server.
    fn wants_write_tls(&self) -> bool;

    /// Reads TLS data from the server.
    fn read_tls(&mut self, buf: &[u8]) -> Result<usize, std::io::Error>;

    /// Writes TLS data for the server into the provided buffer.
    fn write_tls(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error>;

    /// Returns `true` if the client can read plaintext data.
    fn can_read(&self) -> bool;

    /// Returns `true` if the client wants to write plaintext data.
    fn wants_write(&self) -> bool;

    /// Reads plaintext data from the server into the provided buffer.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error>;

    /// Writes plaintext data to be sent to the server.
    fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error>;

    /// Closes the connection.
    fn close(&mut self) -> Result<(), std::io::Error>;

    /// Polls the client to make progress.
    fn poll(
        &mut self,
        cx: &mut Context,
    ) -> Poll<Result<(mpz_common::Context, TlsTranscript), ProverError>> {
        todo!()
    }
}
