use crate::{
    Error,
    deps::ProverZk,
    prover::client::{DecryptState, TlsClient, TlsOutput},
};
use mpc_tls::SessionKeys;
use mpz_common::Context;
use rustls::{ClientConfig, ClientConnection};
use std::{
    io::{Read, Write},
    sync::Arc,
};
use tlsn_core::connection::ServerName;
use tracing::Span;

pub(crate) struct ProxyTlsClient {
    conn: ClientConnection,
    ctx: Context,
    vm: ProverZk,
    decrypt: Arc<DecryptState>,
    client_closed: bool,
    server_closed: bool,
}

impl ProxyTlsClient {
    pub(crate) fn new(
        span: Span,
        keys: SessionKeys,
        vm: ProverZk,
        config: ClientConfig,
        server_name: ServerName,
    ) -> Self {
        todo!()
    }

    fn finalize(self) -> TlsOutput {
        todo!()
    }
}

impl TlsClient for ProxyTlsClient {
    type Error = Error;

    fn wants_read_tls(&self) -> bool {
        self.conn.wants_read()
    }

    fn wants_write_tls(&self) -> bool {
        self.conn.wants_write()
    }

    fn read_tls(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        let mut reader = buf;
        self.conn
            .read_tls(&mut reader)
            .map_err(|e| Error::internal().with_source(e))
    }

    fn write_tls(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let mut writer = buf as &mut [u8];
        self.conn
            .write_tls(&mut writer)
            .map_err(|e| Error::internal().with_source(e))
    }

    fn wants_read(&self) -> bool {
        !self.server_closed
    }

    fn wants_write(&self) -> bool {
        !self.client_closed
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        self.conn
            .reader()
            .read(buf)
            .map_err(|e| Error::internal().with_source(e))
    }

    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        self.conn
            .writer()
            .write(buf)
            .map_err(|e| Error::internal().with_source(e))
    }

    fn client_close(&mut self) {
        self.conn.send_close_notify();
        self.client_closed = true;
    }

    fn server_close(&mut self) {
        self.server_closed = true;
    }

    fn decrypt(&self) -> Arc<DecryptState> {
        self.decrypt.clone()
    }

    fn poll(
        &mut self,
        _cx: &mut std::task::Context,
    ) -> std::task::Poll<Result<super::TlsOutput, Self::Error>> {
        todo!()
    }
}
