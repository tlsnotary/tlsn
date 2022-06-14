use futures::{AsyncRead, AsyncWrite};
use std::sync::Arc;

use tls_client::{ClientConfig, ClientConnection, ServerName};

use super::builder::MasterConfig as Config;
use crate::Error;

pub enum State {
    Initialized,
}

pub struct ConnectionMaster<S> {
    state: State,
    client: ClientConnection,
    slave_conn: S,
}

impl<S> ConnectionMaster<S>
where
    S: AsyncWrite + AsyncRead,
{
    pub fn new(config: Arc<Config>, server_name: ServerName, slave_conn: S) -> Result<Self, Error> {
        Ok(Self {
            state: State::Initialized,
            client: ClientConnection::new(config.client.clone(), server_name)?,
            slave_conn,
        })
    }

    /// Setup all possible 2PC protocols prior to connecting to Server.
    /// Probes Server for supported ciphersuites if configured.
    pub fn setup(&mut self) -> Result<(), Error> {
        todo!()
    }

    /// Runs TLS handshake with Server to completion
    pub fn complete_handshake(&mut self) -> Result<(), Error> {
        todo!()
    }

    /// Sends application payload to Server
    pub fn send(&mut self, payload: &[u8]) -> Result<(), Error> {
        todo!()
    }
}
