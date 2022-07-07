use futures::{AsyncRead, AsyncWrite};
use std::sync::Arc;

use tls_client::{ClientConnection, ServerName};

use super::builder::MasterConfig as Config;
use crate::Error;

pub enum State {
    Initialized,
}

pub struct ConnectionMaster<S> {
    config: Arc<Config>,
    state: State,
    client: ClientConnection,
    slave_conn: S,
}

impl<S> ConnectionMaster<S>
where
    S: AsyncWrite + AsyncRead,
{
    pub fn new(config: Arc<Config>, server_name: ServerName, slave_conn: S) -> Result<Self, Error> {
        let client_config = config.client.clone();
        Ok(Self {
            config,
            state: State::Initialized,
            client: ClientConnection::new(client_config, server_name)?,
            slave_conn,
        })
    }

    /// Setup all possible 2PC protocols prior to connecting to Server.
    /// Probes Server for supported ciphersuites if configured.
    pub async fn setup(&mut self) -> Result<(), Error> {
        todo!()
    }

    /// Runs TLS handshake with Server to completion
    pub async fn complete_handshake(&mut self) -> Result<(), Error> {
        todo!()
    }

    /// Sends application payload to Server
    pub async fn send(&mut self, _payload: &[u8]) -> Result<(), Error> {
        todo!()
    }
}
