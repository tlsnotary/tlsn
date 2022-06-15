use async_trait::async_trait;
use futures::{AsyncRead, AsyncWrite};
use tls_client::{
    Error, Handshake, MessageDecrypter, MessageEncrypter, ProtocolVersion, SupportedCipherSuite,
};
use tls_core::key::PublicKey;
use tls_core::msgs::handshake::Random;

/// HandshakeMaster implements the TLS handshake trait using 2PC protocols.
pub struct HandshakeMaster<S> {
    /// Stream connection to [`HandshakeSlave`]
    stream: S,
}

impl<S> HandshakeMaster<S>
where
    S: AsyncWrite + AsyncRead + Send,
{
    pub fn new(stream: S) -> Self {
        Self { stream }
    }

    /// Perform setup for 2PC sub-protocols
    pub async fn setup(&mut self) {
        todo!()
    }
}

#[async_trait]
impl<S> Handshake for HandshakeMaster<S>
where
    S: AsyncWrite + AsyncRead + Send,
{
    fn select_protocol_version(&mut self, _version: ProtocolVersion) -> Result<(), Error> {
        todo!()
    }
    fn select_cipher_suite(&mut self, _suite: SupportedCipherSuite) -> Result<(), Error> {
        todo!()
    }
    fn suite(&self) -> Result<SupportedCipherSuite, Error> {
        todo!()
    }
    async fn client_random(&mut self) -> Result<Random, Error> {
        todo!()
    }
    async fn client_key_share(&mut self) -> Result<PublicKey, Error> {
        todo!()
    }
    async fn set_server_random(&mut self, _random: Random) -> Result<(), Error> {
        todo!()
    }
    async fn set_server_key_share(&mut self, _key: PublicKey) -> Result<(), Error> {
        todo!()
    }
    async fn set_hs_hash_server_hello(&mut self, _hash: &[u8]) -> Result<(), Error> {
        todo!()
    }
    async fn server_finished(&mut self, _hash: &[u8]) -> Result<Vec<u8>, Error> {
        todo!()
    }
    async fn client_finished(&mut self, _hash: &[u8]) -> Result<Vec<u8>, Error> {
        todo!()
    }
    async fn message_encrypter(&mut self) -> Result<Box<dyn MessageEncrypter>, Error> {
        todo!()
    }
    async fn message_decrypter(&mut self) -> Result<Box<dyn MessageDecrypter>, Error> {
        todo!()
    }
}
