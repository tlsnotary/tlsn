use async_trait::async_trait;
use futures::{AsyncRead, AsyncWrite};
use tls_client::{Crypto, DecryptMode, EncryptMode, Error, ProtocolVersion, SupportedCipherSuite};
use tls_core::{
    key::PublicKey,
    msgs::{
        handshake::Random,
        message::{OpaqueMessage, PlainMessage},
    },
};

/// CryptoMaster implements the TLS Crypto trait using 2PC protocols.
pub struct CryptoMaster<S> {
    /// Stream connection to [`CryptoSlave`]
    stream: S,
}

impl<S> CryptoMaster<S>
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
impl<S> Crypto for CryptoMaster<S>
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
    fn set_encrypt(&mut self, _mode: EncryptMode) -> Result<(), Error> {
        todo!()
    }
    fn set_decrypt(&mut self, _mode: DecryptMode) -> Result<(), Error> {
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
    async fn set_hs_hash_client_key_exchange(&mut self, _hash: &[u8]) -> Result<(), Error> {
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
    async fn encrypt(&mut self, _m: PlainMessage, _seq: u64) -> Result<OpaqueMessage, Error> {
        todo!()
    }
    async fn decrypt(&mut self, _m: OpaqueMessage, _seq: u64) -> Result<PlainMessage, Error> {
        todo!()
    }
}
