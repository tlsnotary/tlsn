use tls_core::msgs::{
    handshake::{KeyShareEntry, Random},
    message::OpaqueMessage,
};

use async_trait::async_trait;

use crate::cipher::{MessageDecrypter, MessageEncrypter};

#[async_trait]
pub trait Handshake: Send + Sync {
    type Error;
    /// Returns client_random value
    async fn client_random(&mut self) -> Result<Random, Self::Error>;
    /// Returns public client keyshare
    async fn initial_key_share(&mut self) -> Result<KeyShareEntry, Self::Error>;
    /// Receives server random
    async fn receive_server_random(&mut self, random: Random) -> Result<(), Self::Error>;
    /// Receives server keyshare
    async fn receive_server_key_share(&mut self, key: KeyShareEntry) -> Result<(), Self::Error>;
    /// Receive handshake hash at ServerHello
    async fn receive_hs_hash_server_hello(&mut self, hash: &[u8]) -> Result<(), Self::Error>;
    /// Returns expected ServerFinished
    async fn server_finished(&mut self, hash: &[u8]) -> Result<Vec<u8>, Self::Error>;
    /// Returns ClientFinished
    async fn client_finished(&mut self, hash: &[u8]) -> Result<OpaqueMessage, Self::Error>;
    /// Returns initialized MessageEncrypter
    async fn message_encrypter(
        &mut self,
    ) -> Result<Box<dyn MessageEncrypter<Error = Self::Error>>, Self::Error>;
    /// Returns initialized MessageDecrypter
    async fn message_decrypter(
        &mut self,
    ) -> Result<Box<dyn MessageDecrypter<Error = Self::Error>>, Self::Error>;
}
