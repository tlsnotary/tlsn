use tls_core::{
    key::PublicKey,
    msgs::{handshake::Random, message::PlainMessage},
};

use async_trait::async_trait;

use crate::cipher::{MessageDecrypter, MessageEncrypter};

#[async_trait]
pub trait Handshake: Send + Sync {
    type Error;
    /// Returns client_random value
    async fn client_random(&mut self) -> Result<Random, Self::Error>;
    /// Returns public client keyshare
    async fn client_key_share(&mut self) -> Result<PublicKey, Self::Error>;
    /// Sets server random
    async fn set_server_random(&mut self, random: Random) -> Result<(), Self::Error>;
    /// Sets server keyshare
    async fn set_server_key_share(&mut self, key: PublicKey) -> Result<(), Self::Error>;
    /// Sets handshake hash at ServerHello
    async fn set_hs_hash_server_hello(&mut self, hash: &[u8]) -> Result<(), Self::Error>;
    /// Returns expected ServerFinished verify_data
    async fn server_finished(&mut self, hash: &[u8]) -> Result<Vec<u8>, Self::Error>;
    /// Returns ClientFinished verify_data
    async fn client_finished(&mut self, hash: &[u8]) -> Result<Vec<u8>, Self::Error>;
    /// Returns initialized MessageEncrypter
    async fn message_encrypter(
        &mut self,
    ) -> Result<Box<dyn MessageEncrypter<Error = Self::Error>>, Self::Error>;
    /// Returns initialized MessageDecrypter
    async fn message_decrypter(
        &mut self,
    ) -> Result<Box<dyn MessageDecrypter<Error = Self::Error>>, Self::Error>;
}
