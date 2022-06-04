use crate::Error;
use tls_aio::{
    cipher::{MessageDecrypter, MessageEncrypter},
    handshaker::Handshake,
};
use tls_core::msgs::{
    handshake::{KeyShareEntry, Random},
    message::OpaqueMessage,
};

use async_trait::async_trait;

pub struct InvalidHandShaker {}

#[async_trait]
impl Handshake for InvalidHandShaker {
    type Error = Error;
    async fn client_random(&mut self) -> Result<Random, Error> {
        Err(Error::General("handshaker not yet available".to_string()))
    }
    async fn initial_key_share(&mut self) -> Result<KeyShareEntry, Error> {
        Err(Error::General("handshaker not yet available".to_string()))
    }
    async fn receive_server_random(&mut self, _random: Random) -> Result<(), Self::Error> {
        Err(Error::General("handshaker not yet available".to_string()))
    }
    async fn receive_server_key_share(&mut self, _key: KeyShareEntry) -> Result<(), Self::Error> {
        Err(Error::General("handshaker not yet available".to_string()))
    }
    async fn receive_hs_hash_server_hello(&mut self, _hash: &[u8]) -> Result<(), Self::Error> {
        Err(Error::General("handshaker not yet available".to_string()))
    }
    async fn server_finished(&mut self, _hash: &[u8]) -> Result<Vec<u8>, Self::Error> {
        Err(Error::General("handshaker not yet available".to_string()))
    }
    async fn client_finished(&mut self, _hash: &[u8]) -> Result<OpaqueMessage, Self::Error> {
        Err(Error::General("handshaker not yet available".to_string()))
    }
    async fn message_encrypter(
        &mut self,
    ) -> Result<Box<dyn MessageEncrypter<Error = Self::Error>>, Self::Error> {
        Err(Error::General("handshaker not yet available".to_string()))
    }
    async fn message_decrypter(
        &mut self,
    ) -> Result<Box<dyn MessageDecrypter<Error = Self::Error>>, Self::Error> {
        Err(Error::General("handshaker not yet available".to_string()))
    }
}
