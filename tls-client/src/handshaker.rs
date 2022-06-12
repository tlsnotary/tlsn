use crate::Error;
use tls_core::msgs::handshake::Random;
use tls_core::{key::PublicKey, suites::SupportedCipherSuite};

use async_trait::async_trait;

use crate::cipher::{MessageDecrypter, MessageEncrypter};

#[async_trait]
pub trait Handshake: Send + Sync {
    fn suite(&self) -> Result<SupportedCipherSuite, Error>;
    /// Returns client_random value
    async fn client_random(&mut self) -> Result<Random, Error>;
    /// Returns public client keyshare
    async fn client_key_share(&mut self) -> Result<PublicKey, Error>;
    /// Sets server random
    async fn set_server_random(&mut self, random: Random) -> Result<(), Error>;
    /// Sets server keyshare
    async fn set_server_key_share(&mut self, key: PublicKey) -> Result<(), Error>;
    /// Sets handshake hash at ServerHello
    async fn set_hs_hash_server_hello(&mut self, hash: &[u8]) -> Result<(), Error>;
    /// Returns expected ServerFinished verify_data
    async fn server_finished(&mut self, hash: &[u8]) -> Result<Vec<u8>, Error>;
    /// Returns ClientFinished verify_data
    async fn client_finished(&mut self, hash: &[u8]) -> Result<Vec<u8>, Error>;
    /// Returns initialized MessageEncrypter
    async fn message_encrypter(&mut self) -> Result<Box<dyn MessageEncrypter>, Error>;
    /// Returns initialized MessageDecrypter
    async fn message_decrypter(&mut self) -> Result<Box<dyn MessageDecrypter>, Error>;
}

pub struct InvalidHandShaker {}

#[async_trait]
impl Handshake for InvalidHandShaker {
    fn suite(&self) -> Result<SupportedCipherSuite, Error> {
        Err(Error::General("handshaker not yet available".to_string()))
    }
    async fn client_random(&mut self) -> Result<Random, Error> {
        Err(Error::General("handshaker not yet available".to_string()))
    }
    async fn client_key_share(&mut self) -> Result<PublicKey, Error> {
        Err(Error::General("handshaker not yet available".to_string()))
    }
    async fn set_server_random(&mut self, _random: Random) -> Result<(), Error> {
        Err(Error::General("handshaker not yet available".to_string()))
    }
    async fn set_server_key_share(&mut self, _key: PublicKey) -> Result<(), Error> {
        Err(Error::General("handshaker not yet available".to_string()))
    }
    async fn set_hs_hash_server_hello(&mut self, _hash: &[u8]) -> Result<(), Error> {
        Err(Error::General("handshaker not yet available".to_string()))
    }
    async fn server_finished(&mut self, _hash: &[u8]) -> Result<Vec<u8>, Error> {
        Err(Error::General("handshaker not yet available".to_string()))
    }
    async fn client_finished(&mut self, _hash: &[u8]) -> Result<Vec<u8>, Error> {
        Err(Error::General("handshaker not yet available".to_string()))
    }
    async fn message_encrypter(&mut self) -> Result<Box<dyn MessageEncrypter>, Error> {
        Err(Error::General("handshaker not yet available".to_string()))
    }
    async fn message_decrypter(&mut self) -> Result<Box<dyn MessageDecrypter>, Error> {
        Err(Error::General("handshaker not yet available".to_string()))
    }
}
