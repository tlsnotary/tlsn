use async_trait::async_trait;
use futures::{AsyncRead, AsyncWrite};
use p256::ecdh::EphemeralSecret;
use p256::SecretKey;
use rand::rngs::OsRng;
use rand::{thread_rng, Rng};
use std::sync::Arc;
use typed_builder::TypedBuilder;

use super::Error;
use tls_client::{
    Crypto, DecryptMode, EncryptMode, Error as ClientError, ProtocolVersion, SupportedCipherSuite,
};
use tls_core::key::PublicKey;
use tls_core::msgs::handshake::Random;
use tls_core::msgs::message::{OpaqueMessage, PlainMessage};

/// CryptoMaster implements the TLS Crypto trait using 2PC protocols.
pub struct CryptoMaster<S> {
    /// Stream connection to [`CryptoSlave`]
    stream: S,
    state: State,
    config: Arc<Config>,

    client_random: Option<Random>,
    server_random: Option<Random>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum State {
    Initialized,
    Setup,
}

/// Configuration for [`CryptoMaster`].
/// TLS protocol version and ciphersuite must be known prior to the connection.
/// This is to allow for heavy setup operations to take place in the offline phase.
#[derive(TypedBuilder)]
pub struct Config {
    protocol_version: ProtocolVersion,
    cipher_suite: SupportedCipherSuite,
}

impl<S> CryptoMaster<S>
where
    S: AsyncWrite + AsyncRead + Send,
{
    pub fn new(stream: S, config: Arc<Config>) -> Self {
        Self {
            stream,
            state: State::Initialized,
            config,
            client_random: None,
            server_random: None,
        }
    }

    /// Perform setup for 2PC sub-protocols
    pub async fn setup(&mut self) -> Result<(), Error> {
        if self.state != State::Initialized {
            return Err(Error::AlreadySetup);
        }

        let sk = EphemeralSecret::random(&mut OsRng);
        Ok(())
    }
}

#[async_trait]
impl<S> Crypto for CryptoMaster<S>
where
    S: AsyncWrite + AsyncRead + Send,
{
    fn select_protocol_version(&mut self, version: ProtocolVersion) -> Result<(), ClientError> {
        if version == self.config.protocol_version {
            Ok(())
        } else {
            Err(ClientError::PeerIncompatibleError(format!(
                "peer selected unsupported version: {:?}",
                version
            )))
        }
    }

    fn select_cipher_suite(&mut self, suite: SupportedCipherSuite) -> Result<(), ClientError> {
        if suite == self.config.cipher_suite {
            Ok(())
        } else {
            Err(ClientError::PeerIncompatibleError(format!(
                "peer selected unsupported ciphersuite: {:?}",
                suite
            )))
        }
    }

    fn suite(&self) -> Result<SupportedCipherSuite, ClientError> {
        todo!()
    }

    fn set_encrypt(&mut self, _mode: EncryptMode) -> Result<(), ClientError> {
        todo!()
    }

    fn set_decrypt(&mut self, _mode: DecryptMode) -> Result<(), ClientError> {
        todo!()
    }

    async fn client_random(&mut self) -> Result<Random, ClientError> {
        // generate client random and store it
        let r = Random(thread_rng().gen());
        self.client_random = Some(r);
        Ok(r)
    }

    async fn client_key_share(&mut self) -> Result<PublicKey, ClientError> {
        todo!()
    }

    async fn set_server_random(&mut self, _random: Random) -> Result<(), ClientError> {
        todo!()
    }

    async fn set_server_key_share(&mut self, _key: PublicKey) -> Result<(), ClientError> {
        todo!()
    }

    async fn set_hs_hash_client_key_exchange(&mut self, _hash: &[u8]) -> Result<(), ClientError> {
        todo!()
    }

    async fn set_hs_hash_server_hello(&mut self, _hash: &[u8]) -> Result<(), ClientError> {
        todo!()
    }

    async fn server_finished(&mut self, _hash: &[u8]) -> Result<Vec<u8>, ClientError> {
        todo!()
    }

    async fn client_finished(&mut self, _hash: &[u8]) -> Result<Vec<u8>, ClientError> {
        todo!()
    }

    async fn encrypt(&mut self, _m: PlainMessage, _seq: u64) -> Result<OpaqueMessage, ClientError> {
        todo!()
    }

    async fn decrypt(&mut self, _m: OpaqueMessage, _seq: u64) -> Result<PlainMessage, ClientError> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use tls_core::suites::{TLS13_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256};

    use super::*;

    pub struct DummyStream;
    impl AsyncWrite for DummyStream {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            unimplemented!()
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            unimplemented!()
        }

        fn poll_close(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            unimplemented!()
        }
    }
    impl AsyncRead for DummyStream {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &mut [u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            unimplemented!()
        }
    }

    #[test]
    fn test_select_protocol_version() {
        let config = Config::builder()
            .protocol_version(ProtocolVersion::TLSv1_2)
            .cipher_suite(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
            .build();

        let mut master = CryptoMaster::new(DummyStream, Arc::new(config));

        assert!(matches!(
            master.select_protocol_version(ProtocolVersion::TLSv1_0),
            Err(ClientError::PeerIncompatibleError(_))
        ));
        assert!(matches!(
            master.select_protocol_version(ProtocolVersion::TLSv1_2),
            Ok(())
        ));
    }

    #[test]
    fn test_select_cipher_suite() {
        let config = Config::builder()
            .protocol_version(ProtocolVersion::TLSv1_2)
            .cipher_suite(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
            .build();

        let mut master = CryptoMaster::new(DummyStream, Arc::new(config));

        assert!(matches!(
            master.select_cipher_suite(TLS13_AES_128_GCM_SHA256),
            Err(ClientError::PeerIncompatibleError(_))
        ));
        assert!(matches!(
            master.select_cipher_suite(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
            Ok(())
        ));
    }
}
