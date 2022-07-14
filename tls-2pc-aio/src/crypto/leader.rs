use async_trait::async_trait;
use futures::{AsyncRead, AsyncWrite};
use p256::SecretKey;
use rand::rngs::OsRng;
use rand::{thread_rng, Rng};
use std::sync::Arc;
use typed_builder::TypedBuilder;

use super::Error;
use mpc_aio::point_addition::{PointAddition2PC, SecretShare};
use tls_client::{
    Crypto, DecryptMode, EncryptMode, Error as ClientError, ProtocolVersion, SupportedCipherSuite,
};
use tls_core::key::PublicKey;
use tls_core::msgs::handshake::Random;
use tls_core::msgs::message::{OpaqueMessage, PlainMessage};

/// CryptoLeader implements the TLS Crypto trait using 2PC protocols.
pub struct CryptoLeader<S, PA> {
    /// Stream connection to [`CryptoSlave`]
    stream: S,
    state: State,
    config: Arc<Config>,
    point_addition: PA,

    client_random: Option<Random>,
    server_random: Option<Random>,

    pms_share: Option<SecretShare>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum State {
    Initialized,
    Setup,
}

/// Configuration for [`CryptoLeader`].
/// TLS protocol version and ciphersuite must be known prior to the connection.
/// This is to allow for heavy setup operations to take place in the offline phase.
#[derive(TypedBuilder)]
pub struct Config {
    protocol_version: ProtocolVersion,
    cipher_suite: SupportedCipherSuite,
}

impl<S, PA> CryptoLeader<S, PA>
where
    S: AsyncWrite + AsyncRead + Send,
    PA: PointAddition2PC,
{
    pub fn new(stream: S, config: Arc<Config>, point_addition: PA) -> Self {
        Self {
            stream,
            state: State::Initialized,
            config,
            point_addition,
            client_random: None,
            server_random: None,
            pms_share: None,
        }
    }

    /// Perform setup for 2PC sub-protocols
    pub async fn setup(&mut self) -> Result<(), Error> {
        if self.state != State::Initialized {
            return Err(Error::AlreadySetup);
        }

        let sk = SecretKey::random(&mut OsRng);
        let pk = sk.public_key();

        Ok(())
    }
}

#[async_trait]
impl<S, PA> Crypto for CryptoLeader<S, PA>
where
    S: AsyncWrite + AsyncRead + Send,
    PA: PointAddition2PC + Send,
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
    use mpc_aio::point_addition::MockPointAddition2PC;
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

        let mut master = CryptoLeader::new(
            DummyStream,
            Arc::new(config),
            MockPointAddition2PC::default(),
        );

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

        let mut master = CryptoLeader::new(
            DummyStream,
            Arc::new(config),
            MockPointAddition2PC::default(),
        );

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
