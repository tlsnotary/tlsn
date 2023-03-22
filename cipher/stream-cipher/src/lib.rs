//! This crate provides a 2PC stream cipher implementation using a block cipher in counter mode.
//!
//! Each party plays a specific role, either the `StreamCipherLeader` or the `StreamCipherFollower`. Both parties
//! work together to encrypt and decrypt messages using a shared key.
//!
//! # Transcript
//!
//! Using the `record` flag, the `StreamCipherFollower` can optionally use a dedicated stream when encoding the plaintext labels, which
//! allows the `StreamCipherLeader` to build a transcript of active labels which are pushed to the provided `TranscriptSink`.
//!
//! Afterwards, the `StreamCipherLeader` can create commitments to the transcript which can be used in a selective disclosure protocol.

pub mod cipher;
pub mod config;
pub(crate) mod counter_block;
mod counter_mode;
mod follower;
mod leader;
pub mod msg;
mod transcript;
mod utils;

pub use config::{
    Role, StreamCipherConfig, StreamCipherConfigBuilder, StreamCipherConfigBuilderError,
};
pub use follower::DEStreamCipherFollower;
pub use leader::DEStreamCipherLeader;
use msg::StreamCipherMessage;
pub use transcript::{MessageTranscript, TranscriptSink};

use utils_aio::Channel;

use std::sync::Arc;

use async_trait::async_trait;
use futures::lock::Mutex;

use mpc_garble_core::{ActiveLabels, ChaChaEncoder, FullLabels};

pub type StreamCipherChannel =
    Box<dyn Channel<StreamCipherMessage, Error = std::io::Error> + Send + Sync + Unpin>;

#[derive(Debug, thiserror::Error)]
pub enum StreamCipherError {
    #[error("IO Error: {0:?}")]
    IOError(#[from] std::io::Error),
    #[error("Muxer error: {0:?}")]
    MuxerError(#[from] utils_aio::mux::MuxerError),
    #[error("GCFactoryError: {0:?}")]
    GCFactoryError(#[from] mpc_garble::factory::GCFactoryError),
    #[error("GCError: {0:?}")]
    GCError(#[from] mpc_garble::GCError),
    #[error("Keys are not set")]
    KeysNotSet,
    #[error("Encoder is not set")]
    EncoderNotSet,
    #[error("Follower sent incorrect number of plaintext labels: expected {0}, got {1}")]
    IncorrectLabelCount(usize, usize),
    #[error("Unexpected message: {0:?}")]
    UnexpectedMessage(StreamCipherMessage),
}

#[async_trait]
pub trait StreamCipherLeader<Cipher>
where
    Cipher: crate::cipher::CtrCircuitSuite,
{
    /// Sets the key input labels for the stream cipher.
    ///
    /// * `labels`: The labels to use for the key input.
    fn set_keys(&mut self, labels: StreamCipherLabels);

    /// Sets the encoder used to generate the input labels
    /// used during 2PC.
    fn set_encoder(&mut self, encoder: Arc<Mutex<ChaChaEncoder>>);

    /// Sets transcript sink
    fn set_transcript_sink(&mut self, sink: TranscriptSink);

    /// Applies the keystream to the given plaintext, where both parties
    /// provide the plaintext as an input.
    ///
    /// * `explicit_nonce`: The explicit nonce to use for the keystream.
    /// * `plaintext`: The message to apply the keystream to.
    /// * `record`: Whether to record the message in the transcript.
    async fn encrypt_public(
        &mut self,
        explicit_nonce: Vec<u8>,
        plaintext: Vec<u8>,
        record: bool,
    ) -> Result<Vec<u8>, StreamCipherError>;

    /// Applies the keystream to the given plaintext without revealing it
    /// to the other party.
    ///
    /// * `explicit_nonce`: The explicit nonce to use for the keystream.
    /// * `plaintext`: The message to apply the keystream to.
    /// * `record`: Whether to record the message in the transcript.
    async fn encrypt_private(
        &mut self,
        explicit_nonce: Vec<u8>,
        plaintext: Vec<u8>,
        record: bool,
    ) -> Result<Vec<u8>, StreamCipherError>;

    /// Decrypts a ciphertext by removing the keystream, where the plaintext
    /// is revealed to both parties.
    ///
    /// * `explicit_nonce`: The explicit nonce to use for the keystream.
    /// * `ciphertext`: The ciphertext to decrypt.
    /// * `record`: Whether to record the message in the transcript.
    async fn decrypt_public(
        &mut self,
        explicit_nonce: Vec<u8>,
        ciphertext: Vec<u8>,
        record: bool,
    ) -> Result<Vec<u8>, StreamCipherError>;

    /// Decrypts a ciphertext by removing the keystream, where the plaintext
    /// is not revealed to the `StreamCipherFollower`.
    ///
    /// * `explicit_nonce`: The explicit nonce to use for the keystream.
    /// * `ciphertext`: The ciphertext to decrypt.
    /// * `record`: Whether to record the message in the transcript.
    async fn decrypt_private(
        &mut self,
        explicit_nonce: Vec<u8>,
        ciphertext: Vec<u8>,
        record: bool,
    ) -> Result<Vec<u8>, StreamCipherError>;

    /// Computes XOR shares of a keystream block.
    ///
    /// Returns the leader's XOR share of the keystream block.
    ///
    /// * `explicit_nonce`: The explicit nonce to use for the keystream block.
    /// * `ctr`: The counter to use for the keystream block.
    async fn share_keystream_block(
        &mut self,
        explicit_nonce: Vec<u8>,
        ctr: u32,
    ) -> Result<Vec<u8>, StreamCipherError>;
}

#[async_trait]
pub trait StreamCipherFollower<Cipher>
where
    Cipher: crate::cipher::CtrCircuitSuite,
{
    /// Sets the key input labels for the stream cipher.
    ///
    /// * `labels`: The labels to use for the key input.
    fn set_keys(&mut self, labels: StreamCipherLabels);

    /// Sets the encoder used to generate the input labels
    /// used during 2PC.
    fn set_encoder(&mut self, encoder: Arc<Mutex<ChaChaEncoder>>);

    /// Applies the keystream to the given plaintext, where both parties
    /// provide the plaintext as an input.
    ///
    /// * `explicit_nonce`: The explicit nonce to use for the keystream.
    /// * `plaintext`: The message to apply the keystream to.
    /// * `record`: Whether to record the message in the transcript.
    async fn encrypt_public(
        &mut self,
        explicit_nonce: Vec<u8>,
        plaintext: Vec<u8>,
        record: bool,
    ) -> Result<Vec<u8>, StreamCipherError>;

    /// Applies the keystream to a plaintext provided by the `StreamCipherLeader`.
    ///
    /// * `explicit_nonce`: The explicit nonce to use for the keystream.
    /// * `len`: The length of the plaintext provided by the other party.
    /// * `record`: Whether to record the message in the transcript.
    async fn encrypt_blind(
        &mut self,
        explicit_nonce: Vec<u8>,
        len: usize,
        record: bool,
    ) -> Result<Vec<u8>, StreamCipherError>;

    /// Decrypts a ciphertext by removing the keystream, where the plaintext
    /// is revealed to both parties.
    ///
    /// * `explicit_nonce`: The explicit nonce to use for the keystream.
    /// * `ciphertext`: The ciphertext to decrypt.
    /// * `record`: Whether to record the message in the transcript.
    async fn decrypt_public(
        &mut self,
        explicit_nonce: Vec<u8>,
        ciphertext: Vec<u8>,
        record: bool,
    ) -> Result<Vec<u8>, StreamCipherError>;

    /// Decrypts a ciphertext by removing the keystream, where the plaintext
    /// is only revealed to the `StreamCipherLeader`.
    ///
    /// * `explicit_nonce`: The explicit nonce to use for the keystream.
    /// * `ciphertext`: The ciphertext to decrypt.
    /// * `record`: Whether to record the message in the transcript.
    async fn decrypt_blind(
        &mut self,
        explicit_nonce: Vec<u8>,
        ciphertext: Vec<u8>,
        record: bool,
    ) -> Result<(), StreamCipherError>;

    /// Computes XOR shares of a keystream block.
    ///
    /// Returns the follower's share of the keystream block.
    ///
    /// * `explicit_nonce`: The explicit nonce to use for the keystream block.
    /// * `ctr`: The counter to use for the keystream block.
    async fn share_keystream_block(
        &mut self,
        explicit_nonce: Vec<u8>,
        ctr: u32,
    ) -> Result<Vec<u8>, StreamCipherError>;
}

#[derive(Clone)]
pub struct StreamCipherLabels {
    pub key_full: FullLabels,
    pub key_active: ActiveLabels,
    pub iv_full: FullLabels,
    pub iv_active: ActiveLabels,
}

impl StreamCipherLabels {
    /// Creates a new set of input labels for the stream cipher.
    pub fn new(
        key_full: FullLabels,
        key_active: ActiveLabels,
        iv_full: FullLabels,
        iv_active: ActiveLabels,
    ) -> Self {
        Self {
            key_full,
            key_active,
            iv_full,
            iv_active,
        }
    }

    /// Returns the full labels for the key input.
    pub fn get_key_full(&self) -> &FullLabels {
        &self.key_full
    }

    /// Returns the active labels for the key input.
    pub fn get_key_active(&self) -> &ActiveLabels {
        &self.key_active
    }

    /// Returns the full labels for the IV input.
    pub fn get_iv_full(&self) -> &FullLabels {
        &self.iv_full
    }

    /// Returns the active labels for the IV input.
    pub fn get_iv_active(&self) -> &ActiveLabels {
        &self.iv_active
    }
}

#[cfg(feature = "mock")]
pub mod mock {
    use super::*;

    use crate::cipher::CtrCircuitSuite;
    use cipher_circuits::AES_CTR;
    use mpc_circuits::{BitOrder, Value};
    use mpc_garble::{
        exec::{
            dual::mock::{MockDualExFollower, MockDualExLeader},
            zk::mock::{MockProver, MockVerifier},
        },
        factory::{
            dual::mock::{create_mock_dualex_factory, MockDualExFactory},
            zk::mock::{create_mock_zk_factory_pair, MockProverFactory, MockVerifierFactory},
        },
    };
    use mpc_garble_core::Encoder;
    use utils_aio::duplex::DuplexChannel;

    pub type MockStreamCipherLeader<C> =
        DEStreamCipherLeader<C, MockDualExFactory, MockDualExLeader, MockProverFactory, MockProver>;

    pub type MockStreamCipherFollower<C> = DEStreamCipherFollower<
        C,
        MockDualExFactory,
        MockDualExFollower,
        MockVerifierFactory,
        MockVerifier,
    >;

    pub fn create_mock_stream_cipher_pair<C: CtrCircuitSuite>(
        leader_config: StreamCipherConfig,
        follower_config: StreamCipherConfig,
    ) -> (MockStreamCipherLeader<C>, MockStreamCipherFollower<C>) {
        let (leader_channel, follower_channel) = DuplexChannel::new();
        let de_factory = create_mock_dualex_factory();
        let (prover_factory, verifier_factory) = create_mock_zk_factory_pair();

        let leader = DEStreamCipherLeader::new(
            leader_config,
            Box::new(leader_channel),
            de_factory.clone(),
            prover_factory,
        );

        let follower = DEStreamCipherFollower::new(
            follower_config,
            Box::new(follower_channel),
            de_factory.clone(),
            verifier_factory,
        );

        (leader, follower)
    }

    pub fn create_mock_labels(
        key: Vec<u8>,
        iv: Vec<u8>,
    ) -> (
        (ChaChaEncoder, StreamCipherLabels),
        (ChaChaEncoder, StreamCipherLabels),
    ) {
        let circ = AES_CTR.clone();

        let mut leader_encoder = ChaChaEncoder::new([0; 32], BitOrder::Msb0);
        let leader_full_key = leader_encoder.encode(1, &circ.input(0).unwrap());
        let leader_full_iv = leader_encoder.encode(1, &circ.input(1).unwrap());

        let mut follower_encoder = ChaChaEncoder::new([1; 32], BitOrder::Msb0);
        let follower_full_key = follower_encoder.encode(1, &circ.input(0).unwrap());
        let follower_full_iv = follower_encoder.encode(1, &circ.input(1).unwrap());

        let leader_labels = StreamCipherLabels {
            key_full: leader_full_key.clone(),
            key_active: follower_full_key
                .select(&Value::Bytes(key.clone()), BitOrder::Msb0)
                .unwrap(),
            iv_full: leader_full_iv.clone(),
            iv_active: follower_full_iv
                .select(&Value::Bytes(iv.clone()), BitOrder::Msb0)
                .unwrap(),
        };

        let follower_labels = StreamCipherLabels {
            key_full: follower_full_key.clone(),
            key_active: leader_full_key
                .select(&Value::Bytes(key), BitOrder::Msb0)
                .unwrap(),
            iv_full: follower_full_iv.clone(),
            iv_active: leader_full_iv
                .select(&Value::Bytes(iv), BitOrder::Msb0)
                .unwrap(),
        };

        (
            (leader_encoder, leader_labels),
            (follower_encoder, follower_labels),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::*;

    use crate::cipher::Aes128Ctr;
    use ::cipher::{KeyIvInit, StreamCipher};
    use aes::Aes128;
    use ctr::Ctr32BE;
    use futures::{channel::mpsc::Receiver, SinkExt, StreamExt};
    use rstest::*;
    use std::time::Duration;

    type TestAes128Ctr = Ctr32BE<Aes128>;

    fn aes_ctr(key: &[u8; 16], iv: &[u8; 4], explicit_nonce: &[u8; 8], msg: &[u8]) -> Vec<u8> {
        let mut full_iv = [0u8; 16];
        full_iv[0..4].copy_from_slice(iv);
        full_iv[4..12].copy_from_slice(explicit_nonce);
        full_iv[15] = 1;
        let mut cipher = TestAes128Ctr::new(key.into(), &full_iv.into());
        let mut buf = msg.to_vec();
        cipher.apply_keystream(&mut buf);
        buf
    }

    fn create_test_pair(
        key: [u8; 16],
        iv: [u8; 4],
    ) -> (
        (
            MockStreamCipherLeader<Aes128Ctr>,
            Receiver<MessageTranscript>,
        ),
        MockStreamCipherFollower<Aes128Ctr>,
    ) {
        let leader_config = StreamCipherConfigBuilder::default()
            .id("test".to_string())
            .start_ctr(1)
            .build()
            .unwrap();
        let follower_config = StreamCipherConfigBuilder::default()
            .id("test".to_string())
            .start_ctr(1)
            .build()
            .unwrap();

        let ((leader_encoder, leader_labels), (follower_encoder, follower_labels)) =
            create_mock_labels(key.to_vec(), iv.to_vec());

        let (transcript_sink, transcript_stream) = futures::channel::mpsc::channel(100);

        let (mut leader, mut follower) =
            create_mock_stream_cipher_pair::<Aes128Ctr>(leader_config, follower_config);

        leader.set_keys(leader_labels);
        leader.set_encoder(Arc::new(Mutex::new(leader_encoder)));
        leader.set_transcript_sink(Box::new(transcript_sink.sink_map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "TranscriptSink closed unexpectedly",
            )
        })));
        follower.set_keys(follower_labels);
        follower.set_encoder(Arc::new(Mutex::new(follower_encoder)));

        ((leader, transcript_stream), follower)
    }

    #[rstest]
    #[timeout(Duration::from_millis(5000))]
    #[tokio::test]
    async fn test_stream_cipher_public() {
        let key = [0u8; 16];
        let iv = [0u8; 4];
        let explicit_nonce = [0u8; 8];

        let msg = b"This is a test message which will be encrypted using AES-CTR.".to_vec();

        let ((mut leader, mut transcript_stream), mut follower) = create_test_pair(key, iv);

        let leader_fut = async {
            let leader_encrypted_msg = leader
                .encrypt_public(explicit_nonce.to_vec(), msg.clone(), true)
                .await
                .unwrap();

            let leader_decrypted_msg = leader
                .decrypt_public(explicit_nonce.to_vec(), leader_encrypted_msg.clone(), false)
                .await
                .unwrap();

            (leader_encrypted_msg, leader_decrypted_msg)
        };

        let follower_fut = async {
            let follower_encrypted_msg = follower
                .encrypt_public(explicit_nonce.to_vec(), msg.clone(), true)
                .await
                .unwrap();

            let follower_decrypted_msg = follower
                .decrypt_public(
                    explicit_nonce.to_vec(),
                    follower_encrypted_msg.clone(),
                    false,
                )
                .await
                .unwrap();

            (follower_encrypted_msg, follower_decrypted_msg)
        };

        let (
            (leader_encrypted_msg, leader_decrypted_msg),
            (follower_encrypted_msg, follower_decrypted_msg),
        ) = futures::join!(leader_fut, follower_fut);

        let reference = aes_ctr(&key, &iv, &explicit_nonce, &msg);

        assert_eq!(leader_encrypted_msg, reference);
        assert_eq!(leader_decrypted_msg, msg);
        assert_eq!(follower_encrypted_msg, reference);
        assert_eq!(follower_decrypted_msg, msg);

        let leader_transcript = transcript_stream.next().await.unwrap();

        assert_eq!(leader_transcript.get_plaintext(), msg);
        assert_eq!(leader_transcript.get_ciphertext(), reference);
    }

    #[rstest]
    #[timeout(Duration::from_millis(5000))]
    #[tokio::test]
    async fn test_stream_cipher_private() {
        let key = [0u8; 16];
        let iv = [0u8; 4];
        let explicit_nonce = [1u8; 8];

        let msg = b"This is a test message which will be encrypted using AES-CTR.".to_vec();

        let ciphertext = aes_ctr(&key, &iv, &explicit_nonce, &msg);

        let ((mut leader, mut transcript_stream), mut follower) = create_test_pair(key, iv);

        let leader_fut = async {
            let leader_decrypted_msg = leader
                .decrypt_private(explicit_nonce.to_vec(), ciphertext.clone(), true)
                .await
                .unwrap();

            let leader_encrypted_msg = leader
                .encrypt_private(explicit_nonce.to_vec(), leader_decrypted_msg.clone(), true)
                .await
                .unwrap();

            (leader_encrypted_msg, leader_decrypted_msg)
        };

        let follower_fut = async {
            follower
                .decrypt_blind(explicit_nonce.to_vec(), ciphertext.clone(), true)
                .await
                .unwrap();

            let follower_encrypted_msg = follower
                .encrypt_blind(explicit_nonce.to_vec(), msg.len(), true)
                .await
                .unwrap();

            follower_encrypted_msg
        };

        let ((leader_encrypted_msg, leader_decrypted_msg), follower_encrypted_msg) =
            futures::join!(leader_fut, follower_fut);

        assert_eq!(leader_encrypted_msg, ciphertext);
        assert_eq!(leader_decrypted_msg, msg);
        assert_eq!(follower_encrypted_msg, ciphertext);

        let leader_transcript_0 = transcript_stream.next().await.unwrap();
        let leader_transcript_1 = transcript_stream.next().await.unwrap();

        assert_eq!(leader_transcript_0.get_plaintext(), msg);
        assert_eq!(leader_transcript_0.get_ciphertext(), ciphertext);

        assert_eq!(leader_transcript_1.get_plaintext(), msg);
        assert_eq!(leader_transcript_1.get_ciphertext(), ciphertext);
    }

    #[rstest]
    #[timeout(Duration::from_millis(5000))]
    #[tokio::test]
    async fn test_stream_cipher_share_key_block() {
        let leader_config = StreamCipherConfigBuilder::default()
            .id("test".to_string())
            .start_ctr(1)
            .build()
            .unwrap();
        let follower_config = StreamCipherConfigBuilder::default()
            .id("test".to_string())
            .start_ctr(1)
            .build()
            .unwrap();

        let key = [0u8; 16];
        let iv = [0u8; 4];
        let explicit_nonce = [0u8; 8];

        let (mut leader, mut follower) =
            create_mock_stream_cipher_pair::<Aes128Ctr>(leader_config, follower_config);

        let ((leader_encoder, leader_labels), (follower_encoder, follower_labels)) =
            create_mock_labels(key.to_vec(), iv.to_vec());

        leader.set_keys(leader_labels);
        leader.set_encoder(Arc::new(Mutex::new(leader_encoder)));
        follower.set_keys(follower_labels);
        follower.set_encoder(Arc::new(Mutex::new(follower_encoder)));

        let leader_fut = async {
            leader
                .share_keystream_block(explicit_nonce.to_vec(), 1)
                .await
                .unwrap()
        };

        let follower_fut = async {
            follower
                .share_keystream_block(explicit_nonce.to_vec(), 1)
                .await
                .unwrap()
        };

        let (leader_share, follower_share) = futures::join!(leader_fut, follower_fut);

        let key_block = leader_share
            .into_iter()
            .zip(follower_share)
            .map(|(a, b)| a ^ b)
            .collect::<Vec<u8>>();

        let reference = aes_ctr(&key, &iv, &explicit_nonce, &[0u8; 16]);

        assert_eq!(reference, key_block);
    }
}
