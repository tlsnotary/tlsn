pub mod cipher;
pub mod config;
pub(crate) mod counter_block;
mod follower;
mod leader;
mod transcript;

pub use config::{
    StreamCipherFollowerConfig, StreamCipherFollowerConfigBuilder,
    StreamCipherFollowerConfigBuilderError, StreamCipherLeaderConfig,
    StreamCipherLeaderConfigBuilder, StreamCipherLeaderConfigBuilderError,
};
pub use follower::DEAPStreamCipherFollower;
pub use leader::DEAPStreamCipherLeader;
pub use transcript::{
    BlindBlockTranscript, BlindMessageTranscript, BlockTranscript, MessageTranscript,
};

use std::sync::Arc;

use async_trait::async_trait;
use futures::{
    channel::mpsc::{SendError, Sender},
    lock::Mutex,
};

use mpc_core::garble::{ActiveLabels, ChaChaEncoder, FullLabels};

#[derive(Debug, thiserror::Error)]
pub enum StreamCipherError {
    #[error("IO Error: {0:?}")]
    IOError(#[from] std::io::Error),
    #[error("Muxer error: {0:?}")]
    MuxerError(#[from] utils_aio::mux::MuxerError),
    #[error("GCFactoryError: {0:?}")]
    GCFactoryError(#[from] mpc_aio::protocol::garble::factory::GCFactoryError),
    #[error("GCError: {0:?}")]
    GCError(#[from] mpc_aio::protocol::garble::GCError),
    #[error("MPSC Channel Error: {0:?}")]
    SendError(#[from] SendError),
    #[error("Keys are not set")]
    KeysNotSet,
    #[error("Encoder is not set")]
    EncoderNotSet,
}

/// A stream cipher that can be used to encrypt and decrypt messages with another
/// party using secure 2-party computation.
///
/// The Leader is the party which provides the plaintext, while it remains
/// hidden from the Follower.
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
    fn set_transcript_sink(&mut self, sink: Sender<MessageTranscript>);

    /// Applies the key stream to the given message.
    ///
    /// * `explicit_nonce`: The explicit nonce to use for the key stream.
    /// * `msg`: The message to apply the key stream to.
    async fn apply_key_stream(
        &mut self,
        explicit_nonce: Vec<u8>,
        msg: Vec<u8>,
        record: bool,
    ) -> Result<Vec<u8>, StreamCipherError>;

    /// Computes additive shares of a key block.
    ///
    /// Returns the leader's additive share of the key block.
    ///
    /// * `explicit_nonce`: The explicit nonce to use for the key block.
    /// * `ctr`: The counter to use for the key block.
    /// * `mask`: The mask to use for the key block.
    async fn share_key_block(
        &mut self,
        explicit_nonce: Vec<u8>,
        ctr: u32,
        mask: Vec<u8>,
    ) -> Result<Vec<u8>, StreamCipherError>;

    /// Proves to the follower that applying the key stream to the given message
    /// results in the given output.
    ///
    /// * `explicit_nonce`: The explicit nonce to use for the key stream.
    /// * `msg_in`: The message to apply the key stream to.
    /// * `msg_out`: The expected output of applying the key stream to the message.
    async fn prove_key_stream(
        &mut self,
        explicit_nonce: Vec<u8>,
        msg_in: Vec<u8>,
        msg_out: Vec<u8>,
        record: bool,
    ) -> Result<(), StreamCipherError>;

    /// Finalizes the stream cipher, proving to the follower that all 2PC
    /// was performed correctly.
    async fn finalize(self) -> Result<(), StreamCipherError>;
}

/// A stream cipher that can be used to encrypt and decrypt messages with another
/// party using secure 2-party computation.
///
/// The plaintext is never revealed to the `StreamCipherFollower`, it is a private input
/// provided by the `StreamCipherLeader`.
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

    /// Sets transcript sink
    fn set_transcript_sink(&mut self, sink: Sender<BlindMessageTranscript>);

    /// Applies the key stream to a message provided by `StreamCipherLeader`.
    ///
    /// * `explicit_nonce`: The explicit nonce to use for the key stream.
    /// * `msg_len`: The length of the message to apply the key stream to.
    /// * `record`: Whether to record the message in the transcript.
    async fn apply_key_stream(
        &mut self,
        explicit_nonce: Vec<u8>,
        msg_len: usize,
        record: bool,
    ) -> Result<Vec<u8>, StreamCipherError>;

    /// Computes additive shares of a key block.
    ///
    /// Returns the follower's additive share of the key block.
    ///
    /// * `explicit_nonce`: The explicit nonce to use for the key block.
    /// * `ctr`: The counter to use for the key block.
    /// * `mask`: The mask to use for the key block.
    async fn share_key_block(
        &mut self,
        explicit_nonce: Vec<u8>,
        ctr: u32,
        mask: Vec<u8>,
    ) -> Result<Vec<u8>, StreamCipherError>;

    /// Proves that applying the key stream to a message provided by `StreamCipherLeader`
    /// results in the given output.
    ///
    /// * `explicit_nonce`: The nonce to use for the key stream.
    /// * `msg_out`: The expected output of applying the key stream to the message.
    /// * `record`: Whether to record the message in the transcript.
    async fn verify_key_stream(
        &mut self,
        explicit_nonce: Vec<u8>,
        msg_out: Vec<u8>,
        record: bool,
    ) -> Result<(), StreamCipherError>;

    /// Finalizes the stream cipher, proving that the leader performed all
    /// 2PC correctly.
    async fn finalize(self) -> Result<(), StreamCipherError>;
}

#[derive(Clone)]
pub struct StreamCipherLabels {
    pub key_full: FullLabels,
    pub key_active: ActiveLabels,
    pub iv_full: FullLabels,
    pub iv_active: ActiveLabels,
}

#[cfg(feature = "mock")]
pub mod mock {
    use super::*;

    use crate::cipher::CtrCircuitSuite;
    use mpc_aio::protocol::garble::{
        exec::{
            deap::mock::{MockDEAPFollower, MockDEAPLeader},
            dual::mock::{MockDualExFollower, MockDualExLeader},
        },
        factory::{
            deap::mock::{
                create_mock_deap_factory_pair, MockDEAPFollowerFactory, MockDEAPLeaderFactory,
            },
            dual::mock::{create_mock_dualex_factory, MockDualExFactory},
        },
    };
    use mpc_circuits::Value;
    use mpc_core::garble::Encoder;
    use tls_2pc_core::AES_CTR;

    pub type MockedStreamCipherLeader<C> = DEAPStreamCipherLeader<
        C,
        MockDEAPLeaderFactory,
        MockDualExFactory,
        MockDEAPLeader,
        MockDualExLeader,
    >;

    pub type MockedStreamCipherFollower<C> = DEAPStreamCipherFollower<
        C,
        MockDEAPFollowerFactory,
        MockDualExFactory,
        MockDEAPFollower,
        MockDualExFollower,
    >;

    pub fn create_mock_stream_cipher_pair<C: CtrCircuitSuite>(
        leader_config: StreamCipherLeaderConfig,
        follower_config: StreamCipherFollowerConfig,
    ) -> (MockedStreamCipherLeader<C>, MockedStreamCipherFollower<C>) {
        let (deap_leader_factory, deap_follower_factory) = create_mock_deap_factory_pair();
        let de_factory = create_mock_dualex_factory();

        let leader =
            DEAPStreamCipherLeader::new(leader_config, deap_leader_factory, de_factory.clone());

        let follower = DEAPStreamCipherFollower::new(
            follower_config,
            deap_follower_factory,
            de_factory.clone(),
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

        let mut leader_encoder = ChaChaEncoder::new([0; 32]);
        let leader_full_key = leader_encoder.encode(1, &circ.input(0).unwrap(), false);
        let leader_full_iv = leader_encoder.encode(1, &circ.input(1).unwrap(), false);

        let mut follower_encoder = ChaChaEncoder::new([1; 32]);
        let follower_full_key = follower_encoder.encode(1, &circ.input(0).unwrap(), false);
        let follower_full_iv = follower_encoder.encode(1, &circ.input(1).unwrap(), false);

        let leader_labels = StreamCipherLabels {
            key_full: leader_full_key.clone().into_labels(),
            key_active: follower_full_key
                .select(&Value::Bytes(key.clone()))
                .unwrap()
                .into_labels(),
            iv_full: leader_full_iv.clone().into_labels(),
            iv_active: follower_full_iv
                .select(&Value::Bytes(iv.clone()))
                .unwrap()
                .into_labels(),
        };

        let follower_labels = StreamCipherLabels {
            key_full: follower_full_key.clone().into_labels(),
            key_active: leader_full_key
                .select(&Value::Bytes(vec![0; 16]))
                .unwrap()
                .into_labels(),
            iv_full: follower_full_iv.clone().into_labels(),
            iv_active: leader_full_iv
                .select(&Value::Bytes(vec![0; 4]))
                .unwrap()
                .into_labels(),
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
    use futures::StreamExt;
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

    #[rstest]
    #[timeout(Duration::from_millis(5000))]
    #[tokio::test]
    async fn test_stream_cipher() {
        let leader_config = StreamCipherLeaderConfigBuilder::default()
            .id("test".to_string())
            .start_ctr(1)
            .build()
            .unwrap();
        let follower_config = StreamCipherFollowerConfigBuilder::default()
            .id("test".to_string())
            .start_ctr(1)
            .build()
            .unwrap();

        let key = [0u8; 16];
        let iv = [0u8; 4];
        let explicit_nonce = [0u8; 8];

        let msg = b"This is a test message which will be encrypted using AES-CTR.".to_vec();
        let msg_len = msg.len();

        let (mut leader, mut follower) =
            create_mock_stream_cipher_pair::<Aes128Ctr>(leader_config, follower_config);

        let ((leader_encoder, leader_labels), (follower_encoder, follower_labels)) =
            create_mock_labels(key.to_vec(), iv.to_vec());

        let (leader_transcript_sink, mut leader_transcript_stream) =
            futures::channel::mpsc::channel(100);
        let (follower_transcript_sink, mut follower_transcript_stream) =
            futures::channel::mpsc::channel(100);

        leader.set_keys(leader_labels);
        leader.set_encoder(Arc::new(Mutex::new(leader_encoder)));
        leader.set_transcript_sink(leader_transcript_sink);
        follower.set_keys(follower_labels);
        follower.set_encoder(Arc::new(Mutex::new(follower_encoder)));
        follower.set_transcript_sink(follower_transcript_sink);

        let follower_task = tokio::spawn(async move {
            let follower_encrypted_msg = follower
                .apply_key_stream(explicit_nonce.to_vec(), msg_len, true)
                .await
                .unwrap();

            let follower_decrypted_msg = follower
                .apply_key_stream(explicit_nonce.to_vec(), msg_len, false)
                .await
                .unwrap();

            follower.finalize().await.unwrap();

            (follower_encrypted_msg, follower_decrypted_msg)
        });

        let leader_encrypted_msg = leader
            .apply_key_stream(explicit_nonce.to_vec(), msg.to_vec(), true)
            .await
            .unwrap();

        let leader_decrypted_msg = leader
            .apply_key_stream(explicit_nonce.to_vec(), leader_encrypted_msg.clone(), false)
            .await
            .unwrap();

        leader.finalize().await.unwrap();

        let (follower_encrypted_msg, follower_decrypted_msg) = follower_task.await.unwrap();

        let reference = aes_ctr(&key, &iv, &explicit_nonce, &msg);

        assert_eq!(leader_encrypted_msg, reference);
        assert_eq!(leader_decrypted_msg, msg);
        assert_eq!(follower_encrypted_msg, reference);
        assert_eq!(follower_decrypted_msg, msg);

        let leader_transcript = leader_transcript_stream.next().await.unwrap();

        let follower_transcript = follower_transcript_stream.next().await.unwrap();

        assert_eq!(leader_transcript.get_msg(), msg);
        assert_eq!(leader_transcript.get_output_msg(), reference);

        assert_eq!(follower_transcript.get_len(), msg.len());
        assert_eq!(follower_transcript.get_output_msg(), reference);
    }

    #[rstest]
    #[timeout(Duration::from_millis(5000))]
    #[tokio::test]
    async fn test_stream_cipher_share_key_block() {
        let leader_config = StreamCipherLeaderConfigBuilder::default()
            .id("test".to_string())
            .start_ctr(1)
            .build()
            .unwrap();
        let follower_config = StreamCipherFollowerConfigBuilder::default()
            .id("test".to_string())
            .start_ctr(1)
            .build()
            .unwrap();

        let key = [0u8; 16];
        let iv = [0u8; 4];
        let explicit_nonce = [0u8; 8];
        let leader_mask = [0u8; 16];
        let follower_mask = [0u8; 16];

        let (mut leader, mut follower) =
            create_mock_stream_cipher_pair::<Aes128Ctr>(leader_config, follower_config);

        let ((leader_encoder, leader_labels), (follower_encoder, follower_labels)) =
            create_mock_labels(key.to_vec(), iv.to_vec());

        leader.set_keys(leader_labels);
        leader.set_encoder(Arc::new(Mutex::new(leader_encoder)));
        follower.set_keys(follower_labels);
        follower.set_encoder(Arc::new(Mutex::new(follower_encoder)));

        let follower_task = tokio::spawn(async move {
            follower
                .share_key_block(explicit_nonce.to_vec(), 1, follower_mask.to_vec())
                .await
                .unwrap()
        });

        let leader_share = leader
            .share_key_block(explicit_nonce.to_vec(), 1, leader_mask.to_vec())
            .await
            .unwrap();

        let follower_share = follower_task.await.unwrap();

        let key_block = leader_share
            .into_iter()
            .zip(follower_share)
            .map(|(a, b)| a ^ b)
            .collect::<Vec<u8>>();

        let reference = aes_ctr(&key, &iv, &explicit_nonce, &[0u8; 16]);

        assert_eq!(reference, key_block);
    }
}
