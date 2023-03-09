use crate::AeadLabels;

use super::*;

use futures::lock::Mutex;
use mpc_circuits::BitOrder;
use std::sync::Arc;

use block_cipher::{
    mock::{create_mock_block_cipher_pair, MockDEBlockCipherFollower, MockDEBlockCipherLeader},
    Aes128, BlockCipher, BlockCipherConfigBuilder, Role as BlockCipherRole,
};
use mpc_core::garble::{ChaChaEncoder, Encoder, FullLabels};
use share_conversion_aio::conversion::recorder::Void;
use tlsn_stream_cipher::{
    cipher::Aes128Ctr,
    mock::{create_mock_stream_cipher_pair, MockStreamCipherFollower, MockStreamCipherLeader},
    StreamCipherConfigBuilder, StreamCipherFollower, StreamCipherLeader,
};
use tlsn_universal_hash::ghash::{mock_ghash_pair, MockGhashReceiver, MockGhashSender};
use utils_aio::duplex::DuplexChannel;

pub type MockAesGcmLeader = AesGcmLeader<
    MockDEBlockCipherLeader<Aes128>,
    MockStreamCipherLeader<Aes128Ctr>,
    MockGhashSender<Void, Void>,
>;

pub type MockAesGcmFollower = AesGcmFollower<
    MockDEBlockCipherFollower<Aes128>,
    MockStreamCipherFollower<Aes128Ctr>,
    MockGhashReceiver<Void, Void>,
>;

pub fn create_mock_aes_gcm_pair(
    leader_config: AesGcmLeaderConfig,
    leader_encoder: Arc<Mutex<ChaChaEncoder>>,
    follower_config: AesGcmFollowerConfig,
    follower_encoder: Arc<Mutex<ChaChaEncoder>>,
) -> (MockAesGcmLeader, MockAesGcmFollower) {
    let (leader_channel, follower_channel) = DuplexChannel::new();

    let (mut block_cipher_leader, mut block_cipher_follower) =
        create_mock_block_cipher_pair::<Aes128>(
            BlockCipherConfigBuilder::default()
                .id("mock-block-cipher".to_string())
                .role(BlockCipherRole::Leader)
                .build()
                .unwrap(),
            BlockCipherConfigBuilder::default()
                .id("mock-block-cipher".to_string())
                .role(BlockCipherRole::Follower)
                .build()
                .unwrap(),
        );

    block_cipher_leader.set_encoder(leader_encoder.clone());
    block_cipher_follower.set_encoder(follower_encoder.clone());

    let (mut stream_cipher_leader, mut stream_cipher_follower) = create_mock_stream_cipher_pair(
        StreamCipherConfigBuilder::default()
            .id("mock-stream-cipher".to_string())
            .start_ctr(2)
            .build()
            .unwrap(),
        StreamCipherConfigBuilder::default()
            .id("mock-stream-cipher".to_string())
            .start_ctr(2)
            .build()
            .unwrap(),
    );

    stream_cipher_leader.set_encoder(leader_encoder.clone());
    stream_cipher_follower.set_encoder(follower_encoder.clone());

    let (universal_hash_sender, universal_hash_receiver) = mock_ghash_pair(1024);

    let leader = AesGcmLeader::new(
        leader_config,
        Box::new(leader_channel),
        block_cipher_leader,
        stream_cipher_leader,
        universal_hash_sender,
    );

    let follower = AesGcmFollower::new(
        follower_config,
        Box::new(follower_channel),
        block_cipher_follower,
        stream_cipher_follower,
        universal_hash_receiver,
    );

    (leader, follower)
}

pub fn create_mock_aead_labels(
    key: Vec<u8>,
    iv: Vec<u8>,
) -> ((ChaChaEncoder, AeadLabels), (ChaChaEncoder, AeadLabels)) {
    let mut leader_encoder = ChaChaEncoder::new([0; 32], BitOrder::Msb0);
    let mut follower_encoder = ChaChaEncoder::new([1; 32], BitOrder::Msb0);

    let leader_delta = leader_encoder.get_delta();
    let leader_key_full_labels =
        FullLabels::generate(leader_encoder.get_stream(0), 128, Some(leader_delta));
    let leader_iv_full_labels =
        FullLabels::generate(leader_encoder.get_stream(0), 32, Some(leader_delta));

    let follower_delta = follower_encoder.get_delta();
    let follower_key_full_labels =
        FullLabels::generate(follower_encoder.get_stream(0), 128, Some(follower_delta));
    let follower_iv_full_labels =
        FullLabels::generate(follower_encoder.get_stream(0), 32, Some(follower_delta));

    let leader_labels = AeadLabels {
        key_full: leader_key_full_labels.clone(),
        key_active: follower_key_full_labels
            .select(&key.clone().into(), BitOrder::Msb0)
            .unwrap(),
        iv_full: leader_iv_full_labels.clone(),
        iv_active: follower_iv_full_labels
            .select(&iv.clone().into(), BitOrder::Msb0)
            .unwrap(),
    };

    let follower_labels = AeadLabels {
        key_full: follower_key_full_labels.clone(),
        key_active: leader_key_full_labels
            .select(&key.clone().into(), BitOrder::Msb0)
            .unwrap(),
        iv_full: follower_iv_full_labels.clone(),
        iv_active: leader_iv_full_labels
            .select(&iv.clone().into(), BitOrder::Msb0)
            .unwrap(),
    };

    (
        (leader_encoder, leader_labels),
        (follower_encoder, follower_labels),
    )
}
