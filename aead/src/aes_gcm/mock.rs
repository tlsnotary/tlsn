use super::*;

use block_cipher::{Aes128, BlockCipher, BlockCipherConfigBuilder, MpcBlockCipher};
use mpc_share_conversion::conversion::recorder::Void;
use tlsn_stream_cipher::{Aes128Ctr, StreamCipher, StreamCipherConfigBuilder};
use tlsn_universal_hash::ghash::{mock_ghash_pair, MockGhashReceiver, MockGhashSender};
use utils_aio::duplex::DuplexChannel;

pub type MockAesGcm =
    AesGcm<MpcBlockCipher<Aes128>, MockStreamCipherLeader<Aes128Ctr>, MockGhashSender<Void, Void>>;

pub fn create_mock_aes_gcm_pair(
    leader_config: AesGcmConfig,
    follower_config: AesGcmConfig,
) -> (MockAesGcm, MockAesGcm) {
    let (leader_channel, follower_channel) = DuplexChannel::new();

    let (mut block_cipher_leader, mut block_cipher_follower) =
        create_mock_block_cipher_pair::<Aes128>(
            BlockCipherConfigBuilder::default()
                .id("mock-block-cipher".to_string())
                .build()
                .unwrap(),
            BlockCipherConfigBuilder::default()
                .id("mock-block-cipher".to_string())
                .build()
                .unwrap(),
        );

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

    let (universal_hash_sender, universal_hash_receiver) = mock_ghash_pair(1024);

    let leader = AesGcm::new(
        leader_config,
        Box::new(leader_channel),
        block_cipher_leader,
        stream_cipher_leader,
        universal_hash_sender,
    );

    let follower = AesGcm::new(
        follower_config,
        Box::new(follower_channel),
        block_cipher_follower,
        stream_cipher_follower,
        universal_hash_receiver,
    );

    (leader, follower)
}
