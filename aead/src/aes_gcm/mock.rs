use block_cipher::{BlockCipherConfigBuilder, MpcBlockCipher};
use mpc_garble::{Decode, DecodePrivate, Execute, Memory, Prove, Verify, Vm};
use mpc_share_conversion::conversion::recorder::Void;
use tlsn_stream_cipher::{MpcStreamCipher, StreamCipherConfigBuilder};
use tlsn_universal_hash::ghash::mock_ghash_pair;
use utils_aio::duplex::DuplexChannel;

use super::*;

pub async fn create_mock_aes_gcm_pair<T>(
    id: &str,
    leader_vm: &mut T,
    follower_vm: &mut T,
    leader_config: AesGcmConfig,
    follower_config: AesGcmConfig,
) -> (MpcAesGcm, MpcAesGcm)
where
    T: Vm + Send,
    <T as Vm>::Thread: Memory + Execute + Decode + DecodePrivate + Prove + Verify + Send + Sync,
{
    let block_cipher_id = format!("{}/block_cipher", id);
    let leader_block_cipher = MpcBlockCipher::new(
        BlockCipherConfigBuilder::default()
            .id(block_cipher_id.clone())
            .build()
            .unwrap(),
        leader_vm.new_thread(&block_cipher_id).await.unwrap(),
    );
    let follower_block_cipher = MpcBlockCipher::new(
        BlockCipherConfigBuilder::default()
            .id(block_cipher_id.clone())
            .build()
            .unwrap(),
        follower_vm.new_thread(&block_cipher_id).await.unwrap(),
    );

    let stream_cipher_id = format!("{}/stream_cipher", id);
    let leader_stream_cipher = MpcStreamCipher::new(
        StreamCipherConfigBuilder::default()
            .id(stream_cipher_id.clone())
            .build()
            .unwrap(),
        leader_vm
            .new_thread_pool(&stream_cipher_id, 4)
            .await
            .unwrap(),
    );
    let follower_stream_cipher = MpcStreamCipher::new(
        StreamCipherConfigBuilder::default()
            .id(stream_cipher_id.clone())
            .build()
            .unwrap(),
        follower_vm
            .new_thread_pool(&stream_cipher_id, 4)
            .await
            .unwrap(),
    );

    let (leader_ghash, follower_ghash) = mock_ghash_pair::<Void, Void>(64);

    let (leader_channel, follower_channel) = DuplexChannel::new();

    let leader = MpcAesGcm::new(
        leader_config,
        Box::new(leader_channel),
        Box::new(leader_block_cipher),
        Box::new(leader_stream_cipher),
        Box::new(leader_ghash),
    );

    let follower = MpcAesGcm::new(
        follower_config,
        Box::new(follower_channel),
        Box::new(follower_block_cipher),
        Box::new(follower_stream_cipher),
        Box::new(follower_ghash),
    );

    (leader, follower)
}
