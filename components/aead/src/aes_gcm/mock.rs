//! Mock implementation of AES-GCM for testing purposes.

use block_cipher::{BlockCipherConfig, MpcBlockCipher};
use mpz_garble::{Decode, DecodePrivate, Execute, Load, Memory, Prove, Verify, Vm};
use tlsn_stream_cipher::{MpcStreamCipher, StreamCipherConfig};
use tlsn_universal_hash::ghash::{mock_ghash_pair, GhashConfig};
use utils_aio::duplex::MemoryDuplex;

use super::*;

/// Creates a mock AES-GCM pair.
///
/// # Arguments
///
/// * `id` - The id of the AES-GCM instances.
/// * `leader_vm` - The VM of the leader.
/// * `follower_vm` - The VM of the follower.
/// * `leader_config` - The configuration of the leader.
/// * `follower_config` - The configuration of the follower.
pub async fn create_mock_aes_gcm_pair<T>(
    id: &str,
    leader_vm: &mut T,
    follower_vm: &mut T,
    leader_config: AesGcmConfig,
    follower_config: AesGcmConfig,
) -> (MpcAesGcm, MpcAesGcm)
where
    T: Vm + Send,
    <T as Vm>::Thread:
        Memory + Execute + Load + Decode + DecodePrivate + Prove + Verify + Send + Sync,
{
    let block_cipher_id = format!("{}/block_cipher", id);
    let leader_block_cipher = MpcBlockCipher::new(
        BlockCipherConfig::builder()
            .id(block_cipher_id.clone())
            .build()
            .unwrap(),
        leader_vm.new_thread(&block_cipher_id).await.unwrap(),
    );
    let follower_block_cipher = MpcBlockCipher::new(
        BlockCipherConfig::builder()
            .id(block_cipher_id.clone())
            .build()
            .unwrap(),
        follower_vm.new_thread(&block_cipher_id).await.unwrap(),
    );

    let stream_cipher_id = format!("{}/stream_cipher", id);
    let leader_stream_cipher = MpcStreamCipher::new(
        StreamCipherConfig::builder()
            .id(stream_cipher_id.clone())
            .build()
            .unwrap(),
        leader_vm
            .new_thread_pool(&stream_cipher_id, 4)
            .await
            .unwrap(),
    );
    let follower_stream_cipher = MpcStreamCipher::new(
        StreamCipherConfig::builder()
            .id(stream_cipher_id.clone())
            .build()
            .unwrap(),
        follower_vm
            .new_thread_pool(&stream_cipher_id, 4)
            .await
            .unwrap(),
    );

    let (leader_ghash, follower_ghash) = mock_ghash_pair(
        GhashConfig::builder()
            .id(format!("{}/ghash", id))
            .initial_block_count(64)
            .build()
            .unwrap(),
        GhashConfig::builder()
            .id(format!("{}/ghash", id))
            .initial_block_count(64)
            .build()
            .unwrap(),
    );

    let (leader_channel, follower_channel) = MemoryDuplex::new();

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
