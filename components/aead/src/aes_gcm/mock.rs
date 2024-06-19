//! Mock implementation of AES-GCM for testing purposes.

use block_cipher::{BlockCipherConfig, MpcBlockCipher};
use mpz_common::executor::{test_st_executor, STExecutor};
use mpz_garble::protocol::deap::mock::{MockFollower, MockLeader};
use mpz_ot::ideal::ot::ideal_ot;
use serio::channel::MemoryDuplex;
use tlsn_stream_cipher::{MpcStreamCipher, StreamCipherConfig};
use tlsn_universal_hash::ghash::ideal_ghash;

use super::*;

/// Creates a mock AES-GCM pair.
///
/// # Arguments
///
/// * `id` - The id of the AES-GCM instances.
/// * `(leader, follower)` - The leader and follower vms.
/// * `leader_config` - The configuration of the leader.
/// * `follower_config` - The configuration of the follower.
pub async fn create_mock_aes_gcm_pair(
    id: &str,
    (leader, follower): (MockLeader, MockFollower),
    leader_config: AesGcmConfig,
    follower_config: AesGcmConfig,
) -> (
    MpcAesGcm<STExecutor<MemoryDuplex>>,
    MpcAesGcm<STExecutor<MemoryDuplex>>,
) {
    let block_cipher_id = format!("{}/block_cipher", id);
    let (ctx_leader, ctx_follower) = test_st_executor(128);

    let (leader_ot_send, follower_ot_recv) = ideal_ot();
    let (follower_ot_send, leader_ot_recv) = ideal_ot();

    let block_leader = leader
        .new_thread(ctx_leader, leader_ot_send, leader_ot_recv)
        .unwrap();

    let block_follower = follower
        .new_thread(ctx_follower, follower_ot_send, follower_ot_recv)
        .unwrap();

    let leader_block_cipher = MpcBlockCipher::new(
        BlockCipherConfig::builder()
            .id(block_cipher_id.clone())
            .build()
            .unwrap(),
        block_leader,
    );
    let follower_block_cipher = MpcBlockCipher::new(
        BlockCipherConfig::builder()
            .id(block_cipher_id.clone())
            .build()
            .unwrap(),
        block_follower,
    );

    let stream_cipher_id = format!("{}/stream_cipher", id);
    let leader_stream_cipher = MpcStreamCipher::new(
        StreamCipherConfig::builder()
            .id(stream_cipher_id.clone())
            .build()
            .unwrap(),
        leader,
    );
    let follower_stream_cipher = MpcStreamCipher::new(
        StreamCipherConfig::builder()
            .id(stream_cipher_id.clone())
            .build()
            .unwrap(),
        follower,
    );

    let (ctx_a, ctx_b) = test_st_executor(128);
    let (leader_ghash, follower_ghash) = ideal_ghash(ctx_a, ctx_b);

    let (ctx_a, ctx_b) = test_st_executor(128);
    let leader = MpcAesGcm::new(
        leader_config,
        ctx_a,
        Box::new(leader_block_cipher),
        Box::new(leader_stream_cipher),
        Box::new(leader_ghash),
    );

    let follower = MpcAesGcm::new(
        follower_config,
        ctx_b,
        Box::new(follower_block_cipher),
        Box::new(follower_stream_cipher),
        Box::new(follower_ghash),
    );

    (leader, follower)
}
