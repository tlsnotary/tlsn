use std::sync::Arc;

use futures::{lock::Mutex, SinkExt};

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};

use tlsn_stream_cipher::{
    cipher::{Aes128Ctr, CtrCircuitSuite},
    mock::{
        create_mock_labels, create_mock_stream_cipher_pair, MockStreamCipherFollower,
        MockStreamCipherLeader,
    },
    StreamCipherConfigBuilder, StreamCipherFollower, StreamCipherLeader,
};

async fn bench_encrypt_private<C: CtrCircuitSuite + 'static>(msg: Vec<u8>) {
    let explicit_nonce = [0u8; 8];
    let (mut leader, mut follower) = create_pair([0u8; 16], [0u8; 4]);

    let leader_fut = async {
        leader
            .encrypt_private(explicit_nonce.to_vec(), msg.clone(), true)
            .await
            .unwrap()
    };

    let follower_fut = async {
        follower
            .encrypt_blind(explicit_nonce.to_vec(), msg.len(), true)
            .await
            .unwrap()
    };

    _ = tokio::join!(leader_fut, follower_fut);
}

async fn bench_decrypt_private<C: CtrCircuitSuite + 'static>(ciphertext: Vec<u8>) {
    let explicit_nonce = [0u8; 8];
    let (mut leader, mut follower) = create_pair([0u8; 16], [0u8; 4]);

    let leader_fut = {
        let ciphertext = ciphertext.clone();
        async {
            leader
                .decrypt_private(explicit_nonce.to_vec(), ciphertext, true)
                .await
                .unwrap()
        }
    };

    let follower_fut = async {
        follower
            .decrypt_blind(explicit_nonce.to_vec(), ciphertext, true)
            .await
            .unwrap()
    };

    _ = tokio::join!(leader_fut, follower_fut);
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("stream_cipher/encrypt_private");

    let len = 128;

    group.throughput(Throughput::Bytes(len as u64));

    group.bench_function(format!("{}", len), |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap())
            .iter(|| async { black_box(bench_encrypt_private::<Aes128Ctr>(vec![0; len]).await) })
    });

    drop(group);

    let mut group = c.benchmark_group("stream_cipher/decrypt_private");

    group.throughput(Throughput::Bytes(len as u64));

    group.bench_function(format!("{}", len), |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap())
            .iter(|| async { black_box(bench_decrypt_private::<Aes128Ctr>(vec![0; len]).await) })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

fn create_pair(
    key: [u8; 16],
    iv: [u8; 4],
) -> (
    MockStreamCipherLeader<Aes128Ctr>,
    MockStreamCipherFollower<Aes128Ctr>,
) {
    let leader_config = StreamCipherConfigBuilder::default()
        .id("bench".to_string())
        .start_ctr(1)
        .build()
        .unwrap();
    let follower_config = StreamCipherConfigBuilder::default()
        .id("bench".to_string())
        .start_ctr(1)
        .build()
        .unwrap();

    let ((leader_encoder, leader_labels), (follower_encoder, follower_labels)) =
        create_mock_labels(key.to_vec(), iv.to_vec());

    let transcript_sink = futures::sink::drain();

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

    (leader, follower)
}
