//! Benches for running the authdecode protocol with the halo2 backend.

use authdecode::{Prover, Verifier};
use authdecode_core::fixtures::{self, commitment_data};
use criterion::{criterion_group, criterion_main, Criterion};
use futures_util::StreamExt;
use utils_aio::duplex::MemoryDuplex;

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("authdecode");
    group.sample_size(10);
    let rt = tokio::runtime::Runtime::new().unwrap();

    group.bench_function("authdecode_halo2", |b| {
        b.to_async(&rt).iter(authdecode_halo2)
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

async fn authdecode_halo2() {
    let pair = authdecode_core::backend::halo2::fixtures::backend_pair_mock();
    let commitment_data = commitment_data();
    let encoding_provider = fixtures::encoding_provider();

    let prover = Prover::new(Box::new(pair.0));
    let verifier = Verifier::new(Box::new(pair.1));

    let (prover_channel, verifier_channel) = MemoryDuplex::new();

    let (mut prover_sink, _) = prover_channel.split();
    let (_, mut verifier_stream) = verifier_channel.split();

    let prover = prover
        .commit(&mut prover_sink, commitment_data)
        .await
        .unwrap();

    let verifier = verifier
        .receive_commitments(&mut verifier_stream)
        .await
        .unwrap();

    // An encoding provider is instantiated with authenticated full encodings from external context.
    let _ = prover
        .prove(&mut prover_sink, &encoding_provider)
        .await
        .unwrap();

    let _ = verifier
        .verify(&mut verifier_stream, &encoding_provider)
        .await
        .unwrap();
}
