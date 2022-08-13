use aes::{cipher::NewBlockCipher, Aes128};
use criterion::{criterion_group, criterion_main, Criterion};
use mpc_circuits::{Circuit, ADDER_64, AES_128_REVERSE};
use mpc_core::garble::{generate_input_labels, generator as gen, WireLabelPair};
use rand::thread_rng;

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("garble_circuits");

    for circ in [ADDER_64, AES_128_REVERSE] {
        let circ = Circuit::load_bytes(circ).unwrap();
        group.bench_function(circ.name(), |b| {
            let mut rng = thread_rng();
            let cipher = Aes128::new_from_slice(&[0u8; 16]).unwrap();
            let (labels, delta) = generate_input_labels(&mut rng, &circ, None);
            let input_labels: Vec<WireLabelPair> = labels
                .iter()
                .map(|pair| pair.as_ref())
                .flatten()
                .copied()
                .collect();
            b.iter(|| gen::garble(&cipher, &circ, delta, &input_labels))
        });
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
