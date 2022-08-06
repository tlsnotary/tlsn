use aes::{cipher::NewBlockCipher, Aes128};
use criterion::{criterion_group, criterion_main, Criterion};
use mpc_circuits::Circuit;
use mpc_core::garble::{circuit::generate_labels, generator as gen};
use rand::thread_rng;
use tls_2pc_core::{CIRCUIT_1, CIRCUIT_2, CIRCUIT_3, CIRCUIT_4, CIRCUIT_5, CIRCUIT_6, CIRCUIT_7};

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("garble_circuits");

    for circ in [
        CIRCUIT_1, CIRCUIT_2, CIRCUIT_3, CIRCUIT_4, CIRCUIT_5, CIRCUIT_6, CIRCUIT_7,
    ] {
        let circ = Circuit::load_bytes(circ).unwrap();
        group.bench_function(circ.name(), |b| {
            let mut rng = thread_rng();
            let cipher = Aes128::new_from_slice(&[0u8; 16]).unwrap();
            let (labels, delta) = generate_labels(&mut rng, None, circ.input_len(), 0);
            b.iter(|| gen::garble(&cipher, &circ, &delta, &labels))
        });
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
