use aes::{cipher::NewBlockCipher, Aes128};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use mpc_circuits::{Circuit, ADDER_64, AES_128_REVERSE};
use mpc_core::garble::{FullInputLabelsSet, GarbledCircuit};
use rand::thread_rng;

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("garble_circuits");

    for circ in [ADDER_64, AES_128_REVERSE] {
        let circ = Circuit::load_bytes(circ).unwrap();
        group.bench_function(circ.id().clone().to_string(), |b| {
            let mut rng = thread_rng();
            let cipher = Aes128::new_from_slice(&[0u8; 16]).unwrap();
            let input_labels = FullInputLabelsSet::generate(&mut rng, &circ, None);
            b.iter(|| {
                black_box(
                    GarbledCircuit::generate(&cipher, circ.clone(), input_labels.clone()).unwrap(),
                )
            })
        });
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
