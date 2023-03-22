use aes::{cipher::NewBlockCipher, Aes128};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use mpc_circuits::{ADDER_64, AES_128};
use mpc_garble_core::{FullInputSet, GarbledCircuit};
use rand::thread_rng;

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("garble_circuits");

    for circ in [ADDER_64.clone(), AES_128.clone()] {
        group.bench_function(circ.id().clone().to_string(), |b| {
            let mut rng = thread_rng();
            let cipher = Aes128::new_from_slice(&[0u8; 16]).unwrap();
            let input_labels = FullInputSet::generate(&mut rng, &circ, None);
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
