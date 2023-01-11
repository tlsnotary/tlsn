use aes::{cipher::NewBlockCipher, Aes128};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use mpc_circuits::Circuit;
use mpc_core::garble::{FullInputLabels, GarbledCircuit};
use rand::thread_rng;

static CIRCUITS: &[&[u8]] = &[
    #[cfg(feature = "c1")]
    tls_2pc_core::CIRCUIT_1_BYTES,
    #[cfg(feature = "c2")]
    tls_2pc_core::CIRCUIT_2_BYTES,
    #[cfg(feature = "c3")]
    tls_2pc_core::CIRCUIT_3_BYTES,
    #[cfg(feature = "c4")]
    tls_2pc_core::CIRCUIT_4_BYTES,
    #[cfg(feature = "c5")]
    tls_2pc_core::CIRCUIT_5_BYTES,
    #[cfg(feature = "c6")]
    tls_2pc_core::CIRCUIT_6_BYTES,
    #[cfg(feature = "c7")]
    tls_2pc_core::CIRCUIT_7_BYTES,
];

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("garble_circuits");

    for circ in CIRCUITS {
        let circ = Circuit::load_bytes(circ).unwrap();
        group.bench_function(circ.description(), |b| {
            let mut rng = thread_rng();
            let cipher = Aes128::new_from_slice(&[0u8; 16]).unwrap();
            let (labels, delta) = FullInputLabels::generate_set(&mut rng, &circ, None);
            b.iter(|| {
                black_box(GarbledCircuit::generate(
                    &cipher,
                    circ.clone(),
                    delta,
                    &labels,
                ))
            })
        });
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
