use criterion::{black_box, criterion_group, criterion_main, Criterion};
use mpc_circuits::Circuit;

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
    let mut group = c.benchmark_group("load_circuits");

    for circ_bytes in CIRCUITS {
        let circ = Circuit::load_bytes(circ_bytes).unwrap();
        group.bench_function(circ.name(), |b| {
            b.iter(|| black_box(Circuit::load_bytes(circ_bytes).unwrap()))
        });
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
