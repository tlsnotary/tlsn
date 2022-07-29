use aes::cipher::{generic_array::GenericArray, NewBlockCipher};
use aes::Aes128;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use mpc_circuits::{Circuit, AES_128_REVERSE};
use mpc_core::block::Block;
use mpc_core::garble::{
    circuit::{generate_labels, generate_public_labels},
    evaluator as ev, generator as gen,
};
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;
use std::sync::Arc;

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("garble_aes_128", move |bench| {
        let mut rng = ChaCha12Rng::from_entropy();
        let cipher = Aes128::new(GenericArray::from_slice(&[0u8; 16]));
        let circ = Arc::new(Circuit::load_bytes(AES_128_REVERSE).unwrap());

        let (labels, delta) = generate_labels(&mut rng, None, 256, 0);
        let public_labels = generate_public_labels(&mut rng, &delta);

        bench.iter(|| {
            let gb = gen::garble(&cipher, &circ, &delta, &labels, &public_labels).unwrap();
            black_box(gb);
        });
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
