use aes::cipher::{generic_array::GenericArray, NewBlockCipher};
use aes::Aes128;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use mpc_core::block::{Block, BLOCK_ONES};
use mpc_core::ot::*;
use mpc_core::utils::u8vec_to_boolvec;
use rand::RngCore;
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("base_ot_1024", move |bench| {
        let mut s_rng = ChaCha12Rng::from_entropy();
        let mut r_rng = ChaCha12Rng::from_entropy();

        let s_inputs = [[BLOCK_ONES; 2]; 1024];
        let choice = [false; 1024];

        bench.iter(|| {
            let mut sender = BaseOtSenderCore::new();
            let sender_setup = sender.setup(&mut s_rng);

            let mut receiver = BaseOtReceiverCore::new();

            let receiver_setup = receiver.setup(&mut r_rng, &choice, sender_setup).unwrap();
            let send = sender.send(&s_inputs, receiver_setup).unwrap();
            let receive = receiver.receive(&choice, send).unwrap();
            black_box(receive);
        });
    });

    c.bench_function("ot_1024", move |bench| {
        let mut choice = vec![0u8; 128];
        let mut rng = ChaCha12Rng::from_entropy();
        rng.fill_bytes(&mut choice);
        let choice = u8vec_to_boolvec(&choice);
        let inputs: Vec<[Block; 2]> = (0..1024)
            .map(|_| [Block::random(&mut rng), Block::random(&mut rng)])
            .collect();

        bench.iter(|| {
            let s_rng = ChaCha12Rng::from_entropy();
            let s_cipher = Aes128::new(GenericArray::from_slice(&[0u8; 16]));
            let r_rng = ChaCha12Rng::from_entropy();
            let r_cipher = Aes128::new(GenericArray::from_slice(&[0u8; 16]));

            let mut receiver = OtReceiverCore::new(r_rng, r_cipher);
            let base_sender_setup = receiver.base_setup().unwrap();

            let mut sender = OtSenderCore::new(s_rng, s_cipher);
            let base_receiver_setup = sender.base_setup(base_sender_setup).unwrap();

            let send_seeds = receiver.base_send(base_receiver_setup).unwrap();
            sender.base_receive(send_seeds).unwrap();
            let receiver_setup = receiver.extension_setup(&choice).unwrap();
            sender.extension_setup(receiver_setup).unwrap();

            let send = sender.send(&inputs).unwrap();
            let receive = receiver.receive(&choice, send).unwrap();

            black_box(receive);
        });
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
