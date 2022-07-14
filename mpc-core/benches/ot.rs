use criterion::{black_box, criterion_group, criterion_main, Criterion};
use mpc_core::block::{Block, BLOCK_ONES};
use mpc_core::ot::{DhOtReceiver, DhOtSender, Kos15Receiver, Kos15Sender};
use mpc_core::utils::u8vec_to_boolvec;
use rand::RngCore;
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("base_ot_1024", move |bench| {
        let s_inputs = [[BLOCK_ONES; 2]; 1024];
        let choice = [false; 1024];

        bench.iter(|| {
            let mut rng = ChaCha12Rng::from_entropy();

            let mut sender = DhOtSender::default();
            let sender_setup = sender.setup(&mut rng).unwrap();

            let mut receiver = DhOtReceiver::default();

            let receiver_setup = receiver.setup(&mut rng, &choice, sender_setup).unwrap();
            let send = sender.send(&s_inputs, receiver_setup).unwrap();
            let receive = receiver.receive(send).unwrap();
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
            let mut receiver = Kos15Receiver::new(1024);
            let base_sender_setup = receiver.base_setup().unwrap();

            let mut sender = Kos15Sender::new(1024);
            let base_receiver_setup = sender.base_setup(base_sender_setup).unwrap();

            let send_seeds = receiver.base_send(base_receiver_setup).unwrap();
            sender.base_receive(send_seeds).unwrap();
            let receiver_setup = receiver.extension_setup(&choice).unwrap();
            sender.extension_setup(receiver_setup).unwrap();

            let send = sender.send(&inputs).unwrap();
            let receive = receiver.receive(send).unwrap();

            black_box(receive);
        });
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
