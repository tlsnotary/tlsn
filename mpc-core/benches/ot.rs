use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use mpc_core::{
    block::BLOCK_ONES,
    ot::{DhOtReceiver, DhOtSender, Kos15Receiver, Kos15Sender},
    utils::u8vec_to_boolvec,
};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha12Rng;

fn base_ot(c: &mut Criterion) {
    let mut group = c.benchmark_group("base_ot");
    for n in [256, 1024, 4096] {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            let msgs = vec![[BLOCK_ONES; 2]; n];
            let mut rng = ChaCha12Rng::from_entropy();
            let mut choice = vec![0u8; n / 8];
            rng.fill_bytes(&mut choice);
            let choice = u8vec_to_boolvec(&choice);
            b.iter(|| {
                let mut sender = DhOtSender::default();
                let sender_setup = sender.setup(&mut rng).unwrap();

                let mut receiver = DhOtReceiver::default();

                let receiver_setup = receiver.setup(&mut rng, &choice, sender_setup).unwrap();
                let send = sender.send(&msgs, receiver_setup).unwrap();
                let _ = receiver.receive(send).unwrap();
            })
        });
    }
}

fn ext_ot(c: &mut Criterion) {
    let mut group = c.benchmark_group("ext_ot");
    for n in [256, 1024, 4096, 12288, 40960] {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            let msgs = vec![[BLOCK_ONES; 2]; n];
            let mut rng = ChaCha12Rng::from_entropy();
            let mut choice = vec![0u8; n / 8];
            rng.fill_bytes(&mut choice);
            let choice = u8vec_to_boolvec(&choice);
            b.iter(|| {
                let mut receiver = Kos15Receiver::new(n);
                let base_sender_setup = receiver.base_setup().unwrap();

                let mut sender = Kos15Sender::new(n);
                let base_receiver_setup = sender.base_setup(base_sender_setup).unwrap();

                let send_seeds = receiver.base_send(base_receiver_setup).unwrap();
                sender.base_receive(send_seeds).unwrap();
                let receiver_setup = receiver.extension_setup(&choice).unwrap();
                sender.extension_setup(receiver_setup).unwrap();

                let send = sender.send(&msgs).unwrap();
                let _ = receiver.receive(send).unwrap();
            })
        });
    }
}

criterion_group! {
    name = base_ot_benches;
    config = Criterion::default().sample_size(50);
    targets = base_ot
}
criterion_group! {
    name = ext_ot_benches;
    config = Criterion::default().sample_size(50);
    targets = ext_ot
}
criterion_main!(base_ot_benches, ext_ot_benches);
