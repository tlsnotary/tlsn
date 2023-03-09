use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use mpc_core::{
    ot::{DhOtReceiver, DhOtSender, Kos15Receiver, Kos15Sender},
    Block,
};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha12Rng;
use utils::bits::IterToBits;

fn base_ot(c: &mut Criterion) {
    let mut group = c.benchmark_group("base_ot");
    for n in [256, 1024, 4096] {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            let msgs = vec![[Block::ONES; 2]; n];
            let mut rng = ChaCha12Rng::from_entropy();
            let mut choice = vec![0u8; n / 8];
            rng.fill_bytes(&mut choice);
            let choice = choice.into_msb0();
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
            let msgs = vec![[Block::ONES; 2]; n];
            let mut rng = ChaCha12Rng::from_entropy();
            let mut choice = vec![0u8; n / 8];
            rng.fill_bytes(&mut choice);
            let choice = choice.into_msb0();
            b.iter(|| {
                let receiver = Kos15Receiver::default();
                let (receiver, base_sender_setup) = receiver.base_setup().unwrap();

                let sender = Kos15Sender::default();
                let (sender, base_receiver_setup) = sender.base_setup(base_sender_setup).unwrap();

                let (receiver, send_seeds) = receiver.base_send(base_receiver_setup).unwrap();
                let sender = sender.base_receive(send_seeds).unwrap();
                let (mut receiver, receiver_setup) = receiver.extension_setup(&choice).unwrap();
                let mut sender = sender
                    .extension_setup(choice.len(), receiver_setup)
                    .unwrap();

                let send = sender.send(&msgs).unwrap();
                let _received = receiver.receive(send).unwrap();
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
