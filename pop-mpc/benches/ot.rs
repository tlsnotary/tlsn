use criterion::{black_box, criterion_group, criterion_main, Criterion};
use pop_mpc::block::BLOCK_ONES;
use pop_mpc::ot::base::*;
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("base_ot_1000", move |bench| {
        let mut s_rng = ChaCha12Rng::from_entropy();
        let mut r_rng = ChaCha12Rng::from_entropy();

        let s_inputs = [[BLOCK_ONES; 2]; 1000];
        let choice = [false; 1000];

        bench.iter(|| {
            let mut sender = BaseOTSender::new(&mut s_rng);
            let sender_setup = sender.setup();

            let mut receiver = BaseOTReceiver::new(sender_setup);

            let receiver_setup = receiver.setup(&mut r_rng, &choice);
            let send = sender.send(&s_inputs, receiver_setup);
            let receive = receiver.receive(&choice, send);
            black_box(receive);
        });
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
