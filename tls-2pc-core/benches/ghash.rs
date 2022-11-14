use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::Rng;
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;
use tls_2pc_core::ghash::{GhashReceiver, GhashSender};
use tls_2pc_core::msgs::ghash::{SenderAddEnvelope, SenderMulEnvelope};

pub mod helper;
use helper::ot_mock_batch;

fn criterion_benchmark(c: &mut Criterion) {
    let mut rng = ChaCha12Rng::from_entropy();

    let h: u128 = rng.gen();
    let h1: u128 = rng.gen();
    let h2 = h ^ h1;

    let ciphertext: Vec<u128> = (0..1026).map(|_| rng.gen()).collect();

    c.bench_function("ghash", move |bench| {
        bench.iter(|| {
            black_box({
                let sender = GhashSender::new(h1, ciphertext.len()).unwrap();
                let receiver = GhashReceiver::new(h2, ciphertext.len()).unwrap();

                let (sender, sharing) = sender.compute_mul_powers();
                let choices = receiver.choices();

                let sender_add_envelope: SenderAddEnvelope = sharing.into();
                let bool_choices: Vec<bool> = choices.into();

                let chosen_inputs =
                    ot_mock_batch(sender_add_envelope.sender_add_envelope, &bool_choices);
                let receiver = receiver.compute_mul_powers(chosen_inputs.into());

                let (sender, sharing) = sender.into_add_powers();
                let choices = receiver.choices().unwrap();

                let sender_mul_envelope: SenderMulEnvelope = sharing.into();
                let bool_choices: Vec<bool> = choices.into();

                let chosen_inputs =
                    ot_mock_batch(sender_mul_envelope.sender_mul_envelope, &bool_choices);
                let receiver = receiver.into_add_powers(Some(chosen_inputs.into()));

                let _h_reconstructed = sender.generate_mac(&ciphertext).unwrap()
                    ^ receiver.generate_mac(&ciphertext).unwrap();
            });
        });
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
