use authdecode::halo2_backend::onetimesetup::OneTimeSetup;
use authdecode::halo2_backend::prover::{Prover, PK};
use authdecode::halo2_backend::verifier::{Verifier, VK};
use authdecode::halo2_backend::Curve;
use authdecode::prover::{AuthDecodeProver, ProofCreation};
use authdecode::verifier::{AuthDecodeVerifier, VerifyMany};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::thread_rng;
use rand::Rng;
use std::env;

pub fn criterion_benchmark(c: &mut Criterion) {
    // benchmarking single threaded halo2
    env::set_var("RAYON_NUM_THREADS", "1");

    let proving_key = OneTimeSetup::proving_key();
    let verification_key = OneTimeSetup::verification_key();

    c.bench_function("halo2_proof_generation_single_threaded", |b| {
        b.iter(|| {
            // Since we can't Clone provers, we generate a new prover for each
            // iteration. This should not add more than 1-2% runtime to the bench
            let (prover, _verifier) = create_prover(proving_key.clone(), verification_key.clone());
            black_box(prover.create_zk_proofs().unwrap());
        })
    });

    // We cannot bench proof verification without running the proof generation.
    // To get the actual verification time, subtract from "generation+verification"
    // time the "generation only" time from the above bench.

    c.bench_function(
        "halo2_proof_generation_and_verification_single_threaded",
        |b| {
            b.iter(|| {
                // Since we can't Clone prover, verifier, we generate a new prover and a new verifier
                // for each iteration. This should not add more than 1-2% runtime to the bench
                let (prover, verifier) =
                    create_prover(proving_key.clone(), verification_key.clone());
                let (proofs, _salts) = prover.create_zk_proofs().unwrap();
                black_box(verifier.verify_many(proofs.clone()).unwrap());
            })
        },
    );
}

// Runs the whole protocol and returns the prover in a state ready to create
// proofs and a verifier ready to verify proofs.
fn create_prover(
    proving_key: PK,
    verification_key: VK,
) -> (
    AuthDecodeProver<ProofCreation>,
    AuthDecodeVerifier<VerifyMany>,
) {
    let prover = Box::new(Prover::new(proving_key));
    let verifier = Box::new(Verifier::new(verification_key, Curve::Pallas));
    let mut rng = thread_rng();

    // generate random plaintext of random size up to 400 bytes
    let plaintext: Vec<u8> = core::iter::repeat_with(|| rng.gen::<u8>())
        .take(thread_rng().gen_range(1..400))
        .collect();

    // Normally, the Prover is expected to obtain her binary labels by
    // evaluating the garbled circuit.
    // To keep this test simple, we don't evaluate the gc, but we generate
    // all labels of the Verifier and give the Prover her active labels.
    let bit_size = plaintext.len() * 8;
    let mut all_binary_labels: Vec<[u128; 2]> = Vec::with_capacity(bit_size);
    let mut delta: u128 = rng.gen();
    // set the last bit
    delta |= 1;
    for _ in 0..bit_size {
        let label_zero: u128 = rng.gen();
        all_binary_labels.push([label_zero, label_zero ^ delta]);
    }
    let prover_labels = choose(&all_binary_labels, &u8vec_to_boolvec(&plaintext));

    let verifier = AuthDecodeVerifier::new(all_binary_labels.clone(), verifier);

    let verifier = verifier.setup().unwrap();

    let prover = AuthDecodeProver::new(plaintext, prover);

    // Perform setup
    let prover = prover.setup().unwrap();

    // Commitment to the plaintext is sent to the Notary
    let (plaintext_hash, prover) = prover.plaintext_commitment().unwrap();

    // Notary sends back encrypted arithm. labels.
    let (ciphertexts, verifier) = verifier.receive_plaintext_hashes(plaintext_hash).unwrap();

    // Hash commitment to the label_sum is sent to the Notary
    let (label_sum_hashes, prover) = prover
        .label_sum_commitment(ciphertexts, &prover_labels)
        .unwrap();

    // Notary sends the arithmetic label seed
    let (seed, verifier) = verifier.receive_label_sum_hashes(label_sum_hashes).unwrap();

    // At this point the following happens in the `committed GC` protocol:
    // - the Notary reveals the GC seed
    // - the User checks that the GC was created from that seed
    // - the User checks that her active output labels correspond to the
    // output labels derived from the seed
    // - we are called with the result of the check and (if successful)
    // with all the output labels

    let prover = prover
        .binary_labels_authenticated(true, Some(all_binary_labels))
        .unwrap();

    // Prover checks the integrity of the arithmetic labels and generates zero_sums and deltas
    let prover = prover.authenticate_arithmetic_labels(seed).unwrap();
    (prover, verifier)
}

/// Unzips a slice of pairs, returning items corresponding to choice
fn choose<T: Clone>(items: &[[T; 2]], choice: &[bool]) -> Vec<T> {
    assert!(items.len() == choice.len(), "arrays are different length");
    items
        .iter()
        .zip(choice)
        .map(|(items, choice)| items[*choice as usize].clone())
        .collect()
}

/// Converts BE bytes into bits in MSB-first order, left-padding with zeroes
/// to the nearest multiple of 8.
pub fn u8vec_to_boolvec(v: &[u8]) -> Vec<bool> {
    let mut bv = Vec::with_capacity(v.len() * 8);
    for byte in v.iter() {
        for i in 0..8 {
            bv.push(((byte >> (7 - i)) & 1) != 0);
        }
    }
    bv
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
