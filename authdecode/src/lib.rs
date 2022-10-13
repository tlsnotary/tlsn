//! This module implements the protocol for zero-knowledge authenticated
//! decoding (aka AuthDecode) of output labels from a garbled circuit (GC)
//! evaluation.
//! The purpose of AuthDecode is to allow the GC evaluator to produce a zk-friendly
//! hash commitment to the GC output. Computing a zk-friendly hash directly inside
//! the GC is too expensive, hence the need for this protocol.
//!
//! The high-level overview of Authdecode is:
//! - The Verifier first reveals all of his secret inputs to the GC
//! - The Prover computes the expected output of GC ("the plaintext") in the
//! clear and commits to it
//! - The Verifier sends the GC but withholds the output decoding information
//! - The Prover evaluates the circuit and commits to his active output labels
//! - The Verifier reveals all the output labels of the circuit
//! - The Prover, without revealing the plaintext, creates a zero-knowledge proof
//! that the plaintext he committed to earlier is the true output of the GC evaluation
//!
//! Authdecode assumes a privacy-free setting for the garbler, i.e. the protocol
//! MUST ONLY start AFTER the garbler reveals all his secret GC inputs.
//! Specifically, in the context of the TLSNotary protocol, AuthDecode MUST ONLY
//! start AFTER the Notary (who is the garbler) has revealed all of his TLS session
//! keys' shares.

pub mod halo2_backend;
mod label;
pub mod prover;
mod utils;
pub mod verifier;

use num::BigUint;

/// The bitsize of an arithmetic label. MUST be > 40 to give statistical
/// security against the Prover guessing the label. For a 254-bit field,
/// the bitsize > 96 would require 2 field elements for the
/// salted label sum instead of 1.
const ARITHMETIC_LABEL_SIZE: usize = 96;

/// The maximum supported size (in bits) of one [Chunk] of plaintext.
/// Should not exceed 2^{ [prover::Prove::useful_bits] - [prover::Prove::salt_size]
/// - [ARITHMETIC_LABEL_SIZE] }.
/// 2^20 should suffice for most use cases.
const MAX_CHUNK_SIZE: usize = 1 << 20;

/// The maximum supported amount of plaintext [Chunk]s ( which is equal to the
/// amount of zk proofs). Having too many zk proofs may be a DOS vector
/// against the Notary who is the verifier of zk proofs.
const MAX_CHUNK_COUNT: usize = 128;

/// The decoded output labels of the garbled circuit. In other words, this is
/// the plaintext output resulting from the evaluation of a garbled circuit.
type Plaintext = Vec<u8>;

/// The size of [Plaintext] in bits.
type PlaintextSize = usize;

/// A chunk of [Plaintext]. The amount of vec elements equals
/// [Prove::poseidon_rate] * [Prove::permutation_count]. Each vec element
/// is an "Elliptic curve field element" into which [Prove::useful_bits] bits
/// of [Plaintext] is packed.
/// The chunk does NOT contain the [Salt].
type Chunk = Vec<BigUint>;

/// Before hashing a [Chunk], it is salted by shifting its last element to the
/// left by [Prove::salt_size] and placing the salt into the low bits.
/// This same salt is also used to salt the sum of all the labels corresponding
/// to the [Chunk].
/// Without the salt, a hash of plaintext with low entropy could be brute-forced.
type Salt = BigUint;

/// A Poseidon hash digest of a [Salt]ed [Chunk]. This is an EC field element.
type PlaintextHash = BigUint;

/// A Poseidon hash digest of a [Salt]ed arithmetic sum of arithmetic labels
/// corresponding to the [Chunk]. This is an EC field element.
type LabelSumHash = BigUint;

/// An arithmetic sum of all "zero" arithmetic labels ( those are the labels
/// which encode the bit value 0) corresponding to one [Chunk].
type ZeroSum = BigUint;

/// An arithmetic difference between the arithmetic label "one" and the
/// arithmetic label "zero".
type Delta = BigUint;

/// A serialized proof proving that a Poseidon hash is the result of hashing a
/// salted [Chunk], which [Chunk] is the result of the decoding of a garbled
/// circuit's labels.
type Proof = Vec<u8>;

#[cfg(test)]
mod tests {
    use crate::prover::{AuthDecodeProver, Prove};
    use crate::utils::*;
    use crate::verifier::VerifyMany;
    use crate::verifier::{AuthDecodeVerifier, VerifierError, Verify};
    use crate::{Proof, Salt};
    use rand::{thread_rng, Rng};

    /// Accepts a concrete Prover and Verifier and runs the whole AuthDecode
    /// protocol end-to-end.
    ///
    /// Corrupts the proof if `will_corrupt_proof` is `true` and expects the
    /// verification to fail.
    pub fn e2e_test(prover: Box<dyn Prove>, verifier: Box<dyn Verify>, will_corrupt_proof: bool) {
        let (proofs, _salts, verifier) = run_until_proofs_are_generated(prover, verifier);

        if !will_corrupt_proof {
            // Notary verifies a good proof
            let (result, _) = verifier.verify_many(proofs).unwrap();
            assert!(result);
        } else {
            // corrupt one byte in each proof
            let corrupted_proofs: Vec<Proof> = proofs
                .iter()
                .map(|p| {
                    let old_byte = p[p.len() / 2];
                    let new_byte = old_byte.checked_add(1).unwrap_or_default();
                    let mut new_proof = p.clone();
                    let p_len = new_proof.len();
                    new_proof[p_len / 2] = new_byte;
                    new_proof
                })
                .collect();
            // Notary tries to verify a corrupted proof
            let res = verifier.verify_many(corrupted_proofs);
            assert_eq!(res.err().unwrap(), VerifierError::VerificationFailed);
        }
    }

    /// Runs the protocol until the moment when Prover returns generated proofs.
    ///
    /// Returns the proofs, the salts, and the verifier in the next expected state.
    pub fn run_until_proofs_are_generated(
        prover: Box<dyn Prove>,
        verifier: Box<dyn Verify>,
    ) -> (Vec<Proof>, Vec<Salt>, AuthDecodeVerifier<VerifyMany>) {
        let mut rng = thread_rng();

        // generate random plaintext of random size up to 1000 bytes
        let plaintext: Vec<u8> = core::iter::repeat_with(|| rng.gen::<u8>())
            .take(thread_rng().gen_range(1..1000))
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

        // Prover generates the proof
        let (proofs, salts) = prover.create_zk_proofs().unwrap();
        (proofs, salts, verifier)
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
}
