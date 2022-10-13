use super::circuit::{AuthDecodeCircuit, SALT_SIZE, TOTAL_FIELD_ELEMENTS};
use super::poseidon::{poseidon_1, poseidon_15};
use super::utils::{bigint_to_f, deltas_to_matrices, f_to_bigint};
use super::{CHUNK_SIZE, USEFUL_BITS};
use crate::prover::{ProofInput, Prove, ProverError};
use halo2_proofs::plonk;
use halo2_proofs::plonk::ProvingKey;
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::transcript::{Blake2bWrite, Challenge255};
use num::BigUint;
use pasta_curves::pallas::Base as F;
use pasta_curves::EqAffine;
use rand::thread_rng;

/// halo2's native ProvingKey can't be used without params, so we wrap
/// them in one struct.
#[derive(Clone)]
pub struct PK {
    pub key: ProvingKey<EqAffine>,
    pub params: Params<EqAffine>,
}

/// Implements the Prover in the authdecode protocol using halo2
/// proof system.
pub struct Prover {
    proving_key: PK,
}

impl Prove for Prover {
    fn prove(&self, input: ProofInput) -> Result<Vec<u8>, ProverError> {
        if input.deltas.len() != self.chunk_size() || input.plaintext.len() != TOTAL_FIELD_ELEMENTS
        {
            // this can only be caused by an error in
            // `crate::prover::AuthDecodeProver` logic
            return Err(ProverError::InternalError);
        }

        // convert into matrices
        let (deltas_as_rows, deltas_as_columns) =
            deltas_to_matrices(&input.deltas, self.useful_bits());

        // convert plaintext into F type
        let plaintext: [F; TOTAL_FIELD_ELEMENTS] = input
            .plaintext
            .iter()
            .map(bigint_to_f)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        // arrange into the format which halo2 expects
        let mut all_inputs: Vec<&[F]> = deltas_as_columns.iter().map(|v| v.as_slice()).collect();

        // add another column with public inputs
        let tmp = &[
            bigint_to_f(&input.plaintext_hash),
            bigint_to_f(&input.label_sum_hash),
            bigint_to_f(&input.sum_of_zero_labels),
        ];
        all_inputs.push(tmp);

        // prepare the proving system and generate the proof:

        let circuit = AuthDecodeCircuit::new(plaintext, bigint_to_f(&input.salt), deltas_as_rows);

        let params = &self.proving_key.params;
        let pk = &self.proving_key.key;

        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);

        let mut rng = thread_rng();

        // let now = Instant::now();

        let res = plonk::create_proof(
            params,
            pk,
            &[circuit],
            &[all_inputs.as_slice()],
            &mut rng,
            &mut transcript,
        );
        if res.is_err() {
            return Err(ProverError::ProvingBackendError);
        }

        // println!("Proof created [{:?}]", now.elapsed());
        let proof = transcript.finalize();
        // println!("Proof size [{} kB]", proof.len() as f64 / 1024.0);
        Ok(proof)
    }

    fn useful_bits(&self) -> usize {
        USEFUL_BITS
    }

    fn poseidon_rate(&self) -> usize {
        TOTAL_FIELD_ELEMENTS
    }

    fn permutation_count(&self) -> usize {
        1
    }

    fn salt_size(&self) -> usize {
        SALT_SIZE
    }

    fn chunk_size(&self) -> usize {
        CHUNK_SIZE
    }

    fn hash(&self, inputs: &[BigUint]) -> Result<BigUint, ProverError> {
        hash_internal(inputs)
    }
}

impl Prover {
    pub fn new(pk: PK) -> Self {
        Self { proving_key: pk }
    }
}

/// Hashes `inputs` with Poseidon and returns the digest as `BigUint`.
fn hash_internal(inputs: &[BigUint]) -> Result<BigUint, ProverError> {
    let digest = match inputs.len() {
        15 => {
            // hash with rate-15 Poseidon
            let fes: [F; 15] = inputs
                .iter()
                .map(bigint_to_f)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();
            poseidon_15(&fes)
        }
        1 => {
            // hash with rate-1 Poseidon
            let fes: [F; 1] = inputs
                .iter()
                .map(bigint_to_f)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();
            poseidon_1(&fes)
        }
        _ => return Err(ProverError::WrongPoseidonInput),
    };
    Ok(f_to_bigint(&digest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::halo2_backend::circuit::{CELLS_PER_ROW, K};
    use crate::halo2_backend::prover::hash_internal;
    use crate::halo2_backend::utils::bigint_to_256bits;
    use crate::halo2_backend::Curve;
    use crate::prover::{ProofInput, Prove, ProverError};
    use crate::tests::run_until_proofs_are_generated;
    use crate::verifier::{VerificationInput, VerifierError, Verify};
    use crate::Proof;
    use halo2_proofs::dev::MockProver;
    use num::BigUint;

    /// TestHalo2Prover is a test prover. It is the same as [Prover] except:
    /// - it doesn't require a proving key
    /// - it uses a `MockProver` inside `prove()`
    ///
    /// This allows us to test the circuit with the correct inputs from the authdecode
    /// protocol execution. Also allows us to corrupt each of the circuit inputs and
    /// expect a failure.
    struct TestHalo2Prover {}
    impl Prove for TestHalo2Prover {
        fn prove(&self, input: ProofInput) -> Result<Proof, ProverError> {
            // convert into matrices
            let (deltas_as_rows, deltas_as_columns) =
                deltas_to_matrices(&input.deltas, self.useful_bits());

            // convert plaintext into F type
            let good_plaintext: [F; TOTAL_FIELD_ELEMENTS] = input
                .plaintext
                .iter()
                .map(bigint_to_f)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();

            // arrange into the format which halo2 expects
            let mut good_inputs: Vec<Vec<F>> =
                deltas_as_columns.iter().map(|v| v.to_vec()).collect();

            // add another column with public inputs
            let tmp = vec![
                bigint_to_f(&input.plaintext_hash),
                bigint_to_f(&input.label_sum_hash),
                bigint_to_f(&input.sum_of_zero_labels),
            ];
            good_inputs.push(tmp);

            let circuit =
                AuthDecodeCircuit::new(good_plaintext, bigint_to_f(&input.salt), deltas_as_rows);

            // Test with the correct inputs.
            // Expect successful verification.

            let prover = MockProver::run(K, &circuit, good_inputs.clone()).unwrap();
            assert!(prover.verify().is_ok());

            // Find one delta which corresponds to plaintext bit 1 and corrupt
            // the delta:

            // Find the first bit 1 in plaintext
            let bits = bigint_to_256bits(input.plaintext[0].clone());
            let mut offset: i32 = -1;
            for (i, b) in bits.iter().enumerate() {
                if *b {
                    offset = i as i32;
                    break;
                }
            }
            // first field element of the plaintext is not expected to have all
            // bits set to zero.
            assert!(offset != -1);
            let offset = offset as usize;

            // Find the position of the corresponding delta. The position is
            // row/column in the halo2 table
            let col = offset % CELLS_PER_ROW;
            let row = offset / CELLS_PER_ROW;

            // Corrupt the delta
            let mut bad_input1 = good_inputs.clone();
            bad_input1[col][row] = F::from(123);

            let prover = MockProver::run(K, &circuit, bad_input1.clone()).unwrap();
            assert!(prover.verify().is_err());

            // One-by-one corrupt the plaintext hash, the label sum hash, the zero sum.
            // Expect verification error.

            for i in 0..3 {
                let mut bad_public_input = good_inputs.clone();
                bad_public_input[CELLS_PER_ROW][i] = F::from(123);
                let prover = MockProver::run(K, &circuit, bad_public_input.clone()).unwrap();
                assert!(prover.verify().is_err());
            }

            // Corrupt only the plaintext.
            // Expect verification error.

            let mut bad_plaintext = good_plaintext;
            bad_plaintext[0] = F::from(123);
            let circuit =
                AuthDecodeCircuit::new(bad_plaintext, bigint_to_f(&input.salt), deltas_as_rows);
            let prover = MockProver::run(K, &circuit, good_inputs.clone()).unwrap();
            assert!(prover.verify().is_err());

            // Corrupt only the salt.
            // Expect verification error.

            let bad_salt = BigUint::from(123u8);
            let circuit =
                AuthDecodeCircuit::new(good_plaintext, bigint_to_f(&bad_salt), deltas_as_rows);
            let prover = MockProver::run(K, &circuit, good_inputs.clone()).unwrap();
            assert!(prover.verify().is_err());

            Ok(Default::default())
        }

        fn useful_bits(&self) -> usize {
            USEFUL_BITS
        }

        fn poseidon_rate(&self) -> usize {
            TOTAL_FIELD_ELEMENTS
        }

        fn permutation_count(&self) -> usize {
            1
        }

        fn salt_size(&self) -> usize {
            SALT_SIZE
        }

        fn chunk_size(&self) -> usize {
            CHUNK_SIZE
        }

        fn hash(&self, inputs: &[BigUint]) -> Result<BigUint, ProverError> {
            hash_internal(inputs)
        }
    }

    impl TestHalo2Prover {
        pub fn new() -> Self {
            Self {}
        }
    }

    /// This verifier is the same as [crate::halo2_backend::verifier::Verifier] except:
    /// - it doesn't require a verifying key
    /// - it does not verify since `MockProver` does that already
    struct TestHalo2Verifier {
        curve: Curve,
    }

    impl TestHalo2Verifier {
        pub fn new(curve: Curve) -> Self {
            Self { curve }
        }
    }

    impl Verify for TestHalo2Verifier {
        fn verify(&self, _: VerificationInput) -> Result<bool, VerifierError> {
            Ok(false)
        }

        fn field_size(&self) -> usize {
            match self.curve {
                Curve::Pallas => 255,
                Curve::BN254 => 254,
            }
        }

        fn useful_bits(&self) -> usize {
            USEFUL_BITS
        }

        fn chunk_size(&self) -> usize {
            CHUNK_SIZE
        }
    }

    #[test]
    // As of Oct 2022 there appears to be a bug in halo2 which causes the prove
    // times with MockProver be as long as with a real prover. Marking this test
    // as expensive.
    #[ignore = "expensive"]
    /// Tests the circuit with the correct inputs as well as wrong inputs. The logic is
    /// in [TestHalo2Prover]'s prove()
    fn test_circuit() {
        // This test causes the "thread ... has overflowed its stack" error
        // The only way to increase the stack size is to spawn a new thread with
        // the test.
        // See https://github.com/rust-lang/rustfmt/issues/3473
        use std::thread;
        thread::Builder::new()
            .stack_size(8388608)
            .spawn(|| {
                let prover = Box::new(TestHalo2Prover::new());
                let verifier = Box::new(TestHalo2Verifier::new(Curve::Pallas));
                let _ = run_until_proofs_are_generated(prover, verifier);
            })
            .expect("Failed to create a test thread")
            .join()
            .expect("Failed to join a test thread");
    }
}
