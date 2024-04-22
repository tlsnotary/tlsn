use crate::{
    backend::{
        halo2::{
            circuit::{AuthDecodeCircuit, BIT_COLUMNS, FIELD_ELEMENTS, SALT_SIZE, USABLE_BYTES},
            poseidon::{poseidon_1, poseidon_15, poseidon_2},
            utils::{bytes_be_to_f, slice_to_columns},
            Bn256F, CHUNK_SIZE, PARAMS,
        },
        traits::{Field, ProverBackend as Backend},
    },
    prover::{error::ProverError, prover::ProofInput},
    Proof,
};

use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr as F, G1Affine},
    plonk,
    plonk::ProvingKey,
    poly::kzg::{commitment::KZGCommitmentScheme, multiopen::ProverGWC},
    transcript::{Blake2bWrite, Challenge255, TranscriptWriterBuffer},
};
#[cfg(test)]
use std::any::Any;

use rand::{thread_rng, Rng};

/// The Prover of the AuthDecode circuit.
#[derive(Clone)]
pub struct Prover {
    proving_key: ProvingKey<G1Affine>,
}

impl Backend<Bn256F> for Prover {
    fn commit_plaintext(&self, plaintext: Vec<u8>) -> (Bn256F, Bn256F) {
        debug_assert!(plaintext.len() <= self.chunk_size());

        // Split up the plaintext bits into field elements.
        let mut plaintext: Vec<Bn256F> = plaintext
            .chunks(self.usable_bytes())
            .map(|bytes| Bn256F::from_bytes_be(bytes.to_vec()))
            .collect::<Vec<_>>();
        // Zero-pad the total count of field elements if needed.
        plaintext.extend(vec![Bn256F::zero(); FIELD_ELEMENTS - plaintext.len()]);

        // Generate random salt and add it to the plaintext.
        let mut rng = thread_rng();
        let salt = core::iter::repeat_with(|| rng.gen::<u8>())
            .take(SALT_SIZE)
            .collect::<Vec<_>>();
        let salt = Bn256F::from_bytes_be(salt);
        plaintext.push(salt.clone());

        (hash_internal(&plaintext), salt)
    }

    fn commit_encoding_sum(&self, encoding_sum: Bn256F) -> (Bn256F, Bn256F) {
        // Generate random salt.
        let mut rng = thread_rng();
        let salt = core::iter::repeat_with(|| rng.gen::<u8>())
            .take(SALT_SIZE)
            .collect::<Vec<_>>();
        let salt = Bn256F::from_bytes_be(salt);

        // TODO: we may want to consider packing sum and salt into a single field element, to
        // achive this order starting from the MSB:
        // zero padding | sum | salt
        // For now, we use a dedicated field element for the salt.
        (hash_internal(&[encoding_sum, salt.clone()]), salt)
    }

    fn prove(&self, input: Vec<ProofInput<Bn256F>>) -> Result<Vec<Proof>, ProverError> {
        // TODO: implement a better proving strategy.
        // For now we just prove one chunk with one proof.
        let mut rng = thread_rng();

        let proofs = input
            .into_iter()
            .map(|input| {
                let (instance_columns, circuit) = self.prepare_circuit_input(&input);

                let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);

                plonk::create_proof::<
                    KZGCommitmentScheme<Bn256>,
                    ProverGWC<'_, Bn256>,
                    Challenge255<G1Affine>,
                    _,
                    Blake2bWrite<Vec<u8>, G1Affine, Challenge255<_>>,
                    _,
                >(
                    &PARAMS,
                    &self.proving_key,
                    &[circuit.clone()],
                    &[&instance_columns
                        .iter()
                        .map(|col| col.as_slice())
                        .collect::<Vec<_>>()],
                    &mut rng,
                    &mut transcript,
                )
                .map_err(|_| ProverError::ProvingBackendError)?;

                Ok(Proof::new(&transcript.finalize()))
            })
            .collect::<Result<Vec<Proof>, ProverError>>()?;

        Ok(proofs)
    }

    fn chunk_size(&self) -> usize {
        CHUNK_SIZE
    }

    #[cfg(test)]
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl Prover {
    pub fn new(proving_key: ProvingKey<G1Affine>) -> Self {
        Self { proving_key }
    }

    /// How many least significant bytes of a field element are used to pack the plaintext into.
    fn usable_bytes(&self) -> usize {
        USABLE_BYTES
    }

    /// Prepares instance columns and an instance of the circuit.
    fn prepare_circuit_input(
        &self,
        input: &ProofInput<Bn256F>,
    ) -> (Vec<Vec<F>>, AuthDecodeCircuit) {
        let deltas = input
            .deltas
            .iter()
            .map(|f: &Bn256F| f.inner)
            .collect::<Vec<_>>();

        // Arrange deltas in instance columns.
        let mut instance_columns = slice_to_columns(
            &deltas,
            self.usable_bytes() * 8,
            BIT_COLUMNS * 4,
            FIELD_ELEMENTS * 4,
            BIT_COLUMNS,
        );

        // Add another column with public inputs.
        instance_columns.push(vec![
            input.plaintext_hash.inner,
            input.encoding_sum_hash.inner,
            input.zero_sum.inner,
        ]);

        // Split up the plaintext into field elements.
        let mut plaintext: Vec<F> = input
            .plaintext
            .chunks(self.usable_bytes())
            .map(|bytes| bytes_be_to_f(bytes.to_vec()))
            .collect::<Vec<_>>();
        // Zero-pad the total count of field elements if needed.
        plaintext.extend(vec![F::zero(); FIELD_ELEMENTS - plaintext.len()]);

        let circuit = AuthDecodeCircuit::new(
            plaintext.try_into().unwrap(),
            input.plaintext_salt.inner,
            input.encoding_sum_salt.inner,
        );

        (instance_columns, circuit)
    }
}

/// Hashes `inputs` with Poseidon and returns the digest.
fn hash_internal(inputs: &[Bn256F]) -> Bn256F {
    match inputs.len() {
        15 => poseidon_15(inputs.try_into().unwrap()),
        2 => poseidon_2(inputs.try_into().unwrap()),
        1 => poseidon_1(inputs.try_into().unwrap()),
        _ => unreachable!(),
    }
}

#[cfg(test)]
// Whether the `test_binary_check_fail` test is running.
pub static mut TEST_BINARY_CHECK_FAIL_IS_RUNNING: bool = false;

#[cfg(test)]
mod tests {
    use crate::{
        backend::halo2::{onetimesetup, verifier::Verifier},
        tests::proof_inputs_for_backend,
    };

    use rstest::{fixture, rstest};

    use super::*;

    use halo2_proofs::{
        dev::{metadata::Constraint, MockProver, VerifyFailure},
        poly::{commitment::Params, kzg::commitment::ParamsKZG},
    };

    #[fixture]
    // Returns the instance columns and the circuit for proof generation.
    fn proof_input() -> (Vec<Vec<F>>, AuthDecodeCircuit) {
        let p = Prover::new(onetimesetup::proving_key());
        let v = Verifier::new(onetimesetup::verification_key());
        let input = proof_inputs_for_backend(p.clone(), v)[0].clone();
        p.prepare_circuit_input(&input)
    }

    #[fixture]
    fn k() -> u32 {
        ParamsKZG::<Bn256>::k(&PARAMS)
    }

    #[rstest]
    // Expect verification to succeed when the correct proof generation inputs are used.
    fn test_ok(proof_input: (Vec<Vec<F>>, AuthDecodeCircuit), k: u32) {
        let prover = MockProver::run(k, &proof_input.1, proof_input.0).unwrap();
        assert!(prover.verify().is_ok());
    }

    #[rstest]
    // Expect verification to fail when the plaintext is wrong.
    fn test_bad_plaintext(mut proof_input: (Vec<Vec<F>>, AuthDecodeCircuit), k: u32) {
        // Flip the lowest bit of the first field element.
        let bit = proof_input.1.plaintext[0][3][63];
        let new_bit = F::one() - bit;
        proof_input.1.plaintext[0][3][63] = new_bit;

        let prover = MockProver::run(k, &proof_input.1, proof_input.0).unwrap();
        assert!(prover.verify().is_err());
    }

    #[rstest]
    // Expect verification to fail when the plaintext salt is wrong.
    fn test_bad_plaintext_salt(mut proof_input: (Vec<Vec<F>>, AuthDecodeCircuit), k: u32) {
        proof_input.1.plaintext_salt += F::one();

        let prover = MockProver::run(k, &proof_input.1, proof_input.0).unwrap();
        assert!(prover.verify().is_err());
    }

    #[rstest]
    // Expect verification to fail when the encoding sum salt is wrong.
    fn test_bad_encoding_sum_salt(mut proof_input: (Vec<Vec<F>>, AuthDecodeCircuit), k: u32) {
        proof_input.1.encoding_sum_salt += F::one();

        let prover = MockProver::run(k, &proof_input.1, proof_input.0).unwrap();
        assert!(prover.verify().is_err());
    }

    #[rstest]
    // Expect verification to fail when a delta is wrong.
    fn test_bad_delta(mut proof_input: (Vec<Vec<F>>, AuthDecodeCircuit), k: u32) {
        // Note that corrupting the delta corresponding to a bit with the value 0 will not cause
        // verification failure, since the dot product will not be affected by the corruption.

        // Find the index of the plaintext bit with the value 1 in the low limb of the first field
        // element.
        let mut index: Option<usize> = None;
        for (idx, bit) in proof_input.1.plaintext[0][3].iter().enumerate() {
            if *bit == F::one() {
                index = Some(idx);
                break;
            }
        }

        // Corrupt the corresponding delta on the 4th row in the `index`-th column.
        proof_input.0[index.unwrap()][3] += F::one();

        let prover = MockProver::run(k, &proof_input.1, proof_input.0).unwrap();
        assert!(prover.verify().is_err());
    }

    #[rstest]
    // Expect verification to fail when the plaintext hash is wrong.
    fn test_bad_plaintext_hash(mut proof_input: (Vec<Vec<F>>, AuthDecodeCircuit), k: u32) {
        // There are as many instance columns with deltas as there are `BIT_COLUMNS`.
        // The value that we need is in the column after the deltas on the first row.
        proof_input.0[BIT_COLUMNS][0] += F::one();

        let prover = MockProver::run(k, &proof_input.1, proof_input.0).unwrap();
        assert!(prover.verify().is_err());
    }

    #[rstest]
    // Expect verification to fail when the encoding sum hash is wrong.
    fn test_bad_encoding_sum_hash(mut proof_input: (Vec<Vec<F>>, AuthDecodeCircuit), k: u32) {
        // There are as many instance columns with deltas as there are `BIT_COLUMNS`.
        // The value that we need is in the column after the deltas on the second row.
        proof_input.0[BIT_COLUMNS][1] += F::one();

        let prover = MockProver::run(k, &proof_input.1, proof_input.0).unwrap();
        assert!(prover.verify().is_err());
    }

    #[rstest]
    // Expect verification to fail when the zero sum is wrong.
    fn test_bad_zero_sum(mut proof_input: (Vec<Vec<F>>, AuthDecodeCircuit), k: u32) {
        // There are as many instance columns with deltas as there are `BIT_COLUMNS`.
        // The value that we need is in the column after the deltas on the third row.
        proof_input.0[BIT_COLUMNS][2] += F::one();

        let prover = MockProver::run(k, &proof_input.1, proof_input.0).unwrap();
        assert!(prover.verify().is_err());
    }

    #[rstest]
    // Expect an unsatisfied constraint in the "binary_check" gate when not all bits of the plaintext
    // are binary.
    fn test_binary_check_fail(mut proof_input: (Vec<Vec<F>>, AuthDecodeCircuit), k: u32) {
        unsafe {
            TEST_BINARY_CHECK_FAIL_IS_RUNNING = true;
        }

        proof_input.1.plaintext[1][2][34] = F::one() + F::one();

        let prover = MockProver::run(k, &proof_input.1, proof_input.0).unwrap();

        // We may need to change gate index here if we modify the circuit.
        let expected_failed_constraint: Constraint = ((7, "binary_check").into(), 34, "").into();

        match &prover.verify().err().unwrap()[0] {
            VerifyFailure::ConstraintNotSatisfied {
                constraint,
                location: _,
                cell_values: _,
            } => assert!(constraint == &expected_failed_constraint),
            _ => panic!("An unexpected constraint was unsatisfied"),
        }
    }

    #[rstest]
    // Expect an unsatisfied constraint in the "eight_bits_zero" gate when not all of the 8 MSBs of a
    // field element are zeroes.
    fn test_eight_bits_zero_fail(mut proof_input: (Vec<Vec<F>>, AuthDecodeCircuit), k: u32) {
        // Set the MSB to 1.
        proof_input.1.plaintext[0][0][0] = F::one();

        let prover = MockProver::run(k, &proof_input.1, proof_input.0).unwrap();

        // We may need to change gate index here if we modify the circuit.
        let expected_failed_constraint: Constraint = ((13, "eight_bits_zero").into(), 0, "").into();

        match &prover.verify().err().unwrap()[0] {
            VerifyFailure::ConstraintNotSatisfied {
                constraint,
                location: _,
                cell_values: _,
            } => assert!(constraint == &expected_failed_constraint),
            _ => panic!("An unexpected constraint was unsatisfied"),
        }
    }
}
