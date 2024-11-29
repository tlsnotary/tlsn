use crate::{
    backend::{
        halo2::{
            circuit::{AuthDecodeCircuit, FIELD_ELEMENTS, SALT_SIZE, USABLE_BYTES},
            onetimesetup::proving_key,
            prepare_instance,
            utils::bytes_to_f,
            Bn256F, CHUNK_SIZE, PARAMS,
        },
        traits::{Field, ProverBackend as Backend},
    },
    prover::{PrivateInput, ProverError, ProverInput},
    Proof,
};

use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr as F, G1Affine},
    plonk,
    plonk::ProvingKey,
    poly::kzg::{commitment::KZGCommitmentScheme, multiopen::ProverGWC},
    transcript::{Blake2bWrite, Challenge255, TranscriptWriterBuffer},
};
use poseidon_bn256_pad14::hash_to_field;
use poseidon_circomlib::hash;

use rand::{thread_rng, Rng};

#[cfg(any(test, feature = "fixtures"))]
use std::any::Any;

#[cfg(feature = "tracing")]
use tracing::{debug, debug_span, instrument, Instrument};

/// The Prover of the AuthDecode circuit.
#[derive(Clone)]
pub struct Prover {
    /// The proving key.
    proving_key: ProvingKey<G1Affine>,
}

impl Backend<Bn256F> for Prover {
    #[cfg_attr(feature = "tracing", instrument(level = "debug", skip_all))]
    fn commit_plaintext(&self, plaintext: &[u8]) -> (Bn256F, Bn256F) {
        // Generate a random salt and add it to the plaintext.
        let mut rng = thread_rng();
        let salt = core::iter::repeat_with(|| rng.gen::<u8>())
            .take(SALT_SIZE)
            .collect::<Vec<_>>();

        (
            self.commit_plaintext_with_salt(plaintext, &salt),
            Bn256F::from_bytes(&salt),
        )
    }

    #[cfg_attr(feature = "tracing", instrument(level = "debug", skip_all))]
    fn commit_plaintext_with_salt(&self, plaintext: &[u8], salt: &[u8]) -> Bn256F {
        Bn256F::new(hash_to_field(plaintext, salt))
    }

    #[cfg_attr(feature = "tracing", instrument(level = "debug", skip_all))]
    fn commit_encoding_sum(&self, encoding_sum: Bn256F) -> (Bn256F, Bn256F) {
        // Generate a random salt.
        let salt = core::iter::repeat_with(|| thread_rng().gen::<u8>())
            .take(SALT_SIZE)
            .collect::<Vec<_>>();
        let salt = Bn256F::from_bytes(&salt);

        // XXX: we could pack the sum and the salt into a single field element at the cost of performing
        // an additional range check in the circuit, but the gains would be negligible.

        // Zero-pad the input before hashing.
        // (Normally, we would use a rate-2 Poseidon without padding, but `halo2_poseidon`
        // is not compatible with the Circomlib's rate-2 spec).
        (
            Bn256F::new(hash(&[encoding_sum.inner, F::zero(), salt.clone().inner])),
            salt,
        )
    }

    #[cfg_attr(feature = "tracing", instrument(level = "debug", skip_all, err))]
    fn prove(&self, input: Vec<ProverInput<Bn256F>>) -> Result<Vec<Proof>, ProverError> {
        // XXX: using the default strategy of proving one chunk of plaintext with one proof.
        // There are considerable gains to be had when proving multiple chunks with one proof.

        let proofs = input
            .into_iter()
            .map(|input| {
                let instance_columns = prepare_instance(input.public(), self.usable_bytes());
                let circuit = prepare_circuit(input.private(), self.usable_bytes());

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
                    &mut thread_rng(),
                    &mut transcript,
                )
                .map_err(|e| ProverError::ProvingBackendError(e.to_string()))?;

                Ok(Proof::new(&transcript.finalize()))
            })
            .collect::<Result<Vec<Proof>, ProverError>>()?;

        Ok(proofs)
    }

    fn chunk_size(&self) -> usize {
        CHUNK_SIZE
    }

    #[cfg(any(test, feature = "fixtures"))]
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl Default for Prover {
    fn default() -> Self {
        Self::new()
    }
}

impl Prover {
    /// Generates a proving key and creates a new prover.
    //
    // To prevent the latency caused by the generation of a proving key, consider caching
    // the proving key and use `new_with_key` instead.
    pub fn new() -> Self {
        Self {
            proving_key: proving_key(),
        }
    }

    /// Creates a new prover with the provided proving key.
    pub fn new_with_key(proving_key: ProvingKey<G1Affine>) -> Self {
        Self { proving_key }
    }

    /// How many least significant bytes of a field element are used to pack the plaintext into.
    fn usable_bytes(&self) -> usize {
        USABLE_BYTES
    }
}

/// Prepares an instance of the circuit.
#[cfg_attr(feature = "tracing", instrument(level = "debug", skip_all))]
fn prepare_circuit(input: &PrivateInput<Bn256F>, usable_bytes: usize) -> AuthDecodeCircuit {
    // Split up the plaintext into field elements.
    let mut plaintext: Vec<F> = input
        .plaintext()
        .chunks(usable_bytes)
        .map(bytes_to_f)
        .collect::<Vec<_>>();
    // Zero-pad the total count of field elements if needed.
    plaintext.extend(vec![F::zero(); FIELD_ELEMENTS - plaintext.len()]);

    AuthDecodeCircuit::new(
        plaintext.try_into().unwrap(),
        input.plaintext_salt().inner,
        input.encoding_sum_salt().inner,
    )
}

#[cfg(any(test, feature = "fixtures"))]
/// Wraps `prepare_circuit` to expose it for fixtures.
pub fn _prepare_circuit(input: &PrivateInput<Bn256F>, usable_bytes: usize) -> AuthDecodeCircuit {
    prepare_circuit(input, usable_bytes)
}

#[cfg(test)]
// Whether the `test_binary_check_fail` test is running.
pub static mut TEST_BINARY_CHECK_FAIL_IS_RUNNING: bool = false;

#[cfg(test)]
mod tests {
    use crate::{
        backend::halo2::{verifier::Verifier, BITS_PER_LIMB},
        tests::proof_inputs_for_backend,
    };

    use rstest::{fixture, rstest};

    use super::*;

    use halo2_proofs::dev::{metadata::Constraint, MockProver, VerifyFailure};

    // Returns the instance columns and the circuit for proof generation.
    #[fixture]
    #[once]
    fn proof_input() -> (Vec<Vec<F>>, AuthDecodeCircuit) {
        let p = Prover::new();
        let v = Verifier::new();
        let input = proof_inputs_for_backend(p.clone(), v)[0].clone();
        (
            prepare_instance(input.public(), p.usable_bytes()),
            prepare_circuit(input.private(), p.usable_bytes()),
        )
    }

    #[fixture]
    #[once]
    fn k() -> u32 {
        crate::backend::halo2::fixtures::k()
    }

    // Expects verification to succeed when the correct proof generation inputs are used.
    #[rstest]
    fn test_ok(proof_input: &(Vec<Vec<F>>, AuthDecodeCircuit), k: &u32) {
        let proof_input: (Vec<Vec<F>>, AuthDecodeCircuit) = proof_input.clone();

        let prover = MockProver::run(*k, &proof_input.1, proof_input.0).unwrap();
        assert!(prover.verify().is_ok());
    }

    // Expects verification to fail when the plaintext is wrong.
    #[rstest]
    fn test_bad_plaintext(proof_input: &(Vec<Vec<F>>, AuthDecodeCircuit), k: &u32) {
        let mut proof_input: (Vec<Vec<F>>, AuthDecodeCircuit) = proof_input.clone();

        // Flip the lowest bit of the first field element.
        let bit = proof_input.1.plaintext[0][3][63];
        let new_bit = F::one() - bit;
        proof_input.1.plaintext[0][3][63] = new_bit;

        let prover = MockProver::run(*k, &proof_input.1, proof_input.0).unwrap();
        assert!(prover.verify().is_err());
    }

    // Expects verification to fail when the plaintext salt is wrong.
    #[rstest]
    fn test_bad_plaintext_salt(proof_input: &(Vec<Vec<F>>, AuthDecodeCircuit), k: &u32) {
        let mut proof_input: (Vec<Vec<F>>, AuthDecodeCircuit) = proof_input.clone();

        proof_input.1.plaintext_salt += F::one();

        let prover = MockProver::run(*k, &proof_input.1, proof_input.0).unwrap();
        assert!(prover.verify().is_err());
    }

    // Expects verification to fail when the encoding sum salt is wrong.
    #[rstest]
    fn test_bad_encoding_sum_salt(proof_input: &(Vec<Vec<F>>, AuthDecodeCircuit), k: &u32) {
        let mut proof_input: (Vec<Vec<F>>, AuthDecodeCircuit) = proof_input.clone();

        proof_input.1.encoding_sum_salt += F::one();

        let prover = MockProver::run(*k, &proof_input.1, proof_input.0).unwrap();
        assert!(prover.verify().is_err());
    }

    // Expects verification to fail when a delta is wrong.
    #[rstest]
    fn test_bad_delta(proof_input: &(Vec<Vec<F>>, AuthDecodeCircuit), k: &u32) {
        let mut proof_input: (Vec<Vec<F>>, AuthDecodeCircuit) = proof_input.clone();

        // Note that corrupting the delta corresponding to a bit with the value 0 will not cause a
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

        let prover = MockProver::run(*k, &proof_input.1, proof_input.0).unwrap();
        assert!(prover.verify().is_err());
    }

    // Expects verification to fail when the plaintext hash is wrong.
    #[rstest]
    fn test_bad_plaintext_hash(proof_input: &(Vec<Vec<F>>, AuthDecodeCircuit), k: &u32) {
        let mut proof_input: (Vec<Vec<F>>, AuthDecodeCircuit) = proof_input.clone();

        // There are as many instance columns with deltas as there are `BIT_COLUMNS`.
        // The value that we need is in the column after the deltas on the first row.
        proof_input.0[BITS_PER_LIMB][0] += F::one();

        let prover = MockProver::run(*k, &proof_input.1, proof_input.0).unwrap();
        assert!(prover.verify().is_err());
    }

    // Expects verification to fail when the encoding sum hash is wrong.
    #[rstest]
    fn test_bad_encoding_sum_hash(proof_input: &(Vec<Vec<F>>, AuthDecodeCircuit), k: &u32) {
        let mut proof_input: (Vec<Vec<F>>, AuthDecodeCircuit) = proof_input.clone();

        // There are as many instance columns with deltas as there are `BIT_COLUMNS`.
        // The value that we need is in the column after the deltas on the second row.
        proof_input.0[BITS_PER_LIMB][1] += F::one();

        let prover = MockProver::run(*k, &proof_input.1, proof_input.0).unwrap();
        assert!(prover.verify().is_err());
    }

    // Expects verification to fail when the zero sum is wrong.
    #[rstest]
    fn test_bad_zero_sum(proof_input: &(Vec<Vec<F>>, AuthDecodeCircuit), k: &u32) {
        let mut proof_input: (Vec<Vec<F>>, AuthDecodeCircuit) = proof_input.clone();

        // There are as many instance columns with deltas as there are `BIT_COLUMNS`.
        // The value that we need is in the column after the deltas on the third row.
        proof_input.0[BITS_PER_LIMB][2] += F::one();

        let prover = MockProver::run(*k, &proof_input.1, proof_input.0).unwrap();
        assert!(prover.verify().is_err());
    }

    // Expects an unsatisfied constraint in the "binary_check" gate when not all bits of the plaintext
    // are binary.
    #[rstest]
    fn test_binary_check_fail(proof_input: &(Vec<Vec<F>>, AuthDecodeCircuit), k: &u32) {
        let mut proof_input: (Vec<Vec<F>>, AuthDecodeCircuit) = proof_input.clone();

        unsafe {
            TEST_BINARY_CHECK_FAIL_IS_RUNNING = true;
        }

        proof_input.1.plaintext[1][2][34] = F::one() + F::one();

        let prover = MockProver::run(*k, &proof_input.1, proof_input.0).unwrap();

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

    // Expects an unsatisfied constraint in the "eight_bits_zero" gate when not all of the 8 MSBs of a
    // field element are zeroes.
    #[rstest]
    fn test_eight_bits_zero_fail(proof_input: &(Vec<Vec<F>>, AuthDecodeCircuit), k: &u32) {
        let mut proof_input: (Vec<Vec<F>>, AuthDecodeCircuit) = proof_input.clone();

        // Set the MSB to 1.
        proof_input.1.plaintext[0][3][BITS_PER_LIMB - 1] = F::one();

        let prover = MockProver::run(*k, &proof_input.1, proof_input.0).unwrap();

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
