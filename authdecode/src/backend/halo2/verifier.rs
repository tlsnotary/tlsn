use super::{
    circuit::{BIT_COLUMNS, FIELD_ELEMENTS, USABLE_BITS},
    utils::deltas_to_matrices,
    Bn256F, CHUNK_SIZE,
};
use crate::{
    backend::{
        halo2::{utils::slice_to_columns, PARAMS},
        traits::VerifierBackend as Backend,
    },
    verifier::{error::VerifierError, verifier::VerificationInputs},
    Proof,
};

use ff::{FromUniformBytes, WithSmallOrderMulGroup};
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr as F, G1Affine},
    plonk::{verify_proof as verify_plonk_proof, VerifyingKey},
    poly::{
        commitment::{CommitmentScheme, Verifier as CommitmentVerifier},
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::VerifierGWC,
            strategy::AccumulatorStrategy,
        },
        VerificationStrategy,
    },
    transcript::{Blake2bRead, Challenge255, EncodedChallenge, TranscriptReadBuffer},
};

/// The Verifier of the authdecode circuit.
pub struct Verifier {
    verification_key: VerifyingKey<G1Affine>,
}
impl Verifier {
    pub fn new(verification_key: VerifyingKey<G1Affine>) -> Self {
        Self { verification_key }
    }

    fn usable_bits(&self) -> usize {
        USABLE_BITS
    }

    /// Prepares instance columns for verification.
    fn prepare_verification_input(&self, input: &VerificationInputs<Bn256F>) -> Vec<Vec<F>> {
        let deltas = input
            .deltas
            .iter()
            .map(|f: &Bn256F| f.inner)
            .collect::<Vec<_>>();

        let (_, instance_columns) = deltas_to_matrices(&deltas, self.usable_bits());
        let mut instance_columns = instance_columns
            .iter()
            .map(|inner| inner.to_vec())
            .collect::<Vec<_>>();

        // Add another column with public inputs.
        instance_columns.push(vec![
            input.plaintext_hash.inner,
            input.encoding_sum_hash.inner,
            input.zero_sum.inner,
        ]);
        instance_columns
    }
}

impl Backend<Bn256F> for Verifier {
    fn verify(
        &self,
        inputs: Vec<VerificationInputs<Bn256F>>,
        proofs: Vec<Proof>,
    ) -> Result<(), VerifierError> {
        // TODO: implement a better proving strategy.
        // For now we just assume that one proof proves one chunk.
        assert!(inputs.len() == proofs.len());

        for (input, proof) in inputs.into_iter().zip(proofs) {
            let instance_columns = self.prepare_verification_input(&input);

            verify_proof::<
                KZGCommitmentScheme<Bn256>,
                VerifierGWC<'_, Bn256>,
                _,
                Blake2bRead<_, _, Challenge255<_>>,
                AccumulatorStrategy<_>,
            >(
                &crate::backend::halo2::onetimesetup::params(),
                &self.verification_key,
                &proof.0,
                &[&instance_columns
                    .iter()
                    .map(|col| col.as_slice())
                    .collect::<Vec<_>>()],
            )?;
        }

        Ok(())
    }

    fn chunk_size(&self) -> usize {
        CHUNK_SIZE
    }
}

fn verify_proof<
    'a,
    'params,
    Scheme: CommitmentScheme<Scalar = halo2_proofs::halo2curves::bn256::Fr>,
    V: CommitmentVerifier<'params, Scheme>,
    E: EncodedChallenge<Scheme::Curve>,
    T: TranscriptReadBuffer<&'a [u8], Scheme::Curve, E>,
    Strategy: VerificationStrategy<'params, Scheme, V, Output = Strategy>,
>(
    params_verifier: &'params Scheme::ParamsVerifier,
    vk: &VerifyingKey<Scheme::Curve>,
    proof: &'a [u8],
    instances: &[&[&[F]]],
) -> Result<(), VerifierError>
where
    Scheme::Scalar: Ord + WithSmallOrderMulGroup<3> + FromUniformBytes<64>,
{
    let mut transcript = T::init(proof);

    let strategy = Strategy::new(params_verifier);
    let strategy = verify_plonk_proof(params_verifier, vk, strategy, instances, &mut transcript);

    if strategy.is_err() {
        return Err(VerifierError::VerificationFailed);
    }

    let str = strategy.unwrap();

    if !str.finalize() {
        return Err(VerifierError::VerificationFailed);
    }

    Ok(())
}
