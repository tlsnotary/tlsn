use super::{utils::deltas_to_matrices, CHUNK_SIZE, USEFUL_BITS};
use crate::{
    backend::halo2::utils::biguint_to_f,
    verifier::{backend::Backend, error::VerifierError, verifier::VerificationInput},
    Proof,
};
use web_time::Instant;

use ff::{FromUniformBytes, WithSmallOrderMulGroup};
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr as F},
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

/// halo2's native [halo2::VerifyingKey] can't be used without params, so we wrap
/// them in one struct.
#[derive(Clone)]
pub struct VK {
    pub key: VerifyingKey<<KZGCommitmentScheme<Bn256> as CommitmentScheme>::Curve>,
    pub params: ParamsKZG<Bn256>,
}

/// Implements the Verifier in the authdecode protocol.
pub struct Verifier {
    verification_key: VK,
}
impl Verifier {
    pub fn new(vk: VK) -> Self {
        Self {
            verification_key: vk,
        }
    }

    fn useful_bits(&self) -> usize {
        USEFUL_BITS
    }
}

impl Backend for Verifier {
    fn verify(
        &self,
        inputs: Vec<VerificationInput>,
        proofs: Vec<Proof>,
    ) -> Result<(), VerifierError> {
        // TODO: implement a better proving strategy.
        // For now we just assume that one proof proves one chunk.
        assert!(inputs.len() == proofs.len());

        let params = &self.verification_key.params;
        let vk = &self.verification_key.key;

        for (input, proof) in inputs.iter().zip(proofs) {
            // convert deltas into a matrix which halo2 expects
            let (_, deltas_as_columns) = deltas_to_matrices(&input.deltas, self.useful_bits());

            let mut all_inputs: Vec<&[F]> =
                deltas_as_columns.iter().map(|v| v.as_slice()).collect();

            // add another column with public inputs
            let tmp = &[
                biguint_to_f(&input.plaintext_hash),
                biguint_to_f(&input.encoding_sum_hash),
                biguint_to_f(&input.zero_sum),
            ];
            all_inputs.push(tmp);

            let now = Instant::now();
            verify_proof::<
                KZGCommitmentScheme<Bn256>,
                VerifierGWC<'_, Bn256>,
                _,
                Blake2bRead<_, _, Challenge255<_>>,
                AccumulatorStrategy<_>,
            >(params, vk, &proof, &[all_inputs.as_slice()])?;
            println!("Proof verified in [{:?}]", now.elapsed());
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
