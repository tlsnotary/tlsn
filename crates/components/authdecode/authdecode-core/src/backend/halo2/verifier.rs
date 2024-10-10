use crate::{
    backend::{
        halo2::{circuit::USABLE_BYTES, Bn256F, CHUNK_SIZE, PARAMS},
        traits::VerifierBackend as Backend,
    },
    verifier::VerifierError,
    Proof, PublicInput,
};

use ff::{FromUniformBytes, WithSmallOrderMulGroup};
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr as F, G1Affine},
    plonk::{verify_proof as verify_plonk_proof, VerifyingKey},
    poly::{
        commitment::{CommitmentScheme, Verifier as CommitmentVerifier},
        kzg::{
            commitment::KZGCommitmentScheme, multiopen::VerifierGWC, strategy::AccumulatorStrategy,
        },
        VerificationStrategy,
    },
    transcript::{Blake2bRead, Challenge255, EncodedChallenge, TranscriptReadBuffer},
};

#[cfg(feature = "tracing")]
use tracing::{debug, debug_span, instrument, Instrument};

use super::{onetimesetup::verification_key, prepare_instance};

/// The Verifier of the authdecode circuit.
pub struct Verifier {
    /// The verification key.
    verification_key: VerifyingKey<G1Affine>,
}

impl Default for Verifier {
    fn default() -> Self {
        Self::new()
    }
}

impl Verifier {
    /// Generates a verification key and creates a new verifier.
    //
    // To prevent the latency caused by the generation of a verification key, consider caching
    // the verification key and use `new_with_key` instead.
    pub fn new() -> Self {
        Self {
            verification_key: verification_key(),
        }
    }

    /// Creates a new verifier with the provided key.
    pub fn new_with_key(verification_key: VerifyingKey<G1Affine>) -> Self {
        Self { verification_key }
    }

    /// How many least significant bytes of a field element are used to pack the plaintext into.
    fn usable_bytes(&self) -> usize {
        USABLE_BYTES
    }
}

impl Backend<Bn256F> for Verifier {
    #[cfg_attr(feature = "tracing", instrument(level = "debug", skip_all, err))]
    fn verify(
        &self,
        inputs: Vec<PublicInput<Bn256F>>,
        proofs: Vec<Proof>,
    ) -> Result<(), VerifierError> {
        // XXX: using the default strategy of "one proof proves one chunk of plaintext".
        if inputs.len() != proofs.len() {
            return Err(VerifierError::WrongProofCount(inputs.len(), proofs.len()));
        }

        for (input, proof) in inputs.into_iter().zip(proofs) {
            let instance_columns = prepare_instance(&input, self.usable_bytes());

            verify_proof::<
                KZGCommitmentScheme<Bn256>,
                VerifierGWC<'_, Bn256>,
                _,
                Blake2bRead<_, _, Challenge255<_>>,
                AccumulatorStrategy<_>,
            >(
                &PARAMS,
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

#[cfg_attr(feature = "tracing", instrument(level = "debug", skip_all, err))]
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
    let strategy = verify_plonk_proof(params_verifier, vk, strategy, instances, &mut transcript)
        .map_err(|e| VerifierError::VerificationFailed(e.to_string()))?;

    if !strategy.finalize() {
        return Err(VerifierError::VerificationFailed(
            "VerificationStrategy::finalize() returned false".to_string(),
        ));
    }

    Ok(())
}
