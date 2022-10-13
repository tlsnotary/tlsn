use super::utils::{bigint_to_f, deltas_to_matrices};
use super::{Curve, CHUNK_SIZE, USEFUL_BITS};
use crate::verifier::{VerificationInput, VerifierError, Verify};
use halo2_proofs::plonk;
use halo2_proofs::plonk::SingleVerifier;
use halo2_proofs::plonk::VerifyingKey;
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::transcript::Blake2bRead;
use halo2_proofs::transcript::Challenge255;
use pasta_curves::pallas::Base as F;
use pasta_curves::EqAffine;

/// halo2's native [halo2::VerifyingKey] can't be used without params, so we wrap
/// them in one struct.
#[derive(Clone)]
pub struct VK {
    pub key: VerifyingKey<EqAffine>,
    pub params: Params<EqAffine>,
}

/// Implements the Verifier in the authdecode protocol.
pub struct Verifier {
    verification_key: VK,
    curve: Curve,
}
impl Verifier {
    pub fn new(vk: VK, curve: Curve) -> Self {
        Self {
            verification_key: vk,
            curve,
        }
    }
}

impl Verify for Verifier {
    fn verify(&self, input: VerificationInput) -> Result<bool, VerifierError> {
        let params = &self.verification_key.params;
        let vk = &self.verification_key.key;

        let strategy = SingleVerifier::new(&params);
        let proof = input.proof;
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);

        // convert deltas into a matrix which halo2 expects
        let (_, deltas_as_columns) = deltas_to_matrices(&input.deltas, self.useful_bits());

        let mut all_inputs: Vec<&[F]> = deltas_as_columns.iter().map(|v| v.as_slice()).collect();

        // add another column with public inputs
        let tmp = &[
            bigint_to_f(&input.plaintext_hash),
            bigint_to_f(&input.label_sum_hash),
            bigint_to_f(&input.sum_of_zero_labels),
        ];
        all_inputs.push(tmp);

        // let now = Instant::now();
        // perform the actual verification
        let res = plonk::verify_proof(
            params,
            vk,
            strategy,
            &[all_inputs.as_slice()],
            &mut transcript,
        );
        // println!("Proof verified [{:?}]", now.elapsed());
        if res.is_err() {
            return Err(VerifierError::VerificationFailed);
        } else {
            Ok(true)
        }
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
