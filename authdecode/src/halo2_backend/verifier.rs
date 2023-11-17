use super::{
    utils::{bigint_to_f, deltas_to_matrices},
    Curve, CHUNK_SIZE, USEFUL_BITS,
};
use crate::verifier::{VerificationInput, VerifierError, Verify};
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr as F, G1Affine},
    plonk,
    plonk::VerifyingKey,
    poly::{
        commitment::CommitmentScheme,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::VerifierGWC,
            strategy::SingleStrategy,
        },
    },
    transcript::{Blake2bRead, Challenge255, TranscriptReadBuffer},
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
}

impl Verify for Verifier {
    fn verify(&self, input: VerificationInput) -> Result<bool, VerifierError> {
        let params = &self.verification_key.params;
        let vk = &self.verification_key.key;

        let strategy = SingleStrategy::new(params);
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
        let res = plonk::verify_proof::<
            KZGCommitmentScheme<Bn256>,
            VerifierGWC<'_, Bn256>,
            Challenge255<G1Affine>,
            Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
            SingleStrategy<'_, Bn256>,
        >(
            params,
            vk,
            strategy,
            &[all_inputs.as_slice()],
            &mut transcript,
        );
        // println!("Proof verified [{:?}]", now.elapsed());
        if res.is_err() {
            Err(VerifierError::VerificationFailed)
        } else {
            Ok(true)
        }
    }

    fn field_size(&self) -> usize {
        254
    }

    fn useful_bits(&self) -> usize {
        USEFUL_BITS
    }

    fn chunk_size(&self) -> usize {
        CHUNK_SIZE
    }
}
