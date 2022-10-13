use super::ARITHMETIC_LABEL_SIZE;
use crate::label::{LabelGenerator, Seed};
use crate::utils::{compute_zero_sum_and_deltas, encrypt_arithmetic_labels, sanitize_biguint};
use crate::{Delta, LabelSumHash, PlaintextHash, Proof, ZeroSum};
use num::BigUint;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum VerifierError {
    #[error("The prover has provided the wrong number of proofs. Expected {0}. Got {1}.")]
    WrongProofCount(usize, usize),
    #[error("The Prover has provided an input that is larger than expected")]
    BigUintTooLarge,
    #[error("The proving system returned an error when verifying a proof")]
    VerifyingBackendError,
    #[error("Proof verification failed")]
    VerificationFailed,
    #[error("An internal error was encountered")]
    InternalError,
}

/// Public inputs and a zk proof that needs to be verified.
#[derive(Default)]
pub struct VerificationInput {
    pub plaintext_hash: PlaintextHash,
    pub label_sum_hash: LabelSumHash,
    pub sum_of_zero_labels: ZeroSum,
    pub deltas: Vec<Delta>,
    pub proof: Proof,
}

pub trait State {}

pub struct Setup {
    binary_labels: Vec<[u128; 2]>,
}
impl State for Setup {}

#[derive(Default)]
pub struct ReceivePlaintextHashes {
    deltas: Vec<Delta>,
    zero_sums: Vec<ZeroSum>,
    ciphertexts: Vec<[[u8; 16]; 2]>,
    arith_label_seed: Seed,
}
impl State for ReceivePlaintextHashes {}

#[derive(Default)]
pub struct ReceiveLabelSumHashes {
    deltas: Vec<Delta>,
    zero_sums: Vec<ZeroSum>,
    plaintext_hashes: Vec<PlaintextHash>,
    arith_label_seed: Seed,
}
impl State for ReceiveLabelSumHashes {}

#[derive(Default)]
pub struct VerifyMany {
    deltas: Vec<Delta>,
    zero_sums: Vec<ZeroSum>,
    plaintext_hashes: Vec<PlaintextHash>,
    label_sum_hashes: Vec<LabelSumHash>,
}
impl State for VerifyMany {}

pub trait Verify {
    /// Verifies the zk proof against public `input`s. Returns `true` on success,
    /// `false` otherwise.
    fn verify(&self, input: VerificationInput) -> Result<bool, VerifierError>;

    /// The EC field size in bits. Verifier uses this to sanitize the `BigUint`s
    /// received from Prover.
    fn field_size(&self) -> usize;

    /// Returns how many bits of plaintext we will pack into one field element.
    /// Normally, this should be [Verify::field_size] minus 1.
    fn useful_bits(&self) -> usize;

    /// How many bits of [Plaintext] can fit into one [Chunk]. This does not
    /// include the [Salt] of the hash - which takes up the remaining least bits
    /// of the last field element of each chunk.
    fn chunk_size(&self) -> usize;
}

/// Implementation of the verifier in the AuthDecode protocol.
pub struct AuthDecodeVerifier<S = Setup>
where
    S: State,
{
    verifier: Box<dyn Verify>,
    state: S,
}

impl AuthDecodeVerifier {
    /// Returns the next expected state.
    pub fn new(
        binary_labels: Vec<[u128; 2]>,
        verifier: Box<dyn Verify>,
    ) -> AuthDecodeVerifier<Setup> {
        AuthDecodeVerifier {
            state: Setup { binary_labels },
            verifier,
        }
    }
}

impl AuthDecodeVerifier<Setup> {
    /// Generates arithmetic labels from a seed, computes the deltas, computes
    /// the sum of zero labels, encrypts arithmetic labels using binary
    /// labels as encryption keys.
    ///
    /// Returns the next expected state.
    pub fn setup(self) -> Result<AuthDecodeVerifier<ReceivePlaintextHashes>, VerifierError> {
        // There will be as many deltas as there are garbled circuit output
        // labels.
        let mut deltas: Vec<BigUint> = Vec::with_capacity(self.state.binary_labels.len());

        let (label_pairs, seed) =
            LabelGenerator::generate(self.state.binary_labels.len(), ARITHMETIC_LABEL_SIZE);

        let zero_sums: Vec<ZeroSum> = label_pairs
            .chunks(self.verifier.chunk_size())
            .map(|chunk_of_alabel_pairs| {
                let (zero_sum, deltas_in_chunk) =
                    compute_zero_sum_and_deltas(chunk_of_alabel_pairs);
                deltas.extend(deltas_in_chunk);
                zero_sum
            })
            .collect();

        let ciphertexts = match encrypt_arithmetic_labels(&label_pairs, &self.state.binary_labels) {
            Ok(ct) => ct,
            Err(_) => return Err(VerifierError::InternalError),
        };

        Ok(AuthDecodeVerifier {
            state: ReceivePlaintextHashes {
                zero_sums,
                deltas,
                ciphertexts,
                arith_label_seed: seed,
            },
            verifier: self.verifier,
        })
    }
}

impl AuthDecodeVerifier<ReceivePlaintextHashes> {
    /// Receives hashes of plaintext and returns the encrypted
    /// arithmetic labels and the next expected state.
    #[allow(clippy::type_complexity)]
    pub fn receive_plaintext_hashes(
        self,
        plaintext_hashes: Vec<PlaintextHash>,
    ) -> Result<
        (
            Vec<[[u8; 16]; 2]>,
            AuthDecodeVerifier<ReceiveLabelSumHashes>,
        ),
        VerifierError,
    > {
        for h in &plaintext_hashes {
            if sanitize_biguint(h, self.verifier.field_size()).is_err() {
                return Err(VerifierError::BigUintTooLarge);
            }
        }

        Ok((
            self.state.ciphertexts,
            AuthDecodeVerifier {
                state: ReceiveLabelSumHashes {
                    zero_sums: self.state.zero_sums,
                    deltas: self.state.deltas,
                    plaintext_hashes,
                    arith_label_seed: self.state.arith_label_seed,
                },
                verifier: self.verifier,
            },
        ))
    }
}

impl AuthDecodeVerifier<ReceiveLabelSumHashes> {
    /// Receives hashes of sums of labels and returns the arithmetic label [Seed]
    /// and the next expected state.
    pub fn receive_label_sum_hashes(
        self,
        label_sum_hashes: Vec<LabelSumHash>,
    ) -> Result<(Seed, AuthDecodeVerifier<VerifyMany>), VerifierError> {
        for h in &label_sum_hashes {
            if sanitize_biguint(h, self.verifier.field_size()).is_err() {
                return Err(VerifierError::BigUintTooLarge);
            }
        }

        Ok((
            self.state.arith_label_seed,
            AuthDecodeVerifier {
                state: VerifyMany {
                    zero_sums: self.state.zero_sums,
                    deltas: self.state.deltas,
                    plaintext_hashes: self.state.plaintext_hashes,
                    label_sum_hashes,
                },
                verifier: self.verifier,
            },
        ))
    }
}

impl AuthDecodeVerifier<VerifyMany> {
    /// Verifies as many proofs as there are [Chunk]s of the plaintext. Returns
    /// the verification result and the hash of the plaintext.
    pub fn verify_many(
        mut self,
        proofs: Vec<Proof>,
    ) -> Result<(bool, Vec<PlaintextHash>), VerifierError> {
        let inputs = self.create_verification_inputs(proofs)?;
        for input in inputs {
            let res = self.verifier.verify(input)?;
            if !res {
                // we will never get here since "?" takes care of the
                // verification error. Still, it is good to have this check
                // just in case.
                return Err(VerifierError::VerificationFailed);
            }
        }
        Ok((true, self.state.plaintext_hashes))
    }

    /// Construct public inputs for the zk circuit for each [Chunk].
    fn create_verification_inputs(
        &mut self,
        proofs: Vec<Proof>,
    ) -> Result<Vec<VerificationInput>, VerifierError> {
        // How many chunks of plaintext are there? ( == how many zk proofs to expect)
        // The amount of deltas corresponds to the amount of bits in the plaintext.
        // Round up the chunk count.
        let chunk_count = (self.state.deltas.len() + (self.verifier.chunk_size() - 1))
            / self.verifier.chunk_size();

        if proofs.len() != chunk_count {
            return Err(VerifierError::WrongProofCount(chunk_count, proofs.len()));
        }

        // Since the last chunk of plaintext is padded with zero bits, we also zero-pad
        // the corresponding deltas of the last chunk to the size of a chunk.
        let delta_pad_count = self.verifier.chunk_size() * chunk_count - self.state.deltas.len();
        let mut deltas = self.state.deltas.clone();
        deltas.extend(vec![0u8.into(); delta_pad_count]);

        let chunks_of_deltas = deltas
            .chunks(self.verifier.chunk_size())
            .map(|i| i.to_vec())
            .collect::<Vec<Vec<_>>>();

        Ok((0..chunk_count)
            .map(|i| VerificationInput {
                plaintext_hash: self.state.plaintext_hashes[i].clone(),
                label_sum_hash: self.state.label_sum_hashes[i].clone(),
                sum_of_zero_labels: self.state.zero_sums[i].clone(),
                deltas: chunks_of_deltas[i].clone(),
                proof: proofs[i].clone(),
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use crate::verifier::AuthDecodeVerifier;
    use crate::verifier::ReceiveLabelSumHashes;
    use crate::verifier::ReceivePlaintextHashes;
    use crate::verifier::VerificationInput;
    use crate::verifier::VerifierError;
    use crate::verifier::Verify;
    use crate::verifier::VerifyMany;
    use crate::Proof;
    use num::BigUint;

    /// The verifier who implements `Verify` with the correct values
    struct CorrectTestVerifier {}
    impl Verify for CorrectTestVerifier {
        fn verify(&self, _input: VerificationInput) -> Result<bool, VerifierError> {
            Ok(true)
        }

        fn field_size(&self) -> usize {
            254
        }

        fn useful_bits(&self) -> usize {
            253
        }

        fn chunk_size(&self) -> usize {
            3670
        }
    }

    #[test]
    /// Provide `BigUint` larger than useful_bits() and trigger
    ///  [VerifierError::BigUintTooLarge]
    fn test_error_biguint_too_large() {
        // test receive_plaintext_hashes()
        let lsv = AuthDecodeVerifier {
            state: ReceivePlaintextHashes::default(),
            verifier: Box::new(CorrectTestVerifier {}),
        };

        let mut hashes: Vec<BigUint> = (0..100).map(|i| BigUint::from(i as u64)).collect();
        hashes[50] = BigUint::from(2u8).pow(lsv.verifier.field_size() as u32);
        let res = lsv.receive_plaintext_hashes(hashes);

        assert_eq!(res.err().unwrap(), VerifierError::BigUintTooLarge);

        // test receive_label_sum_hashes
        let lsv = AuthDecodeVerifier {
            state: ReceiveLabelSumHashes::default(),
            verifier: Box::new(CorrectTestVerifier {}),
        };

        let mut plaintext_hashes: Vec<BigUint> =
            (0..100).map(|i| BigUint::from(i as u64)).collect();
        plaintext_hashes[50] = BigUint::from(2u8).pow(lsv.verifier.field_size() as u32);
        let res = lsv.receive_label_sum_hashes(plaintext_hashes);

        assert_eq!(res.err().unwrap(), VerifierError::BigUintTooLarge);
    }

    #[test]
    /// Provide too many/too few proofs and trigger [VerifierError::WrongProofCount]
    fn test_error_wrong_proof_count() {
        // 3 chunks
        let lsv = AuthDecodeVerifier {
            state: VerifyMany {
                deltas: vec![0u8.into(); 3670 * 2 + 1],
                ..Default::default()
            },
            verifier: Box::new(CorrectTestVerifier {}),
        };
        // 4 proofs
        let res = lsv.verify_many(vec![Proof::default(); 4]);

        assert_eq!(res.err().unwrap(), VerifierError::WrongProofCount(3, 4));

        // 3 chunks
        let lsv = AuthDecodeVerifier {
            state: VerifyMany {
                deltas: vec![0u8.into(); 3670 * 2 + 1],
                ..Default::default()
            },
            verifier: Box::new(CorrectTestVerifier {}),
        };
        // 2 proofs
        let res = lsv.verify_many(vec![Proof::default(); 2]);

        assert_eq!(res.err().unwrap(), VerifierError::WrongProofCount(3, 2));
    }

    #[test]
    /// Returns `false` when attempting to verify and triggers
    /// [VerifierError::VerificationFailed]
    fn test_error_verification_failed() {
        struct TestVerifier {}
        impl Verify for TestVerifier {
            fn verify(&self, _input: VerificationInput) -> Result<bool, VerifierError> {
                Ok(false)
            }

            fn field_size(&self) -> usize {
                254
            }

            fn useful_bits(&self) -> usize {
                253
            }

            fn chunk_size(&self) -> usize {
                3670
            }
        }

        let lsv = AuthDecodeVerifier {
            state: VerifyMany {
                deltas: vec![0u8.into(); 3670 * 2 - 1],
                zero_sums: vec![0u8.into(); 2],
                plaintext_hashes: vec![0u8.into(); 2],
                label_sum_hashes: vec![0u8.into(); 2],
            },
            verifier: Box::new(TestVerifier {}),
        };
        let res = lsv.verify_many(vec![Proof::default(); 2]);

        assert_eq!(res.err().unwrap(), VerifierError::VerificationFailed);
    }

    #[test]
    /// Returns some other error not related to the verification result when
    /// attempting to verify and checks that the error propagates.
    fn test_verification_error() {
        struct TestVerifier {}
        impl Verify for TestVerifier {
            fn verify(&self, _input: VerificationInput) -> Result<bool, VerifierError> {
                Err(VerifierError::VerifyingBackendError)
            }

            fn field_size(&self) -> usize {
                254
            }

            fn useful_bits(&self) -> usize {
                253
            }

            fn chunk_size(&self) -> usize {
                3670
            }
        }

        let lsv = AuthDecodeVerifier {
            state: VerifyMany {
                deltas: vec![0u8.into(); 3670 * 2 - 1],
                zero_sums: vec![0u8.into(); 2],
                plaintext_hashes: vec![0u8.into(); 2],
                label_sum_hashes: vec![0u8.into(); 2],
            },
            verifier: Box::new(TestVerifier {}),
        };
        let res = lsv.verify_many(vec![Proof::default(); 2]);

        assert_eq!(res.err().unwrap(), VerifierError::VerifyingBackendError);
    }
}
