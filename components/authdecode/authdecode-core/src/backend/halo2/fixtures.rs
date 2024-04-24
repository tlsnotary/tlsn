use crate::{
    backend::{
        halo2::{
            circuit::USABLE_BYTES,
            onetimesetup::{proving_key, verification_key},
            prepare_instance,
            prover::{Prover, _prepare_circuit},
            verifier::Verifier,
            Bn256F, PARAMS,
        },
        traits::{Field, ProverBackend, VerifierBackend},
    },
    prover::prover::ProverInput,
    Proof,
};

use halo2_proofs::{
    dev::MockProver,
    halo2curves::bn256::Bn256,
    poly::{commitment::Params, kzg::commitment::ParamsKZG},
};

use serde::{de::DeserializeOwned, Serialize};
use std::{
    any::Any,
    ops::{Add, Sub},
};

/// Returns a pair of backends which use halo2's MockProver to prove and verify.
pub fn backend_pair() -> (ProverBackendWrapper<Bn256F>, VerifierBackendWrapper<Bn256F>) {
    let pair = backend_pair_real();
    (
        ProverBackendWrapper {
            prover: Box::new(pair.0),
        },
        VerifierBackendWrapper {
            verifier: Box::new(pair.1),
        },
    )
}

/// Returns a pair of zk backends which uses halo2's real prover and verifier
/// (i.e. NOT the MockProver).
pub fn backend_pair_real() -> (Prover, Verifier) {
    (
        Prover::new(proving_key()),
        Verifier::new(verification_key()),
    )
}

/// Returns the K parameter.
pub fn k() -> u32 {
    ParamsKZG::<Bn256>::k(&PARAMS)
}

// A wrapper of the prover backend which uses MockProver to prove and verify.
pub struct ProverBackendWrapper<Bn256F> {
    prover: Box<dyn ProverBackend<Bn256F>>,
}

impl ProverBackend<Bn256F> for ProverBackendWrapper<Bn256F> {
    fn chunk_size(&self) -> usize {
        self.prover.chunk_size()
    }

    fn commit_encoding_sum(&self, encoding_sum: Bn256F) -> (Bn256F, Bn256F) {
        self.prover.commit_encoding_sum(encoding_sum)
    }

    fn commit_plaintext(&self, plaintext: Vec<u8>) -> (Bn256F, Bn256F) {
        self.prover.commit_plaintext(plaintext)
    }

    fn prove(
        &self,
        input: Vec<ProverInput<Bn256F>>,
    ) -> Result<Vec<crate::Proof>, crate::prover::error::ProverError> {
        _ = input
            .into_iter()
            .map(|input| {
                let instance_columns = prepare_instance(input.public(), USABLE_BYTES);
                let circuit = _prepare_circuit(input.private(), USABLE_BYTES);

                let prover = MockProver::run(k(), &circuit, instance_columns).unwrap();
                assert!(prover.verify().is_ok());
            })
            .collect::<Vec<_>>();

        // Return a dummy proof.
        Ok(vec![Proof::new(&[0u8])])
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// A wrapper of the verifier backend.
pub struct VerifierBackendWrapper<F> {
    verifier: Box<dyn VerifierBackend<F>>,
}

impl<F> VerifierBackend<F> for VerifierBackendWrapper<F>
where
    F: Field + Add<Output = F> + Sub<Output = F> + Serialize + DeserializeOwned + Clone,
{
    fn chunk_size(&self) -> usize {
        self.verifier.chunk_size()
    }

    fn verify(
        &self,
        _inputs: Vec<crate::PublicInput<F>>,
        _proofs: Vec<Proof>,
    ) -> Result<(), crate::verifier::error::VerifierError> {
        // The proof has already been verified with MockProver::verify().
        Ok(())
    }
}
