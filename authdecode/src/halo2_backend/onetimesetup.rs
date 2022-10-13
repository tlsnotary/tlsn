use super::circuit::{AuthDecodeCircuit, CELLS_PER_ROW, K, USEFUL_ROWS};
use super::prover::PK;
use super::verifier::VK;
use halo2_proofs::plonk;
use halo2_proofs::poly::commitment::Params;
use pasta_curves::EqAffine;

pub struct OneTimeSetup {}

/// OneTimeSetup generates the proving key and the verification key. It can be
/// run ahead of time before the actual zk proving/verification takes place.
///
/// Note that as of Oct 2022 halo2 does not support serializing the proving/verification
/// keys. That's why we can't use cached keys but need to call this one-time setup every
/// time when we instantiate the halo2 prover/verifier.
impl OneTimeSetup {
    /// Returns the verification key for the AuthDecode circuit
    pub fn verification_key() -> VK {
        let params: Params<EqAffine> = Params::new(K);
        // we need an instance of the circuit, the exact inputs don't matter
        let circuit = AuthDecodeCircuit::new(
            Default::default(),
            Default::default(),
            [[Default::default(); CELLS_PER_ROW]; USEFUL_ROWS],
        );

        // safe to unwrap, we are inputting deterministic params and circuit on every
        // invocation
        let vk = plonk::keygen_vk(&params, &circuit).unwrap();
        VK { key: vk, params }
    }

    /// Returns the proving key for the AuthDecode circuit
    pub fn proving_key() -> PK {
        let params: Params<EqAffine> = Params::new(K);
        // we need an instance of the circuit, the exact inputs don't matter
        let circuit = AuthDecodeCircuit::new(
            Default::default(),
            Default::default(),
            [[Default::default(); CELLS_PER_ROW]; USEFUL_ROWS],
        );

        // safe to unwrap, we are inputting deterministic params and circuit on every
        // invocation
        let vk = plonk::keygen_vk(&params, &circuit).unwrap();
        let pk = plonk::keygen_pk(&params, vk, &circuit).unwrap();

        PK { key: pk, params }
    }
}
