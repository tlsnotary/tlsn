use super::{
    circuit::{AuthDecodeCircuit, CELLS_PER_ROW, K, USEFUL_ROWS},
    prover::PK,
    verifier::VK,
};
use halo2_proofs::{
    halo2curves::bn256::Bn256,
    plonk,
    poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
};

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
        let params = ParamsKZG::<Bn256>::new(K);
        // we need an instance of the circuit, the exact inputs don't matter
        let circuit = AuthDecodeCircuit::new(
            Default::default(),
            Default::default(),
            [[Default::default(); CELLS_PER_ROW]; USEFUL_ROWS],
        );

        // safe to unwrap since we are inputting deterministic params and circuit
        let vk = plonk::keygen_vk(&params, &circuit).unwrap();
        VK { key: vk, params }
    }

    /// Returns the proving key for the AuthDecode circuit
    pub fn proving_key() -> PK {
        let params = ParamsKZG::<Bn256>::new(K);
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
