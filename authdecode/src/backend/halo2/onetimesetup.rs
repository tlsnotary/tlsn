use super::{
    circuit::{AuthDecodeCircuit, CELLS_PER_ROW, K, USEFUL_ROWS},
    prover::PK,
    verifier::VK,
};
use halo2_proofs::{
    halo2curves::bn256::Bn256,
    plonk,
    poly::{
        commitment::{Params, ParamsProver},
        kzg::commitment::ParamsKZG,
    },
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
    pub fn verification_key(params: ParamsKZG<Bn256>) -> VK {
        // we need an instance of the circuit, the exact inputs don't matter
        let circuit = AuthDecodeCircuit::new(
            Default::default(),
            Default::default(),
            Default::default(),
            [[Default::default(); CELLS_PER_ROW]; USEFUL_ROWS],
        );

        // safe to unwrap since we are inputting deterministic params and circuit
        let vk = plonk::keygen_vk(&params, &circuit).unwrap();
        VK { key: vk, params }
    }

    /// Returns the proving key for the AuthDecode circuit
    pub fn proving_key(params: ParamsKZG<Bn256>) -> PK {
        // we need an instance of the circuit, the exact inputs don't matter
        let circuit = AuthDecodeCircuit::new(
            Default::default(),
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

    pub fn params() -> ParamsKZG<Bn256> {
        // Parameters were taken from Axiom's trusted setup described here:
        // https://docs.axiom.xyz/docs/transparency-and-security/kzg-trusted-setup ,
        // located at https://axiom-crypto.s3.amazonaws.com/challenge_0085/kzg_bn254_15.srs
        //
        // They were downsized by calling `ParamsKZG::downsize(6)` with v0.3.0 of
        // https://github.com/privacy-scaling-explorations/halo2

        let bytes = include_bytes!("kzg_bn254_6.srs");
        ParamsKZG::read(&mut bytes.as_slice()).unwrap()
    }
}
