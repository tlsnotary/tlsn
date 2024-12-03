// A one-time setup generates the proving key and the verification key. The keys are deterministic, so
// they can be cached and re-used for all future proof generation and verification.

use crate::backend::halo2::{
    circuit::{AuthDecodeCircuit, FIELD_ELEMENTS},
    PARAMS,
};

use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr as F, G1Affine},
    plonk,
    plonk::{ProvingKey, VerifyingKey},
    poly::{commitment::Params, kzg::commitment::ParamsKZG},
};

/// Returns the verification key for the AuthDecode circuit.
pub fn verification_key() -> VerifyingKey<G1Affine> {
    // It is safe to `unwrap` since we are inputting deterministic params and circuit.
    plonk::keygen_vk(&PARAMS.clone(), &circuit_instance()).unwrap()
}

/// Returns the proving key for the AuthDecode circuit.
pub fn proving_key() -> ProvingKey<G1Affine> {
    // It is safe to `unwrap` since we are inputting deterministic params and circuit.
    plonk::keygen_pk(&PARAMS.clone(), verification_key(), &circuit_instance()).unwrap()
}

/// Returns the parameters used to generate the proving and the verification key.
pub(crate) fn params() -> ParamsKZG<Bn256> {
    // Parameters were taken from Axiom's trusted setup described here:
    // https://docs.axiom.xyz/docs/transparency-and-security/kzg-trusted-setup ,
    // located at https://axiom-crypto.s3.amazonaws.com/challenge_0085/kzg_bn254_15.srs
    //
    // They were downsized by calling `ParamsKZG::downsize(6)` with v0.3.0 of
    // https://github.com/privacy-scaling-explorations/halo2

    let bytes = include_bytes!("kzg_bn254_6.srs");
    ParamsKZG::read(&mut bytes.as_slice()).unwrap()
}

/// Returns an instance of the AuthDecode circuit.
fn circuit_instance() -> AuthDecodeCircuit {
    // We need an instance of the circuit, the exact inputs don't matter.
    AuthDecodeCircuit::new([F::default(); FIELD_ELEMENTS], F::default(), F::default())
}
