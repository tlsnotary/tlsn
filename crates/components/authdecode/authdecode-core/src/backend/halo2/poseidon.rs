use halo2_poseidon::poseidon::{Pow5Chip, Pow5Config};
use halo2_proofs::plonk::ConstraintSystem;
use poseidon_circomlib::{CircomlibSpec, F};

/// Configures the in-circuit Poseidon for rate 15 and returns the config.
// Patterned after https://github.com/privacy-scaling-explorations/poseidon-gadget/blob/764a682ee448bfbde0cc92a04d241fe738ba2d14/src/poseidon/pow5.rs#L621
pub fn configure_poseidon_rate_15(meta: &mut ConstraintSystem<F>) -> Pow5Config<F, 16, 15> {
    let state = (0..16).map(|_| meta.advice_column()).collect::<Vec<_>>();
    let partial_sbox = meta.advice_column();

    let rc_a = (0..16).map(|_| meta.fixed_column()).collect::<Vec<_>>();
    let rc_b = (0..16).map(|_| meta.fixed_column()).collect::<Vec<_>>();

    Pow5Chip::configure::<CircomlibSpec<16, 15>>(
        meta,
        state.try_into().unwrap(),
        partial_sbox,
        rc_a.try_into().unwrap(),
        rc_b.try_into().unwrap(),
    )
}

/// Configures the in-circuit Poseidon for rate 3 and returns the config.
// Patterned after https://github.com/privacy-scaling-explorations/poseidon-gadget/blob/764a682ee448bfbde0cc92a04d241fe738ba2d14/src/poseidon/pow5.rs#L621
pub fn configure_poseidon_rate_3(meta: &mut ConstraintSystem<F>) -> Pow5Config<F, 4, 3> {
    let state = (0..4).map(|_| meta.advice_column()).collect::<Vec<_>>();
    let partial_sbox = meta.advice_column();

    let rc_a = (0..4).map(|_| meta.fixed_column()).collect::<Vec<_>>();
    let rc_b = (0..4).map(|_| meta.fixed_column()).collect::<Vec<_>>();

    Pow5Chip::configure::<CircomlibSpec<4, 3>>(
        meta,
        state.try_into().unwrap(),
        partial_sbox,
        rc_a.try_into().unwrap(),
        rc_b.try_into().unwrap(),
    )
}
