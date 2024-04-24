use halo2_poseidon::poseidon::{primitives::Spec, Pow5Chip, Pow5Config};
use halo2_proofs::{halo2curves::bn256::Fr as F, plonk::ConstraintSystem};

/// Configures the in-circuit Poseidon for rate 15 and returns the config.
// Patterned after https://github.com/privacy-scaling-explorations/poseidon-gadget/blob/764a682ee448bfbde0cc92a04d241fe738ba2d14/src/poseidon/pow5.rs#L621
pub fn configure_poseidon_rate_15<S: Spec<F, 16, 15>>(
    rate: usize,
    meta: &mut ConstraintSystem<F>,
) -> Pow5Config<F, 16, 15> {
    let width = rate + 1;
    let state = (0..width).map(|_| meta.advice_column()).collect::<Vec<_>>();
    let partial_sbox = meta.advice_column();

    let rc_a = (0..width).map(|_| meta.fixed_column()).collect::<Vec<_>>();
    let rc_b = (0..width).map(|_| meta.fixed_column()).collect::<Vec<_>>();

    Pow5Chip::configure::<S>(
        meta,
        state.try_into().unwrap(),
        partial_sbox,
        rc_a.try_into().unwrap(),
        rc_b.try_into().unwrap(),
    )
}

/// Configures the in-circuit Poseidon for rate 1 and returns the config
// Patterned after https://github.com/privacy-scaling-explorations/poseidon-gadget/blob/764a682ee448bfbde0cc92a04d241fe738ba2d14/src/poseidon/pow5.rs#L621
#[allow(dead_code)]
pub fn configure_poseidon_rate_1<S: Spec<F, 2, 1>>(
    rate: usize,
    meta: &mut ConstraintSystem<F>,
) -> Pow5Config<F, 2, 1> {
    let width = rate + 1;
    let state = (0..width).map(|_| meta.advice_column()).collect::<Vec<_>>();
    let partial_sbox = meta.advice_column();

    let rc_a = (0..width).map(|_| meta.fixed_column()).collect::<Vec<_>>();
    let rc_b = (0..width).map(|_| meta.fixed_column()).collect::<Vec<_>>();

    Pow5Chip::configure::<S>(
        meta,
        state.try_into().unwrap(),
        partial_sbox,
        rc_a.try_into().unwrap(),
        rc_b.try_into().unwrap(),
    )
}

/// Configures the in-circuit Poseidon for rate 2 and returns the config
// Patterned after https://github.com/privacy-scaling-explorations/poseidon-gadget/blob/764a682ee448bfbde0cc92a04d241fe738ba2d14/src/poseidon/pow5.rs#L621
pub fn configure_poseidon_rate_2<S: Spec<F, 3, 2>>(
    rate: usize,
    meta: &mut ConstraintSystem<F>,
) -> Pow5Config<F, 3, 2> {
    let width = rate + 1;
    let state = (0..width).map(|_| meta.advice_column()).collect::<Vec<_>>();
    let partial_sbox = meta.advice_column();

    let rc_a = (0..width).map(|_| meta.fixed_column()).collect::<Vec<_>>();
    let rc_b = (0..width).map(|_| meta.fixed_column()).collect::<Vec<_>>();

    Pow5Chip::configure::<S>(
        meta,
        state.try_into().unwrap(),
        partial_sbox,
        rc_a.try_into().unwrap(),
        rc_b.try_into().unwrap(),
    )
}
