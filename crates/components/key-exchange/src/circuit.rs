//! This module provides the circuits used in the key exchange protocol.

use mpz_circuits::{ops::add_mod, Circuit, CircuitBuilder};
use std::sync::Arc;

/// Circuit for combining additive shares of the PMS, twice
///
/// # Inputs
///
/// 0. PMS_SHARE_A0: 32 bytes PMS Additive Share
/// 1. PMS_SHARE_B0: 32 bytes PMS Additive Share
/// 2. PMS_SHARE_A1: 32 bytes PMS Additive Share
/// 3. PMS_SHARE_B1: 32 bytes PMS Additive Share
/// 4. MODULUS: 32 bytes field modulus
///
/// # Outputs
/// 0. PMS_0: Pre-master Secret = PMS_SHARE_A0 + PMS_SHARE_B0
/// 1. PMS_1: Pre-master Secret = PMS_SHARE_A1 + PMS_SHARE_B1
/// 2. EQ: Equality check of PMS_0 and PMS_1
pub(crate) fn build_pms_circuit() -> Arc<Circuit> {
    let mut builder = CircuitBuilder::new();
    let share_a0 = (0..32 * 8).map(|_| builder.add_input()).collect::<Vec<_>>();
    let share_b0 = (0..32 * 8).map(|_| builder.add_input()).collect::<Vec<_>>();
    let share_a1 = (0..32 * 8).map(|_| builder.add_input()).collect::<Vec<_>>();
    let share_b1 = (0..32 * 8).map(|_| builder.add_input()).collect::<Vec<_>>();

    let modulus = (0..32 * 8).map(|_| builder.add_input()).collect::<Vec<_>>();

    let pms_0 = add_mod(&mut builder, &share_a0, &share_b0, &modulus);
    for node in pms_0.iter() {
        builder.add_output(*node);
    }

    let pms_1 = add_mod(&mut builder, &share_a1, &share_b1, &modulus);
    for node in pms_1.iter() {
        builder.add_output(*node);
    }

    for (a, b) in pms_0.into_iter().zip(pms_1) {
        let out = builder.add_xor_gate(a, b);
        builder.add_output(out);
    }

    Arc::new(builder.build().expect("pms circuit is valid"))
}
