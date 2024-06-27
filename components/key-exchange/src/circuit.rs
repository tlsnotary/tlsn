//! This module provides the circuits used in the key exchange protocol.

use std::sync::Arc;

use mpz_circuits::{circuits::big_num::nbyte_add_mod_trace, Circuit, CircuitBuilder};

/// NIST P-256 prime big-endian.
static P: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
];

/// Circuit for combining additive shares of the PMS, twice
///
/// # Inputs
///
/// 0. PMS_SHARE_A0: 32 bytes PMS Additive Share
/// 1. PMS_SHARE_B0: 32 bytes PMS Additive Share
/// 2. PMS_SHARE_A1: 32 bytes PMS Additive Share
/// 3. PMS_SHARE_B1: 32 bytes PMS Additive Share
///
/// # Outputs
/// 0. PMS_0: Pre-master Secret = PMS_SHARE_A0 + PMS_SHARE_B0
/// 1. PMS_1: Pre-master Secret = PMS_SHARE_A1 + PMS_SHARE_B1
/// 2. EQ: Equality check of PMS_0 and PMS_1
pub(crate) fn build_pms_circuit() -> Arc<Circuit> {
    let builder = CircuitBuilder::new();
    let share_a0 = builder.add_array_input::<u8, 32>();
    let share_b0 = builder.add_array_input::<u8, 32>();
    let share_a1 = builder.add_array_input::<u8, 32>();
    let share_b1 = builder.add_array_input::<u8, 32>();

    let pms_0 = nbyte_add_mod_trace(builder.state(), share_a0, share_b0, P);
    let pms_1 = nbyte_add_mod_trace(builder.state(), share_a1, share_b1, P);

    let eq: [_; 32] = std::array::from_fn(|i| pms_0[i] ^ pms_1[i]);

    builder.add_output(pms_0);
    builder.add_output(pms_1);
    builder.add_output(eq);

    Arc::new(builder.build().expect("pms circuit is valid"))
}
