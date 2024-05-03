//! This module provides the circuits used in the key exchange protocol.

use std::sync::Arc;

use mpz_circuits::{circuits::big_num::nbyte_add_mod_trace, Circuit, CircuitBuilder};

/// NIST P-256 prime big-endian.
static P: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
];

/// Circuit for combining additive shares of the PMS, twice.
///
/// # Inputs
///
/// 0. PMS_SHARE_A: 32 bytes PMS Additive Share
/// 1. PMS_SHARE_B: 32 bytes PMS Additive Share
/// 2. PMS_SHARE_C: 32 bytes PMS Additive Share
/// 3. PMS_SHARE_D: 32 bytes PMS Additive Share
///
/// # Outputs
/// 0. PMS1: Pre-master Secret = PMS_SHARE_A + PMS_SHARE_B
/// 1. PMS2: Pre-master Secret = PMS_SHARE_C + PMS_SHARE_D
/// 2. EQ: Equality check of PMS1 and PMS2
pub(crate) fn build_pms_circuit() -> Arc<Circuit> {
    let builder = CircuitBuilder::new();
    let share_a = builder.add_array_input::<u8, 32>();
    let share_b = builder.add_array_input::<u8, 32>();
    let share_c = builder.add_array_input::<u8, 32>();
    let share_d = builder.add_array_input::<u8, 32>();

    let a = nbyte_add_mod_trace(builder.state(), share_a, share_b, P);
    let b = nbyte_add_mod_trace(builder.state(), share_c, share_d, P);

    let eq: [_; 32] = std::array::from_fn(|i| a[i] ^ b[i]);

    builder.add_output(a);
    builder.add_output(b);
    builder.add_output(eq);

    Arc::new(builder.build().expect("pms circuit is valid"))
}
