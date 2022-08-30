use mpc_circuits::{
    builder::{CircuitBuilder, Feed, Gates, Sink, WireHandle},
    circuit::GateType,
    circuits::nbit_adder,
    Circuit, ValueType,
};

/// Maps P-256 Prime to sink wires
/// ffffffff00000001000000000000000000000000ffffffffffffffffffffffff
fn p256prime(
    builder: &mut CircuitBuilder<Gates>,
    const_zero: &WireHandle<Feed>,
    const_one: &WireHandle<Feed>,
    sinks: &[WireHandle<Sink>],
) {
    for i in 0..96 {
        builder.connect(&[*const_one], &[sinks[i]]);
    }
    for i in 96..192 {
        builder.connect(&[*const_zero], &[sinks[i]]);
    }
    for i in 192..196 {
        builder.connect(&[*const_one], &[sinks[i]]);
    }
    for i in 196..224 {
        builder.connect(&[*const_zero], &[sinks[i]]);
    }
    for i in 224..256 {
        builder.connect(&[*const_one], &[sinks[i]]);
    }
}

pub fn combine_pms_shares() -> Circuit {
    let mut builder = CircuitBuilder::new("combine_pms_shares", "0.1.0");

    let const_zero = builder.add_input(
        "const_zero",
        "input that is always 0",
        ValueType::ConstZero,
        1,
    );
    let const_one = builder.add_input(
        "const_one",
        "input that is always 1",
        ValueType::ConstOne,
        1,
    );
    let a = builder.add_input(
        "PMS_SHARE_A",
        "256-bit PMS Additive Share",
        ValueType::Bytes,
        256,
    );
    let b = builder.add_input(
        "PMS_SHARE_B",
        "256-bit PMS Additive Share",
        ValueType::Bytes,
        256,
    );

    let mut builder = builder.build_inputs();

    // 257-bit adder for PMS_SHARE_A + PMS_SHARE_B
    let adder257 = builder.add_circ(nbit_adder(257));
    let adder257_a = adder257.input(0).expect("adder257 missing input 0");
    let adder257_b = adder257.input(1).expect("adder257 missing input 1");
    let adder257_out = adder257.output(0).expect("adder257 missing output 0");

    builder.connect(&a[..], &adder257_a[..256]);
    // Set MSB to 0
    builder.connect(&[const_zero[0]], &[adder257_a[256]]);
    builder.connect(&b[..], &adder257_b[..256]);
    // Set MSB to 0
    builder.connect(&[const_zero[0]], &[adder257_b[256]]);

    // Check if (PMS_SHARE_A + PMS_SHARE_B) <  P-256 Prime

    // Reduce (PMS_SHARE_A + PMS_SHARE_B) mod P-256 Prime

    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use mpc_circuits::{circuits::test_circ, Value};

    #[test]
    fn test_combine_pms_shares() {
        todo!()
    }
}
