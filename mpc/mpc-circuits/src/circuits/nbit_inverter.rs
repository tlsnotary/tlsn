use std::sync::Arc;

use crate::{
    builder::{CircuitBuilder, GateHandle},
    circuit::GateType,
    Circuit, ValueType,
};

/// Builds an nbit inverter
pub fn nbit_inverter(n: usize) -> Arc<Circuit> {
    let mut builder = CircuitBuilder::new(
        &format!("{n}BitInverter"),
        &format!("{n}-bit Binary Inverter"),
        "0.1.0",
    );

    let in_0 = builder.add_input("IN", &format!("{}-bit number", n), ValueType::Bits, n);

    let mut builder = builder.build_inputs();

    let inverters: Vec<GateHandle> = (0..n)
        .map(|i| {
            let inv = builder.add_gate(GateType::Inv);
            builder.connect(&[in_0[i]], &[inv.x()]);
            inv
        })
        .collect();

    let mut builder = builder.build_gates();

    let out = builder.add_output("OUT", &format!("{}-bit number", n), ValueType::Bits, n);

    inverters
        .iter()
        .enumerate()
        .for_each(|(i, inv)| builder.connect(&[inv.z()], &[out[i]]));

    builder
        .build_circuit()
        .expect(&format!("failed to build {}-bit inverter", n))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{circuits::test_circ, Value};

    #[test]
    fn test_nbit_inverter() {
        let circ = nbit_inverter(8);
        test_circ(
            &circ,
            &[Value::Bits(vec![false; 8])],
            &[Value::Bits(vec![true; 8])],
        );
        test_circ(
            &circ,
            &[Value::Bits(vec![
                false, false, false, false, true, true, true, true,
            ])],
            &[Value::Bits(vec![
                true, true, true, true, false, false, false, false,
            ])],
        );
    }
}
