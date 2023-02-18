use mpc_circuits::{builder::CircuitBuilder, Circuit, ValueType};
use std::sync::Arc;
use tls_circuits::combine_pms_shares;

pub fn build_double_combine_pms_circuit() -> Arc<Circuit> {
    let mut builder = CircuitBuilder::new("pms_shares_double", "", "0.1.0");

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
    let c = builder.add_input(
        "PMS_SHARE_C",
        "256-bit PMS Additive Share",
        ValueType::Bytes,
        256,
    );
    let d = builder.add_input(
        "PMS_SHARE_C",
        "256-bit PMS Additive Share",
        ValueType::Bytes,
        256,
    );

    let mut builder = builder.build_inputs();
    let handle1 = builder.add_circ(&combine_pms_shares());
    let handle2 = builder.add_circ(&combine_pms_shares());

    let a_input = handle1.input(0).unwrap();
    let b_input = handle1.input(1).unwrap();

    let c_input = handle2.input(0).unwrap();
    let d_input = handle2.input(1).unwrap();

    builder.connect(&a[..], &a_input[..]);
    builder.connect(&b[..], &b_input[..]);
    builder.connect(&c[..], &c_input[..]);
    builder.connect(&d[..], &d_input[..]);

    let pms1_out = handle1.output(0).expect("add mod is missing output 0");
    let pms2_out = handle2.output(0).expect("add mod is missing output 0");

    let mut builder = builder.build_gates();

    let pms1 = builder.add_output("PMS1", "Pre-master Secret", ValueType::Bytes, 256);
    let pms2 = builder.add_output("PMS2", "Pre-master Secret", ValueType::Bytes, 256);

    builder.connect(&pms1_out[..], &pms1[..]);
    builder.connect(&pms2_out[..], &pms2[..]);

    builder.build_circuit().unwrap()
}
