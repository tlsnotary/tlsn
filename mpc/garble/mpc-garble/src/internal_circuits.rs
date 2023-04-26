use std::sync::Arc;

use mpc_circuits::{
    types::{BinaryRepr, ValueType},
    Circuit, CircuitBuilder, Tracer,
};

/// Builds a circuit for applying one-time pads to the provided values.
pub(crate) fn build_otp_circuit(inputs: &[ValueType]) -> Arc<Circuit> {
    let builder = CircuitBuilder::new();

    fn apply_otp(builder: &CircuitBuilder, input: BinaryRepr, otp: BinaryRepr) {
        match (input, otp) {
            (BinaryRepr::U8(input), BinaryRepr::U8(otp)) => {
                let input = Tracer::new(builder.state(), input);
                let otp = Tracer::new(builder.state(), otp);
                let masked = input ^ otp;
                builder.add_output(masked);
            }
            (BinaryRepr::U16(input), BinaryRepr::U16(otp)) => {
                let input = Tracer::new(builder.state(), input);
                let otp = Tracer::new(builder.state(), otp);
                let masked = input ^ otp;
                builder.add_output(masked);
            }
            (BinaryRepr::U32(input), BinaryRepr::U32(otp)) => {
                let input = Tracer::new(builder.state(), input);
                let otp = Tracer::new(builder.state(), otp);
                let masked = input ^ otp;
                builder.add_output(masked);
            }
            (BinaryRepr::U64(input), BinaryRepr::U64(otp)) => {
                let input = Tracer::new(builder.state(), input);
                let otp = Tracer::new(builder.state(), otp);
                let masked = input ^ otp;
                builder.add_output(masked);
            }
            (BinaryRepr::U128(input), BinaryRepr::U128(otp)) => {
                let input = Tracer::new(builder.state(), input);
                let otp = Tracer::new(builder.state(), otp);
                let masked = input ^ otp;
                builder.add_output(masked);
            }
            (BinaryRepr::Array(input_elems), BinaryRepr::Array(otp_elems)) => {
                for (input, otp) in input_elems.into_iter().zip(otp_elems) {
                    apply_otp(builder, input, otp);
                }
            }
            _ => panic!("builder returned unexpected type"),
        }
    }

    for input_ty in inputs {
        let input = builder.add_input_by_type(input_ty.clone());
        let otp = builder.add_input_by_type(input_ty.clone());
        apply_otp(&builder, input, otp);
    }

    let circ = builder.build().expect("circuit should be valid");

    Arc::new(circ)
}

/// Builds a circuit for applying one-time pads to the provided values.
pub(crate) fn build_otp_shared_circuit(inputs: &[ValueType]) -> Arc<Circuit> {
    let builder = CircuitBuilder::new();

    fn apply_otp(
        builder: &CircuitBuilder,
        input: BinaryRepr,
        otp_0: BinaryRepr,
        otp_1: BinaryRepr,
    ) {
        match (input, otp_0, otp_1) {
            (BinaryRepr::U8(input), BinaryRepr::U8(otp_0), BinaryRepr::U8(otp_1)) => {
                let input = Tracer::new(builder.state(), input);
                let otp_0 = Tracer::new(builder.state(), otp_0);
                let otp_1 = Tracer::new(builder.state(), otp_1);
                let masked = input ^ otp_0 ^ otp_1;
                builder.add_output(masked);
            }
            (BinaryRepr::U16(input), BinaryRepr::U16(otp_0), BinaryRepr::U16(otp_1)) => {
                let input = Tracer::new(builder.state(), input);
                let otp_0 = Tracer::new(builder.state(), otp_0);
                let otp_1 = Tracer::new(builder.state(), otp_1);
                let masked = input ^ otp_0 ^ otp_1;
                builder.add_output(masked);
            }
            (BinaryRepr::U32(input), BinaryRepr::U32(otp_0), BinaryRepr::U32(otp_1)) => {
                let input = Tracer::new(builder.state(), input);
                let otp_0 = Tracer::new(builder.state(), otp_0);
                let otp_1 = Tracer::new(builder.state(), otp_1);
                let masked = input ^ otp_0 ^ otp_1;
                builder.add_output(masked);
            }
            (BinaryRepr::U64(input), BinaryRepr::U64(otp_0), BinaryRepr::U64(otp_1)) => {
                let input = Tracer::new(builder.state(), input);
                let otp_0 = Tracer::new(builder.state(), otp_0);
                let otp_1 = Tracer::new(builder.state(), otp_1);
                let masked = input ^ otp_0 ^ otp_1;
                builder.add_output(masked);
            }
            (BinaryRepr::U128(input), BinaryRepr::U128(otp_0), BinaryRepr::U128(otp_1)) => {
                let input = Tracer::new(builder.state(), input);
                let otp_0 = Tracer::new(builder.state(), otp_0);
                let otp_1 = Tracer::new(builder.state(), otp_1);
                let masked = input ^ otp_0 ^ otp_1;
                builder.add_output(masked);
            }
            (
                BinaryRepr::Array(input_elems),
                BinaryRepr::Array(otp_0_elems),
                BinaryRepr::Array(otp_1_elems),
            ) => {
                for ((input, otp_0), otp_1) in
                    input_elems.into_iter().zip(otp_0_elems).zip(otp_1_elems)
                {
                    apply_otp(builder, input, otp_0, otp_1);
                }
            }
            _ => panic!("builder returned unexpected type"),
        }
    }

    for input_ty in inputs {
        let input = builder.add_input_by_type(input_ty.clone());
        let otp_0 = builder.add_input_by_type(input_ty.clone());
        let otp_1 = builder.add_input_by_type(input_ty.clone());
        apply_otp(&builder, input, otp_0, otp_1);
    }

    let circ = builder.build().expect("circuit should be valid");

    Arc::new(circ)
}
