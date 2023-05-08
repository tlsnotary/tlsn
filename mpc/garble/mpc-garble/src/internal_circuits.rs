use std::sync::Arc;

use mpc_circuits::{types::ValueType, Circuit, CircuitBuilder, Tracer};

/// Builds a circuit for applying one-time pads to the provided values.
pub(crate) fn build_otp_circuit(inputs: &[ValueType]) -> Arc<Circuit> {
    let builder = CircuitBuilder::new();

    for input_ty in inputs {
        let input = builder.add_input_by_type(input_ty.clone());
        let otp = builder.add_input_by_type(input_ty.clone());

        let input = Tracer::new(builder.state(), input);
        let otp = Tracer::new(builder.state(), otp);
        let masked = input ^ otp;
        builder.add_output(masked);
    }

    let circ = builder.build().expect("circuit should be valid");

    Arc::new(circ)
}

/// Builds a circuit for applying one-time pads to secret share the provided values.
pub(crate) fn build_otp_shared_circuit(inputs: &[ValueType]) -> Arc<Circuit> {
    let builder = CircuitBuilder::new();

    for input_ty in inputs {
        let input = builder.add_input_by_type(input_ty.clone());
        let otp_0 = builder.add_input_by_type(input_ty.clone());
        let otp_1 = builder.add_input_by_type(input_ty.clone());

        let input = Tracer::new(builder.state(), input);
        let otp_0 = Tracer::new(builder.state(), otp_0);
        let otp_1 = Tracer::new(builder.state(), otp_1);
        let masked = input ^ otp_0 ^ otp_1;
        builder.add_output(masked);
    }

    let circ = builder.build().expect("circuit should be valid");

    Arc::new(circ)
}
