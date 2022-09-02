use crate::combine_pms_shares;
use mpc_circuits::{
    builder::{map_bytes, CircuitBuilder, Feed, Gates, Sink, WireHandle},
    Circuit, ValueType, SHA_256,
};

/// TLS stage 1
///
/// Parties input their additive shares of the pre-master secret (PMS).
/// Outputs sha256(pms xor opad) called "pms outer hash state" to Notary and
/// also outputs sha256(pms xor ipad) called "pms inner hash state" to User.
pub fn c1() -> Circuit {
    let mut builder = CircuitBuilder::new("c1", "0.1.0");

    let share_a = builder.add_input(
        "PMS_SHARE_A",
        "256-bit PMS Additive Share",
        ValueType::Bytes,
        256,
    );
    let share_b = builder.add_input(
        "PMS_SHARE_B",
        "256-bit PMS Additive Share",
        ValueType::Bytes,
        256,
    );
    let mask_a = builder.add_input("MASK_A", "256-bit Mask", ValueType::Bytes, 256);
    let mask_b = builder.add_input("MASK_B", "256-bit Mask", ValueType::Bytes, 256);
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

    let mut builder = builder.build_inputs();

    let combine_pms = builder.add_circ(combine_pms_shares());
    let sha256 =
        builder.add_circ(Circuit::load_bytes(SHA_256).expect("failed to load sha256 circuit"));

    builder.connect(
        &share_a[..],
        &combine_pms
            .input(0)
            .expect("combine_pms_shares missing input 0")[..],
    );
    builder.connect(
        &share_b[..],
        &combine_pms
            .input(1)
            .expect("combine_pms_shares missing input 0")[..],
    );
    builder.connect(
        &const_zero[..],
        &combine_pms
            .input(2)
            .expect("combine_pms_shares missing input 2")[..],
    );
    builder.connect(
        &const_one[..],
        &combine_pms
            .input(3)
            .expect("combine_pms_shares missing input 3")[..],
    );

    let pms = combine_pms
        .output(0)
        .expect("combine_pms_shares missing output 0");

    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_c1() {
        todo!()
    }
}
