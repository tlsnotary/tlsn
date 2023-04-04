use mpc_circuits::{types::ValueType, Circuit};
use std::fs::write;

fn main() {
    build_aes();
    build_sha();
}

fn build_aes() {
    let circ = Circuit::parse(
        "circuits/bristol/aes_128_reverse.txt",
        &[
            ValueType::Array(Box::new(ValueType::U8), 16),
            ValueType::Array(Box::new(ValueType::U8), 16),
        ],
        &[ValueType::Array(Box::new(ValueType::U8), 16)],
    )
    .unwrap()
    .reverse_input(0)
    .reverse_input(1)
    .reverse_output(0);

    let bytes = bincode::serialize(&circ).unwrap();
    write("circuits/bin/aes_128.bin", bytes).unwrap();
}

fn build_sha() {
    let circ = Circuit::parse(
        "circuits/bristol/sha256_reverse.txt",
        &[
            ValueType::Array(Box::new(ValueType::U8), 64),
            ValueType::Array(Box::new(ValueType::U32), 8),
        ],
        &[ValueType::Array(Box::new(ValueType::U32), 8)],
    )
    .unwrap()
    .reverse_inputs()
    .reverse_input(0)
    .reverse_input(1)
    .reverse_output(0);

    let bytes = bincode::serialize(&circ).unwrap();
    write("circuits/bin/sha256.bin", bytes).unwrap();
}
