use crate::{
    spec::{GateSpec, GroupSpec},
    value::ValueType,
};

#[derive(Debug, thiserror::Error)]
pub enum CircuitError {
    #[error("uninitialized wire, id: {0}")]
    UninitializedWire(usize),
    #[error("encountered error while parsing circuit: {0}")]
    ParsingError(String),
    #[error("encountered value error")]
    ValueError(#[from] ValueError),
    #[error("encountered error while constructing a circuit: {0}")]
    InvalidCircuit(String),
    #[error("Input {0} does not exist in {1:?} circuit")]
    InputError(usize, String),
    #[error("Output {0} does not exist in {1:?} circuit")]
    OutputError(usize, String),
    #[error("encountered io error while loading circuit")]
    IoError(#[from] std::io::Error),
    #[error("encountered prost DecodeError while loading circuit")]
    DecodeError(#[from] prost::DecodeError),
    #[error("encountered error while mapping protobuf model to core model")]
    MappingError,
}

#[derive(Debug, thiserror::Error)]
pub enum ValueError {
    #[error("Could not parse {0} bits into a value of type {1:?}")]
    ParseError(usize, ValueType),
    #[error("Invalid number of bits provided for group {0:?}, length {1:?}: {2}")]
    InvalidValue(String, usize, usize),
    #[error("Invalid value type for group {0:?}: Expected {1:?} got {2:?}")]
    InvalidType(String, ValueType, ValueType),
}

#[derive(Debug, thiserror::Error)]
pub enum SpecError {
    #[error("encountered error deserializing spec")]
    ReadError(#[from] serde_yaml::Error),
    #[error("invalid circuit spec")]
    InvalidCircuit(#[from] CircuitError),
    #[error("invalid group spec")]
    InvalidGroup(GroupSpec),
    #[error("invalid gate spec")]
    InvalidGate(GateSpec),
}

#[derive(Debug, thiserror::Error)]
pub enum BuilderError {
    #[error("Circuit input or output was not fully mapped to gates")]
    MissingConnection(String),
    #[error("Circuit error")]
    CircuitError(#[from] crate::CircuitError),
}
