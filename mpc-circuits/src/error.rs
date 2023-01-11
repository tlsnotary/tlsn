use crate::{
    spec::{GateSpec, GroupSpec},
    value::ValueType,
};

#[derive(Debug, thiserror::Error)]
pub enum CircuitError {
    #[error("Uninitialized wire, id: {0}")]
    UninitializedWire(usize),
    #[error("Encountered error while parsing circuit: {0}")]
    ParsingError(String),
    #[error("Encountered group error: {0:?}")]
    GroupError(#[from] GroupError),
    #[error("Encountered value error: {0:?}")]
    ValueError(#[from] ValueError),
    #[error("Encountered error while constructing a circuit: {0}")]
    InvalidCircuit(String),
    #[error("Input {0} does not exist in {1:?} circuit")]
    InputError(usize, String),
    #[error("Output {0} does not exist in {1:?} circuit")]
    OutputError(usize, String),
    #[error("Encountered io error while loading circuit")]
    IoError(#[from] std::io::Error),
    #[error("Encountered prost DecodeError while loading circuit")]
    DecodeError(#[from] prost::DecodeError),
    #[error("Encountered error while mapping protobuf model to core model")]
    MappingError,
}

#[derive(Debug, thiserror::Error)]
pub enum GroupError {
    #[error("Incompatible value type for group {0:?}: expected {1:?} got {2:?}")]
    InvalidType(String, ValueType, ValueType),
    #[error("Incompatible value length for group {0:?}: expected {1} got {2}")]
    InvalidLength(String, usize, usize),
    #[error("Encountered value error for group {0:?}: {1:?}")]
    ValueError(String, ValueError),
}

#[derive(Debug, thiserror::Error)]
pub enum ValueError {
    #[error("Could not parse {0} bits into a value of type {1:?}")]
    ParseError(usize, ValueType),
    #[error("Invalid number of bits provided for value type {0:?}: {1}")]
    InvalidLength(ValueType, usize),
    #[error("Incompatible value types: {0:?} and {1:?}")]
    InvalidType(ValueType, ValueType),
}

#[derive(Debug, thiserror::Error)]
pub enum SpecError {
    #[error("Encountered error deserializing spec")]
    ReadError(#[from] serde_yaml::Error),
    #[error("Invalid circuit spec")]
    InvalidCircuit(#[from] CircuitError),
    #[error("Invalid group spec")]
    InvalidGroup(GroupSpec),
    #[error("Invalid gate spec")]
    InvalidGate(GateSpec),
}

#[derive(Debug, thiserror::Error)]
pub enum BuilderError {
    #[error("Circuit input or output was not fully mapped to gates")]
    MissingConnection(String),
    #[error("Circuit error")]
    CircuitError(#[from] crate::CircuitError),
}
