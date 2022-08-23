use crate::{
    spec::{GateSpec, GroupSpec},
    value::ValueType,
    Group,
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("uninitialized wire, id: {0}")]
    UninitializedWire(usize),
    /// An I/O error occurred.
    #[error("encountered error while parsing circuit: {0}")]
    ParsingError(String),
    #[error("encountered value error")]
    ValueError(#[from] ValueError),
    /// An error occurred while constructing a circuit
    #[error("encountered error while constructing a circuit: {0}")]
    InvalidCircuit(String),
    /// An I/O error occurred.
    #[error("encountered io error while loading circuit")]
    IoError(#[from] std::io::Error),
    /// A decoding error occurred.
    #[error("encountered prost DecodeError while loading circuit")]
    DecodeError(#[from] prost::DecodeError),
    /// Error occurred when mapping models
    #[error("encountered error while mapping protobuf model to core model")]
    MappingError,
}

#[derive(Debug, thiserror::Error)]
pub enum ValueError {
    #[error("Invalid bit string provided for value type")]
    InvalidValue(ValueType, Vec<bool>),
    #[error("Invalid value type for group")]
    InvalidType(Group, ValueType),
}

#[derive(Debug, thiserror::Error)]
pub enum SpecError {
    #[error("encountered error deserializing spec")]
    ReadError(#[from] serde_yaml::Error),
    #[error("invalid circuit spec")]
    InvalidCircuit(#[from] Error),
    #[error("invalid group spec")]
    InvalidGroup(GroupSpec),
    #[error("invalid gate spec")]
    InvalidGate(GateSpec),
}
