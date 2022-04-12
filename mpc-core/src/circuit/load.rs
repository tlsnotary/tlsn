#![cfg(feature = "proto")]

use super::errors::CircuitLoadError;
use super::Circuit;
use crate::proto::circuits::Circuit as ProtoCircuit;
use prost::Message;
use std::convert::TryFrom;
use std::fs::read;

impl Circuit {
    /// Loads a circuit stored in a file in protobuf format
    pub fn load(filename: &str) -> Result<Self, CircuitLoadError> {
        let file = read(filename)?;
        let circ = ProtoCircuit::decode(file.as_slice())?;
        Circuit::try_from(circ).map_err(|_| CircuitLoadError::MappingError)
    }
}
