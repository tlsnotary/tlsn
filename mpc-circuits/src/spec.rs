use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::{error::SpecError as Error, Circuit, Gate, Group, Input, Output, ValueType};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupSpec {
    name: String,
    desc: String,
    value_type: String,
    wire_count: usize,
}

impl GroupSpec {
    fn to_group(self, id_offset: usize) -> Result<Group, Error> {
        let value_type = match self.value_type.to_lowercase().as_str() {
            "bool" => ValueType::Bool,
            "bits" => ValueType::Bits,
            "bytes" => ValueType::Bytes,
            "u8" => ValueType::U8,
            "u16" => ValueType::U16,
            "u32" => ValueType::U32,
            "u64" => ValueType::U64,
            "u128" => ValueType::U128,
            _ => return Err(Error::InvalidGroup(self)),
        };
        Ok(Group::new(
            &self.name,
            &self.desc,
            value_type,
            &(id_offset..id_offset + self.wire_count).collect::<Vec<usize>>(),
        ))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateSpec(String);

impl GateSpec {
    fn to_gate(self, id: usize) -> Result<Gate, Error> {
        lazy_static! {
            static ref RE: Regex =
                Regex::new(r"2 1 (?P<xref>\d+) (?P<yref>\d+) (?P<zref>\d+) (?P<op>AND|XOR)")
                    .expect("invalid regex");
            static ref RE_INV: Regex =
                Regex::new(r"1 1 (?P<xref>\d+) (?P<zref>\d+) (?P<op>INV)").expect("invalid regex");
        }

        if let Some(captures) = RE.captures(&self.0) {
            let xref: usize = captures
                .name("xref")
                .ok_or(Error::InvalidGate(self.clone()))?
                .as_str()
                .parse()
                .map_err(|_| Error::InvalidGate(self.clone()))?;
            let yref: usize = captures
                .name("yref")
                .ok_or(Error::InvalidGate(self.clone()))?
                .as_str()
                .parse()
                .map_err(|_| Error::InvalidGate(self.clone()))?;
            let zref: usize = captures
                .name("zref")
                .ok_or(Error::InvalidGate(self.clone()))?
                .as_str()
                .parse()
                .map_err(|_| Error::InvalidGate(self.clone()))?;
            let gate = match captures
                .name("op")
                .ok_or(Error::InvalidGate(self.clone()))?
                .as_str()
            {
                "XOR" => Gate::Xor {
                    id,
                    xref,
                    yref,
                    zref,
                },
                "AND" => Gate::And {
                    id,
                    xref,
                    yref,
                    zref,
                },
                _ => return Err(Error::InvalidGate(self)),
            };
            Ok(gate)
        } else if let Some(captures) = RE_INV.captures(&self.0) {
            let xref: usize = captures
                .name("xref")
                .ok_or(Error::InvalidGate(self.clone()))?
                .as_str()
                .parse()
                .map_err(|_| Error::InvalidGate(self.clone()))?;
            let zref: usize = captures
                .name("zref")
                .ok_or(Error::InvalidGate(self.clone()))?
                .as_str()
                .parse()
                .map_err(|_| Error::InvalidGate(self.clone()))?;
            let gate = match captures
                .name("op")
                .ok_or(Error::InvalidGate(self.clone()))?
                .as_str()
            {
                "INV" => Gate::Inv { id, xref, zref },
                _ => return Err(Error::InvalidGate(self)),
            };
            Ok(gate)
        } else {
            Err(Error::InvalidGate(self))
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitSpec {
    name: String,
    version: String,
    wires: usize,
    inputs: Vec<GroupSpec>,
    outputs: Vec<GroupSpec>,
    gates: Vec<GateSpec>,
}

impl CircuitSpec {
    /// Deserializes YAML spec from byte slice
    pub fn from_yaml(bytes: &[u8]) -> Result<Self, Error> {
        Ok(serde_yaml::from_slice(bytes)?)
    }

    /// Creates a new [`Circuit`] from spec
    pub fn build(self) -> Result<Circuit, Error> {
        let mut input_id_offset = 0;
        let inputs = self
            .inputs
            .into_iter()
            .enumerate()
            .map(|(id, group)| {
                let input = Input::new(id, group.to_group(input_id_offset)?);
                input_id_offset += input.as_ref().len();
                Ok(input)
            })
            .collect::<Result<Vec<Input>, Error>>()?;

        let mut output_id_offset = self.wires
            - self
                .outputs
                .iter()
                .map(|group| group.wire_count)
                .sum::<usize>();
        let outputs = self
            .outputs
            .into_iter()
            .enumerate()
            .map(|(id, group)| {
                let output = Output::new(id, group.to_group(output_id_offset)?);
                output_id_offset += output.as_ref().len();
                Ok(output)
            })
            .collect::<Result<Vec<Output>, Error>>()?;

        let gates = self
            .gates
            .into_iter()
            .enumerate()
            .map(|(id, gate)| gate.to_gate(id))
            .collect::<Result<Vec<Gate>, Error>>()?;

        Ok(Circuit::new(
            &self.name,
            &self.version,
            inputs,
            outputs,
            gates,
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_adder_64() {
        let bytes = std::fs::read("circuits/specs/adder64.yml").unwrap();
        let _ = CircuitSpec::from_yaml(&bytes).unwrap();
    }

    #[test]
    fn test_load_aes_128() {
        let bytes = std::fs::read("circuits/specs/aes_128.yml").unwrap();
        let _ = CircuitSpec::from_yaml(&bytes).unwrap();
    }

    #[test]
    fn test_gate_spec() {
        let spec = GateSpec("2 1 0 1 2 XOR".to_string());
        let _ = spec.to_gate(0).unwrap();
    }

    #[test]
    fn test_build_adder_64() {
        let bytes = std::fs::read("circuits/specs/adder64.yml").unwrap();
        let spec = CircuitSpec::from_yaml(&bytes).unwrap();
        let _ = spec.build().unwrap();
    }

    #[test]
    fn test_build_aes_128() {
        let bytes = std::fs::read("circuits/specs/aes_128.yml").unwrap();
        let spec = CircuitSpec::from_yaml(&bytes).unwrap();
        let _ = spec.build().unwrap();
    }
}
