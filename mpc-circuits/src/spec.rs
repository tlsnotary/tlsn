use std::sync::Arc;

use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::{
    error::SpecError as Error, group::UncheckedGroup, Circuit, Gate, Group, ValueType, WireGroup,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupSpec {
    id: usize,
    name: String,
    desc: String,
    value_type: String,
    wire_count: usize,
}

impl From<&Group> for GroupSpec {
    fn from(group: &Group) -> Self {
        Self {
            id: group.id(),
            name: group.name().to_string(),
            desc: group.description().to_string(),
            value_type: match group.value_type() {
                ValueType::ConstZero => "zero",
                ValueType::ConstOne => "one",
                ValueType::Bool => "bool",
                ValueType::Bits => "bits",
                ValueType::Bytes => "bytes",
                ValueType::U8 => "u8",
                ValueType::U16 => "u16",
                ValueType::U32 => "u32",
                ValueType::U64 => "u64",
                ValueType::U128 => "u128",
            }
            .to_string(),
            wire_count: group.wires.len(),
        }
    }
}

impl GroupSpec {
    fn to_group(self, id_offset: usize) -> Result<UncheckedGroup, Error> {
        let value_type = match self.value_type.to_lowercase().as_str() {
            "const_0" => ValueType::ConstZero,
            "const_1" => ValueType::ConstOne,
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

        Ok(UncheckedGroup::new(
            self.id,
            self.name,
            self.desc,
            value_type,
            (id_offset..id_offset + self.wire_count).collect::<Vec<usize>>(),
        ))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateSpec(String);

impl From<&Gate> for GateSpec {
    fn from(g: &Gate) -> Self {
        Self(match g {
            Gate::Xor {
                xref, yref, zref, ..
            } => format!("2 1 {xref} {yref} {zref} XOR"),
            Gate::And {
                xref, yref, zref, ..
            } => format!("2 1 {xref} {yref} {zref} AND"),
            Gate::Inv { xref, zref, .. } => format!("1 1 {xref} {zref} INV"),
        })
    }
}

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

impl From<&Circuit> for CircuitSpec {
    fn from(c: &Circuit) -> Self {
        Self {
            name: c.name.clone(),
            version: c.version.clone(),
            wires: c.wire_count,
            inputs: c
                .inputs
                .iter()
                .map(|input| GroupSpec::from(input.as_ref()))
                .collect(),
            outputs: c
                .outputs
                .iter()
                .map(|output| GroupSpec::from(output.as_ref()))
                .collect(),
            gates: c.gates.iter().map(|gate| GateSpec::from(gate)).collect(),
        }
    }
}

impl CircuitSpec {
    /// Deserializes YAML spec from byte slice
    pub fn from_yaml(bytes: &[u8]) -> Result<Self, Error> {
        Ok(serde_yaml::from_slice(bytes)?)
    }

    /// Creates a new [`Circuit`] from spec
    pub fn build(self) -> Result<Arc<Circuit>, Error> {
        let mut input_id_offset = 0;
        let inputs = self
            .inputs
            .into_iter()
            .map(|group| {
                let input = group.to_group(input_id_offset)?;
                input_id_offset += input.len();
                Ok(input)
            })
            .collect::<Result<Vec<UncheckedGroup>, Error>>()?;

        let mut output_id_offset = self.wires
            - self
                .outputs
                .iter()
                .map(|group| group.wire_count)
                .sum::<usize>();
        let outputs = self
            .outputs
            .into_iter()
            .map(|group| {
                let output = group.to_group(output_id_offset)?;
                output_id_offset += output.len();
                Ok(output)
            })
            .collect::<Result<Vec<UncheckedGroup>, Error>>()?;

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
    fn test_load_aes_128_reverse() {
        let bytes = std::fs::read("circuits/specs/aes_128_reverse.yml").unwrap();
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
    fn test_build_aes_128_reverse() {
        let bytes = std::fs::read("circuits/specs/aes_128_reverse.yml").unwrap();
        let spec = CircuitSpec::from_yaml(&bytes).unwrap();
        let _ = spec.build().unwrap();
    }
}
