use std::convert::{From, TryFrom};

use crate::{CircuitError, ValueType};

include!(concat!(env!("OUT_DIR"), "/core.circuits.rs"));

impl From<crate::Group> for Group {
    #[inline]
    fn from(g: crate::Group) -> Self {
        Self {
            name: g.name().to_string(),
            desc: g.desc().to_string(),
            value_type: g.value_type() as i32,
            wires: g.wires().iter().map(|id| *id as u32).collect(),
        }
    }
}

impl TryFrom<Group> for crate::Group {
    type Error = CircuitError;
    #[inline]
    fn try_from(g: Group) -> Result<Self, Self::Error> {
        Ok(crate::Group::new(
            &g.name,
            &g.desc,
            match g.value_type {
                0 => ValueType::Bool,
                1 => ValueType::Bits,
                2 => ValueType::Bytes,
                3 => ValueType::U8,
                4 => ValueType::U16,
                5 => ValueType::U32,
                6 => ValueType::U64,
                7 => ValueType::U128,
                _ => return Err(CircuitError::MappingError),
            },
            &g.wires
                .iter()
                .map(|id| *id as usize)
                .collect::<Vec<usize>>(),
        ))
    }
}

impl From<crate::Gate> for Gate {
    #[inline]
    fn from(g: crate::Gate) -> Self {
        match g {
            crate::Gate::Xor {
                id,
                xref,
                yref,
                zref,
            } => Self {
                id: id as u32,
                xref: xref as u32,
                yref: yref as u32,
                zref: zref as u32,
                gate_type: 0,
            },
            crate::Gate::And {
                id,
                xref,
                yref,
                zref,
            } => Self {
                id: id as u32,
                xref: xref as u32,
                yref: yref as u32,
                zref: zref as u32,
                gate_type: 1,
            },
            crate::Gate::Inv { id, xref, zref } => Self {
                id: id as u32,
                xref: xref as u32,
                yref: 0,
                zref: zref as u32,
                gate_type: 2,
            },
        }
    }
}

impl TryFrom<Gate> for crate::Gate {
    type Error = CircuitError;

    fn try_from(g: Gate) -> Result<Self, Self::Error> {
        let gate = match g.gate_type {
            0 => crate::Gate::Xor {
                id: g.id as usize,
                xref: g.xref as usize,
                yref: g.yref as usize,
                zref: g.zref as usize,
            },
            1 => crate::Gate::And {
                id: g.id as usize,
                xref: g.xref as usize,
                yref: g.yref as usize,
                zref: g.zref as usize,
            },
            2 => crate::Gate::Inv {
                id: g.id as usize,
                xref: g.xref as usize,
                zref: g.zref as usize,
            },
            _ => return Err(CircuitError::MappingError),
        };
        Ok(gate)
    }
}

impl From<crate::Circuit> for Circuit {
    #[inline]
    fn from(c: crate::Circuit) -> Self {
        let gates = c.gates().iter().map(|g| Gate::from(*g)).collect();
        Self {
            id: c.id.as_ref().to_string(),
            name: c.name,
            version: c.version,
            wire_count: c.wire_count as u32,
            and_count: c.and_count as u32,
            xor_count: c.xor_count as u32,
            inputs: c
                .inputs
                .iter()
                .map(|input| Group::from(input.as_ref().clone()))
                .collect(),
            outputs: c
                .outputs
                .iter()
                .map(|output| Group::from(output.as_ref().clone()))
                .collect(),
            gates,
        }
    }
}

impl TryFrom<Circuit> for crate::Circuit {
    type Error = CircuitError;

    #[inline]
    fn try_from(c: Circuit) -> Result<Self, Self::Error> {
        let mut inputs: Vec<crate::Input> = Vec::with_capacity(c.inputs.len());
        for (id, group) in c.inputs.into_iter().enumerate() {
            inputs.push(crate::Input::new(id, crate::Group::try_from(group)?));
        }

        let mut outputs: Vec<crate::Output> = Vec::with_capacity(c.outputs.len());
        for (id, group) in c.outputs.into_iter().enumerate() {
            outputs.push(crate::Output::new(id, crate::Group::try_from(group)?));
        }

        let mut gates: Vec<crate::Gate> = Vec::with_capacity(c.gates.len());
        for gate in c.gates {
            gates.push(crate::Gate::try_from(gate)?);
        }
        Ok(crate::Circuit::new(
            &c.name, &c.version, inputs, outputs, gates,
        )?)
    }
}
