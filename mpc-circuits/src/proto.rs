use std::{
    convert::{From, TryFrom},
    sync::Arc,
};

use crate::{CircuitError, ValueType, WireGroup};

include!(concat!(env!("OUT_DIR"), "/core.circuits.rs"));

impl From<crate::Group> for Group {
    #[inline]
    fn from(group: crate::Group) -> Self {
        Self {
            id: group.id() as u32,
            name: group.name().to_string(),
            desc: group.description().to_string(),
            value_type: group.value_type() as i32,
            wires: group.wires().iter().map(|id| *id as u32).collect(),
        }
    }
}

impl TryFrom<Group> for crate::Group {
    type Error = CircuitError;
    #[inline]
    fn try_from(group: Group) -> Result<Self, Self::Error> {
        Ok(crate::Group::new(
            group.id as usize,
            &group.name,
            &group.desc,
            match group.value_type {
                0 => ValueType::ConstZero,
                1 => ValueType::ConstOne,
                2 => ValueType::Bool,
                3 => ValueType::Bits,
                4 => ValueType::Bytes,
                5 => ValueType::U8,
                6 => ValueType::U16,
                7 => ValueType::U32,
                8 => ValueType::U64,
                9 => ValueType::U128,
                _ => return Err(CircuitError::MappingError),
            },
            group
                .wires
                .into_iter()
                .map(|id| id as usize)
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
        for group in c.inputs.into_iter() {
            inputs.push(crate::Input(Arc::new(crate::Group::try_from(group)?)));
        }

        let mut outputs: Vec<crate::Output> = Vec::with_capacity(c.outputs.len());
        for group in c.outputs.into_iter() {
            outputs.push(crate::Output(Arc::new(crate::Group::try_from(group)?)));
        }

        let mut gates: Vec<crate::Gate> = Vec::with_capacity(c.gates.len());
        for gate in c.gates {
            gates.push(crate::Gate::try_from(gate)?);
        }
        Ok(crate::Circuit::new_unchecked(
            &c.name, &c.version, inputs, outputs, gates,
        ))
    }
}
