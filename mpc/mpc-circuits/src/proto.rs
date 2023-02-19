use std::{
    convert::{From, TryFrom},
    sync::Arc,
};

use crate::{
    group::UncheckedGroup, value::BitOrder, CircuitError, CircuitId, ValueType, WireGroup,
};

include!(concat!(env!("OUT_DIR"), "/core.circuits.rs"));

impl From<&crate::Group> for Group {
    #[inline]
    fn from(group: &crate::Group) -> Self {
        Self {
            index: group.index() as u32,
            id: group.id().as_ref().clone(),
            desc: group.description().to_string(),
            value_type: group.value_type() as i32,
            wires: group.wires().iter().map(|id| *id as u32).collect(),
        }
    }
}

impl TryFrom<Group> for UncheckedGroup {
    type Error = CircuitError;
    #[inline]
    fn try_from(group: Group) -> Result<Self, Self::Error> {
        Ok(UncheckedGroup::new(
            group.index as usize,
            group.id,
            group.desc,
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

impl From<&crate::Gate> for Gate {
    #[inline]
    fn from(g: &crate::Gate) -> Self {
        match g.clone() {
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

impl From<&crate::Circuit> for Circuit {
    #[inline]
    fn from(c: &crate::Circuit) -> Self {
        let gates = c.gates().iter().map(|g| Gate::from(g)).collect();
        Self {
            id: c.id.as_ref().to_string(),
            description: c.description.clone(),
            version: c.version.clone(),
            bit_order: c.bit_order.to_string(),
            wire_count: c.wire_count as u32,
            and_count: c.and_count as u32,
            xor_count: c.xor_count as u32,
            inputs: c
                .inputs
                .iter()
                .map(|input| Group::from(input.0.as_ref()))
                .collect(),
            outputs: c
                .outputs
                .iter()
                .map(|output| Group::from(output.0.as_ref()))
                .collect(),
            gates,
        }
    }
}

impl TryFrom<Circuit> for Arc<crate::Circuit> {
    type Error = CircuitError;

    #[inline]
    fn try_from(c: Circuit) -> Result<Self, Self::Error> {
        let inputs = c
            .inputs
            .into_iter()
            .map(|group| UncheckedGroup::try_from(group))
            .collect::<Result<Vec<UncheckedGroup>, _>>()?
            .into_iter()
            .map(crate::Group::new_unchecked)
            .collect();

        let outputs = c
            .outputs
            .into_iter()
            .map(|group| UncheckedGroup::try_from(group))
            .collect::<Result<Vec<UncheckedGroup>, _>>()?
            .into_iter()
            .map(crate::Group::new_unchecked)
            .collect();

        let gates = c
            .gates
            .into_iter()
            .map(|gate| crate::Gate::try_from(gate))
            .collect::<Result<Vec<crate::Gate>, _>>()?;

        let bit_order = BitOrder::from_str(&c.bit_order).map_err(|_| CircuitError::MappingError)?;

        Ok(crate::Circuit::new_unchecked(
            CircuitId(c.id),
            &c.description,
            &c.version,
            bit_order,
            inputs,
            outputs,
            gates,
        ))
    }
}
