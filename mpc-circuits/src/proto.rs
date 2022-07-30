use std::convert::{From, TryFrom};

use crate::Error;

include!(concat!(env!("OUT_DIR"), "/core.circuits.rs"));

impl From<crate::Group> for Group {
    #[inline]
    fn from(g: crate::Group) -> Self {
        Self {
            name: g.name().to_string(),
            desc: g.desc().to_string(),
            wires: g.wires().iter().map(|id| *id as u32).collect(),
        }
    }
}

impl TryFrom<Group> for crate::Group {
    type Error = Error;
    #[inline]
    fn try_from(g: Group) -> Result<Self, Self::Error> {
        Ok(crate::Group::new(
            &g.name,
            &g.desc,
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
    type Error = Error;

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
            _ => return Err(Error::MappingError),
        };
        Ok(gate)
    }
}

impl From<crate::circuit::CircuitDescription> for CircuitDescription {
    #[inline]
    fn from(c: crate::circuit::CircuitDescription) -> Self {
        Self {
            name: c.name,
            version: c.version,
            wire_count: c.wire_count as u32,
            and_count: c.and_count as u32,
            xor_count: c.xor_count as u32,
            inputs: c.inputs.iter().map(|g| Group::from(g.0.clone())).collect(),
            outputs: c.inputs.iter().map(|g| Group::from(g.0.clone())).collect(),
        }
    }
}

impl TryFrom<CircuitDescription> for crate::circuit::CircuitDescription {
    type Error = Error;

    #[inline]
    fn try_from(c: CircuitDescription) -> Result<Self, Self::Error> {
        let mut inputs: Vec<crate::Group> = Vec::with_capacity(c.inputs.len());
        for group in c.inputs {
            inputs.push(crate::Group::try_from(group)?);
        }

        let mut outputs: Vec<crate::Group> = Vec::with_capacity(c.outputs.len());
        for group in c.outputs {
            outputs.push(crate::Group::try_from(group)?);
        }

        Ok(Self {
            name: c.name,
            version: c.version,
            wire_count: c.wire_count as usize,
            and_count: c.and_count as usize,
            xor_count: c.xor_count as usize,
            inputs: inputs
                .iter()
                .map(|group| crate::Input(group.clone()))
                .collect(),
            outputs: outputs
                .iter()
                .map(|group| crate::Output(group.clone()))
                .collect(),
        })
    }
}

impl From<crate::Circuit> for Circuit {
    #[inline]
    fn from(c: crate::Circuit) -> Self {
        let gates = c.gates().iter().map(|g| Gate::from(*g)).collect();
        Self {
            desc: c.desc.into(),
            gates,
        }
    }
}

impl TryFrom<Circuit> for crate::Circuit {
    type Error = Error;

    #[inline]
    fn try_from(c: Circuit) -> Result<Self, Self::Error> {
        let mut gates: Vec<crate::Gate> = Vec::with_capacity(c.gates.len());
        for gate in c.gates {
            gates.push(crate::Gate::try_from(gate)?);
        }
        Ok(Self {
            desc: crate::circuit::CircuitDescription::try_from(c.desc)?,
            gates,
        })
    }
}
