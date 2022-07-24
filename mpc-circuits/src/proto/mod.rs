use std::convert::{From, TryFrom};
use std::io::{Error, ErrorKind};

include!(concat!(env!("OUT_DIR"), "/core.circuits.rs"));

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

    #[inline]
    fn try_from(g: Gate) -> Result<Self, Self::Error> {
        let g = match g.gate_type {
            0 => Self::Xor {
                id: g.id as usize,
                xref: g.xref as usize,
                yref: g.yref as usize,
                zref: g.zref as usize,
            },
            1 => Self::And {
                id: g.id as usize,
                xref: g.xref as usize,
                yref: g.yref as usize,
                zref: g.zref as usize,
            },
            2 => Self::Inv {
                id: g.id as usize,
                xref: g.xref as usize,
                zref: g.zref as usize,
            },
            _ => {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("Unrecognized gate type: {:?}", g),
                ))
            }
        };
        Ok(g)
    }
}

impl From<crate::CircuitDescription> for CircuitDescription {
    #[inline]
    fn from(c: crate::CircuitDescription) -> Self {
        Self {
            name: c.name,
            version: c.version,
            ngates: c.ngates as u32,
            nwires: c.nwires as u32,
            ninputs: c.ninputs as u32,
            input_nwires: c.input_nwires.into_iter().map(|n| n as u32).collect(),
            ninput_wires: c.ninput_wires as u32,
            noutput_wires: c.noutput_wires as u32,
            nand: c.nand as u32,
            nxor: c.nxor as u32,
        }
    }
}

impl TryFrom<CircuitDescription> for crate::CircuitDescription {
    type Error = Error;

    #[inline]
    fn try_from(c: CircuitDescription) -> Result<Self, Self::Error> {
        Ok(Self {
            name: c.name,
            version: c.version,
            ngates: c.ngates as usize,
            nwires: c.nwires as usize,
            ninputs: c.ninputs as usize,
            input_nwires: c.input_nwires.into_iter().map(|n| n as usize).collect(),
            ninput_wires: c.ninput_wires as usize,
            noutput_wires: c.noutput_wires as usize,
            nand: c.nand as usize,
            nxor: c.nxor as usize,
        })
    }
}

impl From<crate::Circuit> for Circuit {
    #[inline]
    fn from(c: crate::Circuit) -> Self {
        Self {
            description: c.desc.into(),
            gates: c.gates.into_iter().map(Gate::from).collect(),
        }
    }
}

impl TryFrom<Circuit> for crate::Circuit {
    type Error = Error;

    #[inline]
    fn try_from(c: Circuit) -> Result<Self, Self::Error> {
        let mut gates: Vec<crate::Gate> = Vec::with_capacity(c.gates.len());
        for gate in c.gates.into_iter() {
            gates.push(crate::Gate::try_from(gate)?)
        }
        Ok(Self {
            desc: crate::CircuitDescription::try_from(c.description)?,
            gates,
        })
    }
}
