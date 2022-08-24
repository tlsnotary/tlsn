use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    sync::Arc,
};

use crate::{circuit::GateType, Circuit, Gate, Group, Input, Output, ValueType};

#[derive(Debug)]
pub enum BuilderError {}

#[derive(Debug, Clone)]
pub struct CircuitHandle {
    id: usize,
    circ: Arc<Circuit>,
}

impl CircuitHandle {
    pub fn input(&self, id: usize) -> Option<InputHandle> {
        if let Some(input) = self.circ.input(id) {
            Some(InputHandle {
                circ_id: self.id,
                input: input.clone(),
                wire_handles: input
                    .as_ref()
                    .wires()
                    .iter()
                    .map(|wire_id| WireHandle {
                        circ_id: self.id,
                        wire_id: *wire_id,
                    })
                    .collect(),
            })
        } else {
            None
        }
    }

    pub fn output(&self, id: usize) -> Option<OutputHandle> {
        if let Some(output) = self.circ.output(id) {
            Some(OutputHandle {
                circ_id: self.id,
                output: output.clone(),
                wire_handles: output
                    .as_ref()
                    .wires()
                    .iter()
                    .map(|wire_id| WireHandle {
                        circ_id: self.id,
                        wire_id: *wire_id,
                    })
                    .collect(),
            })
        } else {
            None
        }
    }
}

#[derive(Debug, Clone)]
pub struct InputHandle {
    circ_id: usize,
    input: Input,
    wire_handles: Vec<WireHandle>,
}

impl<Idx> std::ops::Index<Idx> for InputHandle
where
    Idx: std::slice::SliceIndex<[WireHandle]>,
{
    type Output = Idx::Output;

    fn index(&self, index: Idx) -> &Self::Output {
        &self.wire_handles[index]
    }
}

#[derive(Debug, Clone)]
pub struct OutputHandle {
    circ_id: usize,
    output: Output,
    wire_handles: Vec<WireHandle>,
}

impl OutputHandle {
    fn offset(&mut self, offset: usize) {
        self.output.group.wires = self
            .output
            .group
            .wires
            .iter()
            .map(|id| id + offset)
            .collect();
    }
}

impl<Idx> std::ops::Index<Idx> for OutputHandle
where
    Idx: std::slice::SliceIndex<[WireHandle]>,
{
    type Output = Idx::Output;

    fn index(&self, index: Idx) -> &Self::Output {
        &self.wire_handles[index]
    }
}

#[derive(Debug, Clone)]
pub struct BuilderGate {
    circ_id: usize,
    xref: usize,
    yref: Option<usize>,
    zref: usize,
    gate_type: GateType,
}

impl BuilderGate {
    fn from_gate(circ_id: usize, gate: &Gate, offset: usize) -> Self {
        Self {
            circ_id,
            xref: gate.xref() + offset,
            yref: gate.yref().and_then(|yref| Some(yref + offset)),
            zref: gate.zref() + offset,
            gate_type: gate.gate_type(),
        }
    }

    fn to_gate(self, id: usize) -> Gate {
        match self.gate_type {
            GateType::Xor => Gate::Xor {
                id,
                xref: self.xref,
                yref: self.yref.unwrap(),
                zref: self.zref,
            },
            GateType::And => Gate::And {
                id,
                xref: self.xref,
                yref: self.yref.unwrap(),
                zref: self.zref,
            },
            GateType::Inv => Gate::Inv {
                id,
                xref: self.xref,
                zref: self.zref,
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct WireHandle {
    circ_id: usize,
    wire_id: usize,
}

#[derive(Debug, Clone)]
pub struct GateHandle {
    circ_id: usize,
    x: WireHandle,
    y: Option<WireHandle>,
    z: WireHandle,
    gate_type: GateType,
}

#[derive(Debug, Default)]
pub struct CircuitBuilder {
    input_wire_id: usize,
    inputs: Vec<InputHandle>,
    output_wire_id: usize,
    outputs: Vec<OutputHandle>,
    gate_wire_id: usize,
    gates: Vec<GateHandle>,
    circs: HashMap<usize, Arc<Circuit>>,
    conns: HashMap<(usize, usize), (usize, usize)>,
}

impl CircuitBuilder {
    pub fn add_input(
        &mut self,
        name: &str,
        desc: &str,
        value_type: ValueType,
        wire_count: usize,
    ) -> InputHandle {
        let wires: Vec<usize> = (self.input_wire_id..self.input_wire_id + wire_count).collect();
        self.input_wire_id += wire_count;
        let input = InputHandle {
            circ_id: 0,
            input: Input::new(
                self.inputs.len(),
                Group::new(name, desc, value_type, &wires),
            ),
            wire_handles: wires
                .iter()
                .map(|id| WireHandle {
                    circ_id: 0,
                    wire_id: *id,
                })
                .collect(),
        };
        self.inputs.push(input.clone());
        input
    }

    pub fn add_output(
        &mut self,
        name: &str,
        desc: &str,
        value_type: ValueType,
        wire_count: usize,
    ) -> OutputHandle {
        let wires: Vec<usize> = (self.output_wire_id..self.output_wire_id + wire_count).collect();
        self.output_wire_id += wire_count;
        let output = OutputHandle {
            circ_id: 0,
            output: Output::new(
                self.outputs.len(),
                Group::new(name, desc, value_type, &wires),
            ),
            wire_handles: wires
                .iter()
                .map(|id| WireHandle {
                    circ_id: 0,
                    wire_id: *id,
                })
                .collect(),
        };
        self.outputs.push(output.clone());
        output
    }

    pub fn add_circ(&mut self, circ: Circuit) -> CircuitHandle {
        // id 0 is reserved for root circuit
        let id = self.circs.len() + 1;
        let circ = Arc::new(circ);
        let handle = CircuitHandle {
            id,
            circ: circ.clone(),
        };
        self.circs.insert(id, circ);
        handle
    }

    pub fn add_gate(&mut self, gate_type: GateType) -> GateHandle {
        let (x, y, z) = match gate_type {
            GateType::Xor => {
                let x = self.gate_wire_id;
                let y = x + 1;
                let z = y + 1;
                self.gate_wire_id += 3;
                (x, Some(y), z)
            }
            GateType::And => {
                let x = self.gate_wire_id;
                let y = x + 1;
                let z = y + 1;
                self.gate_wire_id += 3;
                (x, Some(y), z)
            }
            GateType::Inv => {
                let x = self.gate_wire_id;
                let z = x + 1;
                self.gate_wire_id += 2;
                (x, None, z)
            }
        };
        let handle = GateHandle {
            circ_id: 0,
            x: WireHandle {
                circ_id: 0,
                wire_id: x,
            },
            y: y.and_then(|y| {
                Some(WireHandle {
                    circ_id: 0,
                    wire_id: y,
                })
            }),
            z: WireHandle {
                circ_id: 0,
                wire_id: z,
            },
            gate_type,
        };
        self.gates.push(handle.clone());
        handle
    }

    pub fn connect(
        &mut self,
        feeds: &[WireHandle],
        sinks: &[WireHandle],
    ) -> Result<(), BuilderError> {
        for (feed, sink) in feeds.iter().zip(sinks) {
            self.conns
                .insert((sink.circ_id, sink.wire_id), (feed.circ_id, feed.wire_id));
        }
        Ok(())
    }

    pub fn build(self) -> Result<Circuit, BuilderError> {
        let mut wire_id_offset = self.input_wire_id;
        let mut gates: Vec<BuilderGate> = Vec::new();

        let mut circ_offsets: HashMap<usize, usize> = HashMap::with_capacity(self.circs.len());
        circ_offsets.insert(0, 0);
        for (circ_id, circ) in self.circs {
            circ_offsets.insert(circ_id, wire_id_offset);
            gates.extend(
                circ.gates
                    .iter()
                    .map(|gate| BuilderGate::from_gate(circ_id, gate, wire_id_offset))
                    .collect::<Vec<BuilderGate>>(),
            );
            wire_id_offset += circ.len();
        }

        // Offset wire ids for connections
        let conns: HashMap<usize, usize> = self
            .conns
            .into_iter()
            .map(
                |((sink_circ_id, sink_wire_id), (feed_circ_id, feed_wire_id))| {
                    (
                        sink_wire_id + circ_offsets.get(&sink_circ_id).unwrap(),
                        feed_wire_id + circ_offsets.get(&feed_circ_id).unwrap(),
                    )
                },
            )
            .collect();

        // Map gate wire ids according to connections
        let mut wire_ids: BTreeSet<usize> = BTreeSet::new();
        gates.iter_mut().for_each(|handle| {
            if let Some(new_id) = conns.get(&handle.xref) {
                handle.xref = *new_id;
            }
            if let Some(yref) = &handle.yref {
                if let Some(new_id) = conns.get(yref) {
                    handle.yref = Some(*new_id);
                }
                wire_ids.insert(handle.yref.unwrap());
            }
            wire_ids.insert(handle.xref);
            wire_ids.insert(handle.zref);
        });

        // Create a wire_id map which will left shift all wire ids to remove gaps
        let id_map: BTreeMap<usize, usize> = wire_ids
            .into_iter()
            .enumerate()
            .map(|(ix, id)| (id, ix))
            .collect();
        gates.iter_mut().for_each(|handle| {
            if let Some(new_id) = id_map.get(&handle.xref) {
                handle.xref = *new_id;
            }
            if let Some(yref) = &handle.yref {
                if let Some(new_id) = id_map.get(yref) {
                    handle.yref = Some(*new_id);
                }
            }
            if let Some(new_id) = id_map.get(&handle.zref) {
                handle.zref = *new_id;
            }
        });

        let output_wire_count: usize = self
            .outputs
            .iter()
            .map(|handle| handle.output.group.len())
            .sum();

        let inputs: Vec<Input> = self.inputs.into_iter().map(|handle| handle.input).collect();
        let outputs: Vec<Output> = self
            .outputs
            .into_iter()
            .map(|mut handle| {
                handle.offset(id_map.len() - output_wire_count);
                handle.output
            })
            .collect();
        let gates: Vec<Gate> = gates
            .into_iter()
            .enumerate()
            .map(|(id, handle)| handle.to_gate(id))
            .collect();

        Ok(Circuit::new("", "", inputs, outputs, gates).unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Value, ADDER_64};

    #[test]
    fn test() {
        let mut builder = CircuitBuilder::default();
        let adder_64 = Circuit::load_bytes(ADDER_64).unwrap();

        let in_1 = builder.add_input("in_1", "", ValueType::U64, 64);
        let in_2 = builder.add_input("in_2", "", ValueType::U64, 64);
        let out = builder.add_output("out", "", ValueType::U64, 64);

        let circ_1 = builder.add_circ(adder_64.clone());
        let circ_2 = builder.add_circ(adder_64.clone());

        let a = circ_1.input(0).unwrap();
        let b = circ_1.input(1).unwrap();
        let c = circ_1.output(0).unwrap();

        let x = circ_2.input(0).unwrap();
        let y = circ_2.input(1).unwrap();
        let z = circ_2.output(0).unwrap();

        builder.connect(&in_1[..], &a[..]).unwrap();
        builder.connect(&in_2[..], &b[..]).unwrap();
        builder.connect(&c[..], &x[..]).unwrap();
        builder.connect(&in_1[..], &y[..]).unwrap();
        builder.connect(&z[..], &out[..]).unwrap();

        let circ = builder.build().unwrap();

        let a = circ.input(0).unwrap();
        let b = circ.input(1).unwrap();

        assert_eq!(
            *circ
                .evaluate(&[a.to_value(0u64).unwrap(), b.to_value(1u64).unwrap()])
                .unwrap()[0]
                .value(),
            Value::U64(1)
        );
    }
}
