use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    marker::PhantomData,
    sync::Arc,
};

use crate::{circuit::GateType, Circuit, Gate, Group, Input, Output, ValueType};

#[derive(Debug, thiserror::Error)]
pub enum BuilderError {
    #[error("Circuit input or output was not fully mapped to gates")]
    MissingConnection(String),
    #[error("Circuit error")]
    CircuitError(#[from] crate::Error),
}

#[derive(Debug, Clone, Copy)]
pub struct Feed;
#[derive(Debug, Clone, Copy)]
pub struct Sink;
#[derive(Debug, Clone, Copy)]
pub struct WireHandle<T> {
    id: usize,
    _pd: PhantomData<T>,
}

impl WireHandle<Feed> {
    /// Creates new feed
    fn feed(id: usize) -> WireHandle<Feed> {
        WireHandle {
            id,
            _pd: PhantomData::<Feed>,
        }
    }
}

impl WireHandle<Sink> {
    /// Creates new sink
    fn sink(id: usize) -> WireHandle<Sink> {
        WireHandle {
            id,
            _pd: PhantomData::<Sink>,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CircuitHandle {
    circ: Arc<Circuit>,
}

impl CircuitHandle {
    pub fn input(&self, id: usize) -> Option<SubInputHandle> {
        if let Some(input) = self.circ.input(id) {
            Some(SubInputHandle {
                wire_handles: input
                    .as_ref()
                    .wires()
                    .iter()
                    .copied()
                    .map(WireHandle::sink)
                    .collect(),
            })
        } else {
            None
        }
    }

    pub fn output(&self, id: usize) -> Option<SubOutputHandle> {
        if let Some(output) = self.circ.output(id) {
            Some(SubOutputHandle {
                wire_handles: output
                    .as_ref()
                    .wires()
                    .iter()
                    .copied()
                    .map(WireHandle::feed)
                    .collect(),
            })
        } else {
            None
        }
    }
}

#[derive(Debug, Clone)]
pub struct InputHandle {
    input: Input,
    wire_handles: Vec<WireHandle<Feed>>,
}

impl<Idx> std::ops::Index<Idx> for InputHandle
where
    Idx: std::slice::SliceIndex<[WireHandle<Feed>]>,
{
    type Output = Idx::Output;

    fn index(&self, index: Idx) -> &Self::Output {
        &self.wire_handles[index]
    }
}

#[derive(Debug, Clone)]
pub struct OutputHandle {
    output: Output,
    wire_handles: Vec<WireHandle<Sink>>,
}

impl<Idx> std::ops::Index<Idx> for OutputHandle
where
    Idx: std::slice::SliceIndex<[WireHandle<Sink>]>,
{
    type Output = Idx::Output;

    fn index(&self, index: Idx) -> &Self::Output {
        &self.wire_handles[index]
    }
}

#[derive(Debug, Clone)]
pub struct SubInputHandle {
    wire_handles: Vec<WireHandle<Sink>>,
}

impl<Idx> std::ops::Index<Idx> for SubInputHandle
where
    Idx: std::slice::SliceIndex<[WireHandle<Sink>]>,
{
    type Output = Idx::Output;

    fn index(&self, index: Idx) -> &Self::Output {
        &self.wire_handles[index]
    }
}

#[derive(Debug, Clone)]
pub struct SubOutputHandle {
    wire_handles: Vec<WireHandle<Feed>>,
}

impl<Idx> std::ops::Index<Idx> for SubOutputHandle
where
    Idx: std::slice::SliceIndex<[WireHandle<Feed>]>,
{
    type Output = Idx::Output;

    fn index(&self, index: Idx) -> &Self::Output {
        &self.wire_handles[index]
    }
}

#[derive(Debug, Clone, Copy)]
pub struct GateHandle {
    x: WireHandle<Sink>,
    y: Option<WireHandle<Sink>>,
    z: WireHandle<Feed>,
    gate_type: GateType,
}

impl GateHandle {
    fn from_gate(gate: &Gate) -> Self {
        Self {
            x: WireHandle::sink(gate.xref()),
            y: gate.yref().and_then(|yref| Some(WireHandle::sink(yref))),
            z: WireHandle::feed(gate.zref()),
            gate_type: gate.gate_type(),
        }
    }

    fn to_gate(self, id: usize) -> Gate {
        match self.gate_type {
            GateType::Xor => Gate::Xor {
                id,
                xref: self.x.id,
                yref: self.y.unwrap().id,
                zref: self.z.id,
            },
            GateType::And => Gate::And {
                id,
                xref: self.x.id,
                yref: self.y.unwrap().id,
                zref: self.z.id,
            },
            GateType::Inv => Gate::Inv {
                id,
                xref: self.x.id,
                zref: self.z.id,
            },
        }
    }
}

pub trait BuilderState {}
pub struct Inputs {
    name: String,
    version: String,
    input_wire_id: usize,
    inputs: Vec<InputHandle>,
}
impl BuilderState for Inputs {}
pub struct Gates {
    name: String,
    version: String,
    inputs: Vec<InputHandle>,
    gate_wire_id: usize,
    gates: Vec<GateHandle>,
    conns: HashMap<usize, usize>,
}
impl BuilderState for Gates {}
pub struct Outputs {
    name: String,
    version: String,
    inputs: Vec<InputHandle>,
    gates: Vec<GateHandle>,
    conns: HashMap<usize, usize>,
    output_wire_id: usize,
    outputs: Vec<OutputHandle>,
}
impl BuilderState for Outputs {}

#[derive(Debug)]
pub struct CircuitBuilder<S: BuilderState>(S);

impl CircuitBuilder<Inputs> {
    pub fn new(name: &str, version: &str) -> Self {
        Self(Inputs {
            name: name.to_string(),
            version: version.to_string(),
            input_wire_id: 0,
            inputs: vec![],
        })
    }

    /// Add inputs to circuit
    pub fn add_input(
        &mut self,
        name: &str,
        desc: &str,
        value_type: ValueType,
        wire_count: usize,
    ) -> InputHandle {
        let wires: Vec<usize> = (self.0.input_wire_id..self.0.input_wire_id + wire_count).collect();
        self.0.input_wire_id += wire_count;
        let input = InputHandle {
            input: Input::new(
                self.0.inputs.len(),
                Group::new(name, desc, value_type, &wires),
            ),
            wire_handles: wires.iter().copied().map(WireHandle::feed).collect(),
        };
        self.0.inputs.push(input.clone());
        input
    }

    /// Sets inputs and moves to next state where gates and subcircuits are added
    pub fn build(self) -> CircuitBuilder<Gates> {
        CircuitBuilder(Gates {
            name: self.0.name,
            version: self.0.version,
            inputs: self.0.inputs,
            gate_wire_id: self.0.input_wire_id,
            gates: Vec::new(),
            conns: HashMap::new(),
        })
    }
}

impl CircuitBuilder<Gates> {
    pub fn add_circ(&mut self, mut circ: Circuit) -> CircuitHandle {
        let offset = self.0.gate_wire_id;
        self.0.gate_wire_id += circ.len();

        // Shift gates right
        for gate in circ.gates.iter_mut() {
            gate.set_xref(gate.xref() + offset);
            if let Some(yref) = gate.yref() {
                gate.set_yref(yref + offset);
            }
            gate.set_zref(gate.zref() + offset);
        }

        // Shift input wires right
        for input in circ.inputs.iter_mut() {
            input.group.wires.iter_mut().for_each(|wire_id| {
                *wire_id += offset;
            })
        }
        // Shift output wires right
        for output in circ.outputs.iter_mut() {
            output
                .group
                .wires
                .iter_mut()
                .for_each(|wire_id| *wire_id += offset)
        }

        // Insert gate handles
        self.0.gates.extend(
            circ.gates
                .iter()
                .map(|gate| GateHandle::from_gate(gate))
                .collect::<Vec<GateHandle>>(),
        );

        let circ = Arc::new(circ);
        let handle = CircuitHandle { circ: circ.clone() };
        handle
    }

    pub fn add_gate(&mut self, gate_type: GateType) -> GateHandle {
        let (x, y, z) = match gate_type {
            GateType::Xor => {
                let x = self.0.gate_wire_id;
                let y = x + 1;
                let z = y + 1;
                self.0.gate_wire_id += 3;
                (x, Some(y), z)
            }
            GateType::And => {
                let x = self.0.gate_wire_id;
                let y = x + 1;
                let z = y + 1;
                self.0.gate_wire_id += 3;
                (x, Some(y), z)
            }
            GateType::Inv => {
                let x = self.0.gate_wire_id;
                let z = x + 1;
                self.0.gate_wire_id += 2;
                (x, None, z)
            }
        };
        let handle = GateHandle {
            x: WireHandle::sink(x),
            y: y.and_then(|y| Some(WireHandle::sink(y))),
            z: WireHandle::feed(z),
            gate_type,
        };
        self.0.gates.push(handle.clone());
        handle
    }

    // Connect wires together
    pub fn connect(&mut self, feeds: &[WireHandle<Feed>], sinks: &[WireHandle<Sink>]) {
        for (feed, sink) in feeds.iter().zip(sinks) {
            self.0.conns.insert(sink.id, feed.id);
        }
    }

    // Sets gates and moves to next state where outputs can be added
    pub fn build(self) -> CircuitBuilder<Outputs> {
        CircuitBuilder(Outputs {
            name: self.0.name,
            version: self.0.version,
            inputs: self.0.inputs,
            gates: self.0.gates,
            conns: self.0.conns,
            output_wire_id: self.0.gate_wire_id,
            outputs: Vec::new(),
        })
    }
}

impl CircuitBuilder<Outputs> {
    /// Add outputs to circuit
    pub fn add_output(
        &mut self,
        name: &str,
        desc: &str,
        value_type: ValueType,
        wire_count: usize,
    ) -> OutputHandle {
        let wires: Vec<usize> =
            (self.0.output_wire_id..self.0.output_wire_id + wire_count).collect();
        self.0.output_wire_id += wire_count;
        let output = OutputHandle {
            output: Output::new(
                self.0.outputs.len(),
                Group::new(name, desc, value_type, &wires),
            ),
            wire_handles: wires.iter().copied().map(WireHandle::sink).collect(),
        };
        self.0.outputs.push(output.clone());
        output
    }

    // Connect wires together
    pub fn connect(&mut self, feeds: &[WireHandle<Feed>], sinks: &[WireHandle<Sink>]) {
        for (feed, sink) in feeds.iter().zip(sinks) {
            self.0.conns.insert(sink.id, feed.id);
        }
    }

    // Fully builds circuit
    pub fn build(mut self) -> Result<Circuit, BuilderError> {
        // Connect all gate wires and create id set
        let mut id_set: BTreeSet<usize> = BTreeSet::new();
        self.0.gates.iter_mut().for_each(|gate| {
            if let Some(new_id) = self.0.conns.get(&gate.x.id) {
                gate.x.id = *new_id;
            }
            if let Some(y) = &mut gate.y {
                if let Some(new_id) = self.0.conns.get(&y.id) {
                    y.id = *new_id;
                }
                id_set.insert(y.id);
            }
            id_set.insert(gate.x.id);
            id_set.insert(gate.z.id);
        });

        // Create an id map which will left pack wire ids to remove gaps
        let id_map: BTreeMap<usize, usize> = id_set
            .into_iter()
            .enumerate()
            .map(|(ix, id)| (id, ix))
            .collect();

        // Left pack wire ids
        self.0.gates.iter_mut().for_each(|gate| {
            if let Some(new_id) = id_map.get(&gate.x.id) {
                gate.x.id = *new_id;
            }
            if let Some(y) = &mut gate.y {
                if let Some(new_id) = id_map.get(&y.id) {
                    y.id = *new_id;
                }
            }
            if let Some(new_id) = id_map.get(&gate.z.id) {
                gate.z.id = *new_id;
            }
        });

        // Build inputs
        let inputs = self
            .0
            .inputs
            .into_iter()
            .map(|handle| handle.input)
            .collect::<Vec<Input>>();

        // Build outputs
        let outputs = self
            .0
            .outputs
            .into_iter()
            .map(|handle| {
                let mut output = handle.output;
                output.group.wires = output
                    .group
                    .wires
                    .iter()
                    .map(|id| {
                        let mut feed =
                            self.0.conns.get(id).ok_or(BuilderError::MissingConnection(
                                format!("Output {} was not fully mapped to gates", output.id),
                            ))?;
                        if let Some(new_id) = id_map.get(feed) {
                            feed = new_id;
                        }
                        Ok(*feed)
                    })
                    .collect::<Result<Vec<usize>, BuilderError>>()?;
                Ok(output)
            })
            .collect::<Result<Vec<Output>, BuilderError>>()?;

        let gates: Vec<Gate> = self
            .0
            .gates
            .into_iter()
            .enumerate()
            .map(|(id, handle)| handle.to_gate(id))
            .collect();

        Ok(Circuit::new(
            &self.0.name,
            &self.0.version,
            inputs,
            outputs,
            gates,
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Value, ADDER_64};

    #[test]
    fn test_adder_64() {
        let mut builder = CircuitBuilder::new("", "");
        let adder_64 = Circuit::load_bytes(ADDER_64).unwrap();

        let in_1 = builder.add_input("in_1", "", ValueType::U64, 64);
        let in_2 = builder.add_input("in_2", "", ValueType::U64, 64);

        let mut builder = builder.build();

        let circ_1 = builder.add_circ(adder_64.clone());
        let circ_2 = builder.add_circ(adder_64.clone());

        let a = circ_1.input(0).unwrap();
        let b = circ_1.input(1).unwrap();
        let c = circ_1.output(0).unwrap();

        let x = circ_2.input(0).unwrap();
        let y = circ_2.input(1).unwrap();
        let z = circ_2.output(0).unwrap();

        builder.connect(&in_1[..], &a[..]);
        builder.connect(&in_2[..], &b[..]);
        builder.connect(&c[..], &x[..]);
        builder.connect(&in_1[..], &y[..]);

        let mut builder = builder.build();

        let out = builder.add_output("out", "", ValueType::U64, 64);

        builder.connect(&z[..], &out[..]);

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

    #[test]
    fn test_u8_xor() {
        let mut builder = CircuitBuilder::new("", "");

        let in_1 = builder.add_input("0", "", ValueType::U8, 8);
        let in_2 = builder.add_input("1", "", ValueType::U8, 8);

        let mut builder = builder.build();

        let gates: Vec<GateHandle> = (0..8).map(|_| builder.add_gate(GateType::Xor)).collect();

        gates.iter().cloned().enumerate().for_each(|(i, gate)| {
            builder.connect(&[in_1[i]], &[gate.x]);
            builder.connect(&[in_2[i]], &[gate.y.unwrap()]);
        });

        let mut builder = builder.build();

        let out = builder.add_output("0", "", ValueType::U8, 8);

        gates.iter().enumerate().for_each(|(i, gate)| {
            builder.connect(&[gate.z], &[out[i]]);
        });

        let circ = builder.build().unwrap();

        let a = circ.input(0).unwrap();
        let b = circ.input(1).unwrap();

        assert_eq!(
            *circ
                .evaluate(&[a.to_value(2u8).unwrap(), b.to_value(2u8).unwrap()])
                .unwrap()[0]
                .value(),
            Value::U8(0)
        );
    }
}
