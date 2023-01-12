use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    marker::PhantomData,
    sync::Arc,
};

pub use crate::error::BuilderError;
use crate::{
    circuit::GateType, group::UncheckedGroup, Circuit, Gate, Input, Output, ValueType, WireGroup,
};

/// A circuit feed
#[derive(Debug, Clone, Copy)]
pub struct Feed;
/// A circuit sink
#[derive(Debug, Clone, Copy)]
pub struct Sink;

/// A handle on a circuit wire
#[derive(Debug, Clone, Copy)]
pub struct WireHandle<T> {
    id: usize,
    _pd: PhantomData<T>,
}

impl WireHandle<Feed> {
    /// Creates new feed
    fn new_feed(id: usize) -> WireHandle<Feed> {
        WireHandle {
            id,
            _pd: PhantomData::<Feed>,
        }
    }
}

impl WireHandle<Sink> {
    /// Creates new sink
    fn new_sink(id: usize) -> WireHandle<Sink> {
        WireHandle {
            id,
            _pd: PhantomData::<Sink>,
        }
    }
}

/// A handle on a sub-circuit
#[derive(Debug, Clone)]
pub struct CircuitHandle {
    inputs: Vec<SubInputHandle>,
    outputs: Vec<SubOutputHandle>,
}

impl CircuitHandle {
    /// Returns a handle to the sub-circuit input
    pub fn input(&self, id: usize) -> Option<SubInputHandle> {
        self.inputs.get(id).cloned()
    }

    /// Returns a handle to the sub-circuit output
    pub fn output(&self, id: usize) -> Option<SubOutputHandle> {
        self.outputs.get(id).cloned()
    }
}

/// A handle on a circuit input
#[derive(Debug, Clone)]
pub struct InputHandle {
    input: UncheckedGroup,
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

/// A handle on a circuit output
#[derive(Debug, Clone)]
pub struct OutputHandle {
    output: UncheckedGroup,
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

/// A handle on a sub-circuits input
#[derive(Debug, Clone)]
pub struct SubInputHandle {
    wire_handles: Vec<WireHandle<Sink>>,
}

impl SubInputHandle {
    fn shift_right(&mut self, offset: usize) {
        self.wire_handles
            .iter_mut()
            .for_each(|handle| handle.id += offset);
    }
}

impl From<&Input> for SubInputHandle {
    fn from(input: &Input) -> Self {
        Self {
            wire_handles: input
                .wires()
                .iter()
                .copied()
                .map(|id| WireHandle {
                    id,
                    _pd: PhantomData,
                })
                .collect(),
        }
    }
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

/// A handle on a sub-circuits output
#[derive(Debug, Clone)]
pub struct SubOutputHandle {
    wire_handles: Vec<WireHandle<Feed>>,
}

impl SubOutputHandle {
    fn shift_right(&mut self, offset: usize) {
        self.wire_handles
            .iter_mut()
            .for_each(|handle| handle.id += offset);
    }
}

impl From<&Output> for SubOutputHandle {
    fn from(input: &Output) -> Self {
        Self {
            wire_handles: input
                .wires()
                .iter()
                .copied()
                .map(|id| WireHandle {
                    id,
                    _pd: PhantomData,
                })
                .collect(),
        }
    }
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

/// A handle to a circuit gate
#[derive(Debug, Clone, Copy)]
pub struct GateHandle {
    x: WireHandle<Sink>,
    y: Option<WireHandle<Sink>>,
    z: WireHandle<Feed>,
    gate_type: GateType,
}

impl GateHandle {
    /// Returns handle to x
    pub fn x(&self) -> WireHandle<Sink> {
        self.x
    }

    /// Returns handle to y
    pub fn y(&self) -> Option<WireHandle<Sink>> {
        self.y
    }

    /// Returns handle to z
    pub fn z(&self) -> WireHandle<Feed> {
        self.z
    }

    /// Returns gate type
    pub fn gate_type(&self) -> GateType {
        self.gate_type
    }

    fn shift_right(&mut self, offset: usize) {
        self.x.id += offset;
        if let Some(y) = self.y.as_mut() {
            y.id += offset;
        }
        self.z.id += offset;
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

impl From<&Gate> for GateHandle {
    fn from(gate: &Gate) -> Self {
        Self {
            x: WireHandle::new_sink(gate.xref()),
            y: gate
                .yref()
                .and_then(|yref| Some(WireHandle::new_sink(yref))),
            z: WireHandle::new_feed(gate.zref()),
            gate_type: gate.gate_type(),
        }
    }
}

/// State of [`CircuitBuilder`]
pub trait BuilderState {}

pub struct Inputs {
    id: String,
    description: String,
    version: String,
    input_wire_id: usize,
    inputs: Vec<InputHandle>,
}
impl BuilderState for Inputs {}

pub struct Gates {
    id: String,
    description: String,
    version: String,
    inputs: Vec<InputHandle>,
    gate_wire_id: usize,
    gates: Vec<GateHandle>,
    conns: HashMap<usize, usize>,
}
impl BuilderState for Gates {}
pub struct Outputs {
    id: String,
    description: String,
    version: String,
    inputs: Vec<InputHandle>,
    gates: Vec<GateHandle>,
    conns: HashMap<usize, usize>,
    output_wire_id: usize,
    outputs: Vec<OutputHandle>,
}
impl BuilderState for Outputs {}

/// Circuit Builder
///
/// This can be used to construct new circuits and synthesize existing circuits together.
///
/// It has three states:
/// 1. Define inputs
/// 2. Define gates
/// 3. Define outputs
#[derive(Debug)]
pub struct CircuitBuilder<S: BuilderState>(S);

impl CircuitBuilder<Inputs> {
    /// Creates new builder
    pub fn new(id: &str, description: &str, version: &str) -> Self {
        Self(Inputs {
            id: id.to_string(),
            description: description.to_string(),
            version: version.to_string(),
            input_wire_id: 0,
            inputs: vec![],
        })
    }

    /// Add inputs to circuit
    pub fn add_input(
        &mut self,
        id: &str,
        desc: &str,
        value_type: ValueType,
        wire_count: usize,
    ) -> InputHandle {
        let wires: Vec<usize> = (self.0.input_wire_id..self.0.input_wire_id + wire_count).collect();
        self.0.input_wire_id += wire_count;
        let wire_handles = wires.iter().copied().map(WireHandle::new_feed).collect();
        let input = InputHandle {
            input: UncheckedGroup::new(
                self.0.inputs.len(),
                id.to_string(),
                desc.to_string(),
                value_type,
                wires,
            ),
            wire_handles,
        };
        self.0.inputs.push(input.clone());
        input
    }

    /// Sets inputs and moves to next state where gates and subcircuits are added
    pub fn build_inputs(self) -> CircuitBuilder<Gates> {
        CircuitBuilder(Gates {
            id: self.0.id,
            description: self.0.description,
            version: self.0.version,
            inputs: self.0.inputs,
            gate_wire_id: self.0.input_wire_id,
            gates: Vec::new(),
            conns: HashMap::new(),
        })
    }
}

impl CircuitBuilder<Gates> {
    /// Add sub-circuit to circuit
    pub fn add_circ(&mut self, circ: &Circuit) -> CircuitHandle {
        let offset = self.0.gate_wire_id;
        self.0.gate_wire_id += circ.len();

        // Insert gate handles
        self.0.gates.extend(
            circ.gates
                .iter()
                .map(|gate| {
                    let mut handle: GateHandle = gate.into();
                    handle.shift_right(offset);
                    handle
                })
                .collect::<Vec<GateHandle>>(),
        );

        let inputs = circ
            .inputs
            .iter()
            .map(|input| {
                let mut handle: SubInputHandle = input.into();
                handle.shift_right(offset);
                handle
            })
            .collect::<Vec<SubInputHandle>>();

        let outputs = circ
            .outputs
            .iter()
            .map(|input| {
                let mut handle: SubOutputHandle = input.into();
                handle.shift_right(offset);
                handle
            })
            .collect::<Vec<SubOutputHandle>>();

        CircuitHandle { inputs, outputs }
    }

    /// Add gate to circuit
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
            x: WireHandle::new_sink(x),
            y: y.and_then(|y| Some(WireHandle::new_sink(y))),
            z: WireHandle::new_feed(z),
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

    // Fan out feed to multiple sinks
    pub fn connect_fan_out(&mut self, feed: WireHandle<Feed>, sinks: &[WireHandle<Sink>]) {
        for sink in sinks {
            self.0.conns.insert(sink.id, feed.id);
        }
    }

    // Sets gates and moves to next state where outputs can be added
    pub fn build_gates(self) -> CircuitBuilder<Outputs> {
        CircuitBuilder(Outputs {
            id: self.0.id,
            description: self.0.description,
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
        id: &str,
        desc: &str,
        value_type: ValueType,
        wire_count: usize,
    ) -> OutputHandle {
        let wires: Vec<usize> =
            (self.0.output_wire_id..self.0.output_wire_id + wire_count).collect();
        self.0.output_wire_id += wire_count;
        let wire_handles = wires.iter().copied().map(WireHandle::new_sink).collect();
        let output = OutputHandle {
            output: UncheckedGroup::new(
                self.0.outputs.len(),
                id.to_string(),
                desc.to_string(),
                value_type,
                wires,
            ),
            wire_handles,
        };
        self.0.outputs.push(output.clone());
        output
    }

    /// Connect wires together
    pub fn connect(&mut self, feeds: &[WireHandle<Feed>], sinks: &[WireHandle<Sink>]) {
        for (feed, sink) in feeds.iter().zip(sinks) {
            self.0.conns.insert(sink.id, feed.id);
        }
    }

    /// Fan out feed to multiple sinks
    pub fn connect_fan_out(&mut self, feed: WireHandle<Feed>, sinks: &[WireHandle<Sink>]) {
        for sink in sinks {
            self.0.conns.insert(sink.id, feed.id);
        }
    }

    /// Fully builds circuit
    pub fn build_circuit(mut self) -> Result<Arc<Circuit>, BuilderError> {
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
            .collect::<Vec<UncheckedGroup>>();

        // Build outputs
        let outputs =
            self.0
                .outputs
                .into_iter()
                .map(|mut handle| {
                    handle.output.wires =
                        handle
                            .output
                            .wires
                            .clone()
                            .into_iter()
                            .map(|id| {
                                let mut feed = self.0.conns.get(&id).ok_or(
                                    BuilderError::MissingConnection(
                                        format!(
                                            "Output {} was not fully mapped to gates",
                                            handle.output.index()
                                        )
                                        .to_string(),
                                    ),
                                )?;
                                if let Some(new_id) = id_map.get(feed) {
                                    feed = new_id;
                                }
                                Ok(*feed)
                            })
                            .collect::<Result<Vec<usize>, BuilderError>>()?;

                    Ok(handle.output)
                })
                .collect::<Result<Vec<UncheckedGroup>, BuilderError>>()?;

        let gates: Vec<Gate> = self
            .0
            .gates
            .into_iter()
            .enumerate()
            .map(|(id, handle)| handle.to_gate(id))
            .collect();

        Ok(Circuit::new(
            &self.0.id,
            &self.0.description,
            &self.0.version,
            inputs,
            outputs,
            gates,
        )?)
    }
}

/// Maps byte values to sinks using constant wires
///
/// Bytes must be in little-endian order
///
/// Panics if a sink is not provided for every bit in byte array
pub fn map_le_bytes(
    builder: &mut CircuitBuilder<Gates>,
    zero: WireHandle<Feed>,
    one: WireHandle<Feed>,
    sinks: &[WireHandle<Sink>],
    bytes: &[u8],
) {
    assert_eq!(sinks.len(), bytes.len() * 8);
    bytes.iter().enumerate().for_each(|(n, byte)| {
        (0..8).for_each(|i| {
            if (byte >> i & 1) == 1 {
                builder.connect(&[one], &[sinks[(n * 8) + i]])
            } else {
                builder.connect(&[zero], &[sinks[(n * 8) + i]])
            }
        })
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Value, ADDER_64};

    #[test]
    fn test_adder_64() {
        let mut builder = CircuitBuilder::new("test", "", "");
        let adder_64 = Circuit::load_bytes(ADDER_64).unwrap();

        let in_1 = builder.add_input("in_1", "", ValueType::U64, 64);
        let in_2 = builder.add_input("in_2", "", ValueType::U64, 64);

        let mut builder = builder.build_inputs();

        let circ_1 = builder.add_circ(&adder_64);
        let circ_2 = builder.add_circ(&adder_64);

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

        let mut builder = builder.build_gates();

        let out = builder.add_output("out", "", ValueType::U64, 64);

        builder.connect(&z[..], &out[..]);

        let circ = builder.build_circuit().unwrap();

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
        let mut builder = CircuitBuilder::new("test", "", "");

        let in_1 = builder.add_input("in_0", "", ValueType::U8, 8);
        let in_2 = builder.add_input("in_1", "", ValueType::U8, 8);

        let mut builder = builder.build_inputs();

        let gates: Vec<GateHandle> = (0..8).map(|_| builder.add_gate(GateType::Xor)).collect();

        gates.iter().cloned().enumerate().for_each(|(i, gate)| {
            builder.connect(&[in_1[i]], &[gate.x]);
            builder.connect(&[in_2[i]], &[gate.y.unwrap()]);
        });

        let mut builder = builder.build_gates();

        let out = builder.add_output("out_0", "", ValueType::U8, 8);

        gates.iter().enumerate().for_each(|(i, gate)| {
            builder.connect(&[gate.z], &[out[i]]);
        });

        let circ = builder.build_circuit().unwrap();

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

    #[test]
    fn test_map_bytes() {
        let mut builder = CircuitBuilder::new("test", "", "");

        let const_zero = builder.add_input("const0", "", ValueType::ConstZero, 1);
        let const_one = builder.add_input("const1", "", ValueType::ConstOne, 1);

        let mut builder = builder.build_inputs();

        let gates: Vec<_> = (0..24).map(|_| builder.add_gate(GateType::Inv)).collect();

        map_le_bytes(
            &mut builder,
            const_zero[0],
            const_one[0],
            &gates.iter().map(|gate| gate.x()).collect::<Vec<_>>(),
            &[0xAB, 0x00, 0xCD],
        );

        let mut builder = builder.build_gates();

        let out = builder.add_output("test", "", ValueType::Bytes, 24);

        gates
            .iter()
            .enumerate()
            .for_each(|(i, gate)| builder.connect(&[gate.z()], &[out[i]]));

        let circ = builder.build_circuit().unwrap();

        let result = circ.evaluate(&[]).unwrap();

        assert_eq!(*result[0].value(), Value::Bytes(vec![0x54, 0xFF, 0x32]));
    }
}
