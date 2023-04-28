use crate::{
    components::{Feed, Gate, Node},
    types::{BinaryLength, BinaryRepr, ToBinaryRepr, ValueType},
    Circuit, Tracer,
};
use std::{cell::RefCell, collections::HashMap, mem::discriminant};

/// An error that can occur when building a circuit.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum BuilderError {
    #[error("missing wire connection: sink {0}")]
    MissingWire(usize),
    #[error("error appending circuit: {0}")]
    AppendError(String),
}

/// A circuit builder.
///
/// This type is used in conjunction with [`Tracer`](crate::Tracer) to build a circuit.
///
/// # Example
///
/// The following example shows how to build a circuit that adds two u8 inputs.
///
/// ```
/// use mpc_circuits::{CircuitBuilder, Tracer, ops::WrappingAdd};
/// use std::cell::RefCell;
///
/// let builder = CircuitBuilder::new();
///
/// // Add two u8 inputs to the circuit
/// let a = builder.add_input::<u8>();
/// let b = builder.add_input::<u8>();
///
/// // Add the two inputs together
/// let c = a.wrapping_add(b);
///
/// // Add the output to the circuit
/// builder.add_output(c);
///
/// // Build the circuit
/// let circuit = builder.build().unwrap();
/// ```
#[derive(Default)]
pub struct CircuitBuilder {
    state: RefCell<BuilderState>,
}

impl CircuitBuilder {
    /// Creates a new circuit builder
    pub fn new() -> Self {
        Self {
            state: RefCell::new(BuilderState::default()),
        }
    }

    /// Returns a reference to the internal state of the builder
    pub fn state(&self) -> &RefCell<BuilderState> {
        &self.state
    }

    /// Adds a new input to the circuit of the provided type
    ///
    /// # Returns
    ///
    /// The binary encoded form of the input.
    pub fn add_input<T: ToBinaryRepr + BinaryLength>(&self) -> Tracer<'_, T::Repr> {
        let mut state = self.state.borrow_mut();

        let value = state.add_value::<T>();
        state.inputs.push(value.clone().into());

        Tracer::new(&self.state, value)
    }

    /// Adds a new input to the circuit of the provided type
    ///
    /// # Arguments
    ///
    /// * `typ` - The type of the input.
    ///
    /// # Returns
    ///
    /// The binary encoded form of the input.
    pub fn add_input_by_type(&self, typ: ValueType) -> BinaryRepr {
        let mut state = self.state.borrow_mut();

        let value = state.add_value_by_type(typ);
        state.inputs.push(value.clone());

        value
    }

    /// Adds a new array input to the circuit of the provided type
    ///
    /// # Returns
    ///
    /// The binary encoded form of the array.
    pub fn add_array_input<T: ToBinaryRepr + BinaryLength, const N: usize>(
        &self,
    ) -> [Tracer<'_, T::Repr>; N]
    where
        [T::Repr; N]: Into<BinaryRepr>,
    {
        let mut state = self.state.borrow_mut();

        let values: [T::Repr; N] = std::array::from_fn(|_| state.add_value::<T>());
        state.inputs.push(values.clone().into());

        values.map(|v| Tracer::new(&self.state, v))
    }

    /// Adds a new `Vec<T>` input to the circuit of the provided type
    ///
    /// # Arguments
    ///
    /// * `len` - The length of the vector.
    ///
    /// # Returns
    ///
    /// The binary encoded form of the vector.
    pub fn add_vec_input<T: ToBinaryRepr + BinaryLength>(
        &self,
        len: usize,
    ) -> Vec<Tracer<'_, T::Repr>>
    where
        Vec<T::Repr>: Into<BinaryRepr>,
    {
        let mut state = self.state.borrow_mut();

        let values: Vec<T::Repr> = (0..len).map(|_| state.add_value::<T>()).collect();
        state.inputs.push(values.clone().into());

        values
            .into_iter()
            .map(|v| Tracer::new(&self.state, v))
            .collect()
    }

    /// Adds a new output to the circuit
    pub fn add_output(&self, value: impl Into<BinaryRepr>) {
        let mut state = self.state.borrow_mut();

        state.outputs.push(value.into());
    }

    /// Returns a tracer for a constant value
    pub fn get_constant<T: ToBinaryRepr>(&self, value: T) -> Tracer<'_, T::Repr> {
        let mut state = self.state.borrow_mut();

        let value = state.get_constant(value);
        Tracer::new(&self.state, value)
    }

    /// Appends an existing circuit
    ///
    /// # Arguments
    ///
    /// * `circ` - The circuit to append
    /// * `builder_inputs` - The inputs to the appended circuit
    ///
    /// # Returns
    ///
    /// The outputs of the appended circuit
    pub fn append(
        &self,
        circ: &Circuit,
        builder_inputs: &[BinaryRepr],
    ) -> Result<Vec<BinaryRepr>, BuilderError> {
        self.state.borrow_mut().append(circ, builder_inputs)
    }

    /// Builds the circuit
    pub fn build(self) -> Result<Circuit, BuilderError> {
        self.state.into_inner().build()
    }
}

/// The internal state of the [`CircuitBuilder`]
#[derive(Debug)]
pub struct BuilderState {
    feed_id: usize,
    inputs: Vec<BinaryRepr>,
    outputs: Vec<BinaryRepr>,
    gates: Vec<Gate>,

    and_count: usize,
    xor_count: usize,
}

impl Default for BuilderState {
    fn default() -> Self {
        Self {
            // ids 0 and 1 are reserved for constant zero and one
            feed_id: 2,
            inputs: vec![],
            outputs: vec![],
            gates: vec![],
            and_count: 0,
            xor_count: 0,
        }
    }
}

impl BuilderState {
    /// Returns constant zero node.
    pub(crate) fn get_const_zero(&self) -> Node<Feed> {
        Node::<Feed>::new(0)
    }

    /// Returns constant one node.
    pub(crate) fn get_const_one(&self) -> Node<Feed> {
        Node::<Feed>::new(1)
    }

    /// Returns a value encoded using constant nodes.
    ///
    /// # Arguments
    ///
    /// * `value` - The value to encode.
    pub(crate) fn get_constant<T: ToBinaryRepr>(&mut self, value: T) -> T::Repr {
        let zero = self.get_const_zero();
        let one = self.get_const_one();

        let nodes: Vec<_> = value
            .into_lsb0_iter()
            .map(|bit| if bit { one } else { zero })
            .collect();

        T::new_bin_repr(&nodes).expect("Value should have correct bit length")
    }

    /// Adds a feed to the circuit.
    pub(crate) fn add_feed(&mut self) -> Node<Feed> {
        let feed = Node::<Feed>::new(self.feed_id);
        self.feed_id += 1;

        feed
    }

    /// Adds a value to the circuit.
    pub(crate) fn add_value<T: ToBinaryRepr + BinaryLength>(&mut self) -> T::Repr {
        let nodes: Vec<_> = (0..T::LEN).map(|_| self.add_feed()).collect();
        T::new_bin_repr(&nodes).expect("Value should have correct bit length")
    }

    /// Adds a value to the circuit by type.
    ///
    /// # Arguments
    ///
    /// * `typ` - The type of the value to add.
    pub(crate) fn add_value_by_type(&mut self, typ: ValueType) -> BinaryRepr {
        let nodes: Vec<_> = (0..typ.len()).map(|_| self.add_feed()).collect();
        typ.to_bin_repr(&nodes)
            .expect("Value should have correct bit length")
    }

    /// Adds an XOR gate to the circuit.
    ///
    /// # Arguments
    ///
    /// * `x` - The first input to the gate.
    /// * `y` - The second input to the gate.
    ///
    /// # Returns
    ///
    /// The output of the gate.
    pub(crate) fn add_xor_gate(&mut self, x: Node<Feed>, y: Node<Feed>) -> Node<Feed> {
        // if either input is a constant, we can simplify the gate
        if x.id() == 0 && y.id() == 0 {
            self.get_const_zero()
        } else if x.id() == 1 && y.id() == 1 {
            return self.get_const_zero();
        } else if x.id() == 0 {
            return y;
        } else if y.id() == 0 {
            return x;
        } else if x.id() == 1 {
            let out = self.add_feed();
            self.gates.push(Gate::Inv {
                x: y.into(),
                z: out,
            });
            return out;
        } else if y.id() == 1 {
            let out = self.add_feed();
            self.gates.push(Gate::Inv {
                x: x.into(),
                z: out,
            });
            return out;
        } else {
            let out = self.add_feed();
            self.gates.push(Gate::Xor {
                x: x.into(),
                y: y.into(),
                z: out,
            });
            self.xor_count += 1;
            return out;
        }
    }

    /// Adds an AND gate to the circuit.
    ///
    /// # Arguments
    ///
    /// * `x` - The first input to the gate.
    /// * `y` - The second input to the gate.
    ///
    /// # Returns
    ///
    /// The output of the gate.
    pub(crate) fn add_and_gate(&mut self, x: Node<Feed>, y: Node<Feed>) -> Node<Feed> {
        // if either input is a constant, we can simplify the gate
        if x.id() == 0 || y.id() == 0 {
            self.get_const_zero()
        } else if x.id() == 1 {
            return y;
        } else if y.id() == 1 {
            return x;
        } else {
            let out = self.add_feed();
            self.gates.push(Gate::And {
                x: x.into(),
                y: y.into(),
                z: out,
            });
            self.and_count += 1;
            return out;
        }
    }

    /// Adds an INV gate to the circuit.
    ///
    /// # Arguments
    ///
    /// * `x` - The input to the gate.
    ///
    /// # Returns
    ///
    /// The output of the gate.
    pub(crate) fn add_inv_gate(&mut self, x: Node<Feed>) -> Node<Feed> {
        if x.id() == 0 {
            self.get_const_one()
        } else if x.id() == 1 {
            return self.get_const_zero();
        } else {
            let out = self.add_feed();
            self.gates.push(Gate::Inv {
                x: x.into(),
                z: out,
            });
            return out;
        }
    }

    /// Appends an existing circuit
    ///
    /// # Arguments
    ///
    /// * `circ` - The circuit to append
    /// * `builder_inputs` - The inputs to the appended circuit
    ///
    /// # Returns
    ///
    /// The outputs of the appended circuit
    pub fn append(
        &mut self,
        circ: &Circuit,
        builder_inputs: &[BinaryRepr],
    ) -> Result<Vec<BinaryRepr>, BuilderError> {
        if builder_inputs.len() != circ.inputs().len() {
            return Err(BuilderError::AppendError(
                "Number of inputs does not match number of inputs in circuit".to_string(),
            ));
        }

        // Maps old feed id -> new feed id
        let mut feed_map: HashMap<Node<Feed>, Node<Feed>> = HashMap::default();
        for (i, (builder_input, append_input)) in
            builder_inputs.iter().zip(circ.inputs()).enumerate()
        {
            if discriminant(builder_input) != discriminant(append_input) {
                return Err(BuilderError::AppendError(format!(
                    "Input {i} type does not match input type in circuit, expected {}, got {}",
                    append_input, builder_input,
                )));
            }
            for (builder_node, append_node) in builder_input.iter().zip(append_input.iter()) {
                feed_map.insert(*append_node, *builder_node);
            }
        }

        // Add new gates, mapping the node ids from the old circuit to the new circuit
        for gate in circ.gates() {
            match gate {
                Gate::Xor { x, y, z } => {
                    let new_x = feed_map.get(&(*x).into()).expect("feed should exist");
                    let new_y = feed_map.get(&(*y).into()).expect("feed should exist");
                    let new_z = self.add_xor_gate(*new_x, *new_y);
                    feed_map.insert(*z, new_z);
                }
                Gate::And { x, y, z } => {
                    let new_x = feed_map.get(&(*x).into()).expect("feed should exist");
                    let new_y = feed_map.get(&(*y).into()).expect("feed should exist");
                    let new_z = self.add_and_gate(*new_x, *new_y);
                    feed_map.insert(*z, new_z);
                }
                Gate::Inv { x, z } => {
                    let new_x = feed_map.get(&(*x).into()).expect("feed should exist");
                    let new_z = self.add_inv_gate(*new_x);
                    feed_map.insert(*z, new_z);
                }
            }
        }

        // Update the outputs
        let mut outputs = circ.outputs().to_vec();
        outputs.iter_mut().for_each(|output| {
            for node in output.iter_mut() {
                *node = *feed_map.get(node).expect("feed should exist");
            }
        });

        Ok(outputs)
    }

    /// Builds the circuit.
    pub(crate) fn build(mut self) -> Result<Circuit, BuilderError> {
        // Shift all the node ids to the left by 2 to eliminate
        // the reserved constant nodes (which should be factored out during building)
        self.inputs.iter_mut().for_each(|input| input.shift_left(2));
        self.gates.iter_mut().for_each(|gate| gate.shift_left(2));
        self.outputs
            .iter_mut()
            .for_each(|output| output.shift_left(2));

        Ok(Circuit {
            inputs: self.inputs,
            outputs: self.outputs,
            gates: self.gates,
            feed_count: self.feed_id,
            and_count: self.and_count,
            xor_count: self.xor_count,
        })
    }
}

#[cfg(test)]
mod test {
    use mpc_circuits_macros::evaluate;

    use crate::ops::WrappingAdd;

    use super::*;

    fn build_adder() -> Circuit {
        let builder = CircuitBuilder::new();

        let a = builder.add_input::<u8>();
        let b = builder.add_input::<u8>();

        let c = a.wrapping_add(b);

        builder.add_output(c);

        builder.build().unwrap()
    }

    #[test]
    fn test_build_adder() {
        let circ = build_adder();

        let a = 1u8;
        let b = 255u8;
        let c = a.wrapping_add(b);

        let output = evaluate!(circ, fn(a, b) -> u8).unwrap();

        assert_eq!(output, c);
    }

    #[test]
    fn test_append() {
        let circ = build_adder();

        let builder = CircuitBuilder::new();

        let a = builder.add_input::<u8>();
        let b = builder.add_input::<u8>();

        let c = a.wrapping_add(b);

        let mut appended_outputs = builder.append(&circ, &[a.into(), c.into()]).unwrap();

        let d = appended_outputs.pop().unwrap();

        builder.add_output(d);

        let circ = builder.build().unwrap();

        let mut output = circ.evaluate(&[1u8.into(), 1u8.into()]).unwrap();

        let d: u8 = output.pop().unwrap().try_into().unwrap();

        // a + (a + b) = 2a + b
        assert_eq!(d, 3u8);
    }
}
