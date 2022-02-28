use crate::block::Block;
use crate::circuit::CircuitInput;

/// Input label of a garbled circuit
#[derive(Debug, Clone, Copy)]
pub struct InputLabel {
    /// Input wire label id
    pub id: usize,
    // Input wire label
    pub label: Block,
}

/// Wire label pair of a garbled circuit
#[derive(Debug, Clone, Copy)]
pub struct LabelPair {
    /// Wire label corresponding to low bit
    pub low: Block,
    /// Wire label corresponding to high bit
    pub high: Block,
}

/// Complete garbled circuit data, including private data which should not be revealed
/// to the evaluator
#[derive(Debug, Clone)]
pub struct CompleteGarbledCircuit {
    pub input_labels: Vec<[Block; 2]>,
    pub wire_labels: Vec<[Block; 2]>,
    pub table: Vec<[Block; 2]>,
    pub output_bits: Vec<bool>,
    pub public_labels: [Block; 2],
    pub delta: Block,
}

/// Garbled circuit data safe to share with evaluator
#[derive(Debug, Clone)]
pub struct GarbledCircuit {
    /// Wire labels corresponding to the generators input bits
    pub generator_input_labels: Vec<InputLabel>,
    /// Truth table for garbled AND gates
    pub table: Vec<[Block; 2]>,
    /// Wire labels corresponding to public low and high bits
    pub public_labels: [Block; 2],
    /// LSBs of output labels
    pub output_bits: Vec<bool>,
}

impl CompleteGarbledCircuit {
    pub fn new(
        input_labels: Vec<[Block; 2]>,
        wire_labels: Vec<[Block; 2]>,
        table: Vec<[Block; 2]>,
        output_bits: Vec<bool>,
        public_labels: [Block; 2],
        delta: Block,
    ) -> Self {
        Self {
            input_labels,
            wire_labels,
            table,
            output_bits,
            public_labels,
            delta,
        }
    }

    /// Converts `CompleteGarbledCircuit` to `GarbledCircuit` which is safe to share with the evaluator
    pub fn to_public(&self, inputs: &Vec<CircuitInput>) -> GarbledCircuit {
        let mut generator_input_labels = Vec::with_capacity(inputs.len());
        for input in inputs.into_iter() {
            generator_input_labels.push(InputLabel {
                id: input.id,
                label: self.input_labels[input.id][input.value as usize],
            });
        }
        GarbledCircuit {
            generator_input_labels,
            table: self.table.clone(),
            output_bits: self.output_bits.clone(),
            public_labels: self.public_labels.clone(),
        }
    }
}
