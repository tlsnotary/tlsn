use crate::block::Block;

/// Input label of a garbled circuit
#[derive(Debug, Clone, Copy)]
pub struct InputLabel {
    /// Input wire label id
    id: usize,
    // Input wire label
    label: Block,
}

/// Wire label pair of a garbled circuit
#[derive(Debug, Clone, Copy)]
pub struct LabelPair {
    /// Wire label corresponding to low bit
    low: Block,
    /// Wire label corresponding to high bit
    high: Block,
}

/// Complete garbled circuit data, including private data which should not be revealed
/// to the evaluator
#[derive(Debug, Clone)]
pub struct GarbledCircuit {
    pub input_labels: Vec<[Block; 2]>,
    pub wire_labels: Vec<[Block; 2]>,
    pub table: Vec<[Block; 2]>,
    pub output_bits: Vec<usize>,
    pub public_labels: [Block; 2],
    pub delta: Block,
}

/// Garbled circuit data safe to share with evaluator
#[derive(Debug, Clone)]
pub struct PublicGarbledCircuit {
    /// Wire labels corresponding to the generators input bits
    pub generator_wire_labels: Vec<InputLabel>,
    /// Truth table for garbled AND gates
    pub table: Vec<[Block; 2]>,
    /// LSBs of output labels
    pub output_bits: Vec<usize>,
    /// Wire labels corresponding to public low and high bits
    pub public_labels: [Block; 2],
}

impl GarbledCircuit {
    pub fn new(
        input_labels: Vec<[Block; 2]>,
        wire_labels: Vec<[Block; 2]>,
        table: Vec<[Block; 2]>,
        output_bits: Vec<usize>,
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
}
