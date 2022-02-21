use crate::block::Block;

#[derive(Debug, Clone)]
pub struct GarbledCircuit {
    pub input_labels: Vec<[Block; 2]>,
    pub wire_labels: Vec<[Block; 2]>,
    pub table: Vec<[Block; 2]>,
    pub output_bits: Vec<usize>,
    pub public_labels: [Block; 2],
    pub delta: Block,
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
