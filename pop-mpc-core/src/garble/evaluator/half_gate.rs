use super::GarbledCircuitEvaluator;
use crate::block::{Block, SELECT_MASK};
use crate::circuit::Circuit;
use crate::errors::EvaluatorError;
use crate::garble::circuit::{GarbledCircuit, InputLabel};
use crate::gate::Gate;
use cipher::{consts::U16, generic_array::GenericArray, BlockCipher, BlockEncrypt};

pub struct HalfGateEvaluator {}

impl HalfGateEvaluator {
    pub fn new() -> Self {
        Self {}
    }

    /// Evaluates AND gate
    #[inline]
    pub fn and_gate<C: BlockCipher<BlockSize = U16> + BlockEncrypt>(
        &self,
        c: &mut C,
        x: Block,
        y: Block,
        table: [Block; 2],
        gid: usize,
    ) -> Block {
        let s_a = x.lsb();
        let s_b = y.lsb();

        let j = gid;
        let k = gid + 1;

        let hx = x.hash_tweak(c, j);
        let hy = y.hash_tweak(c, k);

        let w_g = hx ^ (table[0] & SELECT_MASK[s_a]);
        let w_e = hy ^ (SELECT_MASK[s_b] & (table[1] ^ x));

        w_g ^ w_e
    }

    /// Evaluates XOR gate
    #[inline]
    pub fn xor_gate(&self, x: Block, y: Block) -> Block {
        x ^ y
    }

    /// Evaluates INV gate
    #[inline]
    pub fn inv_gate(&self, x: Block, public_label: Block) -> Block {
        x ^ public_label
    }
}

impl GarbledCircuitEvaluator for HalfGateEvaluator {
    fn eval<C: BlockCipher<BlockSize = U16> + BlockEncrypt>(
        &self,
        c: &mut C,
        circ: &Circuit,
        gc: &GarbledCircuit,
        input_labels: Vec<InputLabel>,
    ) -> Result<Vec<bool>, EvaluatorError> {
        let mut cache: Vec<Option<Block>> = vec![None; circ.nwires];

        // todo: assert that inputs are correctly sized and do not overlap
        for input_label in [gc.generator_wire_labels.clone(), input_labels].concat() {
            cache[input_label.id] = Some(input_label.label);
        }

        let mut gid = 1;
        for gate in circ.gates.iter() {
            match *gate {
                Gate::Inv { xref, zref, .. } => {
                    let x = cache[xref].ok_or_else(|| EvaluatorError::UninitializedLabel(xref))?;
                    let z = self.inv_gate(x, gc.public_labels[1]);
                    cache[zref] = Some(z);
                }
                Gate::Xor {
                    xref, yref, zref, ..
                } => {
                    let x = cache[xref].ok_or_else(|| EvaluatorError::UninitializedLabel(xref))?;
                    let y = cache[yref].ok_or_else(|| EvaluatorError::UninitializedLabel(yref))?;
                    let z = self.xor_gate(x, y);
                    cache[zref] = Some(z);
                }
                Gate::And {
                    xref, yref, zref, ..
                } => {
                    let x = cache[xref].ok_or_else(|| EvaluatorError::UninitializedLabel(xref))?;
                    let y = cache[yref].ok_or_else(|| EvaluatorError::UninitializedLabel(yref))?;
                    let z = self.and_gate(c, x, y, gc.table[gid - 1], gid);
                    cache[zref] = Some(z);
                    gid += 1;
                }
            };
        }

        let mut outputs: Vec<bool> = Vec::with_capacity(circ.noutput_wires);
        for (i, id) in ((circ.nwires - circ.noutput_wires)..circ.nwires).enumerate() {
            outputs.push((cache[id].unwrap().lsb() ^ gc.output_bits[i]) != 0);
        }

        Ok(outputs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
}
