use super::GarbledCircuitEvaluator;
use crate::block::{Block, SELECT_MASK};
use crate::circuit::Circuit;
use crate::errors::EvaluatorError;
use crate::garble::circuit::GarbledCircuit;
use crate::garble::hash::WireLabelHasher;
use crate::gate::Gate;
use crate::rng::Rng;

pub struct HalfGateEvaluator;

impl HalfGateEvaluator {
    #[inline]
    pub fn and_gate<H: WireLabelHasher>(
        &self,
        h: &H,
        x: Block,
        y: Block,
        table: [Block; 2],
        gid: usize,
    ) -> Block {
        let s_a = x.lsb();
        let s_b = y.lsb();

        let j = gid;
        let k = gid + 1;

        let hx = h.hash(x, j);
        let hy = h.hash(y, k);

        let w_g = hx ^ (table[0] & SELECT_MASK[s_a]);
        let w_e = hy ^ (SELECT_MASK[s_b] & (table[1] ^ x));

        w_g ^ w_e
    }

    #[inline]
    pub fn xor_gate(&self, x: Block, y: Block) -> Block {
        x ^ y
    }

    #[inline]
    pub fn inv_gate(&self, x: Block, public_label: Block) -> Block {
        x ^ public_label
    }
}

impl GarbledCircuitEvaluator for HalfGateEvaluator {
    fn eval<H: WireLabelHasher>(
        &self,
        h: &H,
        circ: &Circuit,
        gc: &GarbledCircuit,
        input_labels: Vec<Block>,
    ) -> Result<Vec<Block>, EvaluatorError> {
        if input_labels.len() != circ.ninput_wires {
            return Err(EvaluatorError::InvalidInputCount(
                input_labels.len(),
                circ.ninput_wires,
            ));
        }

        let mut cache: Vec<Option<Block>> = vec![None; circ.nwires];

        for i in 0..circ.ninput_wires {
            cache[i] = Some(input_labels[i]);
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
                    let z = self.and_gate(h, x, y, gc.table[gid - 1], gid);
                    cache[zref] = Some(z);
                    gid += 1;
                }
            };
        }

        let mut output_labels: Vec<Block> = Vec::with_capacity(circ.noutput_wires);
        for i in (circ.nwires - circ.noutput_wires)..circ.nwires {
            output_labels.push(cache[i].unwrap());
        }

        Ok(output_labels)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
}
