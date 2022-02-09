use super::GarbledCircuitGenerator;
use crate::block::{Block, SELECT_MASK};
use crate::circuit::Circuit;
use crate::errors::GeneratorError;
use crate::garble::circuit::GarbledCircuit;
use crate::garble::hash::WireLabelHasher;
use crate::gate::Gate;
use crate::rng::{RandomBlock, Rng};

pub struct HalfGateGenerator;

impl HalfGateGenerator {
    #[inline]
    pub fn and_gate<H: WireLabelHasher>(
        &self,
        h: &H,
        x: [Block; 2],
        y: [Block; 2],
        delta: Block,
        gid: usize,
    ) -> ([Block; 2], [Block; 2]) {
        let p_a = x[0].lsb();
        let p_b = y[0].lsb();
        let j = gid;
        let k = gid + 1;

        let hx_0 = h.hash(x[0], j);
        let hy_0 = h.hash(y[0], k);

        let t_g = hx_0 ^ h.hash(x[1], j) ^ (SELECT_MASK[p_b] & delta);
        let w_g = hx_0 ^ (SELECT_MASK[p_a] & t_g);

        let t_e = hy_0 ^ h.hash(y[1], k) ^ x[0];
        let w_e = hy_0 ^ (SELECT_MASK[p_b] & (t_e ^ x[0]));

        let z_0 = w_g ^ w_e;
        let z = [z_0, z_0 ^ delta];

        (z, [t_g, t_e])
    }

    #[inline]
    pub fn xor_gate(&self, x: [Block; 2], y: [Block; 2], delta: Block) -> [Block; 2] {
        let z_0 = x[0] ^ y[0];
        [z_0, z_0 ^ delta]
    }

    #[inline]
    pub fn inv_gate(&self, x: [Block; 2], public_labels: [Block; 2], delta: Block) -> [Block; 2] {
        let z_0 = x[0] ^ public_labels[1];
        [z_0 ^ delta, z_0]
    }
}

impl GarbledCircuitGenerator for HalfGateGenerator {
    fn garble<R: RandomBlock, H: WireLabelHasher>(
        &self,
        h: &H,
        rng: &mut R,
        circ: &Circuit,
    ) -> Result<GarbledCircuit, GeneratorError> {
        let mut delta: Block = rng.random_block();
        delta.set_lsb();

        let public_labels = [rng.random_block(), rng.random_block() ^ delta];

        let mut input_labels: Vec<[Block; 2]> = Vec::with_capacity(circ.ninput_wires);
        let mut table: Vec<[Block; 2]> = Vec::with_capacity(circ.nand);
        let mut cache: Vec<Option<[Block; 2]>> = vec![None; circ.nwires];

        for i in 0..circ.ninput_wires {
            let z_0 = rng.random_block();
            let z_1 = z_0 ^ delta;
            let z = [z_0, z_1];
            input_labels.push(z);
            cache[i] = Some(z);
        }

        let mut gid = 1;
        for gate in circ.gates.iter() {
            match *gate {
                Gate::Inv { xref, zref, .. } => {
                    let x = cache[xref].ok_or_else(|| GeneratorError::UninitializedLabel(xref))?;
                    let z = self.inv_gate(x, public_labels, delta);
                    cache[zref] = Some(z);
                }
                Gate::Xor {
                    xref, yref, zref, ..
                } => {
                    let x = cache[xref].ok_or_else(|| GeneratorError::UninitializedLabel(xref))?;
                    let y = cache[yref].ok_or_else(|| GeneratorError::UninitializedLabel(yref))?;
                    let z = self.xor_gate(x, y, delta);
                    cache[zref] = Some(z);
                }
                Gate::And {
                    xref, yref, zref, ..
                } => {
                    let x = cache[xref].ok_or_else(|| GeneratorError::UninitializedLabel(xref))?;
                    let y = cache[yref].ok_or_else(|| GeneratorError::UninitializedLabel(yref))?;
                    let (z, t) = self.and_gate(h, x, y, delta, gid);
                    table.push(t);
                    cache[zref] = Some(z);
                    gid += 1;
                }
            };
        }

        let mut output_bits: Vec<usize> = Vec::with_capacity(circ.noutput_wires);
        for i in (circ.nwires - circ.noutput_wires)..circ.nwires {
            output_bits.push(cache[i].unwrap()[0].lsb());
        }

        Ok(GarbledCircuit::new(
            input_labels,
            cache.into_iter().map(|w| w.unwrap()).collect(),
            table,
            output_bits,
            public_labels,
            delta,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::garble::hash::aes::Aes;
    use crate::rng::Rng;

    #[test]
    fn test_encode_wire_labels() {
        let mut rng = Rng::new();
        let h = Aes::new(&[0u8; 16]);
        let circ = Circuit::parse("circuits/aes_128_reverse.txt").unwrap();
        let half_gate = HalfGateGenerator;

        let gc = half_gate.garble(&h, &mut rng, &circ);
    }
}
