use super::GarbledCircuitGenerator;
use crate::block::{Block, SELECT_MASK};
use crate::circuit::Circuit;
use crate::errors::GeneratorError;
use crate::garble::circuit::CompleteGarbledCircuit;
use crate::gate::Gate;
use cipher::{consts::U16, generic_array::GenericArray, BlockCipher, BlockEncrypt};
use rand::{CryptoRng, Rng, SeedableRng};

pub struct HalfGateGenerator {}

impl HalfGateGenerator {
    pub fn new() -> Self {
        Self {}
    }

    #[inline]
    pub fn and_gate<C: BlockCipher<BlockSize = U16> + BlockEncrypt>(
        &self,
        c: &mut C,
        x: [Block; 2],
        y: [Block; 2],
        delta: Block,
        gid: usize,
    ) -> ([Block; 2], [Block; 2]) {
        let p_a = x[0].lsb();
        let p_b = y[0].lsb();
        let j = gid;
        let k = gid + 1;

        let hx_0 = x[0].hash_tweak(c, j);
        let hy_0 = y[0].hash_tweak(c, k);

        let t_g = hx_0 ^ x[1].hash_tweak(c, j) ^ (SELECT_MASK[p_b] & delta);
        let w_g = hx_0 ^ (SELECT_MASK[p_a] & t_g);

        let t_e = hy_0 ^ y[1].hash_tweak(c, k) ^ x[0];
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
    fn garble<R: Rng + CryptoRng, C: BlockCipher<BlockSize = U16> + BlockEncrypt>(
        &self,
        c: &mut C,
        rng: &mut R,
        circ: &Circuit,
    ) -> Result<CompleteGarbledCircuit, GeneratorError> {
        let mut delta: Block = Block::random(rng);
        delta.set_lsb();

        let public_labels = [Block::random(rng), Block::random(rng) ^ delta];

        let mut input_labels: Vec<[Block; 2]> = Vec::with_capacity(circ.ninput_wires);
        let mut table: Vec<[Block; 2]> = Vec::with_capacity(circ.nand);
        let mut cache: Vec<Option<[Block; 2]>> = vec![None; circ.nwires];

        for i in 0..circ.ninput_wires {
            let z_0 = Block::random(rng);
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
                    let (z, t) = self.and_gate(c, x, y, delta, gid);
                    table.push(t);
                    cache[zref] = Some(z);
                    gid += 1;
                }
            };
        }

        let mut output_bits: Vec<bool> = Vec::with_capacity(circ.noutput_wires);
        for i in (circ.nwires - circ.noutput_wires)..circ.nwires {
            output_bits.push(cache[i].unwrap()[0].lsb() != 0);
        }

        Ok(CompleteGarbledCircuit::new(
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
    use aes::cipher::{generic_array::GenericArray, NewBlockCipher};
    use aes::Aes128;
    use rand_chacha::ChaCha12Rng;

    #[test]
    fn test_encode_wire_labels() {
        let mut cipher = Aes128::new(GenericArray::from_slice(&[0u8; 16]));
        let mut rng = ChaCha12Rng::from_entropy();
        let circ = Circuit::load("circuits/protobuf/aes_128_reverse.bin").unwrap();
        let half_gate = HalfGateGenerator::new();

        let gc = half_gate.garble(&mut cipher, &mut rng, &circ);
    }
}
