use super::GarbledCircuitGenerator;
use crate::block::Block;
use crate::circuit::Circuit;
use crate::errors::GarbleGeneratorError;
use crate::gate::Gate;
use crate::prg::PRG;

struct HalfGateGenerator<'a, P: PRG> {
    circ: &'a Circuit,
    delta: Block,
    public_labels: [Block; 2],
    wire_labels: Vec<(Block, Block)>,
    current_index: usize,
    prg: P,
}

impl<'a, P: PRG> HalfGateGenerator<'a, P> {
    pub fn new(circ: &'a Circuit, mut prg: P) -> HalfGateGenerator<'a, P> {
        let mut delta: Block = prg.random_block();
        delta.set_lsb();
        let public_labels = [prg.random_block(), prg.random_block() ^ delta];

        HalfGateGenerator {
            circ,
            delta,
            public_labels,
            wire_labels: Vec::new(),
            current_index: 0,
            prg,
        }
    }

    fn public_label(&self, b: bool) -> Block {
        self.public_labels[b as usize]
    }

    fn next_index(&mut self) -> usize {
        self.current_index += 1;
        self.current_index
    }

    fn encode_and(&self, x_0: Block, y_0: Block) -> Block {
        let p_a = x_0.lsb();
        let p_b = y_0.lsb();
        let j = self.next_index();
        let k = self.next_index();
    }
}

impl<'a, P: PRG> GarbledCircuitGenerator for HalfGateGenerator<'a, P> {
    fn encode_wire_labels(&mut self) -> Result<(), GarbleGeneratorError> {
        let mut wire_labels: Vec<Option<(Block, Block)>> = vec![None; self.circ.nwires];
        for i in 0..self.circ.ninput_wires {
            let z0 = self.prg.random_block();
            let z1 = z0 ^ self.delta;
            wire_labels[i] = Some((z0, z1));
        }
        for gate in self.circ.gates.iter() {
            let (zref, z0) = match *gate {
                Gate::Inv { xref, zref, .. } => {
                    let x = wire_labels[xref]
                        .ok_or_else(|| GarbleGeneratorError::UninitializedLabel(xref))?;
                    (zref, x.0 ^ self.public_label(true))
                }
                Gate::Xor {
                    xref, yref, zref, ..
                } => {
                    let x = wire_labels[xref]
                        .ok_or_else(|| GarbleGeneratorError::UninitializedLabel(xref))?;
                    let y = wire_labels[yref]
                        .ok_or_else(|| GarbleGeneratorError::UninitializedLabel(yref))?;
                    (zref, x.0 ^ y.0)
                }
                Gate::And {
                    xref, yref, zref, ..
                } => {
                    let x = wire_labels[xref]
                        .ok_or_else(|| GarbleGeneratorError::UninitializedLabel(xref))?;
                    let y = wire_labels[yref]
                        .ok_or_else(|| GarbleGeneratorError::UninitializedLabel(yref))?;
                    (zref, x.0 ^ y.0)
                }
            };
            let z1 = z0 ^ self.delta;
            wire_labels[zref] = Some((z0, z1));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prg::RandPRG;

    #[test]
    fn test_encode_wire_labels() {
        let mut prg = RandPRG::new();
        let circ = Circuit::parse("circuits/adder64.txt").unwrap();
        let mut half_gate = HalfGateGenerator::new(&circ, prg);

        half_gate.encode_wire_labels();
        //println!("{:?}", half_gate.wire_labels);
        println!(
            "{:?}",
            half_gate
                .wire_labels
                .iter()
                .map(|(a, b)| *b ^ half_gate.delta)
                .collect::<Vec<Block>>()
        );
    }
}
