use std::sync::Arc;

use aes::{Aes128, NewBlockCipher};
use blake3::Hasher;
use cipher::{consts::U16, BlockCipher, BlockEncrypt};

use crate::{
    circuit::EncryptedGate,
    encoding::{state, Delta, EncodedValue, Label},
    CIPHER_FIXED_KEY,
};
use mpc_circuits::{types::TypeError, Circuit, CircuitError, Gate};
use mpc_core::{hash::Hash, Block};

/// Errors that can occur during garbled circuit generation.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum GeneratorError {
    #[error(transparent)]
    TypeError(#[from] TypeError),
    #[error(transparent)]
    CircuitError(#[from] CircuitError),
    #[error("generator not finished")]
    NotFinished,
}

/// Computes half-gate garbled AND gate
#[inline]
pub(crate) fn and_gate<C: BlockCipher<BlockSize = U16> + BlockEncrypt>(
    c: &C,
    x_0: &Label,
    y_0: &Label,
    delta: &Delta,
    gid: usize,
) -> (Label, EncryptedGate) {
    let delta = delta.into_inner();
    let x_0 = x_0.to_inner();
    let x_1 = x_0 ^ delta;
    let y_0 = y_0.to_inner();
    let y_1 = y_0 ^ delta;

    let p_a = x_0.lsb();
    let p_b = y_0.lsb();
    let j = gid;
    let k = gid + 1;

    let hx_0 = x_0.hash_tweak(c, j);
    let hy_0 = y_0.hash_tweak(c, k);

    // Garbled row of generator half-gate
    let t_g = hx_0 ^ x_1.hash_tweak(c, j) ^ (Block::SELECT_MASK[p_b] & delta);
    let w_g = hx_0 ^ (Block::SELECT_MASK[p_a] & t_g);

    // Garbled row of evaluator half-gate
    let t_e = hy_0 ^ y_1.hash_tweak(c, k) ^ x_0;
    let w_e = hy_0 ^ (Block::SELECT_MASK[p_b] & (t_e ^ x_0));

    let z_0 = Label::new(w_g ^ w_e);

    (z_0, EncryptedGate::new([t_g, t_e]))
}

/// Core generator type used to generate garbled circuits.
///
/// A generator is to be used as an iterator of encrypted gates. Each
/// iteration will return the next encrypted gate in the circuit until the
/// entire garbled circuit has been yielded.
pub struct Generator {
    /// Cipher to use to encrypt the gates
    cipher: Aes128,
    /// Circuit to generate a garbled circuit for
    circ: Arc<Circuit>,
    /// Delta value to use while generating the circuit
    delta: Delta,
    /// The 0 bit labels for the garbled circuit
    low_labels: Vec<Option<Label>>,
    /// Current position in the circuit
    pos: usize,
    /// Current gate id
    gid: usize,
    /// Hasher to use to hash the encrypted gates
    hasher: Option<Hasher>,
}

impl Generator {
    /// Creates a new generator for the given circuit.
    ///
    /// # Arguments
    ///
    /// * `circ` - The circuit to generate a garbled circuit for.
    /// * `delta` - The delta value to use.
    /// * `inputs` - The inputs to the circuit.
    pub fn new(
        circ: Arc<Circuit>,
        delta: Delta,
        inputs: &[EncodedValue<state::Full>],
    ) -> Result<Self, GeneratorError> {
        Self::new_with(circ, delta, inputs, None)
    }

    /// Creates a new generator for the given circuit. Generator will compute a hash
    /// of the encrypted gates while they are produced.
    ///
    /// # Arguments
    ///
    /// * `circ` - The circuit to generate a garbled circuit for.
    /// * `delta` - The delta value to use.
    /// * `inputs` - The inputs to the circuit.
    pub fn new_with_hasher(
        circ: Arc<Circuit>,
        delta: Delta,
        inputs: &[EncodedValue<state::Full>],
    ) -> Result<Self, GeneratorError> {
        Self::new_with(circ, delta, inputs, Some(Hasher::new()))
    }

    fn new_with(
        circ: Arc<Circuit>,
        delta: Delta,
        inputs: &[EncodedValue<state::Full>],
        hasher: Option<Hasher>,
    ) -> Result<Self, GeneratorError> {
        if inputs.len() != circ.inputs().len() {
            return Err(CircuitError::InvalidInputCount(
                circ.inputs().len(),
                inputs.len(),
            ))?;
        }

        let mut low_labels: Vec<Option<Label>> = vec![None; circ.feed_count()];
        for (encoded, input) in inputs.iter().zip(circ.inputs()) {
            if encoded.value_type() != input.value_type() {
                return Err(TypeError::UnexpectedType {
                    expected: input.value_type(),
                    actual: encoded.value_type(),
                })?;
            }

            for (label, node) in encoded.iter().zip(input.iter()) {
                low_labels[node.id()] = Some(*label);
            }
        }

        Ok(Self {
            cipher: Aes128::new_from_slice(&CIPHER_FIXED_KEY).expect("cipher should initialize"),
            circ,
            delta,
            low_labels,
            pos: 0,
            gid: 1,
            hasher,
        })
    }

    /// Returns whether the generator has finished generating the circuit.
    pub fn is_complete(&self) -> bool {
        self.pos >= self.circ.gates().len()
    }

    /// Returns the encoded outputs of the circuit.
    pub fn outputs(&self) -> Result<Vec<EncodedValue<state::Full>>, GeneratorError> {
        if !self.is_complete() {
            return Err(GeneratorError::NotFinished);
        }

        Ok(self
            .circ
            .outputs()
            .iter()
            .map(|output| {
                let labels: Vec<Label> = output
                    .iter()
                    .map(|node| self.low_labels[node.id()].expect("feed should be initialized"))
                    .collect();

                EncodedValue::<state::Full>::from_labels(output.value_type(), self.delta, &labels)
                    .expect("encoding should be correct")
            })
            .collect())
    }

    /// Returns the hash of the encrypted gates.
    pub fn hash(&self) -> Option<Hash> {
        self.hasher.as_ref().map(|hasher| {
            let hash: [u8; 32] = hasher.finalize().into();
            Hash::from(hash)
        })
    }
}

impl Iterator for Generator {
    type Item = EncryptedGate;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let low_labels = &mut self.low_labels;
        while let Some(gate) = self.circ.gates().get(self.pos) {
            self.pos += 1;
            match gate {
                Gate::Inv {
                    x: node_x,
                    z: node_z,
                } => {
                    let x_0 = low_labels[node_x.id()].expect("feed should be initialized");
                    low_labels[node_z.id()] = Some(x_0 ^ self.delta);
                }
                Gate::Xor {
                    x: node_x,
                    y: node_y,
                    z: node_z,
                } => {
                    let x_0 = low_labels[node_x.id()].expect("feed should be initialized");
                    let y_0 = low_labels[node_y.id()].expect("feed should be initialized");
                    low_labels[node_z.id()] = Some(x_0 ^ y_0);
                }
                Gate::And {
                    x: node_x,
                    y: node_y,
                    z: node_z,
                } => {
                    let x_0 = low_labels[node_x.id()].expect("feed should be initialized");
                    let y_0 = low_labels[node_y.id()].expect("feed should be initialized");
                    let (z_0, encrypted_gate) =
                        and_gate(&self.cipher, &x_0, &y_0, &self.delta, self.gid);
                    low_labels[node_z.id()] = Some(z_0);
                    self.gid += 2;

                    if let Some(hasher) = &mut self.hasher {
                        hasher.update(&encrypted_gate.to_be_bytes());
                    }

                    return Some(encrypted_gate);
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use crate::{ChaChaEncoder, Encoder};
    use mpc_circuits::circuits::AES128;

    use super::*;

    #[test]
    fn test_generator() {
        let encoder = ChaChaEncoder::new([0; 32]);
        let inputs: Vec<_> = AES128
            .inputs()
            .iter()
            .map(|input| encoder.encode_by_type(0, &input.value_type()))
            .collect();

        let mut gen = Generator::new_with_hasher(AES128.clone(), encoder.delta(), &inputs).unwrap();

        let enc_gates: Vec<EncryptedGate> = gen.by_ref().collect();

        assert!(gen.is_complete());
        assert_eq!(enc_gates.len(), AES128.and_count());

        let _ = gen.outputs().unwrap();
        let _ = gen.hash().unwrap();
    }
}
