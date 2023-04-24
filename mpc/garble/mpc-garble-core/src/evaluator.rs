use std::sync::Arc;

use aes::{Aes128, NewBlockCipher};
use blake3::Hasher;
use cipher::{consts::U16, BlockCipher, BlockEncrypt};

use crate::{
    circuit::EncryptedGate,
    encoding::{state, EncodedValue, Label},
    CIPHER_FIXED_KEY,
};
use mpc_circuits::{types::TypeError, Circuit, CircuitError, Gate};
use mpc_core::{hash::Hash, Block};

/// Errors that can occur during garbled circuit evaluation.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum EvaluatorError {
    #[error(transparent)]
    TypeError(#[from] TypeError),
    #[error(transparent)]
    CircuitError(#[from] CircuitError),
    #[error("evaluator not finished")]
    NotFinished,
}

/// Evaluates half-gate garbled AND gate
#[inline]
pub(crate) fn and_gate<C: BlockCipher<BlockSize = U16> + BlockEncrypt>(
    cipher: &C,
    x: &Label,
    y: &Label,
    encrypted_gate: &EncryptedGate,
    gid: usize,
) -> Label {
    let x = x.to_inner();
    let y = y.to_inner();

    let s_a = x.lsb();
    let s_b = y.lsb();

    let j = gid;
    let k = gid + 1;

    let hx = x.hash_tweak(cipher, j);
    let hy = y.hash_tweak(cipher, k);

    let w_g = hx ^ (encrypted_gate[0] & Block::SELECT_MASK[s_a]);
    let w_e = hy ^ (Block::SELECT_MASK[s_b] & (encrypted_gate[1] ^ x));

    Label::new(w_g ^ w_e)
}

/// Core evaluator type for evaluating a garbled circuit.
pub struct Evaluator {
    /// Cipher to use to encrypt the gates
    cipher: Aes128,
    /// Circuit to evaluate
    circ: Arc<Circuit>,
    /// Active label state
    active_labels: Vec<Option<Label>>,
    /// Current position in the circuit
    pos: usize,
    /// Current gate id
    gid: usize,
    /// Whether the evaluator is finished
    complete: bool,
    /// Hasher to use to hash the encrypted gates
    hasher: Option<Hasher>,
}

impl Evaluator {
    /// Creates a new evaluator for the given circuit.
    ///
    /// # Arguments
    ///
    /// * `circ` - The circuit to evaluate.
    /// * `inputs` - The inputs to the circuit.
    pub fn new(
        circ: Arc<Circuit>,
        inputs: &[EncodedValue<state::Active>],
    ) -> Result<Self, EvaluatorError> {
        Self::new_with(circ, inputs, None)
    }

    /// Creates a new evaluator for the given circuit. Evaluator will compute
    /// a hash of the encrypted gates while they are evaluated.
    ///
    /// # Arguments
    ///
    /// * `circ` - The circuit to evaluate.
    /// * `inputs` - The inputs to the circuit.
    pub fn new_with_hasher(
        circ: Arc<Circuit>,
        inputs: &[EncodedValue<state::Active>],
    ) -> Result<Self, EvaluatorError> {
        Self::new_with(circ, inputs, Some(Hasher::new()))
    }

    fn new_with(
        circ: Arc<Circuit>,
        inputs: &[EncodedValue<state::Active>],
        hasher: Option<Hasher>,
    ) -> Result<Self, EvaluatorError> {
        if inputs.len() != circ.inputs().len() {
            return Err(CircuitError::InvalidInputCount(
                circ.inputs().len(),
                inputs.len(),
            ))?;
        }

        let mut active_labels: Vec<Option<Label>> = vec![None; circ.feed_count()];
        for (encoded, input) in inputs.iter().zip(circ.inputs()) {
            if encoded.value_type() != input.value_type() {
                return Err(TypeError::UnexpectedType {
                    expected: input.value_type(),
                    actual: encoded.value_type(),
                })?;
            }

            for (label, node) in encoded.iter().zip(input.iter()) {
                active_labels[node.id()] = Some(*label);
            }
        }

        let mut ev = Self {
            cipher: Aes128::new_from_slice(&CIPHER_FIXED_KEY).expect("cipher should initialize"),
            circ,
            active_labels,
            pos: 0,
            gid: 1,
            complete: false,
            hasher,
        };

        // If circuit has no AND gates we can evaluate it immediately for cheap
        if ev.circ.and_count() == 0 {
            ev.evaluate(std::iter::empty());
        }

        Ok(ev)
    }

    /// Evaluates the next batch of encrypted gates.
    #[inline]
    pub fn evaluate<'a>(&mut self, mut encrypted_gates: impl Iterator<Item = &'a EncryptedGate>) {
        let labels = &mut self.active_labels;

        // Process gates until we run out of encrypted gates
        while self.pos < self.circ.gates().len() {
            match &self.circ.gates()[self.pos] {
                Gate::Inv {
                    x: node_x,
                    z: node_z,
                } => {
                    let x = labels[node_x.id()].expect("feed should be initialized");
                    labels[node_z.id()] = Some(x);
                }
                Gate::Xor {
                    x: node_x,
                    y: node_y,
                    z: node_z,
                } => {
                    let x = labels[node_x.id()].expect("feed should be initialized");
                    let y = labels[node_y.id()].expect("feed should be initialized");
                    labels[node_z.id()] = Some(x ^ y);
                }
                Gate::And {
                    x: node_x,
                    y: node_y,
                    z: node_z,
                } => {
                    if let Some(encrypted_gate) = encrypted_gates.next() {
                        if let Some(hasher) = &mut self.hasher {
                            hasher.update(&encrypted_gate.to_be_bytes());
                        }

                        let x = labels[node_x.id()].expect("feed should be initialized");
                        let y = labels[node_y.id()].expect("feed should be initialized");
                        let z = and_gate(&self.cipher, &x, &y, encrypted_gate, self.gid);
                        labels[node_z.id()] = Some(z);
                        self.gid += 2;
                    } else {
                        // We ran out of encrypted gates, so we return until we get more
                        return;
                    }
                }
            }
            self.pos += 1;
        }

        self.complete = true;
    }

    /// Returns whether the evaluator has finished evaluating the circuit.
    pub fn is_complete(&self) -> bool {
        self.complete
    }

    /// Returns the active encoded outputs of the circuit.
    pub fn outputs(&self) -> Result<Vec<EncodedValue<state::Active>>, EvaluatorError> {
        if !self.is_complete() {
            return Err(EvaluatorError::NotFinished);
        }

        Ok(self
            .circ
            .outputs()
            .iter()
            .map(|output| {
                let labels: Vec<Label> = output
                    .iter()
                    .map(|node| self.active_labels[node.id()].expect("feed should be initialized"))
                    .collect();

                EncodedValue::<state::Active>::from_labels(output.value_type(), &labels)
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
