use cipher::{consts::U16, BlockCipher, BlockEncrypt};
use std::sync::Arc;

use crate::{
    block::Block,
    garble::{
        evaluator::evaluate,
        generator::garble,
        label::{
            decode_output_labels, extract_output_labels, OutputLabels, OutputLabelsCommitment,
            OutputLabelsEncoding, SanitizedInputLabels,
        },
        Delta, Error, InputLabels, WireLabel, WireLabelPair,
    },
    utils::sha256,
};
use mpc_circuits::{Circuit, InputValue, OutputValue};

#[derive(Debug, Clone, PartialEq)]
pub struct EncryptedGate([Block; 2]);

impl EncryptedGate {
    pub(crate) fn new(inner: [Block; 2]) -> Self {
        Self(inner)
    }
}

impl AsRef<[Block; 2]> for EncryptedGate {
    fn as_ref(&self) -> &[Block; 2] {
        &self.0
    }
}

fn gates_digest(encrypted_gates: &[EncryptedGate]) -> Vec<u8> {
    sha256(
        &encrypted_gates
            .iter()
            .map(|gate| gate.0)
            .flatten()
            .map(|gate| gate.to_be_bytes())
            .flatten()
            .collect::<Vec<u8>>(),
    )
    .to_vec()
}

pub trait Data {}

/// Full garbled circuit data. This includes all wire label pairs, encrypted gates and delta.
#[derive(Debug)]
pub struct Full {
    labels: Vec<WireLabelPair>,
    encrypted_gates: Vec<EncryptedGate>,
    #[allow(dead_code)]
    delta: Delta,
}

/// Garbled circuit data including input labels from the generator and (optionally) the output encoding
/// to reveal the plaintext output of the circuit.
#[derive(Debug)]
pub struct Partial {
    pub(crate) input_labels: Vec<InputLabels<WireLabel>>,
    pub(crate) encrypted_gates: Vec<EncryptedGate>,
    pub(crate) encoding: Option<Vec<OutputLabelsEncoding>>,
    pub(crate) commitments: Option<Vec<OutputLabelsCommitment>>,
}

/// Evaluated garbled circuit data containing all wire labels
#[derive(Debug, Clone)]
pub struct Evaluated {
    input_labels: Vec<InputLabels<WireLabel>>,
    #[allow(dead_code)]
    labels: Vec<WireLabel>,
    encrypted_gates: Vec<EncryptedGate>,
    output_labels: Vec<OutputLabels<WireLabel>>,
    encoding: Option<Vec<OutputLabelsEncoding>>,
    commitments: Option<Vec<OutputLabelsCommitment>>,
}

#[derive(Debug, Clone)]
pub struct Compressed {
    input_labels: Vec<InputLabels<WireLabel>>,
    /// Input labels plus the encrypted gates is what constitutes a garbled circuit (GC).
    /// In scenarios where we expect the generator to prove their honest GC generation,
    /// even after performing the evaluation, we want the evaluator to keep the GC around
    /// in order to compare it against an honestly generated circuit. To reduce the memory
    /// footprint, we keep a hash digest of the encrypted gates.
    gates_digest: Vec<u8>,
    output_labels: Vec<OutputLabels<WireLabel>>,
    encoding: Option<Vec<OutputLabelsEncoding>>,
    commitments: Option<Vec<OutputLabelsCommitment>>,
}

/// Evaluated garbled circuit output data
#[derive(Debug)]
pub struct Output {
    pub(crate) labels: Vec<OutputLabels<WireLabel>>,
    pub(crate) encoding: Option<Vec<OutputLabelsEncoding>>,
}

impl Data for Full {}
impl Data for Partial {}
impl Data for Evaluated {}
impl Data for Compressed {}
impl Data for Output {}

#[derive(Debug, Clone)]
pub struct GarbledCircuit<D: Data> {
    pub circ: Arc<Circuit>,
    pub(crate) data: D,
}

impl GarbledCircuit<Full> {
    /// Generate a garbled circuit with the provided input labels and delta.
    pub fn generate<C: BlockCipher<BlockSize = U16> + BlockEncrypt>(
        cipher: &C,
        circ: Arc<Circuit>,
        delta: Delta,
        input_labels: &[InputLabels<WireLabelPair>],
    ) -> Result<Self, Error> {
        let input_labels: Vec<WireLabelPair> = input_labels
            .iter()
            .map(|pair| pair.as_ref())
            .flatten()
            .copied()
            .collect();
        let (labels, encrypted_gates) = garble(cipher, &circ, delta, &input_labels)?;
        Ok(Self {
            circ,
            data: Full {
                labels,
                encrypted_gates,
                delta,
            },
        })
    }

    /// Returns output label encodings
    pub(crate) fn encoding(&self) -> Vec<OutputLabelsEncoding> {
        self.output_labels()
            .iter()
            .map(|labels| labels.encode())
            .collect()
    }

    /// Returns output label commitments. To protect against the Evaluator using these
    /// commitments to decode their output, we shuffle them.
    pub(crate) fn output_commitments(&self) -> Vec<OutputLabelsCommitment> {
        self.output_labels()
            .iter()
            .map(|labels| labels.commit())
            .collect()
    }

    /// Returns output label pairs for each circuit output
    pub fn output_labels(&self) -> Vec<OutputLabels<WireLabelPair>> {
        self.circ
            .outputs()
            .iter()
            .map(|output| {
                OutputLabels::new(
                    output.clone(),
                    &output
                        .as_ref()
                        .wires()
                        .iter()
                        .map(|wire_id| self.data.labels[*wire_id])
                        .collect::<Vec<WireLabelPair>>(),
                )
            })
            .collect::<Result<Vec<OutputLabels<WireLabelPair>>, Error>>()
            .expect("Garbled circuit output labels should be valid")
    }

    /// Returns [`GarbledCircuit<Partial>`] which is safe to send an evaluator
    ///
    /// `reveal` flag determines whether the output decoding will be included
    /// `commit` flag determines whether commitments to the output labels will be included
    pub fn to_evaluator(
        &self,
        inputs: &[InputValue],
        reveal: bool,
        commit: bool,
    ) -> GarbledCircuit<Partial> {
        let input_labels: Vec<InputLabels<WireLabel>> = inputs
            .iter()
            .map(|value| {
                InputLabels::new(
                    value.input().clone(),
                    &WireLabelPair::choose(&self.data.labels, value.wires(), &value.wire_values()),
                )
                .expect("Circuit invariant violated, wrong wire count")
            })
            .collect();

        let constant_labels = self
            .circ
            .inputs()
            .iter()
            .filter_map(|input| {
                if input.value_type().is_constant() {
                    let value = match input.value_type() {
                        mpc_circuits::ValueType::ConstZero => false,
                        mpc_circuits::ValueType::ConstOne => true,
                        _ => panic!("value type should be constant"),
                    };
                    Some(
                        InputLabels::new(
                            input.clone(),
                            &WireLabelPair::choose(
                                &self.data.labels,
                                input.as_ref().wires(),
                                &[value],
                            ),
                        )
                        .expect("Circuit invariant violated, wrong wire count"),
                    )
                } else {
                    None
                }
            })
            .collect::<Vec<InputLabels<WireLabel>>>();

        GarbledCircuit {
            circ: self.circ.clone(),
            data: Partial {
                input_labels: [input_labels, constant_labels].concat(),
                encrypted_gates: self.data.encrypted_gates.clone(),
                encoding: reveal.then(|| self.encoding()),
                commitments: commit.then(|| self.output_commitments()),
            },
        }
    }

    /// Validates that provided output labels are correct
    pub fn validate_output(&self, output_labels: &[WireLabel]) -> Result<(), Error> {
        if output_labels.len() != self.circ.output_count() {
            return Err(Error::InvalidOutputLabels);
        }
        let pairs = self
            .data
            .labels
            .iter()
            .enumerate()
            .skip(self.circ.len() - self.circ.output_len());

        if output_labels.iter().zip(pairs).all(|(label, (id, pair))| {
            (label.id() == id)
                & ((*label.as_ref() == *pair.low()) | (*label.as_ref() == *pair.high()))
        }) {
            Ok(())
        } else {
            Err(Error::InvalidOutputLabels)
        }
    }
}

impl GarbledCircuit<Partial> {
    /// Returns whether or not output encoding is available
    pub fn has_encoding(&self) -> bool {
        self.data.encoding.is_some()
    }

    /// Returns whether or not output label commitments were provided
    pub fn has_output_commitments(&self) -> bool {
        self.data.commitments.is_some()
    }

    /// Evaluates a garbled circuit using provided input labels. These labels are combined with labels sent by the generator
    /// and checked for correctness using the circuit spec.
    pub fn evaluate<C: BlockCipher<BlockSize = U16> + BlockEncrypt>(
        self,
        cipher: &C,
        input_labels: &[InputLabels<WireLabel>],
    ) -> Result<GarbledCircuit<Evaluated>, Error> {
        let sanitized_input_labels =
            SanitizedInputLabels::new(&self.circ, &self.data.input_labels, input_labels)?;
        let labels = evaluate(
            cipher,
            &self.circ,
            sanitized_input_labels,
            &self.data.encrypted_gates,
        )?;
        let output_labels = extract_output_labels(&self.circ, &labels)?;

        // Always check output labels against commitments if they're available
        if let Some(output_commitments) = self.data.commitments.as_ref() {
            output_commitments
                .iter()
                .zip(&output_labels)
                .map(|(commitment, labels)| commitment.validate(&labels))
                .collect::<Result<(), Error>>()?;
        }

        Ok(GarbledCircuit {
            circ: self.circ.clone(),
            data: Evaluated {
                input_labels: input_labels.to_vec(),
                labels,
                encrypted_gates: self.data.encrypted_gates,
                output_labels,
                encoding: self.data.encoding,
                commitments: self.data.commitments,
            },
        })
    }
}

impl GarbledCircuit<Evaluated> {
    /// Returns all active inputs labels used to evaluate the circuit
    pub fn input_labels(&self) -> &[InputLabels<WireLabel>] {
        &self.data.input_labels
    }

    /// Returns all active output labels which are the result of circuit evaluation
    pub fn output_labels(&self) -> &[OutputLabels<WireLabel>] {
        &self.data.output_labels
    }

    /// Returns whether or not output encoding is available
    pub fn has_encoding(&self) -> bool {
        self.data.encoding.is_some()
    }

    /// Returns whether or not output label commitments were provided
    pub fn has_output_commitments(&self) -> bool {
        self.data.commitments.is_some()
    }

    /// Returns garbled circuit output
    pub fn to_output(&self) -> GarbledCircuit<Output> {
        GarbledCircuit {
            circ: self.circ.clone(),
            data: Output {
                labels: self.output_labels().to_vec(),
                encoding: self.data.encoding.clone(),
            },
        }
    }

    /// Returns a compressed evaluated circuit to reduce memory utilization
    pub fn compress(self) -> GarbledCircuit<Compressed> {
        GarbledCircuit {
            circ: self.circ,
            data: Compressed {
                input_labels: self.data.input_labels,
                gates_digest: gates_digest(&self.data.encrypted_gates),
                output_labels: self.data.output_labels,
                encoding: self.data.encoding,
                commitments: self.data.commitments,
            },
        }
    }

    /// Returns decoded circuit outputs
    pub fn decode(&self) -> Result<Vec<OutputValue>, Error> {
        let encoding = self
            .data
            .encoding
            .as_ref()
            .ok_or(Error::InvalidLabelEncoding)?;
        decode_output_labels(&self.circ, &self.data.output_labels, encoding)
    }
}

impl GarbledCircuit<Compressed> {
    /// Returns all active inputs labels used to evaluate the circuit
    pub fn input_labels(&self) -> &[InputLabels<WireLabel>] {
        &self.data.input_labels
    }

    /// Returns all active output labels which are the result of circuit evaluation
    pub fn output_labels(&self) -> &[OutputLabels<WireLabel>] {
        &self.data.output_labels
    }

    /// Returns whether or not output encoding is available
    pub fn has_encoding(&self) -> bool {
        self.data.encoding.is_some()
    }

    /// Returns garbled circuit output
    pub fn to_output(&self) -> GarbledCircuit<Output> {
        GarbledCircuit {
            circ: self.circ.clone(),
            data: Output {
                labels: self.output_labels().to_vec(),
                encoding: self.data.encoding.clone(),
            },
        }
    }

    /// Returns decoded circuit outputs
    pub fn decode(&self) -> Result<Vec<OutputValue>, Error> {
        let encoding = self
            .data
            .encoding
            .as_ref()
            .ok_or(Error::InvalidLabelEncoding)?;
        decode_output_labels(&self.circ, &self.data.output_labels, encoding)
    }
}

impl GarbledCircuit<Output> {
    /// Returns all output labels
    pub fn output_labels(&self) -> &[OutputLabels<WireLabel>] {
        &self.data.labels
    }

    /// Returns whether or not output encoding is available
    pub fn has_encoding(&self) -> bool {
        self.data.encoding.is_some()
    }

    /// Returns output label encoding if available
    pub fn encoding(&self) -> Option<Vec<OutputLabelsEncoding>> {
        self.data.encoding.clone()
    }

    /// Returns decoded circuit outputs
    pub fn decode(&self) -> Result<Vec<OutputValue>, Error> {
        let encoding = self
            .data
            .encoding
            .as_ref()
            .ok_or(Error::InvalidLabelEncoding)?;
        decode_output_labels(&self.circ, &self.data.labels, encoding)
    }
}

pub fn validate_compressed_circuit<C: BlockCipher<BlockSize = U16> + BlockEncrypt>(
    cipher: &C,
    delta: Delta,
    input_labels: &[InputLabels<WireLabelPair>],
    gc: GarbledCircuit<Compressed>,
) -> Result<GarbledCircuit<Compressed>, Error> {
    validate_circuit(
        cipher,
        &gc.circ,
        delta,
        input_labels,
        None,
        Some(gc.data.gates_digest.clone()),
        gc.data.encoding.as_ref().map(Vec::as_slice),
        gc.data.commitments.as_ref().map(Vec::as_slice),
    )?;
    Ok(gc)
}

pub fn validate_evaluated_circuit<C: BlockCipher<BlockSize = U16> + BlockEncrypt>(
    cipher: &C,
    delta: Delta,
    input_labels: &[InputLabels<WireLabelPair>],
    gc: GarbledCircuit<Evaluated>,
) -> Result<GarbledCircuit<Evaluated>, Error> {
    validate_circuit(
        cipher,
        &gc.circ,
        delta,
        input_labels,
        Some(gc.data.encrypted_gates.as_slice()),
        None,
        gc.data.encoding.as_ref().map(Vec::as_slice),
        gc.data.commitments.as_ref().map(Vec::as_slice),
    )?;
    Ok(gc)
}

fn validate_circuit<C: BlockCipher<BlockSize = U16> + BlockEncrypt>(
    cipher: &C,
    circ: &Circuit,
    delta: Delta,
    input_labels: &[InputLabels<WireLabelPair>],
    encrypted_gates: Option<&[EncryptedGate]>,
    digest: Option<Vec<u8>>,
    output_encoding: Option<&[OutputLabelsEncoding]>,
    output_commitments: Option<&[OutputLabelsCommitment]>,
) -> Result<(), Error> {
    let digest = if let Some(encrypted_gates) = encrypted_gates {
        // If gates are passed in, hash them
        gates_digest(encrypted_gates)
    } else if let Some(digest) = digest {
        // Otherwise if the digest was already computed, use that instead.
        digest
    } else {
        return Err(Error::General(
            "Must provide encrypted gates or digest".to_string(),
        ));
    };

    let input_labels: Vec<WireLabelPair> = input_labels
        .iter()
        .map(|pair| pair.as_ref())
        .flatten()
        .copied()
        .collect();

    // Re-garble circuit using input labels.
    // We rely on the property of the "half-gates" garbling scheme that given the input
    // labels, the encrypted gates will always be computed deterministically.
    let (labels, encrypted_gates) = garble(cipher, circ, delta, &input_labels)?;

    // Compute the expected gates digest
    let expected_digest = gates_digest(&encrypted_gates);

    // If hashes don't match circuit wasn't garbled correctly
    if expected_digest != digest {
        return Err(Error::CorruptedGarbledCircuit);
    }

    // Check output encoding if it was sent
    if let Some(output_encoding) = output_encoding {
        let expected_output_decoding = extract_output_labels(circ, &labels)?
            .iter()
            .map(|labels| labels.encode())
            .collect::<Vec<_>>();

        if &expected_output_decoding != output_encoding {
            return Err(Error::CorruptedDecodingInfo);
        }
    }

    // Check output commitments if they were sent
    if let Some(output_commitments) = output_commitments {
        let expected_output_commitments = extract_output_labels(circ, &labels)?
            .iter()
            .map(|labels| labels.commit())
            .collect::<Vec<_>>();

        if &expected_output_commitments != output_commitments {
            return Err(Error::CorruptedGarbledCircuit);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use aes::{Aes128, NewBlockCipher};
    use mpc_circuits::AES_128_REVERSE;
    use rand_chacha::ChaCha12Rng;
    use rand_core::SeedableRng;

    use super::*;

    #[test]
    fn test_uninitialized_label() {
        let cipher = Aes128::new_from_slice(&[0u8; 16]).unwrap();
        let mut rng = ChaCha12Rng::seed_from_u64(0);
        let circ = Arc::new(Circuit::load_bytes(AES_128_REVERSE).unwrap());

        let (input_labels, delta) = InputLabels::generate(&mut rng, &circ, None);

        let err = GarbledCircuit::generate(&cipher, circ, delta, &input_labels[1..]).unwrap_err();

        assert!(matches!(err, Error::UninitializedLabel(_)));
    }

    #[test]
    fn test_circuit_validation_pass() {
        let cipher = Aes128::new_from_slice(&[0u8; 16]).unwrap();
        let mut rng = ChaCha12Rng::seed_from_u64(0);
        let circ = Arc::new(Circuit::load_bytes(AES_128_REVERSE).unwrap());

        let key = circ.input(0).unwrap().to_value(vec![0u8; 16]).unwrap();
        let msg = circ.input(1).unwrap().to_value(vec![0u8; 16]).unwrap();
        let (input_labels, delta) = InputLabels::generate(&mut rng, &circ, None);

        let gc = GarbledCircuit::generate(&cipher, circ.clone(), delta, &input_labels).unwrap();

        let key_labels = input_labels[0].select(&key).unwrap();
        let msg_labels = input_labels[1].select(&msg).unwrap();

        let partial_gc = gc.to_evaluator(&[], true, false);
        let ev_gc = partial_gc
            .evaluate(&cipher, &[key_labels, msg_labels])
            .unwrap();

        let ev_gc = validate_evaluated_circuit(&cipher, delta, &input_labels, ev_gc).unwrap();

        let cmp_gc = ev_gc.compress();

        validate_compressed_circuit(&cipher, delta, &input_labels, cmp_gc).unwrap();
    }

    #[test]
    fn test_circuit_validation_fail_bad_gate() {
        let cipher = Aes128::new_from_slice(&[0u8; 16]).unwrap();
        let mut rng = ChaCha12Rng::seed_from_u64(0);
        let circ = Arc::new(Circuit::load_bytes(AES_128_REVERSE).unwrap());

        let key = circ.input(0).unwrap().to_value(vec![0u8; 16]).unwrap();
        let msg = circ.input(1).unwrap().to_value(vec![0u8; 16]).unwrap();
        let (input_labels, delta) = InputLabels::generate(&mut rng, &circ, None);

        let mut gc = GarbledCircuit::generate(&cipher, circ.clone(), delta, &input_labels).unwrap();

        // set bogus gate
        gc.data.encrypted_gates[0].0[0] = Block::new(0);

        let key_labels = input_labels[0].select(&key).unwrap();
        let msg_labels = input_labels[1].select(&msg).unwrap();

        let partial_gc = gc.to_evaluator(&[], true, false);
        let ev_gc = partial_gc
            .evaluate(&cipher, &[key_labels, msg_labels])
            .unwrap();

        let err =
            validate_evaluated_circuit(&cipher, delta, &input_labels, ev_gc.clone()).unwrap_err();

        assert!(matches!(err, Error::CorruptedGarbledCircuit));

        let cmp_gc = ev_gc.compress();

        let err = validate_compressed_circuit(&cipher, delta, &input_labels, cmp_gc).unwrap_err();

        assert!(matches!(err, Error::CorruptedGarbledCircuit));
    }

    #[test]
    fn test_circuit_validation_fail_bad_input_label() {
        let cipher = Aes128::new_from_slice(&[0u8; 16]).unwrap();
        let mut rng = ChaCha12Rng::seed_from_u64(0);
        let circ = Arc::new(Circuit::load_bytes(AES_128_REVERSE).unwrap());

        let key = circ.input(0).unwrap().to_value(vec![0u8; 16]).unwrap();
        let msg = circ.input(1).unwrap().to_value(vec![0u8; 16]).unwrap();
        let (mut input_labels, delta) = InputLabels::generate(&mut rng, &circ, None);

        let gc = GarbledCircuit::generate(&cipher, circ.clone(), delta, &input_labels).unwrap();

        // set bogus label
        input_labels[0].set_label(0, WireLabelPair::new(0, Block::new(0), Block::new(0)));

        let key_labels = input_labels[0].select(&key).unwrap();
        let msg_labels = input_labels[1].select(&msg).unwrap();

        let partial_gc = gc.to_evaluator(&[], true, false);
        let ev_gc = partial_gc
            .evaluate(&cipher, &[key_labels, msg_labels])
            .unwrap();

        let err =
            validate_evaluated_circuit(&cipher, delta, &input_labels, ev_gc.clone()).unwrap_err();

        assert!(matches!(err, Error::CorruptedGarbledCircuit));

        let cmp_gc = ev_gc.compress();

        let err = validate_compressed_circuit(&cipher, delta, &input_labels, cmp_gc).unwrap_err();

        assert!(matches!(err, Error::CorruptedGarbledCircuit));
    }

    #[test]
    /// The Generator sends invalid output label decoding info which causes the evaluator to
    /// derive incorrect output. Testing that this will be detected during validation.
    fn test_circuit_validation_fail_bad_output_encoding() {
        let cipher = Aes128::new_from_slice(&[0u8; 16]).unwrap();
        let mut rng = ChaCha12Rng::seed_from_u64(0);
        let circ = Arc::new(Circuit::load_bytes(AES_128_REVERSE).unwrap());

        let key = circ.input(0).unwrap().to_value(vec![0u8; 16]).unwrap();
        let msg = circ.input(1).unwrap().to_value(vec![0u8; 16]).unwrap();
        let (input_labels, delta) = InputLabels::generate(&mut rng, &circ, None);

        let mut gc = GarbledCircuit::generate(&cipher, circ.clone(), delta, &input_labels).unwrap();

        // Flip the last two output labels. This will cause the generator to compute the
        // corrupted decoding info.
        let last_pair = gc.data.labels.pop().unwrap();
        let last_pair_flipped =
            WireLabelPair::new(last_pair.id(), *last_pair.high(), *last_pair.low());
        gc.data.labels.push(last_pair_flipped);

        let key_labels = input_labels[0].select(&key).unwrap();
        let msg_labels = input_labels[1].select(&msg).unwrap();

        let partial_gc = gc.to_evaluator(&[], true, true);

        let ev_gc = partial_gc
            .evaluate(&cipher, &[key_labels, msg_labels])
            .unwrap();

        let err =
            validate_evaluated_circuit(&cipher, delta, &input_labels, ev_gc.clone()).unwrap_err();

        assert!(matches!(err, Error::CorruptedDecodingInfo));

        let cmp_gc = ev_gc.compress();

        let err = validate_compressed_circuit(&cipher, delta, &input_labels, cmp_gc).unwrap_err();

        assert!(matches!(err, Error::CorruptedDecodingInfo));
    }

    #[test]
    fn test_circuit_validation_fail_bad_output_commitment() {
        let cipher = Aes128::new_from_slice(&[0u8; 16]).unwrap();
        let mut rng = ChaCha12Rng::seed_from_u64(0);
        let circ = Arc::new(Circuit::load_bytes(AES_128_REVERSE).unwrap());

        let key = circ.input(0).unwrap().to_value(vec![0u8; 16]).unwrap();
        let msg = circ.input(1).unwrap().to_value(vec![0u8; 16]).unwrap();
        let (mut input_labels, delta) = InputLabels::generate(&mut rng, &circ, None);

        let gc = GarbledCircuit::generate(&cipher, circ.clone(), delta, &input_labels).unwrap();

        // set bogus high label (the opposite label the evaluator receives)
        // evaluation should pass but the circuit validation should fail because the commitment is bad
        let low_label = input_labels[0].get_label(0).low().clone();
        input_labels[0].set_label(0, WireLabelPair::new(0, low_label, Block::new(0)));

        let key_labels = input_labels[0].select(&key).unwrap();
        let msg_labels = input_labels[1].select(&msg).unwrap();

        let partial_gc = gc.to_evaluator(&[], true, true);
        let ev_gc = partial_gc
            .evaluate(&cipher, &[key_labels, msg_labels])
            .unwrap();

        let err =
            validate_evaluated_circuit(&cipher, delta, &input_labels, ev_gc.clone()).unwrap_err();

        assert!(matches!(err, Error::CorruptedGarbledCircuit));

        let cmp_gc = ev_gc.compress();

        let err = validate_compressed_circuit(&cipher, delta, &input_labels, cmp_gc).unwrap_err();

        assert!(matches!(err, Error::CorruptedGarbledCircuit));
    }
}
