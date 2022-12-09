#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, sync::Arc};

use crate::{
    garble::{self, gc_state},
    Block,
};
use mpc_circuits::Circuit;

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum GarbleMessage {
    GarbledCircuit(GarbledCircuit),
    Output(Output),
    HashCommitment(HashCommitment),
    CommitmentOpening(CommitmentOpening),
    OutputCheck(OutputCheck),
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct HashCommitment([u8; 32]);

impl From<garble::commitment::HashCommitment> for HashCommitment {
    fn from(c: garble::commitment::HashCommitment) -> Self {
        Self(c.0)
    }
}

impl From<HashCommitment> for garble::commitment::HashCommitment {
    fn from(c: HashCommitment) -> Self {
        Self(c.0)
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CommitmentKey([u8; 32]);

impl From<garble::commitment::CommitmentKey> for CommitmentKey {
    fn from(key: garble::commitment::CommitmentKey) -> Self {
        Self(key.0)
    }
}

impl From<CommitmentKey> for garble::commitment::CommitmentKey {
    fn from(key: CommitmentKey) -> Self {
        Self(key.0)
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CommitmentOpening {
    key: CommitmentKey,
    message: Vec<u8>,
}

impl From<garble::commitment::Opening> for CommitmentOpening {
    fn from(c: garble::commitment::Opening) -> Self {
        Self {
            key: c.key.into(),
            message: c.message,
        }
    }
}

impl From<CommitmentOpening> for garble::commitment::Opening {
    fn from(c: CommitmentOpening) -> Self {
        Self {
            key: c.key.into(),
            message: c.message,
        }
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct OutputCheck([u8; 32]);

impl From<garble::label::OutputCheck> for OutputCheck {
    fn from(c: garble::label::OutputCheck) -> Self {
        Self(c.0)
    }
}

impl From<OutputCheck> for garble::label::OutputCheck {
    fn from(c: OutputCheck) -> Self {
        Self(c.0)
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct InputLabels {
    pub id: usize,
    pub labels: Vec<Block>,
}

impl From<garble::InputLabels<garble::WireLabel>> for InputLabels {
    fn from(labels: garble::InputLabels<garble::WireLabel>) -> Self {
        Self {
            id: labels.id(),
            labels: labels
                .as_ref()
                .into_iter()
                .map(|label| *label.as_ref())
                .collect::<Vec<Block>>(),
        }
    }
}

impl garble::InputLabels<garble::WireLabel> {
    pub fn from_msg(
        circ: &Circuit,
        input_labels: InputLabels,
    ) -> Result<Self, crate::garble::Error> {
        let input = circ.input(input_labels.id)?;
        if input.as_ref().len() != input_labels.labels.len() {
            return Err(crate::garble::Error::InvalidInputLabels);
        }
        garble::InputLabels::new(
            input.clone(),
            &input_labels
                .labels
                .iter()
                .zip(input.as_ref().wires())
                .map(|(label, wire_id)| garble::WireLabel::new(*wire_id, *label))
                .collect::<Vec<garble::WireLabel>>(),
        )
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct OutputLabels {
    pub id: usize,
    pub labels: Vec<Block>,
}

impl From<garble::OutputLabels<garble::WireLabel>> for OutputLabels {
    fn from(labels: garble::OutputLabels<garble::WireLabel>) -> Self {
        Self {
            id: labels.id(),
            labels: labels
                .as_ref()
                .into_iter()
                .map(|label| *label.as_ref())
                .collect::<Vec<Block>>(),
        }
    }
}

impl garble::OutputLabels<garble::WireLabel> {
    pub fn from_msg(
        circ: &Circuit,
        output_labels: OutputLabels,
    ) -> Result<Self, crate::garble::Error> {
        let output = circ.output(output_labels.id)?;
        if output.as_ref().len() != output_labels.labels.len() {
            return Err(crate::garble::Error::InvalidOutputLabels);
        }
        garble::OutputLabels::new(
            output.clone(),
            &output_labels
                .labels
                .iter()
                .zip(output.as_ref().wires())
                .map(|(label, wire_id)| garble::WireLabel::new(*wire_id, *label))
                .collect::<Vec<garble::WireLabel>>(),
        )
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct OutputDecodingInfo {
    pub id: usize,
    pub decoding: Vec<bool>,
}

impl From<garble::label::OutputLabelsDecodingInfo> for OutputDecodingInfo {
    fn from(decoding: garble::label::OutputLabelsDecodingInfo) -> Self {
        Self {
            id: decoding.output.id,
            decoding: decoding
                .as_ref()
                .iter()
                .copied()
                .map(|enc| *enc)
                .collect::<Vec<bool>>(),
        }
    }
}

impl garble::label::OutputLabelsDecodingInfo {
    pub fn from_msg(
        circ: &Circuit,
        decoding: OutputDecodingInfo,
    ) -> Result<Self, crate::garble::Error> {
        let output = circ.output(decoding.id)?;

        Self::new(output, decoding.decoding)
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct OutputLabelsCommitment {
    pub id: usize,
    pub commitments: Vec<Block>,
}

impl From<garble::label::OutputLabelsCommitment> for OutputLabelsCommitment {
    fn from(commitment: garble::label::OutputLabelsCommitment) -> Self {
        Self {
            id: commitment.output.id,
            commitments: commitment.commitments.into_iter().flatten().collect(),
        }
    }
}

impl garble::label::OutputLabelsCommitment {
    pub fn from_msg(
        circ: &Circuit,
        commitment: OutputLabelsCommitment,
    ) -> Result<Self, crate::garble::Error> {
        let output = circ.output(commitment.id)?;
        if commitment.commitments.len() != output.as_ref().len() * 2 {
            return Err(crate::garble::Error::InvalidOutputLabelCommitment);
        }
        let commitments = commitment
            .commitments
            .chunks_exact(2)
            .into_iter()
            .map(|pair| [pair[0], pair[1]])
            .collect();
        Ok(Self {
            output,
            commitments,
        })
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct GarbledCircuit {
    pub id: String,
    pub input_labels: Vec<InputLabels>,
    pub encrypted_gates: Vec<Block>,
    pub decoding: Option<Vec<OutputDecodingInfo>>,
    pub commitments: Option<Vec<OutputLabelsCommitment>>,
}

impl From<garble::GarbledCircuit<gc_state::Partial>> for GarbledCircuit {
    fn from(gc: garble::GarbledCircuit<gc_state::Partial>) -> Self {
        Self {
            id: (*gc.circ.id().as_ref()).clone(),
            input_labels: gc
                .state
                .input_labels
                .into_iter()
                .map(InputLabels::from)
                .collect::<Vec<InputLabels>>(),
            encrypted_gates: gc
                .state
                .encrypted_gates
                .into_iter()
                .map(|gate| *gate.as_ref())
                .flatten()
                .collect::<Vec<Block>>(),
            decoding: gc.state.decoding.and_then(|decoding| {
                Some(decoding.into_iter().map(OutputDecodingInfo::from).collect())
            }),
            commitments: gc.state.commitments.and_then(|commitments| {
                Some(
                    commitments
                        .into_iter()
                        .map(OutputLabelsCommitment::from)
                        .collect(),
                )
            }),
        }
    }
}

impl crate::garble::GarbledCircuit<gc_state::Partial> {
    pub fn from_msg(circ: Arc<Circuit>, msg: GarbledCircuit) -> Result<Self, crate::garble::Error> {
        // Validate circuit id
        if msg.id != *circ.id().as_ref() {
            return Err(crate::garble::Error::PeerError(format!(
                "Received garbled circuit with wrong id: expected {}, received {}",
                circ.id().as_ref().to_string(),
                msg.id
            )));
        }

        // Validate input labels
        let input_ids: HashSet<usize> = msg.input_labels.iter().map(|input| input.id).collect();
        if input_ids.len() != msg.input_labels.len() {
            return Err(crate::garble::Error::PeerError(
                "Received garbled circuit with duplicate inputs".to_string(),
            ));
        }

        let input_labels = msg
            .input_labels
            .into_iter()
            .map(|labels| garble::InputLabels::from_msg(&circ, labels))
            .collect::<Result<Vec<_>, _>>()?;

        // Validate encrypted gates
        if msg.encrypted_gates.len() != 2 * circ.and_count() {
            return Err(crate::garble::Error::PeerError(
                "Received garbled circuit with incorrect number of encrypted gates".to_string(),
            ));
        }

        let encrypted_gates = msg
            .encrypted_gates
            .chunks_exact(2)
            .into_iter()
            .map(|gate| garble::circuit::EncryptedGate::new([gate[0], gate[1]]))
            .collect();

        // Validate output decoding info
        let decoding = match msg.decoding {
            Some(decoding) => {
                // Check that peer sent all output decodings
                if decoding.len() == circ.output_count() {
                    Some(
                        decoding
                            .into_iter()
                            .map(|e| garble::label::OutputLabelsDecodingInfo::from_msg(&circ, e))
                            .collect::<Result<Vec<_>, _>>()?,
                    )
                } else {
                    return Err(crate::garble::Error::PeerError(
                        "Received garbled circuit with invalid output decoding".to_string(),
                    ));
                }
            }
            None => None,
        };

        let commitments = match msg.commitments {
            Some(commitments) => {
                // Check that peer sent commitments for all outputs
                if commitments.len() == circ.output_count() {
                    Some(
                        commitments
                            .into_iter()
                            .map(|c| garble::label::OutputLabelsCommitment::from_msg(&circ, c))
                            .collect::<Result<Vec<_>, _>>()?,
                    )
                } else {
                    return Err(crate::garble::Error::PeerError(
                        "Received garbled circuit with wrong number of output commitments"
                            .to_string(),
                    ));
                }
            }
            None => None,
        };

        Ok(crate::garble::GarbledCircuit {
            circ,
            state: gc_state::Partial {
                input_labels,
                encrypted_gates,
                decoding,
                commitments,
            },
        })
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Output {
    pub id: String,
    pub output_labels: Vec<OutputLabels>,
}

impl From<garble::GarbledCircuit<gc_state::Output>> for Output {
    fn from(gc: garble::GarbledCircuit<gc_state::Output>) -> Self {
        Self {
            id: gc.circ.id().as_ref().clone(),
            output_labels: gc
                .output_labels()
                .into_iter()
                .cloned()
                .map(OutputLabels::from)
                .collect::<Vec<OutputLabels>>(),
        }
    }
}

impl crate::garble::GarbledCircuit<gc_state::Output> {
    /// Validates and converts an [`Output`] to [`crate::garble::GarbledCircuit<gc_state::Output>`]
    pub fn from_msg(
        gc: &garble::GarbledCircuit<gc_state::Full>,
        msg: Output,
    ) -> Result<Self, crate::garble::Error> {
        // Validate circuit id
        if msg.id != *gc.circ.id().as_ref() {
            return Err(crate::garble::Error::PeerError(format!(
                "Received evaluated circuit with wrong id: expected {}, received {}",
                gc.circ.id().as_ref().to_string(),
                msg.id
            )));
        }

        // Check for duplicates
        let output_ids: HashSet<usize> = msg.output_labels.iter().map(|output| output.id).collect();
        if output_ids.len() != msg.output_labels.len() {
            return Err(crate::garble::Error::PeerError(
                "Received garbled circuit with duplicate outputs".to_string(),
            ));
        }

        let mut output_labels = msg
            .output_labels
            .into_iter()
            .map(|labels| garble::OutputLabels::from_msg(&gc.circ, labels))
            .collect::<Result<Vec<_>, _>>()?;

        // Make sure it is sorted
        output_labels.sort_by_key(|output_label| output_label.id());

        // Check all outputs were received
        if output_labels.len() != gc.output_labels().len() {
            return Err(crate::garble::Error::InvalidOutputLabels);
        }

        // Validates that each output label is authentic
        gc.output_labels()
            .iter()
            .zip(&output_labels)
            .map(|(full, ev)| full.validate(ev))
            .collect::<Result<(), crate::garble::Error>>()?;

        Ok(crate::garble::GarbledCircuit {
            circ: gc.circ.clone(),
            state: gc_state::Output {
                labels: output_labels,
                decoding: Some(gc.decoding()),
            },
        })
    }
}
