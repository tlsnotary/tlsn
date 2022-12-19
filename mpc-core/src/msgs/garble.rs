#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{
    garble::{
        self,
        circuit::{self, unchecked as unchecked_circuit, unchecked::UncheckedCircuitOpening},
        commitment, gc_state, label,
        label::unchecked::{self as unchecked_label, UncheckedInputLabelsDecodingInfo},
    },
    Block,
};
use mpc_circuits::Circuit;

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum GarbleMessage {
    GarbledCircuit(GarbledCircuit),
    CircuitOpening(CircuitOpening),
    Output(Output),
    HashCommitment(HashCommitment),
    CommitmentOpening(CommitmentOpening),
    OutputCheck(OutputCheck),
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct HashCommitment([u8; 32]);

impl From<commitment::HashCommitment> for HashCommitment {
    fn from(c: commitment::HashCommitment) -> Self {
        Self(c.0)
    }
}

impl From<HashCommitment> for commitment::HashCommitment {
    fn from(c: HashCommitment) -> Self {
        Self(c.0)
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CommitmentKey([u8; 32]);

impl From<commitment::CommitmentKey> for CommitmentKey {
    fn from(key: commitment::CommitmentKey) -> Self {
        Self(key.0)
    }
}

impl From<CommitmentKey> for commitment::CommitmentKey {
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

impl From<commitment::Opening> for CommitmentOpening {
    fn from(c: commitment::Opening) -> Self {
        Self {
            key: c.key.into(),
            message: c.message,
        }
    }
}

impl From<CommitmentOpening> for commitment::Opening {
    fn from(c: CommitmentOpening) -> Self {
        Self {
            key: c.key.into(),
            message: c.message,
        }
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CircuitOpening {
    id: String,
    delta: [u8; 16],
    input_decoding: Vec<InputDecodingInfo>,
}

impl From<garble::CircuitOpening> for CircuitOpening {
    fn from(opening: garble::CircuitOpening) -> Self {
        Self {
            id: opening.id.as_ref().into(),
            delta: opening.delta.to_be_bytes(),
            input_decoding: opening
                .input_decoding
                .into_iter()
                .map(InputDecodingInfo::from)
                .collect(),
        }
    }
}

impl From<CircuitOpening> for UncheckedCircuitOpening {
    fn from(opening: CircuitOpening) -> Self {
        Self {
            id: opening.id.into(),
            delta: opening.delta.into(),
            input_decoding: opening
                .input_decoding
                .into_iter()
                .map(UncheckedInputLabelsDecodingInfo::from)
                .collect(),
        }
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct OutputCheck([u8; 32]);

impl From<label::OutputCheck> for OutputCheck {
    fn from(c: label::OutputCheck) -> Self {
        Self(c.0)
    }
}

impl From<OutputCheck> for label::OutputCheck {
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

impl From<label::InputLabels<label::WireLabel>> for InputLabels {
    fn from(labels: label::InputLabels<label::WireLabel>) -> Self {
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

impl From<InputLabels> for unchecked_label::UncheckedInputLabels {
    fn from(labels: InputLabels) -> Self {
        Self {
            id: labels.id,
            labels: labels.labels,
        }
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct OutputLabels {
    pub id: usize,
    pub labels: Vec<Block>,
}

impl From<label::OutputLabels<label::WireLabel>> for OutputLabels {
    fn from(labels: label::OutputLabels<label::WireLabel>) -> Self {
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

impl From<OutputLabels> for unchecked_label::UncheckedOutputLabels {
    fn from(labels: OutputLabels) -> Self {
        Self {
            id: labels.id,
            labels: labels.labels,
        }
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct InputDecodingInfo {
    pub id: usize,
    pub decoding: Vec<bool>,
}

impl From<label::InputLabelsDecodingInfo> for InputDecodingInfo {
    fn from(decoding: label::InputLabelsDecodingInfo) -> Self {
        Self {
            id: decoding.input.id,
            decoding: decoding
                .as_ref()
                .iter()
                .copied()
                .map(|enc| *enc)
                .collect::<Vec<bool>>(),
        }
    }
}

impl From<InputDecodingInfo> for unchecked_label::UncheckedInputLabelsDecodingInfo {
    fn from(decoding: InputDecodingInfo) -> Self {
        Self {
            id: decoding.id,
            decoding: decoding
                .decoding
                .into_iter()
                .map(label::LabelDecodingInfo::from)
                .collect(),
        }
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct OutputDecodingInfo {
    pub id: usize,
    pub decoding: Vec<bool>,
}

impl From<label::OutputLabelsDecodingInfo> for OutputDecodingInfo {
    fn from(decoding: label::OutputLabelsDecodingInfo) -> Self {
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

impl From<OutputDecodingInfo> for unchecked_label::UncheckedOutputLabelsDecodingInfo {
    fn from(decoding: OutputDecodingInfo) -> Self {
        Self {
            id: decoding.id,
            decoding: decoding
                .decoding
                .into_iter()
                .map(label::LabelDecodingInfo::from)
                .collect(),
        }
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct OutputLabelsCommitment {
    pub id: usize,
    pub commitments: Vec<Block>,
}

impl From<label::OutputLabelsCommitment> for OutputLabelsCommitment {
    #[inline]
    fn from(commitment: label::OutputLabelsCommitment) -> Self {
        Self {
            id: commitment.output.id,
            commitments: commitment.commitments.into_iter().flatten().collect(),
        }
    }
}

impl From<OutputLabelsCommitment> for unchecked_label::UncheckedOutputLabelsCommitment {
    #[inline]
    fn from(commitment: OutputLabelsCommitment) -> Self {
        Self {
            id: commitment.id,
            commitments: commitment.commitments,
        }
    }
}

impl label::OutputLabelsCommitment {
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

impl From<circuit::GarbledCircuit<gc_state::Partial>> for GarbledCircuit {
    fn from(gc: circuit::GarbledCircuit<gc_state::Partial>) -> Self {
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

impl From<GarbledCircuit> for unchecked_circuit::UncheckedGarbledCircuit {
    fn from(gc: GarbledCircuit) -> Self {
        Self {
            id: gc.id.into(),
            input_labels: gc
                .input_labels
                .into_iter()
                .map(unchecked_label::UncheckedInputLabels::from)
                .collect(),
            encrypted_gates: gc.encrypted_gates,
            decoding: gc.decoding.and_then(|decoding| {
                Some(
                    decoding
                        .into_iter()
                        .map(unchecked_label::UncheckedOutputLabelsDecodingInfo::from)
                        .collect(),
                )
            }),
            commitments: gc.commitments.and_then(|commitments| {
                Some(
                    commitments
                        .into_iter()
                        .map(unchecked_label::UncheckedOutputLabelsCommitment::from)
                        .collect(),
                )
            }),
        }
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Output {
    pub circ_id: String,
    pub output_labels: Vec<OutputLabels>,
}

impl From<circuit::GarbledCircuit<gc_state::Output>> for Output {
    fn from(gc: circuit::GarbledCircuit<gc_state::Output>) -> Self {
        Self {
            circ_id: gc.circ.id().as_ref().clone(),
            output_labels: gc
                .output_labels()
                .into_iter()
                .cloned()
                .map(OutputLabels::from)
                .collect::<Vec<OutputLabels>>(),
        }
    }
}

impl From<Output> for unchecked_circuit::UncheckedOutput {
    fn from(msg: Output) -> Self {
        Self {
            circ_id: msg.circ_id.into(),
            output_labels: msg
                .output_labels
                .into_iter()
                .map(unchecked_label::UncheckedOutputLabels::from)
                .collect(),
        }
    }
}
