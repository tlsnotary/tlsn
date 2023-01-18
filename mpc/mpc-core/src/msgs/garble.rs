#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{
    garble::{
        self,
        circuit::{self, unchecked as unchecked_circuit, unchecked::UncheckedCircuitOpening},
        commitment, gc_state, label,
        label::{input::unchecked::*, output::unchecked::*, unchecked::*},
    },
    Block,
};
use mpc_circuits::{Circuit, WireGroup};

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum GarbleMessage {
    InputLabels(Vec<InputLabels>),
    GarbledCircuit(GarbledCircuit),
    CircuitOpening(CircuitOpening),
    Output(Output),
    HashCommitment(HashCommitment),
    CommitmentOpening(CommitmentOpening),
    OutputLabelsDigest(OutputLabelsDigest),
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
    delta: [u8; 16],
    input_decoding: Vec<InputDecodingInfo>,
}

impl From<garble::CircuitOpening> for CircuitOpening {
    fn from(opening: garble::CircuitOpening) -> Self {
        Self {
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
            delta: opening.delta.into(),
            input_decoding: opening
                .input_decoding
                .into_iter()
                .map(UncheckedLabelsDecodingInfo::from)
                .collect(),
        }
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct OutputLabelsDigest([u8; 32]);

impl From<label::LabelsDigest> for OutputLabelsDigest {
    fn from(c: label::LabelsDigest) -> Self {
        Self(c.0)
    }
}

impl From<OutputLabelsDigest> for label::LabelsDigest {
    fn from(c: OutputLabelsDigest) -> Self {
        Self(c.0)
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct InputLabels {
    pub index: usize,
    pub labels: Vec<Block>,
}

impl From<label::ActiveInputLabels> for InputLabels {
    fn from(labels: label::ActiveInputLabels) -> Self {
        Self {
            index: labels.index(),
            labels: labels.iter_blocks().collect(),
        }
    }
}

impl From<InputLabels> for UncheckedInputLabels {
    fn from(labels: InputLabels) -> Self {
        Self {
            id: labels.index,
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

impl From<label::ActiveOutputLabels> for OutputLabels {
    fn from(labels: label::ActiveOutputLabels) -> Self {
        Self {
            id: labels.index(),
            labels: labels.iter_blocks().collect(),
        }
    }
}

impl From<OutputLabels> for UncheckedOutputLabels {
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
            id: decoding.id(),
            decoding: decoding.decoding,
        }
    }
}

impl From<InputDecodingInfo> for UncheckedLabelsDecodingInfo {
    fn from(decoding: InputDecodingInfo) -> Self {
        Self {
            id: decoding.id,
            decoding: decoding.decoding,
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
            id: decoding.id(),
            decoding: decoding.decoding,
        }
    }
}

impl From<OutputDecodingInfo> for UncheckedLabelsDecodingInfo {
    fn from(decoding: OutputDecodingInfo) -> Self {
        Self {
            id: decoding.id,
            decoding: decoding.decoding,
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
            id: commitment.output.index(),
            commitments: commitment.commitments.into_iter().flatten().collect(),
        }
    }
}

impl From<OutputLabelsCommitment> for UncheckedOutputLabelsCommitment {
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
        if commitment.commitments.len() != output.len() * 2 {
            return Err(crate::garble::LabelError::InvalidLabelCommitment(
                output.id().clone(),
            ))?;
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
    pub encrypted_gates: Vec<Block>,
    pub decoding: Option<Vec<OutputDecodingInfo>>,
    pub commitments: Option<Vec<OutputLabelsCommitment>>,
}

impl From<circuit::GarbledCircuit<gc_state::Partial>> for GarbledCircuit {
    fn from(gc: circuit::GarbledCircuit<gc_state::Partial>) -> Self {
        Self {
            id: (*gc.circ.id().as_ref()).clone(),
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
            id: gc.id,
            encrypted_gates: gc.encrypted_gates,
            decoding: gc.decoding.and_then(|decoding| {
                Some(
                    decoding
                        .into_iter()
                        .map(UncheckedLabelsDecodingInfo::from)
                        .collect(),
                )
            }),
            commitments: gc.commitments.and_then(|commitments| {
                Some(
                    commitments
                        .into_iter()
                        .map(UncheckedOutputLabelsCommitment::from)
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
                .state
                .output_labels
                .to_inner()
                .into_iter()
                .map(OutputLabels::from)
                .collect::<Vec<OutputLabels>>(),
        }
    }
}

impl From<Output> for unchecked_circuit::UncheckedOutput {
    fn from(msg: Output) -> Self {
        Self {
            circ_id: msg.circ_id,
            output_labels: msg
                .output_labels
                .into_iter()
                .map(UncheckedOutputLabels::from)
                .collect(),
        }
    }
}
