#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, sync::Arc};

use crate::{garble, Block};
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
pub struct OutputEncoding {
    pub id: usize,
    pub encoding: Vec<bool>,
}

impl From<garble::label::OutputLabelsEncoding> for OutputEncoding {
    fn from(encoding: garble::label::OutputLabelsEncoding) -> Self {
        Self {
            id: encoding.output.id,
            encoding: encoding
                .as_ref()
                .iter()
                .copied()
                .map(|enc| *enc)
                .collect::<Vec<bool>>(),
        }
    }
}

impl garble::label::OutputLabelsEncoding {
    pub fn from_msg(
        circ: &Circuit,
        encoding: OutputEncoding,
    ) -> Result<Self, crate::garble::Error> {
        let output = circ.output(encoding.id)?;

        Self::new(output, encoding.encoding)
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
    pub encoding: Option<Vec<OutputEncoding>>,
    pub commitments: Option<Vec<OutputLabelsCommitment>>,
}

impl From<garble::GarbledCircuit<garble::Partial>> for GarbledCircuit {
    fn from(gc: garble::GarbledCircuit<garble::Partial>) -> Self {
        Self {
            id: (*gc.circ.id().as_ref()).clone(),
            input_labels: gc
                .data
                .input_labels
                .into_iter()
                .map(InputLabels::from)
                .collect::<Vec<InputLabels>>(),
            encrypted_gates: gc
                .data
                .encrypted_gates
                .into_iter()
                .map(|gate| *gate.as_ref())
                .flatten()
                .collect::<Vec<Block>>(),
            encoding: gc.data.encoding.and_then(|encoding| {
                Some(encoding.into_iter().map(OutputEncoding::from).collect())
            }),
            commitments: gc.data.commitments.and_then(|commitments| {
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

impl crate::garble::GarbledCircuit<garble::Partial> {
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

        // Validate output encoding
        let encoding = match msg.encoding {
            Some(encoding) => {
                // Check that peer sent all output encodings
                if encoding.len() == circ.output_count() {
                    Some(
                        encoding
                            .into_iter()
                            .map(|e| garble::label::OutputLabelsEncoding::from_msg(&circ, e))
                            .collect::<Result<Vec<_>, _>>()?,
                    )
                } else {
                    return Err(crate::garble::Error::PeerError(
                        "Received garbled circuit with invalid output encoding".to_string(),
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
            data: garble::Partial {
                input_labels,
                encrypted_gates,
                encoding,
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

impl From<garble::GarbledCircuit<garble::Output>> for Output {
    fn from(gc: garble::GarbledCircuit<garble::Output>) -> Self {
        Self {
            id: (*gc.circ.id().as_ref()).clone(),
            output_labels: gc
                .output_labels()
                .into_iter()
                .cloned()
                .map(OutputLabels::from)
                .collect::<Vec<OutputLabels>>(),
        }
    }
}

impl crate::garble::GarbledCircuit<garble::Output> {
    /// Validates and converts an [`Output`] to [`crate::garble::GarbledCircuit<garble::Output>`]
    pub fn from_msg(
        gc: &garble::GarbledCircuit<garble::Full>,
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
            data: garble::Output {
                labels: output_labels,
                encoding: Some(gc.encoding()),
            },
        })
    }
}

// #[cfg(feature = "proto")]
// mod proto {
//     use std::convert::TryFrom;

//     use super::*;
//     use crate::proto;

//     impl From<GarbleMessage> for proto::garble::Message {
//         fn from(m: GarbleMessage) -> Self {
//             Self {
//                 msg: Some(match m {
//                     GarbleMessage::GarbledCircuit(gc) => {
//                         proto::garble::message::Msg::GarbledCircuit(gc.into())
//                     }
//                     _ => todo!(),
//                 }),
//             }
//         }
//     }

//     impl TryFrom<proto::garble::Message> for GarbleMessage {
//         type Error = std::io::Error;

//         fn try_from(m: proto::garble::Message) -> Result<Self, Self::Error> {
//             let msg = if let Some(m) = m.msg {
//                 match m {
//                     proto::garble::message::Msg::GarbledCircuit(gc) => {
//                         GarbleMessage::GarbledCircuit(GarbledCircuit::try_from(gc)?)
//                     }
//                 }
//             } else {
//                 return Err(std::io::Error::new(
//                     std::io::ErrorKind::InvalidData,
//                     format!("{:?}", m),
//                 ));
//             };
//             Ok(msg)
//         }
//     }

//     impl From<InputLabels> for proto::garble::InputLabels {
//         fn from(labels: InputLabels) -> Self {
//             Self {
//                 id: labels.id as u32,
//                 labels: labels
//                     .labels
//                     .into_iter()
//                     .map(|block| block.into())
//                     .collect::<Vec<proto::Block>>(),
//             }
//         }
//     }

//     impl TryFrom<proto::garble::InputLabels> for InputLabels {
//         type Error = std::io::Error;

//         fn try_from(labels: proto::garble::InputLabels) -> Result<Self, Self::Error> {
//             Ok(InputLabels {
//                 id: labels.id as usize,
//                 labels: labels.labels.into_iter().map(Block::from).collect(),
//             })
//         }
//     }

//     impl From<OutputEncoding> for proto::garble::OutputEncoding {
//         fn from(encoding: OutputEncoding) -> Self {
//             Self {
//                 id: encoding.id as u32,
//                 encoding: encoding.encoding,
//             }
//         }
//     }

//     impl TryFrom<proto::garble::OutputEncoding> for OutputEncoding {
//         type Error = std::io::Error;

//         fn try_from(encoding: proto::garble::OutputEncoding) -> Result<Self, Self::Error> {
//             Ok(OutputEncoding {
//                 id: encoding.id as usize,
//                 encoding: encoding.encoding,
//             })
//         }
//     }

//     impl From<GarbledCircuit> for proto::garble::GarbledCircuit {
//         fn from(gc: GarbledCircuit) -> Self {
//             Self {
//                 id: gc.id,
//                 input_labels: gc
//                     .input_labels
//                     .into_iter()
//                     .map(|l| proto::garble::InputLabels::from(l))
//                     .collect(),
//                 encrypted_gates: gc
//                     .encrypted_gates
//                     .into_iter()
//                     .map(proto::Block::from)
//                     .collect(),
//                 encoding: if let Some(encoding) = gc.encoding {
//                     encoding
//                         .into_iter()
//                         .map(proto::garble::OutputEncoding::from)
//                         .collect()
//                 } else {
//                     Vec::new()
//                 },
//             }
//         }
//     }

//     impl TryFrom<proto::garble::GarbledCircuit> for GarbledCircuit {
//         type Error = std::io::Error;

//         fn try_from(gc: proto::garble::GarbledCircuit) -> Result<Self, Self::Error> {
//             let mut input_labels: Vec<InputLabels> = Vec::with_capacity(gc.input_labels.len());
//             for labels in gc.input_labels {
//                 input_labels.push(InputLabels::try_from(labels)?);
//             }
//             Ok(Self {
//                 id: gc.id.into(),
//                 input_labels,
//                 encrypted_gates: gc.encrypted_gates.into_iter().map(Block::from).collect(),
//                 encoding: if gc.encoding.len() == 0 {
//                     None
//                 } else {
//                     let mut encoding: Vec<OutputEncoding> = Vec::with_capacity(gc.encoding.len());
//                     for enc in gc.encoding {
//                         encoding.push(OutputEncoding::try_from(enc)?);
//                     }
//                     Some(encoding)
//                 },
//             })
//         }
//     }
// }

// #[cfg(feature = "proto")]
// pub use proto::*;
