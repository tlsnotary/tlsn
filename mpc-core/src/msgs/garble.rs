use std::{collections::HashSet, sync::Arc};

use crate::{garble, Block};
use mpc_circuits::{Circuit, CircuitId};

#[derive(Debug, Clone)]
pub enum GarbleMessage {
    GarbledCircuit(GarbledCircuit),
}

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
pub struct GarbledCircuit {
    pub id: CircuitId,
    pub input_labels: Vec<InputLabels>,
    pub encrypted_gates: Vec<Block>,
    pub encoding: Option<Vec<OutputEncoding>>,
}

impl From<garble::GarbledCircuit<garble::Partial>> for GarbledCircuit {
    fn from(gc: garble::GarbledCircuit<garble::Partial>) -> Self {
        Self {
            id: gc.circ.id().clone(),
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
                Some(
                    encoding
                        .into_iter()
                        .map(OutputEncoding::from)
                        .collect::<Vec<OutputEncoding>>(),
                )
            }),
        }
    }
}

impl crate::garble::GarbledCircuit<garble::Partial> {
    pub fn from_msg(circ: Arc<Circuit>, msg: GarbledCircuit) -> Result<Self, crate::garble::Error> {
        // Validate circuit id
        if msg.id != *circ.id() {
            return Err(crate::garble::Error::PeerError(format!(
                "Received garbled circuit with wrong id: expected {}, received {}",
                circ.id().as_ref().to_string(),
                msg.id.as_ref().to_string()
            )));
        }

        // Validate input labels
        let input_ids: HashSet<usize> = msg.input_labels.iter().map(|input| input.id).collect();
        if input_ids.len() != msg.input_labels.len() {
            return Err(crate::garble::Error::PeerError(
                "Received garbled circuit with duplicate inputs".to_string(),
            ));
        }

        let mut input_labels: Vec<garble::InputLabels<garble::WireLabel>> =
            Vec::with_capacity(msg.input_labels.len());
        for input in msg.input_labels.into_iter() {
            let circ_input = match circ.input(input.id) {
                Some(circ_input) => circ_input,
                None => {
                    return Err(crate::garble::Error::PeerError(format!(
                        "Received garbled circuit with invalid input {}",
                        input.id
                    )))
                }
            };
            if circ_input.as_ref().len() != input.labels.len() {
                return Err(crate::garble::Error::PeerError(format!(
                    "Received invalid garbled circuit input {}, expected {} labels received {}",
                    input.id,
                    circ_input.as_ref().len(),
                    input.labels.len()
                )));
            }
            input_labels.push(garble::InputLabels::new(
                circ_input,
                &input
                    .labels
                    .iter()
                    .map(|label| garble::WireLabel::new(input.id, *label))
                    .collect::<Vec<garble::WireLabel>>(),
            ))
        }

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
            Some(enc) => {
                // Check that peer sent all output encodings
                if enc.len() == circ.output_count() {
                    let mut encoding: Vec<garble::label::OutputLabelsEncoding> =
                        Vec::with_capacity(circ.output_count());
                    for encoding_ in enc {
                        let circ_output = match circ.output(encoding_.id) {
                            Some(circ_output) => circ_output,
                            None => {
                                return Err(crate::garble::Error::PeerError(
                                    "Received garbled circuit with invalid output encoding"
                                        .to_string(),
                                ));
                            }
                        };
                        encoding.push(garble::label::OutputLabelsEncoding::new(
                            circ_output,
                            encoding_.encoding,
                        ))
                    }
                    Some(encoding)
                } else {
                    return Err(crate::garble::Error::PeerError(
                        "Received garbled circuit with invalid output encoding".to_string(),
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
            },
        })
    }
}

#[cfg(feature = "proto")]
mod proto {
    use std::convert::TryFrom;

    use super::*;
    use crate::proto;

    impl From<GarbleMessage> for proto::garble::Message {
        fn from(m: GarbleMessage) -> Self {
            Self {
                msg: Some(match m {
                    GarbleMessage::GarbledCircuit(gc) => {
                        proto::garble::message::Msg::GarbledCircuit(gc.into())
                    }
                }),
            }
        }
    }

    impl TryFrom<proto::garble::Message> for GarbleMessage {
        type Error = std::io::Error;

        fn try_from(m: proto::garble::Message) -> Result<Self, Self::Error> {
            let msg = if let Some(m) = m.msg {
                match m {
                    proto::garble::message::Msg::GarbledCircuit(gc) => {
                        GarbleMessage::GarbledCircuit(GarbledCircuit::try_from(gc)?)
                    }
                }
            } else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("{:?}", m),
                ));
            };
            Ok(msg)
        }
    }

    impl From<InputLabels> for proto::garble::InputLabels {
        fn from(labels: InputLabels) -> Self {
            Self {
                id: labels.id as u32,
                labels: labels
                    .labels
                    .into_iter()
                    .map(|block| block.into())
                    .collect::<Vec<proto::Block>>(),
            }
        }
    }

    impl TryFrom<proto::garble::InputLabels> for InputLabels {
        type Error = std::io::Error;

        fn try_from(labels: proto::garble::InputLabels) -> Result<Self, Self::Error> {
            Ok(InputLabels {
                id: labels.id as usize,
                labels: labels.labels.into_iter().map(Block::from).collect(),
            })
        }
    }

    impl From<OutputEncoding> for proto::garble::OutputEncoding {
        fn from(encoding: OutputEncoding) -> Self {
            Self {
                id: encoding.id as u32,
                encoding: encoding.encoding,
            }
        }
    }

    impl TryFrom<proto::garble::OutputEncoding> for OutputEncoding {
        type Error = std::io::Error;

        fn try_from(encoding: proto::garble::OutputEncoding) -> Result<Self, Self::Error> {
            Ok(OutputEncoding {
                id: encoding.id as usize,
                encoding: encoding.encoding,
            })
        }
    }

    impl From<GarbledCircuit> for proto::garble::GarbledCircuit {
        fn from(gc: GarbledCircuit) -> Self {
            Self {
                id: gc.id.as_ref().to_string(),
                input_labels: gc
                    .input_labels
                    .into_iter()
                    .map(|l| proto::garble::InputLabels::from(l))
                    .collect(),
                encrypted_gates: gc
                    .encrypted_gates
                    .into_iter()
                    .map(proto::Block::from)
                    .collect(),
                encoding: if let Some(encoding) = gc.encoding {
                    encoding
                        .into_iter()
                        .map(proto::garble::OutputEncoding::from)
                        .collect()
                } else {
                    Vec::new()
                },
            }
        }
    }

    impl TryFrom<proto::garble::GarbledCircuit> for GarbledCircuit {
        type Error = std::io::Error;

        fn try_from(gc: proto::garble::GarbledCircuit) -> Result<Self, Self::Error> {
            let mut input_labels: Vec<InputLabels> = Vec::with_capacity(gc.input_labels.len());
            for labels in gc.input_labels {
                input_labels.push(InputLabels::try_from(labels)?);
            }
            Ok(Self {
                id: gc.id.into(),
                input_labels,
                encrypted_gates: gc.encrypted_gates.into_iter().map(Block::from).collect(),
                encoding: if gc.encoding.len() == 0 {
                    None
                } else {
                    let mut encoding: Vec<OutputEncoding> = Vec::with_capacity(gc.encoding.len());
                    for enc in gc.encoding {
                        encoding.push(OutputEncoding::try_from(enc)?);
                    }
                    Some(encoding)
                },
            })
        }
    }
}

#[cfg(feature = "proto")]
pub use proto::*;
