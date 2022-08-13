use crate::garble::{BinaryLabel, EncryptedGate};
use mpc_circuits::CircuitId;

#[derive(Debug, Clone)]
pub enum GarbleMessage {
    GarbledCircuit(GarbledCircuit),
}

#[derive(Debug, Clone)]
pub struct GarbledCircuit {
    pub id: CircuitId,
    pub input_labels: Vec<BinaryLabel>,
    pub encrypted_gates: Vec<EncryptedGate>,
    pub decoding: Option<Vec<bool>>,
}

impl From<crate::garble::GarbledCircuit> for GarbledCircuit {
    fn from(gc: crate::garble::GarbledCircuit) -> Self {
        Self {
            id: gc.circ.id().clone(),
            input_labels: gc.input_labels,
            encrypted_gates: gc.encrypted_gates,
            decoding: gc.decoding,
        }
    }
}

impl crate::garble::GarbledCircuit {
    pub fn from_msg(circ: Arc<Circuit>, msg: GarbledCircuit) -> Result<Self, Error> {
        if msg.id != *circ.id() {
            return Err(Error::PeerError(format!(
                "Received garbled circuit with wrong id: expected {}, received {}",
                circ.id().as_ref().to_string(),
                msg.id.as_ref().to_string()
            )));
        }

        Ok(crate::garble::GarbledCircuit {
            circ,
            input_labels: msg.input_labels,
            encrypted_gates: msg.encrypted_gates,
            decoding: msg.decoding,
        })
    }
}

#[cfg(feature = "proto")]
mod proto {
    use std::convert::TryFrom;

    use super::*;
    use crate::{garble::BinaryLabel, proto};

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

    impl From<BinaryLabel> for proto::garble::BinaryLabel {
        fn from(label: BinaryLabel) -> Self {
            Self {
                id: label.id as u32,
                value: (*label.as_ref()).into(),
            }
        }
    }

    impl TryFrom<proto::garble::BinaryLabel> for BinaryLabel {
        type Error = std::io::Error;

        fn try_from(label: proto::garble::BinaryLabel) -> Result<Self, Self::Error> {
            Ok(Self::new(label.id as usize, label.value.into()))
        }
    }

    impl From<GarbledCircuit> for proto::garble::GarbledCircuit {
        fn from(gc: GarbledCircuit) -> Self {
            Self {
                id: gc.id.as_ref().to_string(),
                input_labels: gc
                    .input_labels
                    .into_iter()
                    .map(|l| proto::garble::BinaryLabel::from(l))
                    .collect(),
                encrypted_gates: gc
                    .encrypted_gates
                    .into_iter()
                    .map(|e| {
                        let e = *e.as_ref();
                        [proto::Block::from(e[0]), proto::Block::from(e[1])]
                    })
                    .flatten()
                    .collect(),
                decoding: if let Some(decoding) = gc.decoding {
                    decoding
                } else {
                    Vec::new()
                },
            }
        }
    }

    impl TryFrom<proto::garble::GarbledCircuit> for GarbledCircuit {
        type Error = std::io::Error;

        fn try_from(gc: proto::garble::GarbledCircuit) -> Result<Self, Self::Error> {
            let mut input_labels = Vec::with_capacity(gc.input_labels.len());
            for label in gc.input_labels.into_iter() {
                input_labels.push(BinaryLabel::try_from(label)?);
            }

            if gc.encrypted_gates.len() % 2 != 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid number of encrypted gates",
                ));
            }
            let mut encrypted_gates = Vec::with_capacity(gc.encrypted_gates.len());
            for gates in gc.encrypted_gates.chunks_exact(2) {
                encrypted_gates.push(EncryptedGate::new([
                    gates[0].clone().into(),
                    gates[1].clone().into(),
                ]));
            }
            Ok(Self {
                id: gc.id.into(),
                input_labels,
                encrypted_gates,
                decoding: if gc.decoding.len() > 0 {
                    Some(gc.decoding)
                } else {
                    None
                },
            })
        }
    }
}

#[cfg(feature = "proto")]
pub use proto::*;
