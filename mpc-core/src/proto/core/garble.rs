#![cfg(feature = "garble")]
use crate::{garble::circuit, Block};

include!(concat!(env!("OUT_DIR"), "/core.garble.rs"));

// impl From<circuit::WireLabel> for WireLabel {
//     #[inline]
//     fn from(l: circuit::WireLabel) -> Self {
//         Self {
//             id: l.id as u32,
//             label: l.value.into(),
//         }
//     }
// }

// impl From<WireLabel> for circuit::WireLabel {
//     #[inline]
//     fn from(l: WireLabel) -> Self {
//         Self {
//             id: l.id as usize,
//             label: l.value.into(),
//         }
//     }
// }

// impl From<circuit::GarbledCircuit> for GarbledCircuit {
//     #[inline]
//     fn from(c: circuit::GarbledCircuit) -> Self {
//         Self {
//             generator_input_labels: c
//                 .generator_input_labels
//                 .into_iter()
//                 .map(WireLabel::from)
//                 .collect(),
//             table: c
//                 .table
//                 .into_iter()
//                 .map(|pair| super::LabelPair {
//                     low: pair[0].into(),
//                     high: pair[1].into(),
//                 })
//                 .collect(),
//             public_labels: super::LabelPair {
//                 low: c.public_labels[0].into(),
//                 high: c.public_labels[1].into(),
//             },
//             output_bits: c.decode_bits,
//         }
//     }
// }

// impl From<GarbledCircuit> for circuit::GarbledCircuit {
//     #[inline]
//     fn from(c: GarbledCircuit) -> Self {
//         Self {
//             generator_input_labels: c
//                 .generator_input_labels
//                 .into_iter()
//                 .map(circuit::WireLabel::from)
//                 .collect(),
//             table: c
//                 .table
//                 .into_iter()
//                 .map(|pair| [pair.low.into(), pair.high.into()])
//                 .collect::<Vec<[Block; 2]>>(),
//             public_labels: [c.public_labels.low.into(), c.public_labels.high.into()],
//             decode_bits: c.output_bits,
//         }
//     }
// }
