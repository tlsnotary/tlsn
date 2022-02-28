use crate::{garble::circuit, Block};

include!(concat!(env!("OUT_DIR"), "/core.garble.rs"));

impl From<circuit::InputLabel> for InputLabel {
    #[inline]
    fn from(l: circuit::InputLabel) -> Self {
        Self {
            id: l.id as u32,
            label: l.label.into(),
        }
    }
}

impl From<InputLabel> for circuit::InputLabel {
    #[inline]
    fn from(l: InputLabel) -> Self {
        Self {
            id: l.id as usize,
            label: l.label.into(),
        }
    }
}

impl From<circuit::GarbledCircuit> for GarbledCircuit {
    #[inline]
    fn from(c: circuit::GarbledCircuit) -> Self {
        Self {
            generator_input_labels: c
                .generator_input_labels
                .into_iter()
                .map(|l| InputLabel::from(l))
                .collect(),
            table: c
                .table
                .into_iter()
                .map(|pair| super::LabelPair {
                    low: pair[0].into(),
                    high: pair[1].into(),
                })
                .collect(),
            public_labels: super::LabelPair {
                low: c.public_labels[0].into(),
                high: c.public_labels[1].into(),
            },
            output_bits: c.output_bits,
        }
    }
}

impl From<GarbledCircuit> for circuit::GarbledCircuit {
    #[inline]
    fn from(c: GarbledCircuit) -> Self {
        Self {
            generator_input_labels: c
                .generator_input_labels
                .into_iter()
                .map(|label| circuit::InputLabel::from(label))
                .collect(),
            table: c
                .table
                .into_iter()
                .map(|pair| [pair.low.into(), pair.high.into()])
                .collect::<Vec<[Block; 2]>>(),
            public_labels: [c.public_labels.low.into(), c.public_labels.high.into()],
            output_bits: c.output_bits,
        }
    }
}
