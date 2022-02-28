use crate::garble::circuit;

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
