use crate::ValueType;

pub trait WireGroup {
    /// Returns id of group
    fn id(&self) -> usize;
    /// Returns group name
    fn name(&self) -> &str;
    /// Returns group description
    fn description(&self) -> &str;
    /// Returns group value type
    fn value_type(&self) -> ValueType;
    /// Returns group wire ids
    fn wires(&self) -> &[usize];
    /// Returns number of wires
    fn len(&self) -> usize {
        self.wires().len()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Group {
    id: usize,
    name: String,
    desc: String,
    value_type: ValueType,
    pub(crate) wires: Vec<usize>,
}

impl Group {
    pub(crate) fn new(
        id: usize,
        name: &str,
        desc: &str,
        value_type: ValueType,
        mut wires: Vec<usize>,
    ) -> Self {
        // Ensure wire ids are always sorted
        wires.sort();
        Self {
            id,
            name: name.to_string(),
            desc: desc.to_string(),
            value_type,
            wires,
        }
    }

    /// Shifts all wire ids to the right by an offset
    pub(crate) fn shift_right(&self, offset: usize) -> Self {
        let mut clone = self.clone();
        clone
            .wires
            .iter_mut()
            .for_each(|wire_id| *wire_id += offset);
        clone
    }
}

impl WireGroup for Group {
    fn id(&self) -> usize {
        self.id
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> &str {
        &self.desc
    }

    fn value_type(&self) -> ValueType {
        self.value_type
    }

    fn wires(&self) -> &[usize] {
        &self.wires
    }
}
