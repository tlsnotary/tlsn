use crate::{Value, ValueError, ValueType};

pub trait WireGroup
where
    Self: Sized,
{
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
    /// Converts to group with associated value
    #[inline]
    fn to_value(self, value: impl Into<Value>) -> Result<GroupValue<Self>, ValueError> {
        let value = value.into();
        if self.value_type() != value.value_type() {
            return Err(ValueError::InvalidType(
                self.name().to_string(),
                self.value_type(),
                value.value_type(),
            ));
        } else if self.len() != value.len() {
            return Err(ValueError::InvalidValue(
                self.name().to_string(),
                self.len(),
                value.len(),
            ));
        }
        Ok(GroupValue { group: self, value })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Group {
    id: usize,
    name: String,
    desc: String,
    value_type: ValueType,
    // a vec containing ids of the wires
    pub(crate) wires: Vec<usize>,
}

impl Group {
    #[inline]
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
    #[inline]
    fn id(&self) -> usize {
        self.id
    }

    #[inline]
    fn name(&self) -> &str {
        &self.name
    }

    #[inline]
    fn description(&self) -> &str {
        &self.desc
    }

    #[inline]
    fn value_type(&self) -> ValueType {
        self.value_type
    }

    #[inline]
    fn wires(&self) -> &[usize] {
        &self.wires
    }
}

/// Group of wires with an associated value
#[derive(Debug, Clone, PartialEq)]
pub struct GroupValue<T>
where
    T: WireGroup,
{
    group: T,
    value: Value,
}

impl<T> GroupValue<T>
where
    T: WireGroup,
{
    /// Returns reference to group
    #[inline]
    pub fn group(&self) -> &T {
        &self.group
    }

    /// Returns reference to value
    #[inline]
    pub fn value(&self) -> &Value {
        &self.value
    }

    /// Returns wire ids and values
    #[inline]
    pub fn wire_values(&self) -> Vec<(usize, bool)> {
        self.group
            .wires()
            .iter()
            .copied()
            .zip(self.value.to_lsb0_bits().into_iter())
            .collect()
    }

    /// Creates group value from LSB0 bit string
    #[inline]
    pub fn from_bits(group: T, bits: Vec<bool>) -> Result<Self, ValueError> {
        if group.len() != bits.len() {
            return Err(ValueError::InvalidValue(
                group.name().to_string(),
                group.len(),
                bits.len(),
            ));
        }
        let value = Value::new(group.value_type(), bits)?;
        Ok(Self { group, value })
    }
}

impl<T> WireGroup for GroupValue<T>
where
    T: WireGroup,
{
    #[inline]
    fn id(&self) -> usize {
        self.group.id()
    }

    #[inline]
    fn name(&self) -> &str {
        self.group.name()
    }

    #[inline]
    fn description(&self) -> &str {
        self.group.description()
    }

    #[inline]
    fn value_type(&self) -> ValueType {
        self.group.value_type()
    }

    #[inline]
    fn wires(&self) -> &[usize] {
        self.group.wires()
    }
}
