use std::sync::{Arc, Weak};

use crate::{value::BitOrder, Circuit, GroupError, Value, ValueType};

/// A unique identifier for a `Group` belonging to a `Circuit`.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct GroupId(String);

impl GroupId {
    pub(crate) fn new(id: String) -> Result<Self, GroupError> {
        if id.len() == 0 || id.len() > 16 {
            return Err(GroupError::InvalidId(
                "Group id must be 1-16 bytes long".to_string(),
                id,
            ));
        }
        Ok(Self(id))
    }
}

impl AsRef<String> for GroupId {
    fn as_ref(&self) -> &String {
        &self.0
    }
}

pub trait WireGroup
where
    Self: Sized,
{
    /// Returns Arc reference to circuit
    fn circuit(&self) -> Arc<Circuit>;
    /// Returns group id
    fn id(&self) -> &GroupId;
    /// Returns index of group
    fn index(&self) -> usize;
    /// Returns group description
    fn description(&self) -> &str;
    /// Returns group value type
    fn value_type(&self) -> ValueType;
    /// Returns bit order of group
    fn bit_order(&self) -> BitOrder {
        self.circuit().bit_order()
    }
    /// Returns group wire ids
    fn wires(&self) -> &[usize];
    /// Returns number of wires
    fn len(&self) -> usize {
        self.wires().len()
    }
    /// Converts to group with associated value
    #[inline]
    fn to_value(self, value: impl Into<Value>) -> Result<GroupValue<Self>, GroupError> {
        let value = value.into();
        if self.value_type() != value.value_type() {
            return Err(GroupError::InvalidType(
                self.id().clone(),
                self.value_type(),
                value.value_type(),
            ));
        } else if self.len() != value.len() {
            return Err(GroupError::InvalidLength(
                self.id().clone(),
                self.len(),
                value.len(),
            ));
        }
        Ok(GroupValue { group: self, value })
    }
}

#[derive(Debug, Clone)]
pub struct Group {
    // a reference to the circuit which this group belongs to
    circ: Weak<Circuit>,
    index: usize,
    id: GroupId,
    desc: String,
    value_type: ValueType,
    // a vec containing ids of the wires
    pub(crate) wires: Vec<usize>,
}

impl Group {
    pub(crate) fn new(
        circ: Weak<Circuit>,
        index: usize,
        id: String,
        desc: String,
        value_type: ValueType,
        mut wires: Vec<usize>,
    ) -> Result<Self, GroupError> {
        let id = GroupId::new(id)?;

        // Check if group is valid length for this type
        value_type
            .valid_length(wires.len())
            .map_err(|e| GroupError::ValueError(id.clone(), e))?;

        // Ensure wire ids are always sorted
        wires.sort();

        Ok(Self {
            circ,
            index,
            id,
            desc: desc.to_string(),
            value_type,
            wires,
        })
    }

    /// Converts an unchecked group to the checked variant bypassing
    /// all validation
    ///
    /// **Important**
    ///
    /// The weak reference to [`Circuit`] must be initialized after this
    /// instance is created
    pub(crate) fn new_unchecked(unchecked: UncheckedGroup) -> Self {
        Self {
            circ: Weak::new(),
            index: unchecked.index,
            id: GroupId(unchecked.id),
            desc: unchecked.desc,
            value_type: unchecked.value_type,
            wires: unchecked.wires,
        }
    }

    /// Converts an unchecked group to the checked variant
    ///
    /// **Important**
    ///
    /// The weak reference to [`Circuit`] must be initialized after this
    /// instance is created
    pub(crate) fn from_unchecked(unchecked: UncheckedGroup) -> Result<Self, GroupError> {
        Self::new(
            Weak::new(),
            unchecked.index,
            unchecked.id,
            unchecked.desc,
            unchecked.value_type,
            unchecked.wires,
        )
    }

    pub(crate) fn set_circuit(&mut self, circuit: Weak<Circuit>) {
        self.circ = circuit;
    }
}

impl PartialEq for Group {
    fn eq(&self, other: &Self) -> bool {
        self.circuit().id() == other.circuit().id() && self.index == other.index
    }
}

impl WireGroup for Group {
    fn circuit(&self) -> Arc<Circuit> {
        self.circ.upgrade().expect("Circuit should not be dropped")
    }

    #[inline]
    fn index(&self) -> usize {
        self.index
    }

    #[inline]
    fn id(&self) -> &GroupId {
        &self.id
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
    pub fn wire_values(&self, order: BitOrder) -> Vec<(usize, bool)> {
        self.group
            .wires()
            .iter()
            .copied()
            .zip(self.value.to_bits(order).into_iter())
            .collect()
    }

    /// Creates group value from LSB0 bit string
    #[inline]
    pub fn from_bits(group: T, bits: Vec<bool>, order: BitOrder) -> Result<Self, GroupError> {
        if group.len() != bits.len() {
            return Err(GroupError::InvalidLength(
                group.id().clone(),
                group.len(),
                bits.len(),
            ));
        }

        let value = Value::new(group.value_type(), bits, order)
            .map_err(|e| GroupError::ValueError(group.id().clone(), e))?;

        Ok(Self { group, value })
    }
}

impl<T> WireGroup for GroupValue<T>
where
    T: WireGroup,
{
    fn circuit(&self) -> Arc<Circuit> {
        self.group.circuit()
    }

    #[inline]
    fn index(&self) -> usize {
        self.group.index()
    }

    #[inline]
    fn id(&self) -> &GroupId {
        self.group.id()
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

#[derive(Debug, Clone)]
pub(crate) struct UncheckedGroup {
    index: usize,
    id: String,
    desc: String,
    value_type: ValueType,
    pub(crate) wires: Vec<usize>,
}

impl UncheckedGroup {
    pub(crate) fn new(
        index: usize,
        id: String,
        desc: String,
        value_type: ValueType,
        wires: Vec<usize>,
    ) -> Self {
        Self {
            index,
            id,
            desc,
            value_type,
            wires,
        }
    }
}

impl WireGroup for UncheckedGroup {
    fn circuit(&self) -> Arc<Circuit> {
        unimplemented!()
    }

    #[inline]
    fn index(&self) -> usize {
        self.index
    }

    #[inline]
    fn id(&self) -> &GroupId {
        unimplemented!()
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

impl From<Group> for UncheckedGroup {
    fn from(group: Group) -> Self {
        Self {
            index: group.index,
            id: group.id.0,
            desc: group.desc,
            value_type: group.value_type,
            wires: group.wires,
        }
    }
}
