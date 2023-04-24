//! Various configuration used in the protocol

use mpc_circuits::types::{StaticValueType, Value, ValueType};

use crate::{ValueId, ValueRef};

/// Role in 2PC.
#[derive(Debug, Default, Clone, Copy, PartialEq)]
#[allow(missing_docs)]
pub enum Role {
    #[default]
    Leader,
    Follower,
}

#[derive(Debug)]
#[allow(missing_docs)]
#[allow(dead_code)]
pub struct ValueConfigError {
    value_ref: ValueRef,
    ty: ValueType,
    value: Option<Value>,
    visibility: Visibility,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum Visibility {
    Public,
    Private,
}

/// Configuration of a value
#[derive(Debug, Clone)]
#[allow(missing_docs)]
pub enum ValueConfig {
    /// A value known to all parties
    Public {
        value_ref: ValueRef,
        ty: ValueType,
        value: Value,
    },
    /// A private value
    Private {
        value_ref: ValueRef,
        ty: ValueType,
        value: Option<Value>,
    },
}

/// Configuration of a value
#[derive(Debug, Clone)]
#[allow(missing_docs)]
pub(crate) enum ValueIdConfig {
    /// A value known to all parties
    Public {
        id: ValueId,
        ty: ValueType,
        value: Value,
    },
    /// A private value
    Private {
        id: ValueId,
        ty: ValueType,
        value: Option<Value>,
    },
}

impl ValueConfig {
    /// Creates a new public value config
    pub fn new_public<T: StaticValueType>(
        value_ref: ValueRef,
        value: impl Into<Value>,
    ) -> Result<Self, ValueConfigError> {
        let value = value.into();
        let ty = value.value_type();
        Self::new(value_ref, ty, Some(value), Visibility::Public)
    }

    /// Creates a new public array value config
    pub fn new_public_array<T: StaticValueType>(
        value_ref: ValueRef,
        value: Vec<T>,
    ) -> Result<Self, ValueConfigError>
    where
        Vec<T>: Into<Value>,
    {
        let value = value.into();
        let ty = value.value_type();
        Self::new(value_ref, ty, Some(value), Visibility::Public)
    }

    /// Creates a new private value config
    pub fn new_private<T: StaticValueType>(
        value_ref: ValueRef,
        value: Option<T>,
    ) -> Result<Self, ValueConfigError> {
        let ty = T::value_type();
        let value = value.map(|value| value.into());
        Self::new(value_ref, ty, value, Visibility::Private)
    }

    /// Creates a new private array value config
    pub fn new_private_array<T: StaticValueType>(
        value_ref: ValueRef,
        value: Option<Vec<T>>,
        len: usize,
    ) -> Result<Self, ValueConfigError>
    where
        Vec<T>: Into<Value>,
    {
        let ty = ValueType::new_array::<T>(len);
        let value = value.map(|value| value.into());
        Self::new(value_ref, ty, value, Visibility::Private)
    }

    /// Creates a new value config
    pub(crate) fn new(
        value_ref: ValueRef,
        ty: ValueType,
        value: Option<Value>,
        visibility: Visibility,
    ) -> Result<Self, ValueConfigError> {
        // combinatorial explosion, anyone?
        // there must be a better way...
        //
        // invariants:
        // - public values are always set
        // - types and lengths are consistent across `value_ref`, `ty`, and `value`
        //
        // the outer context must ensure that the provided `ty` is correct for the
        // provided `value_ref`.
        Ok(match (&value_ref, &ty, &visibility, &value) {
            (_, _, Visibility::Private, _) if !value_ref.is_array() && !ty.is_array() => {
                Self::Private {
                    value_ref,
                    ty,
                    value,
                }
            }
            (_, _, Visibility::Public, Some(_)) if !value_ref.is_array() && !ty.is_array() => {
                Self::Public {
                    value_ref,
                    ty,
                    value: value.unwrap(),
                }
            }
            (ValueRef::Array(ids), ValueType::Array(_, len), Visibility::Private, _)
                if ids.len() == *len =>
            {
                Self::Private {
                    value_ref,
                    ty,
                    value,
                }
            }
            (ValueRef::Array(ids), ValueType::Array(_, len), Visibility::Public, Some(_))
                if ids.len() == *len =>
            {
                Self::Public {
                    value_ref,
                    ty,
                    value: value.unwrap(),
                }
            }
            _ => {
                return Err(ValueConfigError {
                    value_ref,
                    ty,
                    value,
                    visibility,
                })
            }
        })
    }

    /// Flattens to a vector of `ValueConfig`
    pub(crate) fn flatten(self) -> Vec<ValueIdConfig> {
        match self {
            ValueConfig::Public {
                value_ref,
                ty,
                value,
            } => match value_ref {
                ValueRef::Value { id } => {
                    vec![ValueIdConfig::Public { id, ty, value }]
                }
                ValueRef::Array(ids) => {
                    let ValueType::Array(elem_ty, _) = ty else {
                        panic!("expected array type");
                    };

                    let elem_ty = *elem_ty;

                    let Value::Array(value) = value else {
                        panic!("expected array value");
                    };

                    ids.into_iter()
                        .zip(value)
                        .map(|(id, value)| ValueIdConfig::Public {
                            id,
                            ty: elem_ty.clone(),
                            value,
                        })
                        .collect()
                }
            },
            ValueConfig::Private {
                value_ref,
                ty,
                value,
            } => match value_ref {
                ValueRef::Value { id } => {
                    vec![ValueIdConfig::Private { id, ty, value }]
                }
                ValueRef::Array(ids) => {
                    let ValueType::Array(elem_ty, _) = ty else {
                        panic!("expected array type");
                    };

                    let elem_ty = *elem_ty;

                    let values = if let Some(value) = value {
                        let Value::Array(value) = value else {
                            panic!("expected array value");
                        };

                        value.into_iter().map(Option::Some).collect()
                    } else {
                        vec![None; ids.len()]
                    };

                    ids.into_iter()
                        .zip(values)
                        .map(|(id, value)| ValueIdConfig::Private {
                            id,
                            ty: elem_ty.clone(),
                            value,
                        })
                        .collect()
                }
            },
        }
    }
}

impl ValueIdConfig {
    /// Returns the ID of the value
    pub(crate) fn id(&self) -> &ValueId {
        match self {
            ValueIdConfig::Public { id, .. } => id,
            ValueIdConfig::Private { id, .. } => id,
        }
    }

    /// Returns the value type
    pub(crate) fn value_type(&self) -> &ValueType {
        match self {
            ValueIdConfig::Public { ty, .. } => ty,
            ValueIdConfig::Private { ty, .. } => ty,
        }
    }
}
