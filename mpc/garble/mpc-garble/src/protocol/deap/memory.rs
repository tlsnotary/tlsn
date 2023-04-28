use mpc_circuits::types::{StaticValueType, TypeError, Value, ValueType};

use crate::{
    config::{ValueConfig, Visibility},
    Memory, MemoryError, ValueRef,
};

use super::DEAP;

impl Memory for DEAP {
    fn new_public_input<T: StaticValueType>(
        &self,
        id: &str,
        value: T,
    ) -> Result<ValueRef, crate::MemoryError> {
        let mut state = self.state();

        let ty = T::value_type();
        let value_ref = state.value_registry.add_value(id, ty)?;

        state.add_input_config(
            &value_ref,
            ValueConfig::new_public::<T>(value_ref.clone(), value).expect("config is valid"),
        );

        Ok(value_ref)
    }

    fn new_public_array_input<T: StaticValueType>(
        &self,
        id: &str,
        value: Vec<T>,
    ) -> Result<ValueRef, crate::MemoryError>
    where
        Vec<T>: Into<Value>,
    {
        let mut state = self.state();

        let value: Value = value.into();
        let ty = value.value_type();
        let value_ref = state.value_registry.add_value(id, ty)?;

        state.add_input_config(
            &value_ref,
            ValueConfig::new_public::<T>(value_ref.clone(), value).expect("config is valid"),
        );

        Ok(value_ref)
    }

    fn new_public_input_by_type(&self, id: &str, value: Value) -> Result<ValueRef, MemoryError> {
        let mut state = self.state();

        let ty = value.value_type();
        let value_ref = state.value_registry.add_value(id, ty.clone())?;

        state.add_input_config(
            &value_ref,
            ValueConfig::new(value_ref.clone(), ty, Some(value), Visibility::Public)
                .expect("config is valid"),
        );

        Ok(value_ref)
    }

    fn new_private_input<T: StaticValueType>(
        &self,
        id: &str,
        value: Option<T>,
    ) -> Result<ValueRef, crate::MemoryError> {
        let mut state = self.state();

        let ty = T::value_type();
        let value_ref = state.value_registry.add_value(id, ty)?;

        state.add_input_config(
            &value_ref,
            ValueConfig::new_private::<T>(value_ref.clone(), value).expect("config is valid"),
        );

        Ok(value_ref)
    }

    fn new_private_array_input<T: StaticValueType>(
        &self,
        id: &str,
        value: Option<Vec<T>>,
        len: usize,
    ) -> Result<ValueRef, crate::MemoryError>
    where
        Vec<T>: Into<Value>,
    {
        let mut state = self.state();

        let ty = ValueType::new_array::<T>(len);
        let value_ref = state.value_registry.add_value(id, ty)?;

        state.add_input_config(
            &value_ref,
            ValueConfig::new_private_array::<T>(value_ref.clone(), value, len)
                .expect("config is valid"),
        );

        Ok(value_ref)
    }

    fn new_private_input_by_type(
        &self,
        id: &str,
        ty: &ValueType,
        value: Option<Value>,
    ) -> Result<ValueRef, MemoryError> {
        if let Some(value) = &value {
            if &value.value_type() != ty {
                return Err(TypeError::UnexpectedType {
                    expected: ty.clone(),
                    actual: value.value_type(),
                })?;
            }
        }

        let mut state = self.state();

        let value_ref = state.value_registry.add_value(id, ty.clone())?;

        state.add_input_config(
            &value_ref,
            ValueConfig::new(value_ref.clone(), ty.clone(), value, Visibility::Private)
                .expect("config is valid"),
        );

        Ok(value_ref)
    }

    fn new_output<T: StaticValueType>(&self, id: &str) -> Result<ValueRef, crate::MemoryError> {
        let mut state = self.state();

        let ty = T::value_type();
        let value_ref = state.value_registry.add_value(id, ty)?;

        Ok(value_ref)
    }

    fn new_array_output<T: StaticValueType>(
        &self,
        id: &str,
        len: usize,
    ) -> Result<ValueRef, crate::MemoryError>
    where
        Vec<T>: Into<Value>,
    {
        let mut state = self.state();

        let ty = ValueType::new_array::<T>(len);
        let value_ref = state.value_registry.add_value(id, ty)?;

        Ok(value_ref)
    }

    fn new_output_by_type(&self, id: &str, ty: &ValueType) -> Result<ValueRef, MemoryError> {
        let mut state = self.state();

        let value_ref = state.value_registry.add_value(id, ty.clone())?;

        Ok(value_ref)
    }

    fn get_value(&self, id: &str) -> Option<ValueRef> {
        self.state().value_registry.get_value(id)
    }

    fn get_value_type(&self, id: &str) -> Option<ValueType> {
        self.state().value_registry.get_value_type(id)
    }
}
