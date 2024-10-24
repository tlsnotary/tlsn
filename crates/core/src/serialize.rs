/// Canonical serialization of TLSNotary types.
///
/// This trait is used to serialize types into a canonical byte representation.
pub(crate) trait CanonicalSerialize {
    /// Serializes the type.
    fn serialize(&self) -> Vec<u8>;
}

impl<T> CanonicalSerialize for T
where
    T: serde::Serialize,
{
    fn serialize(&self) -> Vec<u8> {
        // For now we use BCS for serialization. In future releases we will want to
        // consider this further, particularly with respect to EVM compatibility.
        bcs::to_bytes(self).unwrap()
    }
}
