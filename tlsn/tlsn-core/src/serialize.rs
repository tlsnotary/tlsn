/// Canonical serialization of TLSNotary types.
///
/// This trait is used to serialize types into a canonical byte representation.
///
/// It is critical that the serialization is deterministic and unambiguous.
pub(crate) trait CanonicalSerialize {
    /// Serializes the type into a byte vector.
    fn serialize(&self) -> Vec<u8>;
}
