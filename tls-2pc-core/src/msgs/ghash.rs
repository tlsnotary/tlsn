#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[allow(clippy::large_enum_variant)]
/// Messages for 2PC Ghash computation
pub enum GhashMessage {
    SenderAddSharing(SenderAddSharing),
    SenderMulSharings(SenderMulSharings),
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
/// The sender input for the oblivious transfer of the additive share of `H`
pub struct SenderAddSharing {
    pub sender_add_sharing: ([u128; 128], [u128; 128]),
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
/// The sender input for the batched oblivious transfer of the powers of the multiplicative share
/// `H`
pub struct SenderMulSharings {
    pub sender_mul_sharing: Vec<([u128; 128], [u128; 128])>,
}

#[derive(Debug, Clone)]
/// The receiver choice for the oblivious transfer of the additive share of `H`
pub struct ReceiverAddChoice(pub u128);

#[derive(Debug, Clone)]
/// The receiver choices for the batched oblivious transfer of the powers of the multiplicative share `H`
pub struct ReceiverMulPowerChoices(pub Vec<u128>);
