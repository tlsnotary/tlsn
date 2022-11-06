use gf2_128::MaskedPartialValue;

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
/// Messages for 2PC Ghash computation
pub enum GhashMessage {
    SenderAddSharing(SenderAddSharing),
    SenderMulPowerSharings(SenderMulPowerSharings),
    ReceiverAddChoice(ReceiverAddChoice),
    ReceiverMulPowerChoices(ReceiverMulPowerChoices),
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
/// The sender input for the oblivious transfer of the additive share of `H`
pub struct SenderAddSharing(pub Box<MaskedPartialValue>);

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
/// The sender input for the batched oblivious transfer of the powers of the multiplicative share
/// `H`
pub struct SenderMulPowerSharings(pub Vec<MaskedPartialValue>);

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
/// The receiver choice for the oblivious transfer of the additive share of `H`
pub struct ReceiverAddChoice(pub u128);

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
/// The receiver choices for the batched oblivious transfer of the powers of the multiplicative share `H`
pub struct ReceiverMulPowerChoices(pub Vec<u128>);
