pub mod base;
pub mod extension;

pub use base::*;
pub use extension::*;

#[derive(Debug, Clone)]
pub enum Kos15Message {
    SenderSetup(dh_ot::SenderSetup),
    BaseSenderSetup(kos15::BaseSenderSetup),
    SenderPayload(dh_ot::SenderPayload),
    BaseSenderPayload(kos15::BaseSenderPayload),
    ReceiverSetup(dh_ot::ReceiverChoices),
    BaseReceiverSetup(kos15::BaseReceiverSetup),
    ExtReceiverSetup(kos15::ExtReceiverSetup),
    ExtDerandomize(kos15::ExtDerandomize),
    ExtSenderPayload(kos15::ExtSenderPayload),
}
