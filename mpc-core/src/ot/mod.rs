pub mod base;
pub mod extension;

pub use base::*;
pub use extension::*;

#[derive(Debug, Clone)]
pub enum Kos15Message {
    SenderSetup(dh_ot::SenderSetup),
    BaseSenderSetup(kos15::SenderSetup),
    SenderPayload(dh_ot::SenderPayload),
    BaseSenderPayload(kos15::BaseSenderPayloadWrapper),
    ReceiverSetup(dh_ot::ReceiverSetup),
    BaseReceiverSetup(kos15::BaseReceiverSetupWrapper),
    ExtReceiverSetup(kos15::ReceiverSetup),
    ExtDerandomize(kos15::ExtDerandomize),
    ExtSenderPayload(kos15::SenderPayload),
}
