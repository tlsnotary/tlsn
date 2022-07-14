pub mod base;
pub mod extension;

pub use base::*;
pub use extension::*;

#[derive(Debug, Clone)]
pub enum Message {
    BaseSenderSetup(dh_ot::SenderSetup),
    BaseSenderSetupWrapper(kos15::BaseSenderSetupWrapper),
    BaseSenderPayload(dh_ot::SenderPayload),
    BaseSenderPayloadWrapper(kos15::BaseSenderPayloadWrapper),
    BaseReceiverSetup(dh_ot::ReceiverSetup),
    BaseReceiverSetupWrapper(kos15::BaseReceiverSetupWrapper),
    ExtReceiverSetup(kos15::ExtReceiverSetup),
    ExtDerandomize(kos15::ExtDerandomize),
    ExtSenderPayload(kos15::ExtSenderPayload),
}
