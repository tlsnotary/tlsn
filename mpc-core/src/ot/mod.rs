pub mod base;
pub mod extension;

pub use base::*;
pub use extension::*;

#[derive(Debug, Clone)]
pub enum Message {
    SenderSetup(SenderSetup),
    BaseSenderSetup(BaseSenderSetup),
    SenderPayload(SenderPayload),
    BaseSenderPayload(BaseSenderPayload),
    ReceiverSetup(ReceiverSetup),
    BaseReceiverSetup(BaseReceiverSetup),
    ExtReceiverSetup(ExtReceiverSetup),
    ExtDerandomize(ExtDerandomize),
    ExtSenderPayload(ExtSenderPayload),
}
