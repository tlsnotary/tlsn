pub mod base;
pub mod extension;

pub use base::*;
pub use extension::*;

#[derive(Debug, Clone)]
pub enum Message {
    SenderSetup(SenderSetup),
    SenderPayload(SenderPayload),
    ReceiverSetup(ReceiverSetup),
    ExtReceiverSetup(ExtReceiverSetup),
    ExtSenderPayload(ExtSenderPayload),
}
