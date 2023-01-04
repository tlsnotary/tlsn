mod receiver;
mod sender;

pub use receiver::{Receiver, ReceiverControl};
pub use sender::{Sender, SenderControl};

pub struct SendTapeMessage;
pub struct VerifyTapeMessage;
pub struct M2AMessage<T>(T);
pub struct A2MMessage<T>(T);
