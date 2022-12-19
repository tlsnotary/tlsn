mod receiver;
mod sender;

pub use receiver::Receiver;
pub use sender::Sender;

pub struct SendTapeMessage;
pub struct VerifyTapeMessage;
pub struct M2AMessage<T>(T);
pub struct A2MMessage<T>(T);
