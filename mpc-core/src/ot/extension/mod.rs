mod kos15;

pub use kos15::receiver::{error::ExtReceiverCoreError, state as r_state, Kos15Receiver};
pub use kos15::sender::{error::ExtSenderCoreError, state as s_state, Kos15Sender};

pub use kos15::BASE_COUNT;
