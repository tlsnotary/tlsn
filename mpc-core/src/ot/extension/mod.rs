mod kos15;

pub use kos15::receiver::r_state;
pub use kos15::receiver::{error::ExtReceiverCoreError, Kos15Receiver};

pub use kos15::sender::s_state;
pub use kos15::sender::{error::ExtSenderCoreError, Kos15Sender};

pub use kos15::BASE_COUNT;
